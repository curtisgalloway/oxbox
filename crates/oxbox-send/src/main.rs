// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! Supervised bridge to an untrusted model.
//!
//! Text in, text out. No tools are ever registered with the model, so it has
//! no way to run a command, read a file it was not handed, or write to disk.
//! Every request and response is logged for audit. The caller reviews the
//! output before anything touches a real tree.
//!
//! This is the executable `oxbox send` runs, and the only one in the
//! workspace that talks to the network -- so the only one carrying
//! dependencies beyond the standard library.

use std::env;
use std::fs;
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fancy_regex::Regex;
use serde_json::{Map, Value, json};
use sha2::{Digest, Sha256};

use oxbox_core as core;

const PROG: &str = "oxbox-send";

/// Where a request may be sent, and which key goes with it.
///
/// The pairing is the point. The key goes out as a Bearer token to whatever
/// URL this is pointed at, so one `--base-url` flag over one hardcoded key
/// would mean a mistyped host receives your OpenRouter credential. Binding
/// each venue to its own environment variable makes that impossible by
/// construction: asking for zenmux reads ZENMUX_API_KEY and nothing else.
///
/// No venue names a default model, on purpose: the listings worth pointing
/// this at change week to week, and a default that names one goes stale
/// without saying so. The survey is the list that gets updated.
struct Venue {
    name: &'static str,
    url: &'static str,
    key_env: &'static str,
}

const VENUES: [Venue; 4] = [
    Venue {
        name: "openrouter",
        url: "https://openrouter.ai/api/v1/chat/completions",
        key_env: "OPENROUTER_API_KEY",
    },
    Venue {
        name: "zenmux",
        url: "https://zenmux.ai/api/v1/chat/completions",
        key_env: "ZENMUX_API_KEY",
    },
    Venue {
        name: "opencode",
        url: "https://opencode.ai/zen/v1/chat/completions",
        key_env: "OPENCODE_ZEN_API_KEY",
    },
    Venue {
        name: "requesty",
        url: "https://router.requesty.ai/v1/chat/completions",
        key_env: "REQUESTY_API_KEY",
    },
];
const DEFAULT_VENUE: &str = "openrouter";
const USER_AGENT: &str = "oxbox (+https://github.com/curtisgalloway/oxbox)";
const MAX_PAYLOAD_BYTES: usize = 400_000;
const TIMEOUT_SECONDS: u64 = 900;
const DEFAULT_MAX_TOKENS: u64 = 100_000;
/// The reasoning-effort ladder, weakest first: the levels venues accept,
/// not a scale of this tool's own. No model accepts all five, so the ladder
/// is a vocabulary rather than a promise; which levels a model takes is a
/// per-model fact that belongs in the manifest entry beside max_tokens.
const EFFORTS: [&str; 5] = ["low", "medium", "high", "xhigh", "max"];
const DEFAULT_EFFORT: &str = "high";
const MANIFEST_VERSION: i64 = 0;
/// A manifest fetched by URL is a few kilobytes of JSON; anything past this
/// cap is not one.
const MANIFEST_MAX_BYTES: usize = 1_048_576;
const MANIFEST_TIMEOUT_SECONDS: u64 = 30;

/// The same patterns the Python scanner carried, as data. fancy-regex is
/// used rather than regex because two of them need lookahead
/// (`token(?!s)`) and case-insensitive groups, and rewriting them would make
/// this a different scanner.
const SECRET_PATTERNS: [(&str, &str); 9] = [
    (r"sk-[A-Za-z0-9_\-]{20,}", "OpenAI-style API key"),
    (r"sk-ant-[A-Za-z0-9_\-]{20,}", "Anthropic API key"),
    (r"ghp_[A-Za-z0-9]{36}", "GitHub personal access token"),
    (r"github_pat_[A-Za-z0-9_]{50,}", "GitHub fine-grained token"),
    (r"AKIA[0-9A-Z]{16}", "AWS access key id"),
    (r"xox[baprs]-[A-Za-z0-9\-]{10,}", "Slack token"),
    (r"-----BEGIN [A-Z ]*PRIVATE KEY-----", "private key block"),
    // "_" is a word character, so \bsecret\b never matches inside
    // client_secret or aws_secret_access_key; the identifier run on either
    // side fixes that, and the unquoted alternative catches .env files and
    // shell exports. token(?!s) keeps max_tokens and completion_tokens from
    // matching every request this tool builds.
    (
        r#"(?i)[A-Za-z0-9_\-]*(?:api[_\-]?key|secret|password|passwd|token(?!s)|credential)[A-Za-z0-9_\-]*\s*[:=]\s*(?:["'][^"'\s]{12,}["']|[^\s"'()\[\]{}#,;]{16,})"#,
        "hardcoded credential assignment",
    ),
    // AKIA... above is only the access key id, which is not itself a secret.
    (
        r#"(?i)aws[_\-]?secret[_\-]?access[_\-]?key["']?\s*[:=]\s*["']?[A-Za-z0-9/+=]{40}"#,
        "AWS secret access key",
    ),
];

const MODES: [&str; 3] = ["ask", "diff", "review"];

fn system_prompt(mode: &str) -> &'static str {
    match mode {
        "diff" => {
            "You are a software engineer. Produce a fix for the task described.\n\
             \n\
             Output contract, strictly:\n\
             1. A short plain-text explanation of what you changed and why (max 10 lines).\n\
             2. Then a single fenced block tagged `diff` containing a unified diff.\n\
             \n\
             Diff rules:\n\
             - Use `--- a/<path>` and `+++ b/<path>` headers with the exact paths given to you.\n\
             - Include at least 3 lines of context per hunk so the patch applies cleanly.\n\
             - Change only what the task requires. Do not reformat, rename, or tidy\n\
             \x20 unrelated code. Do not add dependencies unless the task requires it, and\n\
             \x20 if you do, say so explicitly in the explanation.\n\
             - If you cannot solve it, say so plainly instead of guessing."
        }
        "review" => {
            "You are reviewing code. Report concrete defects only: correctness bugs,\n\
             security issues, resource leaks, race conditions, incorrect error handling.\n\
             \n\
             For each finding give: file and line, a one-sentence statement of the defect,\n\
             and a concrete failure scenario (specific inputs or state leading to the wrong\n\
             outcome). If you are not confident a finding is real, label it UNCERTAIN.\n\
             Do not report style preferences. If the code is fine, say so."
        }
        _ => {
            "Answer the question directly and concretely. If you are uncertain about an\n\
             API, a version, or a behavior, say that you are uncertain rather than\n\
             presenting a guess as fact."
        }
    }
}

// ── test overrides ──────────────────────────────────────────────────────────
//
// wiretest drives a copy of the Python oxbox-send with its venue URLs and
// scheme guards rewritten to point at a loopback listener. A binary cannot be
// patched that way, so the same knobs are compiled in behind a feature that a
// release build does not have. Without the feature these return the built-in
// values and the environment is not consulted.

fn venue_url(venue: &Venue) -> String {
    #[cfg(feature = "test-overrides")]
    if let Ok(raw) = env::var("OXBOX_TEST_VENUE_URLS")
        && let Ok(Value::Object(map)) = serde_json::from_str::<Value>(&raw)
        && let Some(Value::String(url)) = map.get(venue.name)
    {
        return url.clone();
    }
    venue.url.to_string()
}

fn https_required() -> bool {
    #[cfg(feature = "test-overrides")]
    if env::var("OXBOX_TEST_ALLOW_HTTP").is_ok_and(|v| v == "1") {
        return false;
    }
    true
}

fn manifest_max_bytes() -> usize {
    #[cfg(feature = "test-overrides")]
    if let Some(n) = env::var("OXBOX_TEST_MANIFEST_MAX_BYTES")
        .ok()
        .and_then(|v| v.parse().ok())
    {
        return n;
    }
    MANIFEST_MAX_BYTES
}

// ── how a run ends ──────────────────────────────────────────────────────────

/// Every way out of `run` other than success. `Message` is Python's
/// `sys.exit("text")`: printed to stderr, exit 1, recorded in the status
/// file. `Code` is a bare exit whose diagnosis is already on stderr.
enum Exit {
    Message(String),
    Code(i32),
}

fn quit(message: impl Into<String>) -> Exit {
    Exit::Message(message.into())
}

/// A post-send failure: the request went out and came back unusable. Kept
/// separate from `Exit` so `--failover` can move to the next manifest entry;
/// without `--failover` it becomes the same exit it always was.
struct AttemptFailed(String);

fn say(message: &str) {
    core::diagnose(PROG, message);
}

fn write_lf(path: &Path, text: &str) -> io::Result<()> {
    fs::write(path, text.as_bytes())
}

/// Write one audit artifact, or say on stderr why it could not be. A log
/// write can fail for reasons that have nothing to do with the run, and a
/// completed response that cannot be filed is still a completed response.
fn write_log(path: &Path, text: &str) {
    if let Err(error) = write_lf(path, text) {
        say(&format!(
            "could not write {}: {error}",
            path.file_name()
                .map(|n| n.to_string_lossy())
                .unwrap_or_default()
        ));
    }
}

fn pretty(value: &Value) -> String {
    serde_json::to_string_pretty(value).unwrap_or_else(|_| "{}".to_string())
}

/// The first `n` characters of a string, the way Python's `text[:n]` cuts.
fn head(text: &str, n: usize) -> String {
    text.chars().take(n).collect()
}

// ── the status record ───────────────────────────────────────────────────────

/// The run summary, written on every exit after argument parsing so a script
/// checks a fact instead of relying on pipeline exit codes. Keys stay in this
/// order because the record is read by people as well as scripts.
fn new_status() -> Map<String, Value> {
    let mut status = Map::new();
    for (key, value) in [
        ("ox_version", json!(core::VERSION)),
        ("ok", json!(false)),
        ("exit_code", Value::Null),
        ("error", Value::Null),
        ("venue", Value::Null),
        ("model", Value::Null),
        ("mode", Value::Null),
        ("dry_run", json!(false)),
        ("log_dir", Value::Null),
        ("output", Value::Null),
        ("finish_reason", Value::Null),
        ("prompt_tokens", Value::Null),
        ("completion_tokens", Value::Null),
        ("reasoning_tokens", Value::Null),
        ("reasoning_chars", Value::Null),
        ("truncated", Value::Null),
        ("venue_cost", Value::Null),
        ("route", Value::Null),
        ("manifest", Value::Null),
        ("attempts", Value::Null),
        ("status_file", Value::Null),
    ] {
        status.insert(key.to_string(), value);
    }
    status
}

/// Write the run summary everywhere it belongs: `status.json` beside the
/// other audit artifacts once the log directory exists, and the path named
/// by `--status-file` if the caller gave one. A failed write warns rather
/// than fails -- this runs on the way out.
fn write_status(status: &Map<String, Value>) {
    let mut record = status.clone();
    record.remove("status_file");
    let text = pretty(&Value::Object(record));
    let mut targets = Vec::new();
    if let Some(Value::String(dir)) = status.get("log_dir") {
        targets.push(PathBuf::from(dir).join("status.json"));
    }
    if let Some(Value::String(file)) = status.get("status_file") {
        targets.push(PathBuf::from(file));
    }
    for target in targets {
        if let Err(error) = write_lf(&target, &text) {
            say(&format!(
                "could not write status to {}: {error}",
                target.display()
            ));
        }
    }
}

// ── the secret scanner ──────────────────────────────────────────────────────

fn scan_for_secrets(text: &str, label: &str) -> Vec<String> {
    let mut hits = Vec::new();
    for (pattern, description) in SECRET_PATTERNS {
        let regex = Regex::new(pattern).expect("a scanner pattern is invalid");
        for found in regex.find_iter(text).flatten() {
            let line_no = text[..found.start()].matches('\n').count() + 1;
            hits.push(format!("{label}:{line_no}: possible {description}"));
        }
    }
    hits
}

struct Context {
    text: String,
    total_bytes: usize,
    findings: Vec<String>,
}

fn build_context(paths: &[String], force: bool, task: &str) -> Result<Context, Exit> {
    let mut blocks = Vec::new();
    // The task string goes to the provider exactly like file bodies do, so
    // it gets scanned exactly like file bodies do.
    let mut findings = if task.is_empty() {
        Vec::new()
    } else {
        scan_for_secrets(task, "<task text>")
    };
    let mut total = 0;
    for raw in paths {
        let path = Path::new(raw);
        if !path.is_file() {
            return Err(quit(format!("not a file: {raw}")));
        }
        let bytes = fs::read(path).map_err(|error| quit(format!("cannot read {raw}: {error}")))?;
        let body = String::from_utf8(bytes).map_err(|_| quit(format!("not a text file: {raw}")))?;
        total += body.len();
        findings.extend(scan_for_secrets(&body, raw));
        let suffix = path
            .extension()
            .map(|ext| ext.to_string_lossy().into_owned())
            .filter(|ext| !ext.is_empty())
            .unwrap_or_else(|| "text".to_string());
        blocks.push(format!("### File: {raw}\n```{suffix}\n{body}\n```"));
    }

    if !findings.is_empty() && !force {
        eprintln!("{PROG}: refusing to send; possible secrets detected:");
        for finding in &findings {
            eprintln!("  {finding}");
        }
        eprintln!(
            "{PROG}: this model logs prompts and shares them with the provider.\n\
             {PROG}: remove the secrets, or re-run with --force if these are false positives."
        );
        return Err(Exit::Code(2));
    }
    if total > MAX_PAYLOAD_BYTES && !force {
        return Err(quit(format!(
            "refusing to send {total} bytes of context (limit {MAX_PAYLOAD_BYTES}); \
             narrow --files or pass --force"
        )));
    }
    Ok(Context {
        text: blocks.join("\n\n"),
        total_bytes: total,
        findings,
    })
}

// ── the manifest ────────────────────────────────────────────────────────────

struct Entry {
    position: usize,
    venue: String,
    model: String,
    why: String,
    params: Map<String, Value>,
    skip: Option<String>,
    url: String,
    key_env: String,
}

struct ManifestInfo {
    path: String,
    sha256: String,
    fetched: bool,
    raw: Vec<u8>,
    defaults: Map<String, Value>,
}

fn agent(timeout: u64) -> ureq::Agent {
    ureq::Agent::config_builder()
        // A 3xx is answered, not followed: the default handler would rebuild
        // the request keeping every header, Authorization included, and hand
        // the Bearer token to whatever host the Location line names.
        .max_redirects(0)
        .http_status_as_error(false)
        .user_agent(USER_AGENT)
        .timeout_global(Some(Duration::from_secs(timeout)))
        .build()
        .new_agent()
}

/// Download a survey manifest, carrying nothing and following nothing:
/// https only, no redirects, no credential. The bytes come back exactly as
/// served, and the caller writes them into the run's log directory.
fn fetch_manifest(url: &str) -> Result<Vec<u8>, Exit> {
    if https_required() && !url.starts_with("https://") {
        return Err(quit(format!(
            "--manifest URL must be https:// (got {url:?}); a manifest chooses where the \
             payload goes, so it must not arrive in cleartext"
        )));
    }
    let cap = manifest_max_bytes();
    let response = agent(MANIFEST_TIMEOUT_SECONDS)
        .get(url)
        .header("Accept", "application/json")
        .call()
        .map_err(|error| quit(format!("cannot fetch manifest {url}: {error}")))?;
    let code = response.status().as_u16();
    if (300..400).contains(&code) {
        let target = response
            .headers()
            .get("Location")
            .and_then(|value| value.to_str().ok())
            .unwrap_or("an unnamed location");
        return Err(quit(format!(
            "manifest {url} redirected (HTTP {code} to {target}); a manifest is read from \
             where it was named or not at all"
        )));
    }
    if code >= 400 {
        return Err(quit(format!("manifest {url}: HTTP {code}")));
    }
    let mut response = response;
    let raw = response
        .body_mut()
        .with_config()
        .limit(cap as u64 + 1)
        .read_to_vec()
        .map_err(|error| quit(format!("cannot fetch manifest {url}: {error}")))?;
    if raw.len() > cap {
        return Err(quit(format!(
            "manifest {url} is larger than {cap} bytes, which no manifest is"
        )));
    }
    say(&format!("fetched manifest {url} ({} bytes)", raw.len()));
    Ok(raw)
}

/// Take an effort level from a manifest, or nothing if it is not one. A
/// manifest is an outside document, and an effort this tool does not know is
/// an effort no venue knows either.
fn manifest_effort(value: &Value, where_: &str) -> Value {
    if let Value::String(level) = value
        && EFFORTS.contains(&level.as_str())
    {
        return value.clone();
    }
    say(&format!(
        "ignoring unrecognized effort {} in {where_} (known: {})",
        python_repr(value),
        EFFORTS.join(", ")
    ));
    Value::Null
}

/// `repr()` for the JSON values that appear in diagnostics, so the messages
/// read the way the Python ones did.
fn python_repr(value: &Value) -> String {
    match value {
        Value::String(text) => format!("'{text}'"),
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        other => other.to_string(),
    }
}

/// Read a survey manifest -- a file or an https URL -- and decide which
/// entries this run may use. The manifest chooses provider and model; it
/// never chooses where a credential goes: `venue` must name an entry in the
/// VENUES table, and a `base_url` in the file is documentation only.
fn load_manifest(path: &str, allow_paid: bool) -> Result<(Vec<Entry>, ManifestInfo), Exit> {
    let fetched = path.contains("://");
    let raw = if fetched {
        fetch_manifest(path)?
    } else {
        fs::read(path).map_err(|error| quit(format!("cannot read manifest {path}: {error}")))?
    };
    let sha256 = format!("{:x}", Sha256::digest(&raw));
    let text = std::str::from_utf8(&raw)
        .map_err(|error| quit(format!("manifest {path} is not valid JSON: {error}")))?;
    let data: Value = serde_json::from_str(text)
        .map_err(|error| quit(format!("manifest {path} is not valid JSON: {error}")))?;

    // The survey ships more than one manifest-shaped file; this is the field
    // that tells a recommendations manifest from its corpus manifest.
    let version = data.get("manifest_version").cloned().unwrap_or(Value::Null);
    let Some(version_number) = version.as_i64().filter(|_| !version.is_boolean()) else {
        return Err(quit(format!(
            "{path} is not a recommendations manifest: manifest_version must be an integer, \
             found {}",
            python_repr(&version)
        )));
    };
    if version_number > MANIFEST_VERSION {
        return Err(quit(format!(
            "manifest version {version_number} is newer than this ox understands \
             ({MANIFEST_VERSION}); update ox, or use an older manifest"
        )));
    }

    let mut defaults = match data.get("defaults") {
        Some(Value::Object(map)) => map.clone(),
        Some(Value::Null) | None => Map::new(),
        Some(_) => {
            say("manifest defaults is not an object; ignoring it");
            Map::new()
        }
    };
    let unknown: Vec<&String> = defaults
        .keys()
        .filter(|key| key.as_str() != "max_tokens" && key.as_str() != "effort")
        .collect();
    if !unknown.is_empty() {
        let mut names: Vec<String> = unknown.into_iter().cloned().collect();
        names.sort();
        say(&format!(
            "ignoring unrecognized manifest defaults: {}",
            names.join(", ")
        ));
    }
    if let Some(effort) = defaults.get("effort").cloned() {
        defaults.insert(
            "effort".to_string(),
            manifest_effort(&effort, "manifest defaults"),
        );
    }

    let Some(Value::Array(recs)) = data.get("recommendations") else {
        return Err(quit(format!("manifest {path} has no recommendations")));
    };
    if recs.is_empty() {
        return Err(quit(format!("manifest {path} has no recommendations")));
    }

    let mut entries = Vec::new();
    for (index, rec) in recs.iter().enumerate() {
        let Value::Object(rec) = rec else {
            return Err(quit(format!(
                "manifest {path} recommendation {} is not an object",
                index + 1
            )));
        };
        let mut params = match rec.get("params") {
            Some(Value::Object(map)) => map.clone(),
            _ => Map::new(),
        };
        if let Some(effort) = params.get("effort").cloned() {
            params.insert(
                "effort".to_string(),
                manifest_effort(&effort, &format!("recommendation {}", index + 1)),
            );
        }
        let venue = rec
            .get("venue")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        let model = rec
            .get("model")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        // Omitted cost means unknown, and unknown behaves as paid.
        let cost = rec
            .get("cost")
            .and_then(Value::as_str)
            .filter(|cost| !cost.is_empty())
            .unwrap_or("unknown")
            .to_string();
        let why = rec
            .get("why")
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_string();
        if let Some(rank) = rec.get("rank")
            && !rank.is_null()
            && rank.as_u64() != Some(index as u64 + 1)
        {
            say(&format!(
                "manifest rank {rank} disagrees with position {}; position is authoritative",
                index + 1
            ));
        }
        let mut entry = Entry {
            position: index + 1,
            venue: venue.clone(),
            model: model.clone(),
            why,
            params,
            skip: None,
            url: String::new(),
            key_env: String::new(),
        };
        let spec = VENUES.iter().find(|spec| spec.name == venue);
        match spec {
            None => {
                entry.skip = Some(format!(
                    "unknown venue {}",
                    python_repr(rec.get("venue").unwrap_or(&Value::Null))
                ))
            }
            Some(_) if model.is_empty() => entry.skip = Some("no model named".to_string()),
            Some(_) if cost != "free" && !allow_paid => {
                entry.skip = Some(format!("cost={cost} (pass --allow-paid to use it)"))
            }
            Some(spec) if env::var(spec.key_env).map(|v| v.is_empty()).unwrap_or(true) => {
                entry.skip = Some(format!("{} not set", spec.key_env))
            }
            Some(spec) => {
                entry.url = venue_url(spec);
                entry.key_env = spec.key_env.to_string();
                let base = rec
                    .get("base_url")
                    .and_then(Value::as_str)
                    .unwrap_or("")
                    .trim_end_matches('/')
                    .to_string();
                if !base.is_empty()
                    && entry.url != base
                    && !entry.url.starts_with(&format!("{base}/"))
                {
                    say(&format!(
                        "WARNING: manifest base_url {} for venue {venue} disagrees with ox's \
                         table ({}); the table wins — a manifest never chooses where a \
                         credential goes",
                        python_repr(rec.get("base_url").unwrap_or(&Value::Null)),
                        entry.url
                    ));
                }
            }
        }
        entries.push(entry);
    }

    Ok((
        entries,
        ManifestInfo {
            path: path.to_string(),
            sha256,
            fetched,
            raw,
            defaults,
        },
    ))
}

// ── the audit log ───────────────────────────────────────────────────────────

/// `%Y-%m-%dT%H-%M-%SZ` for now, in UTC, without a calendar crate.
fn utc_stamp() -> String {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0) as i64;
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (hour, minute, second) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    // Howard Hinnant's civil-from-days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{m:02}-{d:02}T{hour:02}-{minute:02}-{second:02}Z")
}

/// Claim a fresh directory for one request. The stamp has one-second
/// resolution, so two runs in the same second claim the directory
/// exclusively and suffix on collision rather than sharing it and
/// overwriting each other's request.json.
fn make_log_dir(base: &Path) -> Result<(String, PathBuf), Exit> {
    let stamp = utc_stamp();
    fs::create_dir_all(base).map_err(|error| {
        quit(format!(
            "cannot create log directory {}: {error}",
            base.display()
        ))
    })?;
    let mut attempt = 1;
    loop {
        let log_dir = if attempt == 1 {
            base.join(&stamp)
        } else {
            base.join(format!("{stamp}-{attempt}"))
        };
        match fs::create_dir(&log_dir) {
            Ok(()) => return Ok((stamp, log_dir)),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => attempt += 1,
            Err(error) => {
                return Err(quit(format!(
                    "cannot create log directory {}: {error}",
                    log_dir.display()
                )));
            }
        }
    }
}

// ── the request ─────────────────────────────────────────────────────────────

struct Answer {
    choice: Map<String, Value>,
    usage: Map<String, Value>,
    reasoning: String,
    content: String,
    route: Option<String>,
}

/// Send one request and extract the answer, or fail the attempt. Every
/// outcome leaves evidence in the log directory -- response.json on any JSON
/// reply, error.txt on an HTTP error or a non-JSON body, reasoning.txt and
/// content.md on success -- so a failed attempt is as auditable as a
/// successful one.
fn send_and_parse(
    api_url: &str,
    api_key: &str,
    payload: &Value,
    log_dir: &Path,
) -> Result<Answer, AttemptFailed> {
    let body_bytes = serde_json::to_vec(payload).unwrap_or_default();
    let response = agent(TIMEOUT_SECONDS)
        .post(api_url)
        .header("Authorization", format!("Bearer {api_key}"))
        .header("Content-Type", "application/json")
        .header("X-Title", "oxbox supervised bridge")
        .send(&body_bytes[..]);
    let mut response = match response {
        Ok(response) => response,
        Err(ureq::Error::Timeout(kind)) => {
            return Err(AttemptFailed(format!(
                "{PROG}: timed out after {TIMEOUT_SECONDS}s reading the response ({kind})"
            )));
        }
        Err(error) => return Err(AttemptFailed(format!("{PROG}: network error: {error}"))),
    };
    let code = response.status().as_u16();
    let raw = match response.body_mut().read_to_vec() {
        Ok(raw) => raw,
        Err(ureq::Error::Timeout(kind)) => {
            return Err(AttemptFailed(format!(
                "{PROG}: timed out after {TIMEOUT_SECONDS}s reading the response ({kind})"
            )));
        }
        Err(error) => {
            // A body that cannot be read is still an outcome to record.
            let detail = format!("<response body unreadable: {error}>");
            write_log(&log_dir.join("error.txt"), &format!("{code}\n{detail}"));
            return Err(AttemptFailed(format!("{PROG}: HTTP {code}: {detail}")));
        }
    };
    if code >= 300 {
        // 3xx included: a redirect is answered, not followed, and reported
        // like any other non-answer.
        let detail = String::from_utf8_lossy(&raw).into_owned();
        write_log(&log_dir.join("error.txt"), &format!("{code}\n{detail}"));
        return Err(AttemptFailed(format!(
            "{PROG}: HTTP {code}: {}",
            head(&detail, 500)
        )));
    }

    let body: Value = match std::str::from_utf8(&raw)
        .map_err(|e| e.to_string())
        .and_then(|text| serde_json::from_str(text).map_err(|e| e.to_string()))
    {
        Ok(body) => body,
        Err(error) => {
            // A 200 carrying HTML -- a proxy error page, a captive portal --
            // is not a protocol error. Keep the bytes; they are the evidence.
            let sample: Vec<u8> = raw.iter().copied().take(2000).collect();
            write_log(
                &log_dir.join("error.txt"),
                &format!(
                    "non-JSON response body\n{error}\n\n{}",
                    String::from_utf8_lossy(&sample)
                ),
            );
            return Err(AttemptFailed(format!(
                "{PROG}: provider returned a non-JSON body ({error}); raw bytes in {}",
                log_dir.join("error.txt").display()
            )));
        }
    };
    write_log(&log_dir.join("response.json"), &pretty(&body));

    if let Some(error) = body.get("error")
        && !error.is_null()
        && error != &Value::Bool(false)
    {
        return Err(AttemptFailed(format!(
            "{PROG}: api error: {}",
            head(&error.to_string(), 500)
        )));
    }

    let choices = body.get("choices").and_then(Value::as_array);
    // Some providers return an empty choices list on a content filter. That
    // is a real response, not a crash, and the log already holds the body.
    let Some(choice) = choices.and_then(|list| list.first()) else {
        return Err(AttemptFailed(format!(
            "{PROG}: provider returned no choices (see response.json in the log)"
        )));
    };
    let choice = choice.as_object().cloned().unwrap_or_default();
    let message = choice
        .get("message")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let reasoning = message
        .get("reasoning")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();
    let content = message
        .get("content")
        .and_then(Value::as_str)
        .unwrap_or("")
        .to_string();

    if !reasoning.is_empty() {
        write_log(&log_dir.join("reasoning.txt"), &reasoning);
    }
    write_log(&log_dir.join("content.md"), &content);

    if message
        .get("tool_calls")
        .is_some_and(|calls| !calls.is_null() && calls != &json!([]))
    {
        say("WARNING: model emitted tool_calls despite no tools being offered; logged but ignored");
    }

    let usage = body
        .get("usage")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    // Who actually served the request, when the venue says: a model name is
    // a listing several upstream providers may serve, and the bill follows
    // the route. Recorded verbatim when it is a string, never guessed.
    let route = body
        .get("provider")
        .and_then(Value::as_str)
        .map(str::to_string);
    let finish = choice.get("finish_reason").unwrap_or(&Value::Null);
    let route_note = route
        .as_deref()
        .map(|r| format!(" route={r}"))
        .unwrap_or_default();
    eprintln!(
        "{PROG}: finish={} prompt_tokens={} completion_tokens={} reasoning_chars={}{route_note}",
        python_repr_plain(finish),
        python_repr_plain(usage.get("prompt_tokens").unwrap_or(&Value::Null)),
        python_repr_plain(usage.get("completion_tokens").unwrap_or(&Value::Null)),
        reasoning.chars().count()
    );

    // An empty completion is a failure for every caller, and the API called
    // it a success. The usage numbers are the diagnosis, so include them.
    if content.trim().is_empty() {
        let reasoning_tokens = usage
            .get("completion_tokens_details")
            .and_then(|d| d.get("reasoning_tokens"))
            .filter(|v| !v.is_null() && *v != &json!(0));
        let detail = match reasoning_tokens {
            Some(tokens) => format!(
                " — {tokens} of {} completion tokens went to reasoning",
                python_repr_plain(usage.get("completion_tokens").unwrap_or(&Value::Null))
            ),
            None => String::new(),
        };
        return Err(AttemptFailed(format!(
            "{PROG}: model returned no content (finish={}){detail}\n\
             {PROG}: the raw response and any reasoning are in {}",
            python_repr_plain(finish),
            log_dir.display()
        )));
    }

    Ok(Answer {
        choice,
        usage,
        reasoning,
        content,
        route,
    })
}

/// `str()` rather than `repr()`: strings bare, None for null, numbers as is.
fn python_repr_plain(value: &Value) -> String {
    match value {
        Value::String(text) => text.clone(),
        Value::Null => "None".to_string(),
        Value::Bool(true) => "True".to_string(),
        Value::Bool(false) => "False".to_string(),
        other => other.to_string(),
    }
}

// ── arguments ───────────────────────────────────────────────────────────────

struct Args {
    task: Option<String>,
    files: String,
    mode: String,
    venue: Option<String>,
    manifest: Option<String>,
    allow_paid: bool,
    failover: bool,
    base_url: Option<String>,
    api_key_env: Option<String>,
    model: Option<String>,
    effort: Option<String>,
    max_tokens: Option<u64>,
    temperature: f64,
    stdin: bool,
    log_dir: PathBuf,
    output: Option<String>,
    status_file: Option<String>,
    force: bool,
    dry_run: bool,
}

const USAGE_LINE: &str =
    "usage: oxbox send [-h] [--version] [--files FILES] [--mode {ask,diff,review}]
                  [--venue {opencode,openrouter,requesty,zenmux}]
                  [--manifest MANIFEST] [--allow-paid] [--failover]
                  [--base-url BASE_URL] [--api-key-env API_KEY_ENV]
                  [--model MODEL] [--effort {low,medium,high,xhigh,max}]
                  [--max-tokens MAX_TOKENS] [--temperature TEMPERATURE]
                  [--stdin] [--log-dir LOG_DIR] [--output OUTPUT]
                  [--status-file STATUS_FILE] [--force] [--dry-run] [--skill]
                  [task]
";

fn help_text() -> String {
    format!(
        "{USAGE_LINE}
Send a task to an untrusted model. No tools, full audit log.

positional arguments:
  task                  the task or question (or use --stdin)

options:
  -h, --help            show this help message and exit
  --version             show program's version number and exit
  --files FILES         comma-separated files to include as context
  --mode {{ask,diff,review}}
                        output contract (default: diff)
  --venue {{opencode,openrouter,requesty,zenmux}}
                        where to send the request; each venue uses its own API
                        key variable (default: {DEFAULT_VENUE})
  --manifest MANIFEST   pick venue and model from a survey manifest -- a file,
                        or an https:// URL such as the survey's latest.json
                        (first permitted entry). The manifest chooses provider
                        and model only; credentials always come from the
                        venue's own environment variable. The bytes used are
                        kept as manifest.json in the run's log directory.
  --allow-paid          let --manifest use entries whose cost is not confirmed
                        free (paid or unknown)
  --failover            with --manifest: on a failure after the request is
                        sent, move to the next permitted entry instead of
                        stopping (default: probe mode — one request, one
                        destination)
  --base-url BASE_URL   send to an arbitrary chat-completions endpoint.
                        Requires --api-key-env, so a credential is never sent
                        to an unlisted host by default.
  --api-key-env API_KEY_ENV
                        environment variable holding the key for --base-url
  --model MODEL         model id to send to. There is no default -- see
                        https://oxbox.ai for what is currently worth pointing
                        at, or use --manifest
  --effort {{low,medium,high,xhigh,max}}
                        reasoning effort (default: {DEFAULT_EFFORT}, or the
                        manifest's value when --manifest is given). No model
                        takes every level: Gemini Flash stops at high, and max
                        is served by few models
  --max-tokens MAX_TOKENS
                        completion budget; reasoning tokens count against it
                        (default: {DEFAULT_MAX_TOKENS}, or the manifest's value
                        when --manifest is given)
  --temperature TEMPERATURE
  --stdin               read the task from stdin instead of an argument
  --log-dir LOG_DIR
  --output OUTPUT       write the model's answer to this file instead of
                        stdout; written only when the run succeeds
  --status-file STATUS_FILE
                        write a JSON run summary here on every exit, success
                        or failure, so a script checks a fact instead of
                        relying on pipeline exit codes
  --force               send even if the secret scan or size guard trips
  --dry-run             build and log the request, print it, send nothing
  --skill               print the ox-review agent skill — a runbook for driving
                        a review from an agent, with the script paths this
                        installation actually uses — and exit
"
    )
}

fn usage_error(message: &str) -> ! {
    eprint!("{USAGE_LINE}");
    eprintln!("oxbox send: error: {message}");
    process::exit(2);
}

fn parse_args() -> Args {
    let raw: Vec<String> = env::args().skip(1).collect();
    let mut args = Args {
        task: None,
        files: String::new(),
        mode: "diff".to_string(),
        venue: None,
        manifest: None,
        allow_paid: false,
        failover: false,
        base_url: None,
        api_key_env: None,
        model: None,
        effort: None,
        max_tokens: None,
        temperature: 0.2,
        stdin: false,
        log_dir: env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join("logs"),
        output: None,
        status_file: None,
        force: false,
        dry_run: false,
    };
    let mut skill = false;
    let mut index = 0;
    let mut positional_done = false;
    while index < raw.len() {
        let arg = raw[index].as_str();
        let take = |index: usize| -> &str {
            raw.get(index + 1)
                .map(String::as_str)
                .unwrap_or_else(|| usage_error(&format!("argument {arg}: expected one argument")))
        };
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
            _ => (arg, None),
        };
        let value_of = |index: &mut usize| -> String {
            match inline {
                Some(value) => value.to_string(),
                None => {
                    let value = take(*index).to_string();
                    *index += 1;
                    value
                }
            }
        };
        if positional_done || !arg.starts_with('-') || arg == "-" {
            if args.task.is_some() {
                usage_error(&format!("unrecognized arguments: {arg}"));
            }
            args.task = Some(arg.to_string());
            index += 1;
            continue;
        }
        match flag {
            "--" => positional_done = true,
            "-h" | "--help" => {
                print!("{}", help_text());
                process::exit(0);
            }
            "--version" => {
                println!("{PROG} {}", core::VERSION);
                process::exit(0);
            }
            "--files" => args.files = value_of(&mut index),
            "--mode" => {
                let value = value_of(&mut index);
                if !MODES.contains(&value.as_str()) {
                    usage_error(&format!(
                        "argument --mode: invalid choice: '{value}' (choose from 'ask', 'diff', 'review')"
                    ));
                }
                args.mode = value;
            }
            "--venue" => {
                let value = value_of(&mut index);
                if !VENUES.iter().any(|venue| venue.name == value) {
                    usage_error(&format!(
                        "argument --venue: invalid choice: '{value}' (choose from 'opencode', 'openrouter', 'requesty', 'zenmux')"
                    ));
                }
                args.venue = Some(value);
            }
            "--manifest" => args.manifest = Some(value_of(&mut index)),
            "--allow-paid" => args.allow_paid = true,
            "--failover" => args.failover = true,
            "--base-url" => args.base_url = Some(value_of(&mut index)),
            "--api-key-env" => args.api_key_env = Some(value_of(&mut index)),
            "--model" => args.model = Some(value_of(&mut index)),
            "--effort" => {
                let value = value_of(&mut index);
                if !EFFORTS.contains(&value.as_str()) {
                    usage_error(&format!(
                        "argument --effort: invalid choice: '{value}' (choose from 'low', 'medium', 'high', 'xhigh', 'max')"
                    ));
                }
                args.effort = Some(value);
            }
            "--max-tokens" => {
                let value = value_of(&mut index);
                args.max_tokens = Some(value.parse().unwrap_or_else(|_| {
                    usage_error(&format!(
                        "argument --max-tokens: invalid int value: '{value}'"
                    ))
                }));
            }
            "--temperature" => {
                let value = value_of(&mut index);
                args.temperature = value.parse().unwrap_or_else(|_| {
                    usage_error(&format!(
                        "argument --temperature: invalid float value: '{value}'"
                    ))
                });
            }
            "--stdin" => args.stdin = true,
            "--log-dir" => args.log_dir = PathBuf::from(value_of(&mut index)),
            "--output" => args.output = Some(value_of(&mut index)),
            "--status-file" => args.status_file = Some(value_of(&mut index)),
            "--force" => args.force = true,
            "--dry-run" => args.dry_run = true,
            "--skill" => skill = true,
            _ => usage_error(&format!("unrecognized arguments: {arg}")),
        }
        index += 1;
    }
    if skill {
        // Answered before the status record is touched: a question about the
        // installation rather than a run.
        process::exit(core::print_skill(PROG));
    }
    args
}

// ── the run ─────────────────────────────────────────────────────────────────

/// Python's truthiness for a manifest value: absent, null, 0, "" and false
/// all mean "not set", so the next rung of the precedence ladder applies.
fn truthy(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| !v.is_null() && *v != &json!(0) && *v != &json!("") && *v != &json!(false))
}

fn main() {
    let args = parse_args();
    let mut status = new_status();
    match run(&args, &mut status) {
        Ok(()) => {
            status.insert("ok".into(), json!(true));
            status.insert("exit_code".into(), json!(0));
            write_status(&status);
        }
        Err(Exit::Message(message)) => {
            status.insert("ok".into(), json!(false));
            status.insert("exit_code".into(), json!(1));
            status.insert("error".into(), json!(format!("{PROG}: {message}")));
            write_status(&status);
            // Python's sys.exit("text") printed the text as given; every
            // message here already carries the program name.
            eprintln!("{PROG}: {message}");
            process::exit(1);
        }
        Err(Exit::Code(code)) => {
            status.insert("ok".into(), json!(false));
            status.insert("exit_code".into(), json!(code));
            status.insert(
                "error".into(),
                json!(format!("exited {code}; the diagnosis is on stderr")),
            );
            write_status(&status);
            process::exit(code);
        }
    }
}

fn run(args: &Args, status: &mut Map<String, Value>) -> Result<(), Exit> {
    status.insert("mode".into(), json!(args.mode));
    status.insert("dry_run".into(), json!(args.dry_run));
    status.insert("output".into(), json!(args.output));
    status.insert("status_file".into(), json!(args.status_file));
    if args.status_file.is_some() {
        // Mark the run in progress immediately, so a crash or kill can never
        // leave a stale success record from an earlier run for a script.
        write_status(status);
    }
    if let Some(output) = &args.output
        && Path::new(output).exists()
        && let Err(error) = fs::remove_file(output)
    {
        // A leftover answer from a previous run must not read as this run's.
        return Err(quit(format!("cannot clear --output {output}: {error}")));
    }

    let task = if args.stdin {
        let mut text = String::new();
        io::stdin()
            .read_to_string(&mut text)
            .map_err(|error| quit(format!("cannot read stdin: {error}")))?;
        text
    } else {
        args.task.clone().unwrap_or_default()
    };
    if task.trim().is_empty() {
        return Err(quit("no task given"));
    }

    // Resolve destination and credential together. They are never chosen
    // independently: an unlisted host requires you to name the variable
    // whose key it may have, and a manifest may only name venues from the
    // table, so no credential travels somewhere by default.
    if args.failover && args.manifest.is_none() {
        return Err(quit(
            "--failover requires --manifest; a single destination has nothing to fail over to",
        ));
    }
    let mut manifest_info: Option<ManifestInfo> = None;
    let entries: Vec<Entry> = if let Some(manifest) = &args.manifest {
        for (value, name) in [
            (&args.venue, "--venue"),
            (&args.model, "--model"),
            (&args.base_url, "--base-url"),
            (&args.api_key_env, "--api-key-env"),
        ] {
            if value.as_deref().is_some_and(|v| !v.is_empty()) {
                return Err(quit(format!(
                    "{name} conflicts with --manifest; the manifest chooses the destination"
                )));
            }
        }
        let (entries, info) = load_manifest(manifest, args.allow_paid)?;
        status.insert(
            "manifest".into(),
            json!({"path": info.path, "sha256": info.sha256}),
        );
        manifest_info = Some(info);
        entries
    } else if let Some(base_url) = &args.base_url {
        let Some(key_env) = &args.api_key_env else {
            return Err(quit(
                "--base-url requires --api-key-env, so a key is never sent to an unlisted \
                 host by accident",
            ));
        };
        // https only: a plaintext endpoint puts the Bearer token on the wire
        // in cleartext, which defeats the point of pairing it with a host.
        if https_required() && !base_url.starts_with("https://") {
            return Err(quit(format!(
                "--base-url must be an https:// URL (got {base_url:?}); a credential must \
                 not travel in cleartext"
            )));
        }
        let Some(model) = &args.model else {
            return Err(quit("--model is required for venue 'custom' (no default)"));
        };
        vec![Entry {
            position: 1,
            venue: "custom".into(),
            model: model.clone(),
            why: String::new(),
            params: Map::new(),
            skip: None,
            url: base_url.clone(),
            key_env: key_env.clone(),
        }]
    } else {
        if args.api_key_env.is_some() {
            return Err(quit(
                "--api-key-env only applies with --base-url; a named venue already carries \
                 its own key variable",
            ));
        }
        let venue_name = args.venue.as_deref().unwrap_or(DEFAULT_VENUE);
        let spec = VENUES
            .iter()
            .find(|venue| venue.name == venue_name)
            .expect("the venue was validated");
        let Some(model) = &args.model else {
            return Err(quit(format!(
                "no model chosen, and '{venue_name}' has no default.\n\
                 \n\
                 ox names no model of its own: the free and cloaked listings\n\
                 worth pointing it at change week to week, and a default that\n\
                 names one goes stale without saying so.\n\
                 \n\
                 \x20 --manifest https://oxbox.ai/manifests/latest.json   this week's pick\n\
                 \x20 --model <id>                                        a model you chose\n\
                 \n\
                 The Oxbox Survey publishes what is currently worth trying,\n\
                 with the runs behind each recommendation: https://oxbox.ai"
            )));
        };
        vec![Entry {
            position: 1,
            venue: venue_name.into(),
            model: model.clone(),
            why: String::new(),
            params: Map::new(),
            skip: None,
            url: venue_url(spec),
            key_env: spec.key_env.into(),
        }]
    };

    if args.manifest.is_none()
        && !args.dry_run
        && env::var(&entries[0].key_env)
            .map(|v| v.is_empty())
            .unwrap_or(true)
    {
        return Err(quit(format!(
            "{} not set (run under: op run --env-file .env -- oxbox send ...)",
            entries[0].key_env
        )));
    }

    let paths: Vec<String> = args
        .files
        .split(',')
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(str::to_string)
        .collect();
    let context = build_context(&paths, args.force, &task)?;
    let user_content = if context.text.is_empty() {
        task.trim().to_string()
    } else {
        format!("{}\n\n{}", task.trim(), context.text)
    };

    let mut attempts: Option<Vec<Value>> = manifest_info.as_ref().map(|_| Vec::new());
    let total = entries.len();
    let mut chosen: Option<String> = None;
    for entry in &entries {
        let label = match &manifest_info {
            Some(_) => format!(
                "manifest[{}/{total}] {}/{}",
                entry.position, entry.venue, entry.model
            ),
            None => format!("{}/{}", entry.venue, entry.model),
        };
        if let Some(reason) = &entry.skip {
            say(&format!("{label} skipped: {reason}"));
            if let Some(list) = attempts.as_mut() {
                list.push(json!({
                    "position": entry.position, "venue": entry.venue,
                    "model": entry.model, "skipped": reason,
                }));
            }
            continue;
        }

        // Explicit flag beats the entry's params, which beat the manifest's
        // issue-wide defaults, which beat the built-in default.
        let defaults = manifest_info.as_ref().map(|info| &info.defaults);
        let max_tokens: Value = match args.max_tokens {
            Some(n) => json!(n),
            None => truthy(entry.params.get("max_tokens"))
                .or_else(|| defaults.and_then(|d| truthy(d.get("max_tokens"))))
                .cloned()
                .unwrap_or(json!(DEFAULT_MAX_TOKENS)),
        };
        let effort: String = match &args.effort {
            Some(level) => level.clone(),
            None => truthy(entry.params.get("effort"))
                .or_else(|| defaults.and_then(|d| truthy(d.get("effort"))))
                .and_then(Value::as_str)
                .unwrap_or(DEFAULT_EFFORT)
                .to_string(),
        };

        let payload = json!({
            "model": entry.model,
            "messages": [
                {"role": "system", "content": system_prompt(&args.mode)},
                {"role": "user", "content": user_content},
            ],
            "max_tokens": max_tokens,
            "temperature": args.temperature,
            "reasoning": {"effort": effort},
            "include_reasoning": true,
        });

        let (stamp, log_dir) = make_log_dir(&args.log_dir)?;
        status.insert("log_dir".into(), json!(log_dir.to_string_lossy()));
        status.insert("venue".into(), json!(entry.venue));
        status.insert("model".into(), json!(entry.model));
        let mut meta = json!({
            "timestamp": stamp,
            // The directory carries a -N suffix when two runs start in the
            // same second; the survey reads runs back by directory name.
            "log_dir": log_dir.file_name().map(|n| n.to_string_lossy().into_owned()),
            "ox_version": core::VERSION,
            "model": entry.model,
            "venue": entry.venue,
            "endpoint": entry.url,
            "key_env": entry.key_env,
            "mode": args.mode,
            "effort": effort,
            "max_tokens": max_tokens,
            "files": paths,
            "context_bytes": context.total_bytes,
            "secret_scan_hits": context.findings,
            "forced": args.force,
        });
        if let Some(info) = &manifest_info {
            // An audit trail that says where the code went but not why the
            // destination was chosen is incomplete: record which manifest,
            // byte-exactly, and which entry.
            meta["manifest"] = json!({
                "path": info.path, "sha256": info.sha256,
                "entry_position": entry.position, "fetched": info.fetched,
                "saved_as": "manifest.json",
            });
            if let Err(error) = fs::write(log_dir.join("manifest.json"), &info.raw) {
                say(&format!("could not write manifest.json: {error}"));
            }
        }
        write_lf(&log_dir.join("request.json"), &pretty(&payload))
            .map_err(|error| quit(format!("cannot write request.json: {error}")))?;
        write_lf(&log_dir.join("meta.json"), &pretty(&meta))
            .map_err(|error| quit(format!("cannot write meta.json: {error}")))?;

        say(&format!("log -> {}", log_dir.display()));
        if manifest_info.is_some() {
            let why = if entry.why.is_empty() {
                String::new()
            } else {
                format!(" — {}", entry.why)
            };
            say(&format!("{label}{why}"));
        }
        say(&format!(
            "venue={} model={} mode={} effort={effort} context={}B files={}",
            entry.venue,
            entry.model,
            args.mode,
            context.total_bytes,
            paths.len()
        ));

        if args.dry_run {
            say("dry run, nothing sent");
            println!("{}", pretty(&payload));
            return Ok(());
        }

        let mut record = json!({
            "position": entry.position, "venue": entry.venue,
            "model": entry.model, "log_dir": log_dir.to_string_lossy(),
        });
        let api_key = env::var(&entry.key_env).unwrap_or_default();
        let answer = match send_and_parse(&entry.url, &api_key, &payload, &log_dir) {
            Ok(answer) => answer,
            Err(AttemptFailed(failure)) => {
                if let Some(list) = attempts.as_mut() {
                    record["error"] = json!(failure);
                    list.push(record);
                    status.insert("attempts".into(), json!(list));
                }
                if !args.failover {
                    // The failure text already carries the program name;
                    // the exit path adds it back once.
                    return Err(Exit::Message(strip_prog(&failure)));
                }
                eprintln!("{failure}\n{PROG}: {label} failed; trying the next entry");
                continue;
            }
        };

        let details = answer
            .usage
            .get("completion_tokens_details")
            .and_then(Value::as_object)
            .cloned()
            .unwrap_or_default();
        let finish = answer
            .choice
            .get("finish_reason")
            .cloned()
            .unwrap_or(Value::Null);
        status.insert("finish_reason".into(), finish.clone());
        status.insert(
            "prompt_tokens".into(),
            answer
                .usage
                .get("prompt_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        );
        status.insert(
            "completion_tokens".into(),
            answer
                .usage
                .get("completion_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        );
        status.insert(
            "reasoning_tokens".into(),
            details
                .get("reasoning_tokens")
                .cloned()
                .unwrap_or(Value::Null),
        );
        status.insert(
            "reasoning_chars".into(),
            json!(answer.reasoning.chars().count()),
        );
        // Whatever the venue reported in usage.cost, unconverted and
        // unchecked: its claim about its own charge, not a price this tool
        // computed. None when the venue sends nothing, which stays
        // distinguishable from a real zero.
        status.insert(
            "venue_cost".into(),
            answer.usage.get("cost").cloned().unwrap_or(Value::Null),
        );
        status.insert("route".into(), json!(answer.route));
        // A provider that reports no finish reason has said nothing about
        // whether the answer was cut off; None means unknown.
        let truncated = match &finish {
            Value::Null => Value::Null,
            other => json!(other == &json!("length")),
        };
        status.insert("truncated".into(), truncated.clone());
        if let Some(list) = attempts.as_mut() {
            record["finish_reason"] = finish;
            record["venue_cost"] = answer.usage.get("cost").cloned().unwrap_or(Value::Null);
            record["route"] = json!(answer.route);
            list.push(record);
        }
        chosen = Some(answer.content);
        break;
    }

    status.insert("attempts".into(), json!(attempts));
    let Some(content) = chosen else {
        // Only reachable with --manifest: every entry was skipped, or (under
        // --failover) every attempted entry failed after sending.
        let mut lines = Vec::new();
        for item in attempts.unwrap_or_default() {
            let reason = ["skipped", "error"]
                .iter()
                .find_map(|key| item.get(*key).and_then(Value::as_str))
                .unwrap_or("not attempted");
            lines.push(format!(
                "  [{}] {}/{}: {}",
                python_repr_plain(item.get("position").unwrap_or(&Value::Null)),
                python_repr_plain(item.get("venue").unwrap_or(&Value::Null)),
                python_repr_plain(item.get("model").unwrap_or(&Value::Null)),
                reason.lines().next().unwrap_or("")
            ));
        }
        return Err(quit(format!(
            "no manifest entry produced an answer:\n{}",
            lines.join("\n")
        )));
    };

    // Truncation with content is quieter than truncation without: warn
    // rather than fail, and let scripts check `truncated` in the record.
    match status.get("truncated") {
        Some(Value::Bool(true)) => say(
            "WARNING: output truncated at the max_tokens cap (finish=length); raise --max-tokens",
        ),
        Some(Value::Null) | None => say(
            "WARNING: the provider reported no finish reason, so whether this answer is \
             complete is unknown; check the tail before trusting it",
        ),
        _ => {}
    }

    match &args.output {
        Some(output) => {
            // Match stdout byte-for-byte: print() appends the trailing newline.
            let text = if content.ends_with('\n') {
                content
            } else {
                format!("{content}\n")
            };
            write_lf(Path::new(output), &text)
                .map_err(|error| quit(format!("cannot write --output {output}: {error}")))?;
            say(&format!("answer -> {output}"));
        }
        None => {
            let mut out = io::stdout().lock();
            let _ = writeln!(out, "{content}");
            let _ = out.flush();
        }
    }
    Ok(())
}

/// An AttemptFailed message already starts with the program name; the status
/// record's `error` field carried it that way in Python too, so strip the
/// prefix here and let the Exit path add it back once.
fn strip_prog(message: &str) -> String {
    message
        .strip_prefix(&format!("{PROG}: "))
        .unwrap_or(message)
        .to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scanner_catches_the_measured_forms() {
        let text = "api_key = \"abcdefghijklmnop\"\nclient_secret=abcdefghijklmnopqrst\nmy_api_key = \"abcdefghijklmnopqrst\"\nDB_PASSWORD=abcdefghijklmnopqrstu\ntoken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\naws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl/+\n";
        let hits = scan_for_secrets(text, "t");
        assert!(hits.len() >= 6, "{hits:?}");
        assert!(
            scan_for_secrets("\"max_tokens\": 100000\ncompletion_tokens = 512\n", "t").is_empty()
        );
    }

    #[test]
    fn stamps_look_like_the_python_ones() {
        let stamp = utc_stamp();
        assert_eq!(stamp.len(), 20, "{stamp}");
        assert!(stamp.ends_with('Z'));
        assert_eq!(&stamp[4..5], "-");
        assert_eq!(&stamp[10..11], "T");
    }

    #[test]
    fn head_cuts_characters_not_bytes() {
        assert_eq!(head("héllo", 2), "hé");
    }
}
