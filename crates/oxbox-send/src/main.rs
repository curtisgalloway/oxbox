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

use regex::Regex;
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
/// Two venues may share a key variable, and exactly two do: `openrouter` and
/// `openrouter-us` are the same account reached through two of OpenRouter's
/// own hostnames. What the rule actually protects is a credential crossing a
/// vendor boundary, and these do not cross one. The pairing stays one-way --
/// a venue names one variable, never a choice of them -- so the guarantee
/// wiretest checks (which variable was read, and which URL it went to) is
/// unchanged.
///
/// No venue names a default model, on purpose: the listings worth pointing
/// this at change week to week, and a default that names one goes stale
/// without saying so. The survey is the list that gets updated.
struct Venue {
    name: &'static str,
    url: &'static str,
    key_env: &'static str,
    /// Whether the venue takes a `provider` object in the request body
    /// to choose among the upstream endpoints serving a model. OpenRouter
    /// does (order, only, ignore, allow_fallbacks, max_price, ...); the
    /// others route their own way and would drop the object silently, so
    /// a pin on them is refused rather than sent.
    provider_routing: bool,
}

const VENUES: [Venue; 5] = [
    Venue {
        name: "openrouter",
        url: "https://openrouter.ai/api/v1/chat/completions",
        key_env: "OPENROUTER_API_KEY",
        provider_routing: true,
    },
    // OpenRouter's US in-region endpoint: the request is decrypted inside the
    // region and served only by provider endpoints in it. A separate venue
    // rather than a `--base-url`, because `--base-url` refuses `--provider`
    // and the region has to survive into the record -- an observation that
    // says `openrouter` when the request was pinned to a region is wrong
    // about where the code went, which is the one thing the log is for.
    //
    // It fails closed: a model with no in-region endpoint returns an error
    // instead of falling back to a global one, so the refusal is the finding
    // and must not be smoothed over. Business or Enterprise plans only.
    // https://openrouter.ai/docs/guides/features/in-region-routing
    //
    // EU is the same table row with `eu.` and would be added the same way;
    // it is left out until something needs it, rather than shipped untested.
    Venue {
        name: "openrouter-us",
        url: "https://us.openrouter.ai/api/v1/chat/completions",
        key_env: "OPENROUTER_API_KEY",
        provider_routing: true,
    },
    Venue {
        name: "zenmux",
        url: "https://zenmux.ai/api/v1/chat/completions",
        key_env: "ZENMUX_API_KEY",
        provider_routing: false,
    },
    Venue {
        name: "opencode",
        url: "https://opencode.ai/zen/v1/chat/completions",
        key_env: "OPENCODE_ZEN_API_KEY",
        provider_routing: false,
    },
    Venue {
        name: "requesty",
        url: "https://router.requesty.ai/v1/chat/completions",
        key_env: "REQUESTY_API_KEY",
        provider_routing: false,
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
/// 1 added the per-entry `provider` object. An ox that predates it refuses
/// a version-1 manifest with a pointer to update, which is the point of the
/// number: an older ox would otherwise drop the pin and send the same
/// request unpinned, and the caller would get an endpoint the survey did
/// not measure. A version-0 manifest carrying `provider` is honored too.
const MANIFEST_VERSION: i64 = 1;
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
    // shell exports. The Python reference writes token(?!s) to keep
    // max_tokens and completion_tokens from matching every request this
    // tool builds. The regex crate has no lookahead, so the same rule is
    // spelled out: after "token", the identifier either ends or continues
    // with something other than s. The two agree match for match on the
    // suites and on this repository's own sources.
    //
    // Not fancy-regex, which has lookahead: its backtracking engine took
    // more than ten minutes on a 433 KB file of ordinary source that Python
    // scans in 0.15 s and the regex crate in 2 ms (measured 2026-09-06).
    (
        r#"(?i)[A-Za-z0-9_\-]*(?:(?:api[_\-]?key|secret|password|passwd|credential)[A-Za-z0-9_\-]*|token(?:[A-RT-Za-rt-z0-9_\-][A-Za-z0-9_\-]*)?)\s*[:=]\s*(?:["'][^"'\s]{12,}["']|[^\s"'()\[\]{}#,;]{16,})"#,
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
#[derive(Debug, PartialEq)]
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
#[derive(Debug, PartialEq)]
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
        for found in regex.find_iter(text) {
            let line_no = text[..found.start()].matches('\n').count() + 1;
            hits.push(format!("{label}:{line_no}: possible {description}"));
        }
    }
    hits
}

#[derive(Debug)]
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
        // Text mode, as the reference reads it: a CRLF checkout sends the
        // same bytes and counts the same size as an LF one.
        let body = core::normalize_newlines(&body);
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

#[derive(Debug)]
struct Entry {
    position: usize,
    venue: String,
    model: String,
    why: String,
    params: Map<String, Value>,
    /// The entry's routing pin, an OpenRouter provider object passed
    /// through verbatim. None when absent, null or empty.
    provider: Option<Map<String, Value>>,
    skip: Option<String>,
    url: String,
    key_env: String,
}

#[derive(Debug)]
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
    let raw = match response
        .body_mut()
        .with_config()
        .limit(cap as u64 + 1)
        .read_to_vec()
    {
        Ok(raw) => raw,
        Err(ureq::Error::BodyExceedsLimit(_)) => {
            return Err(quit(format!(
                "manifest {url} is larger than {cap} bytes, which no manifest is"
            )));
        }
        Err(error) => return Err(quit(format!("cannot fetch manifest {url}: {error}"))),
    };
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
///
/// `provider` is the --provider flag's object, if given: it applies to every
/// entry, over the entry's own, and an entry whose venue cannot honor a pin
/// is skipped rather than sent unpinned.
fn load_manifest(
    path: &str,
    allow_paid: bool,
    provider: Option<&Map<String, Value>>,
) -> Result<(Vec<Entry>, ManifestInfo), Exit> {
    let fetched = path.contains("://");
    let raw = if fetched {
        fetch_manifest(path)?
    } else {
        fs::read(path).map_err(|error| quit(format!("cannot read manifest {path}: {error}")))?
    };
    // Spelled out rather than `{:x}` on the digest: the output type's
    // formatting has changed across sha2 releases, and the hex is the same.
    let sha256: String = Sha256::digest(&raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
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
        // The entry's routing pin. Absent, null or empty means no preference;
        // a value of any other shape is a pin this ox cannot honor, and an
        // entry whose pin cannot be honored is skipped, not sent unpinned.
        let pin = rec.get("provider");
        let bad_pin = pin.is_some_and(|p| !p.is_null() && !p.is_object());
        let pin: Option<Map<String, Value>> = pin
            .and_then(Value::as_object)
            .filter(|map| !map.is_empty())
            .cloned();
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
            provider: pin,
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
            Some(_) if bad_pin => entry.skip = Some("provider is not an object".to_string()),
            Some(spec)
                if (provider.is_some() || entry.provider.is_some()) && !spec.provider_routing =>
            {
                entry.skip = Some(format!(
                    "provider pin on venue {venue}, which does not honor one"
                ))
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
    civil_stamp(secs)
}

/// The stamp for a given number of seconds since the Unix epoch.
fn civil_stamp(secs: i64) -> String {
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
    let log_dir = claim_log_dir(base, &stamp)?;
    Ok((stamp, log_dir))
}

/// `<base>/<stamp>`, or `<base>/<stamp>-N` when that already exists.
fn claim_log_dir(base: &Path, stamp: &str) -> Result<PathBuf, Exit> {
    fs::create_dir_all(base).map_err(|error| {
        quit(format!(
            "cannot create log directory {}: {error}",
            base.display()
        ))
    })?;
    let mut attempt = 1;
    loop {
        let log_dir = if attempt == 1 {
            base.join(stamp)
        } else {
            base.join(format!("{stamp}-{attempt}"))
        };
        match fs::create_dir(&log_dir) {
            Ok(()) => return Ok(log_dir),
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

#[derive(Debug)]
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

    // Python's truthiness: an empty object beside a valid answer is not an
    // error, and some venues send exactly that.
    if let Some(error) = truthy(body.get("error")) {
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

#[derive(Debug, PartialEq)]
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
    provider: Option<Map<String, Value>>,
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
                  [--venue {opencode,openrouter,openrouter-us,requesty,zenmux}]
                  [--manifest MANIFEST] [--allow-paid] [--failover]
                  [--base-url BASE_URL] [--api-key-env API_KEY_ENV]
                  [--model MODEL] [--provider PROVIDER]
                  [--effort {low,medium,high,xhigh,max}]
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
  --venue {{opencode,openrouter,openrouter-us,requesty,zenmux}}
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
  --provider PROVIDER   OpenRouter routing preference, a JSON object sent
                        verbatim in the request body (order, only, ignore,
                        allow_fallbacks, max_price, quantizations, sort, ...).
                        Beats the manifest entry's provider; refused on a
                        venue that does not honor one. See
                        https://openrouter.ai/docs/features/provider-routing
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
  --skill               print the oxbox-review agent skill — a runbook for driving
                        a review from an agent, with the script paths this
                        installation actually uses — and exit
"
    )
}

/// What a command line asks for. The three informational answers come
/// before any run state exists; `Run` carries everything a run needs.
#[derive(Debug, PartialEq)]
enum Parsed {
    Help,
    Version,
    Skill,
    Run(Box<Args>),
}

/// An argparse-shaped usage error: the message after `oxbox send: error:`.
fn usage(message: impl Into<String>) -> String {
    message.into()
}

impl Args {
    /// The values argparse would give with no flags at all.
    fn defaults() -> Args {
        Args {
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
            provider: None,
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
        }
    }
}

/// The --provider value: a JSON object, or nothing. An empty value means
/// "not given", the way every other flag here reads one, and so does an
/// empty object. Anything else that is not an object is refused at the
/// parser: the venue would take a string or a list without complaint and
/// route by its defaults, which is the unpinned request this flag exists to
/// prevent.
fn parse_provider(text: &str) -> Result<Option<Map<String, Value>>, String> {
    if text.is_empty() {
        return Ok(None);
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(map)) => Ok(Some(map).filter(|map| !map.is_empty())),
        Ok(_) => Err(usage(format!(
            "argument --provider: not a JSON object: {text}"
        ))),
        Err(error) => Err(usage(format!(
            "argument --provider: not a JSON object: {error}"
        ))),
    }
}

fn parse_args(raw: &[String]) -> Result<Parsed, String> {
    let mut args = Args::defaults();
    let mut skill = false;
    let mut index = 0;
    let mut positional_done = false;
    while index < raw.len() {
        let arg = raw[index].as_str();
        let (flag, inline) = match arg.split_once('=') {
            Some((flag, value)) if flag.starts_with("--") => (flag, Some(value)),
            _ => (arg, None),
        };
        // The flag's value: the text after `=`, or the next word.
        let mut value_of = || -> Result<String, String> {
            match inline {
                Some(value) => Ok(value.to_string()),
                None => {
                    index += 1;
                    raw.get(index)
                        .cloned()
                        .ok_or_else(|| usage(format!("argument {arg}: expected one argument")))
                }
            }
        };
        if positional_done || !arg.starts_with('-') || arg == "-" {
            if args.task.is_some() {
                return Err(usage(format!("unrecognized arguments: {arg}")));
            }
            args.task = Some(arg.to_string());
            index += 1;
            continue;
        }
        match flag {
            "--" => positional_done = true,
            "-h" | "--help" => return Ok(Parsed::Help),
            "--version" => return Ok(Parsed::Version),
            "--files" => args.files = value_of()?,
            "--mode" => {
                let value = value_of()?;
                if !MODES.contains(&value.as_str()) {
                    return Err(usage(format!(
                        "argument --mode: invalid choice: '{value}' (choose from 'ask', 'diff', 'review')"
                    )));
                }
                args.mode = value;
            }
            "--venue" => {
                let value = value_of()?;
                if !VENUES.iter().any(|venue| venue.name == value) {
                    return Err(usage(format!(
                        "argument --venue: invalid choice: '{value}' (choose from 'opencode', 'openrouter', 'openrouter-us', 'requesty', 'zenmux')"
                    )));
                }
                args.venue = Some(value);
            }
            "--manifest" => args.manifest = Some(value_of()?),
            "--allow-paid" => args.allow_paid = true,
            "--failover" => args.failover = true,
            "--base-url" => args.base_url = Some(value_of()?),
            "--api-key-env" => args.api_key_env = Some(value_of()?),
            "--model" => args.model = Some(value_of()?),
            "--provider" => {
                let value = value_of()?;
                args.provider = parse_provider(&value)?;
            }
            "--effort" => {
                let value = value_of()?;
                if !EFFORTS.contains(&value.as_str()) {
                    return Err(usage(format!(
                        "argument --effort: invalid choice: '{value}' (choose from 'low', 'medium', 'high', 'xhigh', 'max')"
                    )));
                }
                args.effort = Some(value);
            }
            "--max-tokens" => {
                let value = value_of()?;
                args.max_tokens = Some(value.parse().map_err(|_| {
                    usage(format!(
                        "argument --max-tokens: invalid int value: '{value}'"
                    ))
                })?);
            }
            "--temperature" => {
                let value = value_of()?;
                args.temperature = value.parse().map_err(|_| {
                    usage(format!(
                        "argument --temperature: invalid float value: '{value}'"
                    ))
                })?;
            }
            "--stdin" => args.stdin = true,
            "--log-dir" => args.log_dir = PathBuf::from(value_of()?),
            "--output" => args.output = Some(value_of()?),
            "--status-file" => args.status_file = Some(value_of()?),
            "--force" => args.force = true,
            "--dry-run" => args.dry_run = true,
            "--skill" => skill = true,
            _ => return Err(usage(format!("unrecognized arguments: {arg}"))),
        }
        index += 1;
    }
    if skill {
        // Answered before the status record is touched: a question about the
        // installation rather than a run.
        return Ok(Parsed::Skill);
    }
    // An empty value means "not given", as the reference's truthiness reads
    // it: `--model ''` chooses no model rather than sending an empty id.
    for slot in [
        &mut args.manifest,
        &mut args.base_url,
        &mut args.api_key_env,
        &mut args.model,
        &mut args.output,
        &mut args.status_file,
    ] {
        if slot.as_deref() == Some("") {
            *slot = None;
        }
    }
    Ok(Parsed::Run(Box::new(args)))
}

// ── the run ─────────────────────────────────────────────────────────────────

/// Python's truthiness for a manifest value: absent, null, 0, "" and false
/// all mean "not set", so the next rung of the precedence ladder applies.
fn truthy(value: Option<&Value>) -> Option<&Value> {
    value.filter(|v| match v {
        Value::Null | Value::Bool(false) => false,
        Value::Number(n) => n.as_f64() != Some(0.0),
        Value::String(s) => !s.is_empty(),
        Value::Array(a) => !a.is_empty(),
        Value::Object(o) => !o.is_empty(),
        Value::Bool(true) => true,
    })
}

fn main() {
    let raw: Vec<String> = env::args().skip(1).collect();
    let args = match parse_args(&raw) {
        Ok(Parsed::Help) => {
            print!("{}", help_text());
            process::exit(0);
        }
        Ok(Parsed::Version) => {
            println!("{PROG} {}", core::VERSION);
            process::exit(0);
        }
        Ok(Parsed::Skill) => process::exit(core::print_skill(PROG)),
        Ok(Parsed::Run(args)) => *args,
        Err(message) => {
            eprint!("{USAGE_LINE}");
            eprintln!("oxbox send: error: {message}");
            process::exit(2);
        }
    };
    let mut status = new_status();
    let stdin = io::stdin();
    let mut input = stdin.lock();
    let mut out = io::stdout().lock();
    let code = finish(run(&args, &mut status, &mut input, &mut out), &mut status);
    drop(out);
    process::exit(code);
}

/// Record how the run ended in the status record, write it everywhere it
/// belongs, print the diagnosis if there is one, and give back the exit code.
fn finish(outcome: Result<(), Exit>, status: &mut Map<String, Value>) -> i32 {
    match outcome {
        Ok(()) => {
            status.insert("ok".into(), json!(true));
            status.insert("exit_code".into(), json!(0));
            write_status(status);
            0
        }
        Err(Exit::Message(message)) => {
            status.insert("ok".into(), json!(false));
            status.insert("exit_code".into(), json!(1));
            status.insert("error".into(), json!(format!("{PROG}: {message}")));
            write_status(status);
            // Python's sys.exit("text") printed the text as given; every
            // message here already carries the program name.
            eprintln!("{PROG}: {message}");
            1
        }
        Err(Exit::Code(code)) => {
            status.insert("ok".into(), json!(false));
            status.insert("exit_code".into(), json!(code));
            status.insert(
                "error".into(),
                json!(format!("exited {code}; the diagnosis is on stderr")),
            );
            write_status(status);
            code
        }
    }
}

fn run(
    args: &Args,
    status: &mut Map<String, Value>,
    input: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<(), Exit> {
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
        input
            .read_to_string(&mut text)
            .map_err(|error| quit(format!("cannot read stdin: {error}")))?;
        core::normalize_newlines(&text)
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
    // A configured manifest stands in for --manifest when nothing on the
    // command line names a destination, and only then: a typed --model or
    // --venue is a choice, and a config file does not overrule what was
    // typed. Announced, so a run's stderr says where the destination came
    // from; the audit trail then carries the manifest like any other.
    let mut manifest_choice = args.manifest.clone();
    if manifest_choice.is_none()
        && args.venue.is_none()
        && args.model.is_none()
        && args.base_url.is_none()
        && args.api_key_env.is_none()
        && let Some((value, path)) = core::config_get("send", "manifest").map_err(quit)?
    {
        say(&format!("manifest from {}: {value}", path.display()));
        manifest_choice = Some(value);
    }
    if args.failover && manifest_choice.is_none() {
        return Err(quit(
            "--failover requires --manifest; a single destination has nothing to fail over to",
        ));
    }
    let mut manifest_info: Option<ManifestInfo> = None;
    let entries: Vec<Entry> = if let Some(manifest) = &manifest_choice {
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
        // The cost gate opens once, in the config file, for someone who has
        // decided paid entries are fine: `allow_paid = true` under [send]
        // reads exactly as --allow-paid. The file only ever opens the
        // gate; the flag cannot close it, and the default stays free-only.
        let mut allow_paid = args.allow_paid;
        if !allow_paid
            && let Some((true, path)) = core::config_flag("send", "allow_paid").map_err(quit)?
        {
            say(&format!("allow_paid from {}", path.display()));
            allow_paid = true;
        }
        let (entries, info) = load_manifest(manifest, allow_paid, args.provider.as_ref())?;
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
        // An unlisted endpoint makes no promise about routing, so a pin
        // there would be a request the caller believes is pinned and is not.
        if args.provider.is_some() {
            return Err(quit(
                "--provider does not apply with --base-url; an unlisted endpoint makes no \
                 promise about honoring it",
            ));
        }
        vec![Entry {
            position: 1,
            venue: "custom".into(),
            model: model.clone(),
            why: String::new(),
            params: Map::new(),
            provider: None,
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
        if args.provider.is_some() && !spec.provider_routing {
            return Err(quit(format!(
                "--provider is an OpenRouter routing preference; venue '{venue_name}' does \
                 not honor one, so the request would go out unpinned"
            )));
        }
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
                 Or set the first one once, as `manifest = <file or URL>` under\n\
                 [send] in ~/.config/oxbox/config.ini.\n\
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
            provider: None,
            skip: None,
            url: venue_url(spec),
            key_env: spec.key_env.into(),
        }]
    };

    if manifest_choice.is_none()
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

        // The routing pin: the flag over the entry's own, and only where the
        // venue honors one (load_manifest and the venue checks above have
        // already refused the rest). Verbatim, uninterpreted: what the
        // fields mean is OpenRouter's contract, not this tool's.
        let provider = args.provider.as_ref().or(entry.provider.as_ref());

        let mut payload = json!({
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
        if let Some(pin) = provider {
            payload["provider"] = Value::Object(pin.clone());
        }

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
            "provider": provider,
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
            // Not a warning: the README promises the bytes are recorded,
            // and a run whose manifest cannot be filed does not send.
            fs::write(log_dir.join("manifest.json"), &info.raw)
                .map_err(|error| quit(format!("cannot write manifest.json: {error}")))?;
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
            let _ = writeln!(out, "{}", pretty(&payload));
            let _ = out.flush();
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
    use std::io::{BufRead, BufReader, Cursor};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
    use std::thread;

    /// Tests that set environment variables take this lock; the process has
    /// one environment and the test runner is multi-threaded.
    static ENV: Mutex<()> = Mutex::new(());

    fn lock_env() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Point this test binary's config home at an empty directory.
    ///
    /// `run` reads `[send] manifest` and `[send] allow_paid` from
    /// `~/.config/oxbox/config.ini`, so without this a developer's own
    /// settings decide what these tests observe. Both leaks are real:
    /// `allow_paid = true` opens the cost gate, and the manifest dry run
    /// then records a paid entry where the case expects the free one; a
    /// configured `manifest` gives a run with nothing typed a destination
    /// where a case expects a refusal. Neither shows up on a CI runner,
    /// which has no config file -- the suite passes there and fails on the
    /// maintainer's machine, which is the worst way for a test to be wrong.
    /// wiretest closed the same leak for the Python suite by handing every
    /// ox it starts an empty config home; this is that, for runs in process.
    ///
    /// Set once and never restored: nothing in this binary should read the
    /// real file. The cases that do test these settings pin their own home
    /// through `with_env`, which applies its variables after this and so
    /// still wins. The writes happen inside `get_or_init` so that a thread
    /// leaving this function is guaranteed to see them.
    fn isolate_config_home() {
        static EMPTY_CONFIG_HOME: OnceLock<PathBuf> = OnceLock::new();
        EMPTY_CONFIG_HOME.get_or_init(|| {
            let dir = env::temp_dir().join(format!("oxbox-send-no-config-{}", process::id()));
            let _ = fs::remove_dir_all(&dir);
            fs::create_dir_all(&dir).unwrap();
            unsafe {
                env::set_var("XDG_CONFIG_HOME", &dir);
                env::set_var("APPDATA", &dir);
            }
            dir
        });
    }

    /// Run `body` with the given variables set, then restore the previous
    /// values, whether or not `body` panics.
    fn with_env<T>(vars: &[(&str, Option<&str>)], body: impl FnOnce() -> T) -> T {
        isolate_config_home();
        let _guard = lock_env();
        let previous: Vec<(String, Option<String>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), env::var(key).ok()))
            .collect();
        for (key, value) in vars {
            match value {
                Some(value) => unsafe { env::set_var(key, value) },
                None => unsafe { env::remove_var(key) },
            }
        }
        struct Restore(Vec<(String, Option<String>)>);
        impl Drop for Restore {
            fn drop(&mut self) {
                for (key, value) in &self.0 {
                    match value {
                        Some(value) => unsafe { env::set_var(key, value) },
                        None => unsafe { env::remove_var(key) },
                    }
                }
            }
        }
        let _restore = Restore(previous);
        body()
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("oxbox-send-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn parsed(words: &[&str]) -> Args {
        match parse_args(&args(words)) {
            Ok(Parsed::Run(args)) => *args,
            other => panic!("{words:?}: {other:?}"),
        }
    }

    fn message(exit: Exit) -> String {
        match exit {
            Exit::Message(text) => text,
            Exit::Code(code) => panic!("expected a message, got exit {code}"),
        }
    }

    // ── a loopback provider ───────────────────────────────────────────────

    /// One HTTP request as the listener saw it.
    struct Seen {
        request_line: String,
        headers: Vec<(String, String)>,
        body: Vec<u8>,
    }

    impl Seen {
        fn header(&self, name: &str) -> Option<&str> {
            self.headers
                .iter()
                .find(|(key, _)| key.eq_ignore_ascii_case(name))
                .map(|(_, value)| value.as_str())
        }
    }

    fn read_request(stream: &mut TcpStream) -> Seen {
        let mut reader = BufReader::new(stream);
        let mut request_line = String::new();
        reader.read_line(&mut request_line).unwrap();
        let mut headers = Vec::new();
        let mut length = 0;
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let line = line.trim_end().to_string();
            if line.is_empty() {
                break;
            }
            if let Some((key, value)) = line.split_once(':') {
                let (key, value) = (key.trim().to_string(), value.trim().to_string());
                if key.eq_ignore_ascii_case("content-length") {
                    length = value.parse().unwrap();
                }
                headers.push((key, value));
            }
        }
        let mut body = vec![0; length];
        reader.read_exact(&mut body).unwrap();
        Seen {
            request_line: request_line.trim_end().to_string(),
            headers,
            body,
        }
    }

    /// A loopback provider: serves `responses` in order, one per connection,
    /// and hands back the requests it saw.
    struct Server {
        url: String,
        total: usize,
        served: Arc<AtomicUsize>,
        handle: thread::JoinHandle<Vec<Seen>>,
    }

    impl Server {
        /// Collect what was seen. Any response the client never asked for is
        /// drained first, so a failed assertion in the test surfaces as a
        /// panic rather than as a thread blocked in accept forever.
        fn finish(self) -> Vec<Seen> {
            let address = self.url.trim_start_matches("http://").to_string();
            while self.served.load(Ordering::SeqCst) < self.total {
                if let Ok(mut stream) = TcpStream::connect(&address) {
                    let _ = stream.write_all(b"GET /drain HTTP/1.1\r\nContent-Length: 0\r\n\r\n");
                    let mut sink = Vec::new();
                    let _ = stream.read_to_end(&mut sink);
                } else {
                    break;
                }
            }
            self.handle.join().unwrap()
        }
    }

    type Response = (&'static str, Vec<(&'static str, String)>, Vec<u8>);

    fn serve(responses: Vec<Response>) -> Server {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let total = responses.len();
        let served = Arc::new(AtomicUsize::new(0));
        let counter = Arc::clone(&served);
        let handle = thread::spawn(move || {
            let mut seen = Vec::new();
            for (status, headers, body) in responses {
                let (mut stream, _) = listener.accept().unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                seen.push(read_request(&mut stream));
                let mut reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n",
                    body.len()
                );
                for (key, value) in headers {
                    reply.push_str(&format!("{key}: {value}\r\n"));
                }
                reply.push_str("\r\n");
                stream.write_all(reply.as_bytes()).unwrap();
                stream.write_all(&body).unwrap();
                stream.flush().unwrap();
            }
            seen
        });
        Server {
            url,
            total,
            served,
            handle,
        }
    }

    fn ok_json(body: Value) -> Response {
        (
            "200 OK",
            vec![("Content-Type", "application/json".to_string())],
            serde_json::to_vec(&body).unwrap(),
        )
    }

    fn good_answer() -> Value {
        json!({
            "id": "gen-1",
            "provider": "SomeUpstream",
            "choices": [{
                "finish_reason": "stop",
                "message": {"role": "assistant", "content": "the answer\n", "reasoning": "thinking"}
            }],
            "usage": {"prompt_tokens": 10, "completion_tokens": 5, "cost": 0.0,
                      "completion_tokens_details": {"reasoning_tokens": 2}}
        })
    }

    // ── small pieces ──────────────────────────────────────────────────────

    #[test]
    fn the_scanner_catches_the_measured_forms() {
        let text = "api_key = \"abcdefghijklmnop\"\nclient_secret=abcdefghijklmnopqrst\nmy_api_key = \"abcdefghijklmnopqrst\"\nDB_PASSWORD=abcdefghijklmnopqrstu\ntoken: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9\naws_secret_access_key=ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijkl/+\n";
        let hits = scan_for_secrets(text, "t");
        assert!(hits.len() >= 6, "{hits:?}");
        assert!(hits[0].starts_with("t:1: possible "), "{}", hits[0]);
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
        assert_eq!(civil_stamp(0), "1970-01-01T00-00-00Z");
        assert_eq!(civil_stamp(1_600_000_000), "2020-09-13T12-26-40Z");
        assert_eq!(civil_stamp(951_782_400), "2000-02-29T00-00-00Z");
        assert_eq!(civil_stamp(4_102_444_799), "2099-12-31T23-59-59Z");
    }

    #[test]
    fn head_cuts_characters_not_bytes() {
        assert_eq!(head("héllo", 2), "hé");
        assert_eq!(head("ab", 5), "ab");
    }

    #[test]
    fn python_spellings_of_json_values() {
        assert_eq!(python_repr(&json!("x")), "'x'");
        assert_eq!(python_repr(&Value::Null), "None");
        assert_eq!(python_repr(&json!(true)), "True");
        assert_eq!(python_repr(&json!(3)), "3");
        assert_eq!(python_repr_plain(&json!("x")), "x");
        assert_eq!(python_repr_plain(&Value::Null), "None");
        assert_eq!(python_repr_plain(&json!(false)), "False");
        assert_eq!(python_repr_plain(&json!(2.5)), "2.5");
    }

    #[test]
    fn truthiness_follows_python() {
        let zero = json!(0);
        let empty = json!("");
        let no = json!(false);
        let yes = json!("high");
        assert_eq!(truthy(None), None);
        assert_eq!(truthy(Some(&Value::Null)), None);
        assert_eq!(truthy(Some(&zero)), None);
        assert_eq!(truthy(Some(&empty)), None);
        assert_eq!(truthy(Some(&no)), None);
        assert_eq!(truthy(Some(&yes)), Some(&yes));
        let empty_object = json!({});
        let empty_array = json!([]);
        let full = json!({"message": "x"});
        assert_eq!(truthy(Some(&empty_object)), None);
        assert_eq!(truthy(Some(&empty_array)), None);
        assert_eq!(truthy(Some(&full)), Some(&full));
    }

    #[test]
    fn every_mode_has_a_system_prompt_and_the_venues_have_urls() {
        for mode in MODES {
            assert!(!system_prompt(mode).is_empty(), "{mode}");
        }
        assert_ne!(system_prompt("diff"), system_prompt("review"));
        assert_ne!(system_prompt("ask"), system_prompt("review"));
        // The override knobs are read from the environment under the
        // test-overrides feature, and the loopback tests set them on other
        // threads, so this holds the lock and clears them first.
        with_env(
            &[
                ("OXBOX_TEST_ALLOW_HTTP", None),
                ("OXBOX_TEST_VENUE_URLS", None),
                ("OXBOX_TEST_MANIFEST_MAX_BYTES", None),
            ],
            || {
                for venue in &VENUES {
                    assert!(venue_url(venue).starts_with("https://"), "{}", venue.name);
                }
                assert!(https_required());
                assert_eq!(manifest_max_bytes(), MANIFEST_MAX_BYTES);
            },
        );
    }

    #[test]
    fn manifest_effort_keeps_known_levels_only() {
        assert_eq!(manifest_effort(&json!("high"), "x"), json!("high"));
        assert_eq!(manifest_effort(&json!("extreme"), "x"), Value::Null);
        assert_eq!(manifest_effort(&json!(3), "x"), Value::Null);
    }

    #[test]
    fn strip_prog_removes_one_prefix() {
        assert_eq!(strip_prog("oxbox-send: api error: x"), "api error: x");
        assert_eq!(strip_prog("plain"), "plain");
    }

    // ── arguments ─────────────────────────────────────────────────────────

    #[test]
    fn defaults_match_argparse() {
        let a = parsed(&["fix it"]);
        assert_eq!(a.task.as_deref(), Some("fix it"));
        assert_eq!(a.mode, "diff");
        assert_eq!(a.temperature, 0.2);
        assert!(a.venue.is_none() && a.model.is_none() && a.manifest.is_none());
        assert!(!a.allow_paid && !a.failover && !a.force && !a.dry_run && !a.stdin);
        assert!(a.log_dir.ends_with("logs"));
        let none = parsed(&[]);
        assert_eq!(none.task, None);
    }

    #[test]
    fn every_flag_parses_in_both_spellings() {
        let a = parsed(&[
            "--files",
            "a.py,b.py",
            "--mode",
            "review",
            "--venue",
            "zenmux",
            "--manifest",
            "m.json",
            "--allow-paid",
            "--failover",
            "--base-url",
            "https://x/v1",
            "--api-key-env",
            "K",
            "--model",
            "m",
            "--effort",
            "low",
            "--max-tokens",
            "42",
            "--temperature",
            "0.7",
            "--stdin",
            "--log-dir",
            "/tmp/l",
            "--output",
            "o.md",
            "--status-file",
            "s.json",
            "--force",
            "--dry-run",
            "the task",
        ]);
        assert_eq!(a.files, "a.py,b.py");
        assert_eq!(a.mode, "review");
        assert_eq!(a.venue.as_deref(), Some("zenmux"));
        assert_eq!(a.manifest.as_deref(), Some("m.json"));
        assert!(a.allow_paid && a.failover && a.stdin && a.force && a.dry_run);
        assert_eq!(a.base_url.as_deref(), Some("https://x/v1"));
        assert_eq!(a.api_key_env.as_deref(), Some("K"));
        assert_eq!(a.model.as_deref(), Some("m"));
        assert_eq!(a.effort.as_deref(), Some("low"));
        assert_eq!(a.max_tokens, Some(42));
        assert_eq!(a.temperature, 0.7);
        assert_eq!(a.log_dir, PathBuf::from("/tmp/l"));
        assert_eq!(a.output.as_deref(), Some("o.md"));
        assert_eq!(a.status_file.as_deref(), Some("s.json"));
        assert_eq!(a.task.as_deref(), Some("the task"));
        let b = parsed(&["--mode=ask", "--max-tokens=7", "--model=m", "task"]);
        assert_eq!(b.mode, "ask");
        assert_eq!(b.max_tokens, Some(7));
        assert_eq!(b.model.as_deref(), Some("m"));
        // After `--`, anything is the task, and a lone dash is too.
        let c = parsed(&["--", "--not-a-flag"]);
        assert_eq!(c.task.as_deref(), Some("--not-a-flag"));
        let d = parsed(&["-"]);
        assert_eq!(d.task.as_deref(), Some("-"));
        // Empty values are "not given".
        let e = parsed(&[
            "--model",
            "",
            "--base-url=",
            "--output",
            "",
            "--status-file",
            "",
            "t",
        ]);
        assert!(
            e.model.is_none()
                && e.base_url.is_none()
                && e.output.is_none()
                && e.status_file.is_none()
        );
    }

    #[test]
    fn informational_flags_win_and_usage_errors_read_like_argparse() {
        assert_eq!(parse_args(&args(&["--help"])), Ok(Parsed::Help));
        assert_eq!(parse_args(&args(&["-h", "task"])), Ok(Parsed::Help));
        assert_eq!(parse_args(&args(&["--version"])), Ok(Parsed::Version));
        assert_eq!(parse_args(&args(&["--skill"])), Ok(Parsed::Skill));
        assert_eq!(
            parse_args(&args(&["--skill", "--model", "m"])),
            Ok(Parsed::Skill)
        );
        for (bad, needle) in [
            (vec!["a", "b"], "unrecognized arguments: b"),
            (vec!["--nope"], "unrecognized arguments: --nope"),
            (vec!["--model"], "argument --model: expected one argument"),
            (
                vec!["--mode", "poem"],
                "argument --mode: invalid choice: 'poem'",
            ),
            (
                vec!["--venue", "nowhere"],
                "argument --venue: invalid choice: 'nowhere'",
            ),
            (
                vec!["--effort", "extreme"],
                "argument --effort: invalid choice: 'extreme'",
            ),
            (
                vec!["--max-tokens", "lots"],
                "argument --max-tokens: invalid int value: 'lots'",
            ),
            (
                vec!["--temperature", "warm"],
                "argument --temperature: invalid float value: 'warm'",
            ),
            (
                vec!["--provider", "nope"],
                "argument --provider: not a JSON object",
            ),
            (
                vec!["--provider", "[\"novita\"]"],
                "argument --provider: not a JSON object: [\"novita\"]",
            ),
        ] {
            let error = parse_args(&args(&bad)).unwrap_err();
            assert!(error.contains(needle), "{bad:?}: {error}");
        }
        assert!(help_text().contains("--dry-run"));
        assert!(help_text().starts_with(USAGE_LINE));
    }

    #[test]
    fn the_provider_flag_is_an_object_or_nothing() {
        let pinned = parsed(&[
            "--provider",
            r#"{"order": ["novita"], "allow_fallbacks": false}"#,
            "t",
        ]);
        let pin = pinned.provider.expect("an object");
        assert_eq!(pin.get("order"), Some(&json!(["novita"])));
        assert_eq!(pin.get("allow_fallbacks"), Some(&json!(false)));
        let inline = parsed(&[r#"--provider={"sort":"price"}"#, "t"]);
        assert_eq!(inline.provider.unwrap().get("sort"), Some(&json!("price")));
        // Empty, and an empty object, are "not given".
        assert!(parsed(&["--provider", "", "t"]).provider.is_none());
        assert!(parsed(&["--provider", "{}", "t"]).provider.is_none());
        assert!(parsed(&["t"]).provider.is_none());
        assert!(help_text().contains("--provider PROVIDER"));
        assert!(USAGE_LINE.contains("[--provider PROVIDER]"));
    }

    // ── the status record ─────────────────────────────────────────────────

    #[test]
    fn the_status_record_keeps_its_key_order_and_lands_in_both_places() {
        let status = new_status();
        let keys: Vec<&str> = status.keys().map(String::as_str).collect();
        assert_eq!(&keys[..4], &["ox_version", "ok", "exit_code", "error"]);
        assert!(keys.contains(&"route") && keys.contains(&"venue_cost"));
        assert_eq!(*keys.last().unwrap(), "status_file");

        let dir = scratch("status");
        let mut status = new_status();
        status.insert("log_dir".into(), json!(dir.to_string_lossy()));
        let file = dir.join("s.json");
        status.insert("status_file".into(), json!(file.to_string_lossy()));
        let code = finish(Ok(()), &mut status);
        assert_eq!(code, 0);
        let beside: Value =
            serde_json::from_slice(&fs::read(dir.join("status.json")).unwrap()).unwrap();
        let named: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(beside, named);
        assert_eq!(named["ok"], json!(true));
        assert_eq!(named["exit_code"], json!(0));
        assert!(
            named.get("status_file").is_none(),
            "the path is not part of the record"
        );

        let mut status = new_status();
        status.insert("status_file".into(), json!(file.to_string_lossy()));
        assert_eq!(finish(Err(quit("bad thing")), &mut status), 1);
        let named: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(named["error"], json!("oxbox-send: bad thing"));
        assert_eq!(finish(Err(Exit::Code(2)), &mut status), 2);
        let named: Value = serde_json::from_slice(&fs::read(&file).unwrap()).unwrap();
        assert_eq!(named["exit_code"], json!(2));
        assert!(named["error"].as_str().unwrap().contains("stderr"));
        // An unwritable target warns and does not fail.
        let mut status = new_status();
        status.insert(
            "status_file".into(),
            json!(dir.join("no").join("such").join("s.json").to_string_lossy()),
        );
        assert_eq!(finish(Ok(()), &mut status), 0);
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── context ───────────────────────────────────────────────────────────

    #[test]
    fn context_blocks_carry_the_path_and_language() {
        let dir = scratch("context");
        fs::write(dir.join("a.py"), "x = 1\n").unwrap();
        fs::write(dir.join("README"), "hello\n").unwrap();
        let a = dir.join("a.py").to_string_lossy().into_owned();
        let r = dir.join("README").to_string_lossy().into_owned();
        let context = build_context(&[a.clone(), r.clone()], false, "task").unwrap();
        assert_eq!(context.total_bytes, 12);
        // CRLF on disk is LF on the wire, and counts as LF.
        fs::write(dir.join("win.py"), "x = 1\r\ny = 2\r\n").unwrap();
        let w = dir.join("win.py").to_string_lossy().into_owned();
        let windows = build_context(std::slice::from_ref(&w), false, "task").unwrap();
        assert_eq!(windows.total_bytes, 12);
        assert!(!windows.text.contains('\r'), "{}", windows.text);
        assert!(context.findings.is_empty());
        assert!(
            context
                .text
                .starts_with(&format!("### File: {a}\n```py\nx = 1\n\n```")),
            "{}",
            context.text
        );
        assert!(
            context
                .text
                .contains(&format!("### File: {r}\n```text\nhello\n\n```")),
            "{}",
            context.text
        );
        let empty = build_context(&[], false, "").unwrap();
        assert_eq!(empty.text, "");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn context_refuses_missing_binary_and_secret_bearing_files_unless_forced() {
        let dir = scratch("context-refuse");
        let missing = dir.join("nope.py").to_string_lossy().into_owned();
        assert!(message(build_context(&[missing], false, "t").unwrap_err()).contains("not a file"));
        fs::write(dir.join("blob.bin"), [0xff, 0xfe, 0x00, 0x80]).unwrap();
        let blob = dir.join("blob.bin").to_string_lossy().into_owned();
        assert!(
            message(build_context(&[blob], false, "t").unwrap_err()).contains("not a text file")
        );
        fs::write(
            dir.join("cfg.py"),
            "api_key = \"abcdefghijklmnopqrstuvwx\"\n",
        )
        .unwrap();
        let cfg = dir.join("cfg.py").to_string_lossy().into_owned();
        assert_eq!(
            build_context(std::slice::from_ref(&cfg), false, "t").unwrap_err(),
            Exit::Code(2)
        );
        let forced = build_context(std::slice::from_ref(&cfg), true, "t").unwrap();
        assert_eq!(forced.findings.len(), 1);
        assert!(
            forced.findings[0].starts_with(&format!("{cfg}:1: possible ")),
            "{:?}",
            forced.findings
        );
        // The task text is scanned like a file body, labeled as such.
        let task = "here: token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9";
        assert_eq!(build_context(&[], false, task).unwrap_err(), Exit::Code(2));
        let forced = build_context(&[], true, task).unwrap();
        assert!(
            forced.findings[0].starts_with("<task text>:1:"),
            "{:?}",
            forced.findings
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn context_refuses_oversized_payloads_unless_forced() {
        let dir = scratch("context-size");
        let big = dir.join("big.txt");
        fs::write(&big, "0\n".repeat(MAX_PAYLOAD_BYTES / 2 + 1)).unwrap();
        let path = big.to_string_lossy().into_owned();
        let error = message(build_context(std::slice::from_ref(&path), false, "t").unwrap_err());
        assert!(error.contains("refusing to send"), "{error}");
        assert!(error.contains("--force"), "{error}");
        assert!(build_context(&[path], true, "t").unwrap().total_bytes > MAX_PAYLOAD_BYTES);
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── the manifest ──────────────────────────────────────────────────────

    fn write_manifest(dir: &Path, name: &str, value: &Value) -> String {
        let path = dir.join(name);
        fs::write(&path, serde_json::to_vec(value).unwrap()).unwrap();
        path.to_string_lossy().into_owned()
    }

    #[test]
    fn manifest_shape_errors_name_the_problem() {
        let dir = scratch("manifest-shape");
        let cases: Vec<(&str, Value, &str)> = vec![
            (
                "v-missing",
                json!({"recommendations": []}),
                "manifest_version must be an integer, found None",
            ),
            (
                "v-bool",
                json!({"manifest_version": true}),
                "manifest_version must be an integer, found True",
            ),
            (
                "v-new",
                json!({"manifest_version": 99}),
                "newer than this ox understands",
            ),
            (
                "no-recs",
                json!({"manifest_version": 0}),
                "has no recommendations",
            ),
            (
                "empty-recs",
                json!({"manifest_version": 0, "recommendations": []}),
                "has no recommendations",
            ),
            (
                "bad-rec",
                json!({"manifest_version": 0, "recommendations": [3]}),
                "recommendation 1 is not an object",
            ),
        ];
        for (name, value, needle) in cases {
            let path = write_manifest(&dir, name, &value);
            let error = message(load_manifest(&path, false, None).unwrap_err());
            assert!(error.contains(needle), "{name}: {error}");
        }
        fs::write(dir.join("not.json"), b"{not json").unwrap();
        let error = message(
            load_manifest(dir.join("not.json").to_str().unwrap(), false, None).unwrap_err(),
        );
        assert!(error.contains("is not valid JSON"), "{error}");
        fs::write(dir.join("bytes.json"), [0xff, 0xfe]).unwrap();
        let error = message(
            load_manifest(dir.join("bytes.json").to_str().unwrap(), false, None).unwrap_err(),
        );
        assert!(error.contains("is not valid JSON"), "{error}");
        let error = message(
            load_manifest(dir.join("absent.json").to_str().unwrap(), false, None).unwrap_err(),
        );
        assert!(error.contains("cannot read manifest"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn manifest_entries_are_permitted_or_skipped_for_the_right_reasons() {
        let dir = scratch("manifest-entries");
        let manifest = json!({
            "manifest_version": 0,
            "defaults": {"max_tokens": 5000, "effort": "extreme", "color": "blue"},
            "recommendations": [
                {"venue": "nowhere", "model": "m0"},
                {"venue": "openrouter"},
                {"venue": "openrouter", "model": "paid/one", "cost": "paid"},
                {"venue": "openrouter", "model": "mystery/one"},
                {"venue": "zenmux", "model": "z/free", "cost": "free"},
                {"venue": "openrouter", "model": "or/free", "cost": "free", "rank": 9,
                 "why": "fast", "base_url": "https://elsewhere.example/v1",
                 "params": {"max_tokens": 0, "effort": "low"}},
            ]
        });
        let path = write_manifest(&dir, "m.json", &manifest);
        with_env(
            &[("OPENROUTER_API_KEY", Some("k")), ("ZENMUX_API_KEY", None)],
            || {
                let (entries, info) = load_manifest(&path, false, None).unwrap();
                assert_eq!(info.path, path);
                assert_eq!(info.sha256.len(), 64);
                assert!(!info.fetched);
                assert_eq!(info.raw, fs::read(&path).unwrap());
                assert_eq!(info.defaults.get("max_tokens"), Some(&json!(5000)));
                assert_eq!(
                    info.defaults.get("effort"),
                    Some(&Value::Null),
                    "unknown effort dropped"
                );
                let skips: Vec<Option<String>> = entries.iter().map(|e| e.skip.clone()).collect();
                assert_eq!(skips[0].as_deref(), Some("unknown venue 'nowhere'"));
                assert_eq!(skips[1].as_deref(), Some("no model named"));
                assert_eq!(
                    skips[2].as_deref(),
                    Some("cost=paid (pass --allow-paid to use it)")
                );
                assert_eq!(
                    skips[3].as_deref(),
                    Some("cost=unknown (pass --allow-paid to use it)")
                );
                assert_eq!(skips[4].as_deref(), Some("ZENMUX_API_KEY not set"));
                assert_eq!(skips[5], None);
                let live = &entries[5];
                assert_eq!(live.position, 6);
                assert_eq!(
                    live.url, "https://openrouter.ai/api/v1/chat/completions",
                    "the table wins"
                );
                assert_eq!(live.key_env, "OPENROUTER_API_KEY");
                assert_eq!(live.why, "fast");
                assert_eq!(live.params.get("effort"), Some(&json!("low")));
                assert_eq!(live.params.get("max_tokens"), Some(&json!(0)));
                // --allow-paid admits paid and unknown alike.
                let (entries, _) = load_manifest(&path, true, None).unwrap();
                assert_eq!(entries[2].skip, None);
                assert_eq!(entries[3].skip, None);
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_provider_pin_is_kept_only_where_the_venue_honors_it() {
        let dir = scratch("manifest-provider");
        let pin = json!({"only": ["novita"], "allow_fallbacks": false});
        let manifest = json!({
            "manifest_version": 1,
            "recommendations": [
                {"venue": "openrouter", "model": "or/pinned", "cost": "free", "provider": pin},
                {"venue": "zenmux", "model": "z/pinned", "cost": "free", "provider": pin},
                {"venue": "openrouter", "model": "or/string", "cost": "free", "provider": "novita"},
                {"venue": "openrouter", "model": "or/empty", "cost": "free", "provider": {}},
                {"venue": "openrouter", "model": "or/null", "cost": "free", "provider": null},
                {"venue": "zenmux", "model": "z/plain", "cost": "free"},
            ]
        });
        let path = write_manifest(&dir, "m.json", &manifest);
        with_env(
            &[
                ("OPENROUTER_API_KEY", Some("k")),
                ("ZENMUX_API_KEY", Some("k")),
            ],
            || {
                // A version-1 manifest is this ox's own version, so it is read.
                let (entries, _) = load_manifest(&path, false, None).unwrap();
                let skips: Vec<Option<String>> = entries.iter().map(|e| e.skip.clone()).collect();
                assert_eq!(skips[0], None);
                assert_eq!(
                    entries[0].provider.as_ref().map(|p| json!(p)),
                    Some(pin.clone())
                );
                assert_eq!(
                    skips[1].as_deref(),
                    Some("provider pin on venue zenmux, which does not honor one")
                );
                assert_eq!(skips[2].as_deref(), Some("provider is not an object"));
                assert_eq!(skips[3], None);
                assert_eq!(
                    entries[3].provider, None,
                    "an empty object is no preference"
                );
                assert_eq!(skips[4], None);
                assert_eq!(entries[4].provider, None);
                assert_eq!(skips[5], None);
                // The flag applies to every entry: a venue that cannot honor it
                // is skipped even when the entry itself carries no pin.
                let flag = pin.as_object().unwrap();
                let (entries, _) = load_manifest(&path, false, Some(flag)).unwrap();
                assert_eq!(entries[0].skip, None);
                assert_eq!(
                    entries[5].skip.as_deref(),
                    Some("provider pin on venue zenmux, which does not honor one")
                );
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_manifest_url_must_be_https_and_is_never_followed_through_a_redirect() {
        with_env(&[("OXBOX_TEST_ALLOW_HTTP", None)], || {
            let error = message(fetch_manifest("http://example.invalid/m.json").unwrap_err());
            assert!(error.contains("must be https://"), "{error}");
            let error =
                message(load_manifest("http://example.invalid/m.json", false, None).unwrap_err());
            assert!(error.contains("must be https://"), "{error}");
        });
    }

    #[cfg(feature = "test-overrides")]
    #[test]
    fn fetching_a_manifest_over_loopback() {
        let manifest = json!({"manifest_version": 0, "recommendations": [{"venue": "openrouter", "model": "m", "cost": "free"}]});
        let body = serde_json::to_vec(&manifest).unwrap();
        let server = serve(vec![
            ok_json(manifest.clone()),
            (
                "302 Found",
                vec![("Location", "https://elsewhere.example/m.json".to_string())],
                Vec::new(),
            ),
            ("404 Not Found", vec![], b"gone".to_vec()),
            ok_json(manifest.clone()),
        ]);
        let url = server.url.clone();
        with_env(
            &[
                ("OXBOX_TEST_ALLOW_HTTP", Some("1")),
                ("OXBOX_TEST_MANIFEST_MAX_BYTES", None),
                ("OPENROUTER_API_KEY", Some("k")),
            ],
            || {
                assert!(!https_required());
                let address = format!("{url}/m.json");
                let (entries, info) = load_manifest(&address, false, None).unwrap();
                assert!(info.fetched);
                assert_eq!(info.raw, body);
                assert_eq!(entries[0].skip, None);
                let error = message(fetch_manifest(&address).unwrap_err());
                assert!(
                    error.contains("redirected (HTTP 302 to https://elsewhere.example/m.json)"),
                    "{error}"
                );
                let error = message(fetch_manifest(&address).unwrap_err());
                assert!(error.contains("HTTP 404"), "{error}");
                unsafe { env::set_var("OXBOX_TEST_MANIFEST_MAX_BYTES", "10") };
                assert_eq!(manifest_max_bytes(), 10);
                let error = message(fetch_manifest(&address).unwrap_err());
                assert!(error.contains("larger than 10 bytes"), "{error}");
                unsafe { env::remove_var("OXBOX_TEST_MANIFEST_MAX_BYTES") };
                // Nothing listens here any more: a connection error is reported, not retried.
                let error = message(fetch_manifest("http://127.0.0.1:9/m.json").unwrap_err());
                assert!(error.contains("cannot fetch manifest"), "{error}");
            },
        );
        let seen = server.finish();
        assert_eq!(seen.len(), 4);
        assert!(
            seen[0].request_line.starts_with("GET /m.json "),
            "{}",
            seen[0].request_line
        );
        assert_eq!(seen[0].header("accept"), Some("application/json"));
        assert_eq!(
            seen[0].header("authorization"),
            None,
            "a manifest fetch carries no credential"
        );
        assert!(seen[0].header("user-agent").unwrap().starts_with("oxbox ("));
    }

    // ── the audit log ─────────────────────────────────────────────────────

    #[test]
    fn log_directories_are_claimed_exclusively() {
        let dir = scratch("logdir");
        let base = dir.join("logs");
        let first = claim_log_dir(&base, "2026-01-01T00-00-00Z").unwrap();
        assert_eq!(first, base.join("2026-01-01T00-00-00Z"));
        let second = claim_log_dir(&base, "2026-01-01T00-00-00Z").unwrap();
        assert_eq!(second, base.join("2026-01-01T00-00-00Z-2"));
        let third = claim_log_dir(&base, "2026-01-01T00-00-00Z").unwrap();
        assert_eq!(third, base.join("2026-01-01T00-00-00Z-3"));
        let (stamp, made) = make_log_dir(&base).unwrap();
        assert_eq!(made.file_name().unwrap().to_string_lossy(), stamp);
        // A base that cannot be created is a message, not a panic.
        fs::write(dir.join("file"), b"x").unwrap();
        let error = message(claim_log_dir(&dir.join("file").join("logs"), "s").unwrap_err());
        assert!(error.contains("cannot create log directory"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn write_log_warns_instead_of_failing() {
        let dir = scratch("writelog");
        write_log(&dir.join("ok.txt"), "fine");
        assert_eq!(fs::read_to_string(dir.join("ok.txt")).unwrap(), "fine");
        write_log(&dir.join("no").join("such").join("x.txt"), "lost");
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── the request ───────────────────────────────────────────────────────

    #[test]
    fn a_good_answer_is_parsed_and_filed() {
        let dir = scratch("send-good");
        let server = serve(vec![ok_json(good_answer())]);
        let url = server.url.clone();
        let payload = json!({"model": "m", "messages": [], "max_tokens": 5});
        let answer = send_and_parse(&url, "sekrit", &payload, &dir).unwrap();
        assert_eq!(answer.content, "the answer\n");
        assert_eq!(answer.reasoning, "thinking");
        assert_eq!(answer.route.as_deref(), Some("SomeUpstream"));
        assert_eq!(answer.choice.get("finish_reason"), Some(&json!("stop")));
        assert_eq!(answer.usage.get("cost"), Some(&json!(0.0)));
        assert_eq!(
            fs::read_to_string(dir.join("content.md")).unwrap(),
            "the answer\n"
        );
        assert_eq!(
            fs::read_to_string(dir.join("reasoning.txt")).unwrap(),
            "thinking"
        );
        let filed: Value =
            serde_json::from_slice(&fs::read(dir.join("response.json")).unwrap()).unwrap();
        assert_eq!(filed, good_answer());
        let seen = server.finish();
        assert!(
            seen[0].request_line.starts_with("POST / "),
            "{}",
            seen[0].request_line
        );
        assert_eq!(seen[0].header("authorization"), Some("Bearer sekrit"));
        assert_eq!(seen[0].header("content-type"), Some("application/json"));
        assert_eq!(seen[0].header("x-title"), Some("oxbox supervised bridge"));
        let sent: Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert_eq!(
            sent, payload,
            "bytes on the wire are the payload, untouched"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn every_non_answer_fails_the_attempt_and_leaves_evidence() {
        let dir = scratch("send-bad");
        let payload = json!({"model": "m"});
        let no_content = json!({"choices": [{"finish_reason": "length", "message": {"content": "  "}}],
            "usage": {"completion_tokens": 7, "completion_tokens_details": {"reasoning_tokens": 7}}});
        let server = serve(vec![
            (
                "500 Internal Server Error",
                vec![],
                b"upstream fell over".to_vec(),
            ),
            (
                "302 Found",
                vec![("Location", "https://elsewhere.example/".to_string())],
                Vec::new(),
            ),
            (
                "200 OK",
                vec![("Content-Type", "text/html".to_string())],
                b"<html>captive portal</html>".to_vec(),
            ),
            ok_json(json!({"error": {"message": "bad key", "code": 401}})),
            ok_json(json!({"choices": []})),
            ok_json(no_content.clone()),
            ok_json(
                json!({"choices": [{"message": {"content": "ok", "tool_calls": [{"id": "x"}]}}]}),
            ),
            ok_json(json!({"error": {}, "choices": [{"message": {"content": "fine"}}]})),
        ]);
        let url = server.url.clone();
        let text =
            |result: Result<Answer, AttemptFailed>| result.err().map(|f| f.0).unwrap_or_default();

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(
            failure.contains("HTTP 500: upstream fell over"),
            "{failure}"
        );
        assert_eq!(
            fs::read_to_string(dir.join("error.txt")).unwrap(),
            "500\nupstream fell over"
        );

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(
            failure.contains("HTTP 302"),
            "a redirect is answered, not followed: {failure}"
        );

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(failure.contains("non-JSON body"), "{failure}");
        assert!(
            fs::read_to_string(dir.join("error.txt"))
                .unwrap()
                .contains("captive portal")
        );

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(
            failure.contains("api error:") && failure.contains("bad key"),
            "{failure}"
        );

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(failure.contains("no choices"), "{failure}");

        let failure = text(send_and_parse(&url, "k", &payload, &dir));
        assert!(failure.contains("no content (finish=length)"), "{failure}");
        assert!(
            failure.contains("7 of 7 completion tokens went to reasoning"),
            "{failure}"
        );

        // tool_calls are logged and ignored; the answer still comes back.
        let answer = send_and_parse(&url, "k", &payload, &dir).unwrap();
        assert_eq!(answer.content, "ok");
        assert_eq!(answer.route, None);

        // An empty error object is no error.
        let answer = send_and_parse(&url, "k", &payload, &dir).unwrap();
        assert_eq!(answer.content, "fine");

        let failure = text(send_and_parse("http://127.0.0.1:9/", "k", &payload, &dir));
        assert!(failure.contains("network error"), "{failure}");
        server.finish();
        fs::remove_dir_all(&dir).unwrap();
    }

    // ── the run ───────────────────────────────────────────────────────────

    fn run_with(words: &[&str], stdin: &str) -> (Result<(), Exit>, Map<String, Value>, String) {
        isolate_config_home();
        let args = parsed(words);
        let mut status = new_status();
        let mut input = Cursor::new(stdin.as_bytes().to_vec());
        let mut out = Vec::new();
        let result = run(&args, &mut status, &mut input, &mut out);
        (result, status, String::from_utf8_lossy(&out).into_owned())
    }

    #[test]
    fn allow_paid_in_the_config_file_opens_the_cost_gate_like_the_flag() {
        let dir = scratch("config-allow-paid");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let manifest = write_manifest(
            &dir,
            "m.json",
            &json!({"manifest_version": 0, "recommendations": [
                {"venue": "openrouter", "model": "or/paid", "cost": "paid"}]}),
        );
        let cfg = dir.join("oxbox");
        fs::create_dir_all(&cfg).unwrap();
        let dir_text = dir.to_string_lossy().into_owned();
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some(&dir_text)),
                ("APPDATA", Some(&dir_text)),
                ("OPENROUTER_API_KEY", Some("k")),
            ],
            || {
                let argv = [
                    "--dry-run",
                    "--manifest",
                    &manifest,
                    "--log-dir",
                    &logs,
                    "hi",
                ];
                // No file: free-only, and the paid entry is skipped.
                let (result, status, _) = run_with(&argv, "");
                let error = message(result.unwrap_err());
                assert!(error.contains("cost=paid"), "{error}");
                assert_eq!(status["model"], Value::Null);
                // The file opens the gate exactly as the flag does.
                fs::write(cfg.join(core::CONFIG_FILE), "[send]\nallow_paid = yes\n").unwrap();
                let (result, status, _) = run_with(&argv, "");
                assert_eq!(result, Ok(()));
                assert_eq!(status["model"], json!("or/paid"));
                // false is the default spelled out.
                fs::write(cfg.join(core::CONFIG_FILE), "[send]\nallow_paid = false\n").unwrap();
                let (result, _, _) = run_with(&argv, "");
                assert!(message(result.unwrap_err()).contains("cost=paid"));
                // A value that is neither is an error, not a closed gate.
                fs::write(cfg.join(core::CONFIG_FILE), "[send]\nallow_paid = maybe\n").unwrap();
                let (result, _, _) = run_with(&argv, "");
                let error = message(result.unwrap_err());
                assert!(error.contains("must be true or false"), "{error}");
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_configured_manifest_stands_in_for_the_flag_until_a_destination_is_typed() {
        let dir = scratch("config-manifest");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let manifest = write_manifest(
            &dir,
            "m.json",
            &json!({"manifest_version": 0, "recommendations": [
                {"venue": "openrouter", "model": "or/configured", "cost": "free"}]}),
        );
        let cfg = dir.join("oxbox");
        fs::create_dir_all(&cfg).unwrap();
        fs::write(
            cfg.join(core::CONFIG_FILE),
            format!("[send]\nmanifest = {manifest}\n"),
        )
        .unwrap();
        let dir_text = dir.to_string_lossy().into_owned();
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some(&dir_text)),
                ("APPDATA", Some(&dir_text)),
                ("OPENROUTER_API_KEY", Some("k")),
            ],
            || {
                // Nothing typed: the configured manifest chooses, and
                // --failover is allowed because a manifest is in play.
                let (result, status, _) =
                    run_with(&["--dry-run", "--failover", "--log-dir", &logs, "hi"], "");
                assert_eq!(result, Ok(()));
                assert_eq!(status["manifest"]["path"], json!(manifest));
                assert_eq!(status["model"], json!("or/configured"));
                // A typed destination wins over the config file.
                let (result, status, _) = run_with(
                    &["--dry-run", "--model", "typed", "--log-dir", &logs, "hi"],
                    "",
                );
                assert_eq!(result, Ok(()));
                assert_eq!(status["manifest"], Value::Null);
                assert_eq!(status["model"], json!("typed"));
                // An empty value is unset, and the no-model refusal names the key.
                fs::write(cfg.join(core::CONFIG_FILE), "[send]\nmanifest =\n").unwrap();
                let (result, _, _) = run_with(&["--dry-run", "--log-dir", &logs, "hi"], "");
                let error = message(result.unwrap_err());
                assert!(error.contains("no model chosen"), "{error}");
                assert!(error.contains("[send]"), "{error}");
                // A config file that cannot be parsed is an error, not "unset".
                fs::write(cfg.join(core::CONFIG_FILE), "[send]\nbroken\n").unwrap();
                let (result, _, _) = run_with(&["--dry-run", "--log-dir", &logs, "hi"], "");
                let error = message(result.unwrap_err());
                assert!(error.contains("cannot parse"), "{error}");
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_provider_pin_rides_in_the_request_and_the_meta() {
        let dir = scratch("dry-provider");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let pin = r#"{"only": ["novita"], "allow_fallbacks": false}"#;
        with_env(&[("OPENROUTER_API_KEY", None)], || {
            let (result, status, out) = run_with(
                &[
                    "--dry-run",
                    "--model",
                    "m",
                    "--provider",
                    pin,
                    "--log-dir",
                    &logs,
                    "hi",
                ],
                "",
            );
            assert_eq!(result, Ok(()));
            let printed: Value = serde_json::from_str(&out).unwrap();
            let expected: Value = serde_json::from_str(pin).unwrap();
            assert_eq!(printed["provider"], expected, "verbatim");
            let log_dir = PathBuf::from(status["log_dir"].as_str().unwrap());
            let meta: Value =
                serde_json::from_slice(&fs::read(log_dir.join("meta.json")).unwrap()).unwrap();
            assert_eq!(meta["provider"], expected);

            // Without the flag: no key in the request, null in the meta.
            let (result, status, out) =
                run_with(&["--dry-run", "--model", "m", "--log-dir", &logs, "hi"], "");
            assert_eq!(result, Ok(()));
            let printed: Value = serde_json::from_str(&out).unwrap();
            assert!(printed.get("provider").is_none());
            let log_dir = PathBuf::from(status["log_dir"].as_str().unwrap());
            let meta: Value =
                serde_json::from_slice(&fs::read(log_dir.join("meta.json")).unwrap()).unwrap();
            assert_eq!(meta["provider"], Value::Null);

            // A venue that does not honor a pin refuses it before anything
            // is built, and so does an unlisted endpoint.
            let (result, _, _) = run_with(
                &[
                    "--dry-run",
                    "--venue",
                    "zenmux",
                    "--model",
                    "m",
                    "--provider",
                    pin,
                    "hi",
                ],
                "",
            );
            let error = message(result.unwrap_err());
            assert!(
                error.contains("venue 'zenmux' does not honor one"),
                "{error}"
            );
            let (result, _, _) = run_with(
                &[
                    "--dry-run",
                    "--base-url",
                    "https://x.example/v1",
                    "--api-key-env",
                    "K",
                    "--model",
                    "m",
                    "--provider",
                    pin,
                    "hi",
                ],
                "",
            );
            let error = message(result.unwrap_err());
            assert!(error.contains("does not apply with --base-url"), "{error}");
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_dry_run_builds_and_files_the_request_without_a_key() {
        let dir = scratch("dry");
        fs::write(dir.join("a.py"), "x = 1\n").unwrap();
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let file = dir.join("a.py").to_string_lossy().into_owned();
        with_env(&[("OPENROUTER_API_KEY", None)], || {
            let (result, status, out) = run_with(
                &[
                    "--dry-run",
                    "--model",
                    "m/x",
                    "--files",
                    &file,
                    "--log-dir",
                    &logs,
                    "--effort",
                    "low",
                    "fix it",
                ],
                "",
            );
            assert_eq!(result, Ok(()));
            let printed: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(printed["model"], json!("m/x"));
            assert!(
                printed.get("tools").is_none()
                    && printed.get("tool_choice").is_none()
                    && printed.get("functions").is_none()
            );
            assert_eq!(printed["messages"][0]["role"], json!("system"));
            assert!(
                printed["messages"][1]["content"]
                    .as_str()
                    .unwrap()
                    .starts_with("fix it\n\n### File: ")
            );
            assert_eq!(printed["reasoning"]["effort"], json!("low"));
            assert_eq!(printed["max_tokens"], json!(DEFAULT_MAX_TOKENS));
            assert_eq!(status["venue"], json!("openrouter"));
            assert_eq!(status["model"], json!("m/x"));
            assert_eq!(status["dry_run"], json!(true));
            let log_dir = PathBuf::from(status["log_dir"].as_str().unwrap());
            let request: Value =
                serde_json::from_slice(&fs::read(log_dir.join("request.json")).unwrap()).unwrap();
            assert_eq!(request, printed);
            let meta: Value =
                serde_json::from_slice(&fs::read(log_dir.join("meta.json")).unwrap()).unwrap();
            assert_eq!(meta["venue"], json!("openrouter"));
            assert_eq!(meta["key_env"], json!("OPENROUTER_API_KEY"));
            assert_eq!(
                meta["endpoint"],
                json!("https://openrouter.ai/api/v1/chat/completions")
            );
            assert_eq!(meta["files"], json!([file]));
            assert_eq!(meta["context_bytes"], json!(6));
            assert_eq!(
                meta["log_dir"],
                json!(log_dir.file_name().unwrap().to_string_lossy())
            );
            assert!(meta.get("manifest").is_none());
            assert!(!log_dir.join("response.json").exists());
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_task_can_come_from_stdin_and_must_not_be_empty() {
        let dir = scratch("stdin");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let (result, _, out) = run_with(
            &["--dry-run", "--stdin", "--model", "m", "--log-dir", &logs],
            "from stdin\n",
        );
        assert_eq!(result, Ok(()));
        let printed: Value = serde_json::from_str(&out).unwrap();
        assert_eq!(printed["messages"][1]["content"], json!("from stdin"));
        let (result, _, _) = run_with(&["--dry-run", "--stdin", "--model", "m"], "   \n");
        assert_eq!(message(result.unwrap_err()), "no task given");
        let (result, _, _) = run_with(&["--dry-run", "--model", "m"], "");
        assert_eq!(message(result.unwrap_err()), "no task given");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn destination_and_credential_are_resolved_together() {
        with_env(
            &[
                ("OPENROUTER_API_KEY", None),
                ("MY_KEY", None),
                ("OXBOX_TEST_ALLOW_HTTP", None),
            ],
            || {
                let cases: Vec<(Vec<&str>, &str)> = vec![
                    (
                        vec!["--failover", "--model", "m", "t"],
                        "--failover requires --manifest",
                    ),
                    (
                        vec!["--manifest", "m.json", "--venue", "zenmux", "t"],
                        "--venue conflicts with --manifest",
                    ),
                    (
                        vec!["--manifest", "m.json", "--model", "m", "t"],
                        "--model conflicts with --manifest",
                    ),
                    (
                        vec!["--manifest", "m.json", "--base-url", "https://x", "t"],
                        "--base-url conflicts with --manifest",
                    ),
                    (
                        vec!["--manifest", "m.json", "--api-key-env", "K", "t"],
                        "--api-key-env conflicts with --manifest",
                    ),
                    (
                        vec!["--base-url", "https://x/v1", "--model", "m", "t"],
                        "--base-url requires --api-key-env",
                    ),
                    (
                        vec![
                            "--base-url",
                            "http://x/v1",
                            "--api-key-env",
                            "K",
                            "--model",
                            "m",
                            "t",
                        ],
                        "must be an https:// URL",
                    ),
                    (
                        vec!["--base-url", "https://x/v1", "--api-key-env", "K", "t"],
                        "--model is required for venue 'custom'",
                    ),
                    (
                        vec!["--api-key-env", "K", "--model", "m", "t"],
                        "--api-key-env only applies with --base-url",
                    ),
                    (
                        vec!["--venue", "zenmux", "t"],
                        "no model chosen, and 'zenmux' has no default",
                    ),
                    (vec!["--model", "m", "t"], "OPENROUTER_API_KEY not set"),
                    (
                        vec![
                            "--base-url",
                            "https://x/v1",
                            "--api-key-env",
                            "MY_KEY",
                            "--model",
                            "m",
                            "t",
                        ],
                        "MY_KEY not set",
                    ),
                ];
                for (words, needle) in cases {
                    let (result, _, _) = run_with(&words, "");
                    let error = message(result.unwrap_err());
                    assert!(error.contains(needle), "{words:?}: {error}");
                }
            },
        );
    }

    #[test]
    fn a_leftover_output_file_is_cleared_first_and_a_status_file_marks_the_run_in_progress() {
        let dir = scratch("output");
        let output = dir.join("answer.md");
        fs::write(&output, "stale").unwrap();
        let status_file = dir.join("s.json");
        let (result, _, _) = run_with(
            &[
                "--dry-run",
                "--output",
                output.to_str().unwrap(),
                "--status-file",
                status_file.to_str().unwrap(),
            ],
            "",
        );
        assert_eq!(message(result.unwrap_err()), "no task given");
        assert!(
            !output.exists(),
            "the stale answer is gone even though the run failed"
        );
        let record: Value = serde_json::from_slice(&fs::read(&status_file).unwrap()).unwrap();
        assert_eq!(record["ok"], json!(false));
        assert_eq!(
            record["exit_code"],
            Value::Null,
            "written before the outcome is known"
        );
        assert_eq!(record["output"], json!(output.to_string_lossy()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_manifest_dry_run_records_the_choice_and_skips_the_rest() {
        let dir = scratch("manifest-dry");
        let manifest = json!({
            "manifest_version": 0,
            "defaults": {"max_tokens": 4321, "effort": "medium"},
            "recommendations": [
                {"venue": "openrouter", "model": "paid/one", "cost": "paid"},
                {"venue": "openrouter", "model": "or/free", "cost": "free", "why": "quick",
                 "params": {"effort": "xhigh"}},
                {"venue": "openrouter", "model": "or/other", "cost": "free"},
            ]
        });
        let path = write_manifest(&dir, "m.json", &manifest);
        let logs = dir.join("logs").to_string_lossy().into_owned();
        with_env(&[("OPENROUTER_API_KEY", Some("k"))], || {
            let (result, status, out) = run_with(
                &["--dry-run", "--manifest", &path, "--log-dir", &logs, "t"],
                "",
            );
            assert_eq!(result, Ok(()));
            let printed: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(printed["model"], json!("or/free"));
            assert_eq!(printed["max_tokens"], json!(4321), "issue-wide default");
            assert_eq!(
                printed["reasoning"]["effort"],
                json!("xhigh"),
                "entry params beat defaults"
            );
            assert_eq!(status["manifest"]["path"], json!(path));
            assert_eq!(status["manifest"]["sha256"].as_str().unwrap().len(), 64);
            let log_dir = PathBuf::from(status["log_dir"].as_str().unwrap());
            assert_eq!(
                fs::read(log_dir.join("manifest.json")).unwrap(),
                fs::read(&path).unwrap()
            );
            let meta: Value =
                serde_json::from_slice(&fs::read(log_dir.join("meta.json")).unwrap()).unwrap();
            assert_eq!(meta["manifest"]["entry_position"], json!(2));
            assert_eq!(meta["manifest"]["fetched"], json!(false));
            assert_eq!(meta["manifest"]["saved_as"], json!("manifest.json"));
            // Explicit flags beat everything in the manifest.
            let (_, _, out) = run_with(
                &[
                    "--dry-run",
                    "--manifest",
                    &path,
                    "--log-dir",
                    &logs,
                    "--max-tokens",
                    "9",
                    "--effort",
                    "low",
                    "t",
                ],
                "",
            );
            let printed: Value = serde_json::from_str(&out).unwrap();
            assert_eq!(printed["max_tokens"], json!(9));
            assert_eq!(printed["reasoning"]["effort"], json!("low"));
        });
        // With nothing permitted, the run says which entries were skipped and why.
        with_env(&[("OPENROUTER_API_KEY", None)], || {
            let (result, status, _) = run_with(
                &["--dry-run", "--manifest", &path, "--log-dir", &logs, "t"],
                "",
            );
            let error = message(result.unwrap_err());
            assert!(
                error.starts_with("no manifest entry produced an answer:"),
                "{error}"
            );
            assert!(
                error.contains("[1] openrouter/paid/one: cost=paid"),
                "{error}"
            );
            assert!(
                error.contains("[2] openrouter/or/free: OPENROUTER_API_KEY not set"),
                "{error}"
            );
            assert_eq!(status["attempts"].as_array().unwrap().len(), 3);
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-overrides")]
    #[test]
    fn a_live_run_over_loopback_prints_the_answer_and_fills_the_record() {
        let dir = scratch("live");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let output = dir.join("answer.md");
        let server = serve(vec![
            ok_json(good_answer()),
            ok_json(
                json!({"choices": [{"finish_reason": "length", "message": {"content": "cut off"}}], "usage": {}}),
            ),
            ok_json(json!({"choices": [{"message": {"content": "no finish"}}]})),
        ]);
        let url = server.url.clone();
        with_env(
            &[
                ("OXBOX_TEST_ALLOW_HTTP", Some("1")),
                ("MY_KEY", Some("sekrit")),
            ],
            || {
                let base = [
                    "--base-url",
                    &url,
                    "--api-key-env",
                    "MY_KEY",
                    "--model",
                    "m",
                    "--log-dir",
                    &logs,
                ];
                let mut words = base.to_vec();
                words.extend(["--output", output.to_str().unwrap(), "the task"]);
                let (result, status, out) = run_with(&words, "");
                assert_eq!(result, Ok(()));
                assert_eq!(out, "", "the answer went to --output, not stdout");
                assert_eq!(fs::read_to_string(&output).unwrap(), "the answer\n");
                assert_eq!(status["venue"], json!("custom"));
                assert_eq!(status["finish_reason"], json!("stop"));
                assert_eq!(status["prompt_tokens"], json!(10));
                assert_eq!(status["completion_tokens"], json!(5));
                assert_eq!(status["reasoning_tokens"], json!(2));
                assert_eq!(status["reasoning_chars"], json!(8));
                assert_eq!(status["truncated"], json!(false));
                assert_eq!(status["venue_cost"], json!(0.0));
                assert_eq!(status["route"], json!("SomeUpstream"));
                assert_eq!(
                    status["attempts"],
                    Value::Null,
                    "attempts are a manifest thing"
                );
                let log_dir = PathBuf::from(status["log_dir"].as_str().unwrap());
                assert!(log_dir.join("response.json").exists());
                let meta: Value =
                    serde_json::from_slice(&fs::read(log_dir.join("meta.json")).unwrap()).unwrap();
                assert_eq!(meta["endpoint"], json!(url));
                assert_eq!(meta["key_env"], json!("MY_KEY"));

                let mut words = base.to_vec();
                words.push("the task");
                let (result, status, out) = run_with(&words, "");
                assert_eq!(result, Ok(()));
                assert_eq!(out, "cut off\n", "stdout gets print()'s newline");
                assert_eq!(status["truncated"], json!(true));
                assert_eq!(status["venue_cost"], Value::Null);

                let (result, status, out) = run_with(&words, "");
                assert_eq!(result, Ok(()));
                assert_eq!(out, "no finish\n");
                assert_eq!(
                    status["truncated"],
                    Value::Null,
                    "no finish reason means unknown"
                );
            },
        );
        let seen = server.finish();
        assert_eq!(seen.len(), 3);
        assert_eq!(seen[0].header("authorization"), Some("Bearer sekrit"));
        let sent: Value = serde_json::from_slice(&seen[0].body).unwrap();
        assert!(sent.get("tools").is_none());
        assert_eq!(sent["messages"][1]["content"], json!("the task"));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(feature = "test-overrides")]
    #[test]
    fn failover_moves_to_the_next_entry_and_records_every_attempt() {
        let dir = scratch("failover");
        let logs = dir.join("logs").to_string_lossy().into_owned();
        let manifest = json!({
            "manifest_version": 0,
            "recommendations": [
                {"venue": "openrouter", "model": "or/first", "cost": "free"},
                {"venue": "zenmux", "model": "z/second", "cost": "free"},
                {"venue": "openrouter", "model": "or/third", "cost": "free"},
            ]
        });
        let path = write_manifest(&dir, "m.json", &manifest);
        let server = serve(vec![
            ok_json(json!({"error": {"message": "over capacity"}})),
            ok_json(good_answer()),
            ok_json(json!({"choices": []})),
        ]);
        let url = server.url.clone();
        let venue_urls = json!({"openrouter": url, "zenmux": url}).to_string();
        with_env(
            &[
                ("OXBOX_TEST_ALLOW_HTTP", Some("1")),
                ("OXBOX_TEST_VENUE_URLS", Some(&venue_urls)),
                ("OPENROUTER_API_KEY", Some("or-key")),
                ("ZENMUX_API_KEY", Some("z-key")),
            ],
            || {
                let (result, status, out) = run_with(
                    &["--manifest", &path, "--failover", "--log-dir", &logs, "t"],
                    "",
                );
                assert_eq!(result, Ok(()));
                assert_eq!(
                    out, "the answer\n\n",
                    "print() adds a newline to content that has one"
                );
                assert_eq!(status["venue"], json!("zenmux"));
                assert_eq!(status["model"], json!("z/second"));
                let attempts = status["attempts"].as_array().unwrap();
                assert_eq!(attempts.len(), 2, "the third entry was never needed");
                assert!(
                    attempts[0]["error"]
                        .as_str()
                        .unwrap()
                        .contains("over capacity")
                );
                assert_eq!(attempts[0]["venue"], json!("openrouter"));
                assert_eq!(attempts[1]["finish_reason"], json!("stop"));
                assert_eq!(attempts[1]["route"], json!("SomeUpstream"));
                assert!(attempts[1].get("error").is_none());

                // Without --failover the first failure is the end, recorded once.
                let (result, status, _) =
                    run_with(&["--manifest", &path, "--log-dir", &logs, "t"], "");
                let error = message(result.unwrap_err());
                assert!(error.contains("no choices"), "{error}");
                assert!(
                    !error.starts_with("oxbox-send:"),
                    "the exit path adds the prefix once"
                );
                let attempts = status["attempts"].as_array().unwrap();
                assert_eq!(attempts.len(), 1);
                assert!(
                    attempts[0]["error"]
                        .as_str()
                        .unwrap()
                        .contains("no choices")
                );
            },
        );
        let seen = server.finish();
        assert_eq!(seen[0].header("authorization"), Some("Bearer or-key"));
        assert_eq!(
            seen[1].header("authorization"),
            Some("Bearer z-key"),
            "each venue gets only its own key"
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
