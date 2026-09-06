// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! What the five oxbox executables share.
//!
//! In the Python tools each of these lived as a copy per script, because a
//! standalone script cannot import a sibling without shipping a module and a
//! `sys.path` to find it on, and wiretest existed partly to keep the copies
//! in agreement. Here there is one implementation of each, and the process
//! separation stays: every executable links this crate and nothing else that
//! is not the standard library, except `oxbox-send`, which also needs a
//! network stack.

use std::env;
use std::fs;
use std::io::{self, Write};
use std::path::{Component, Path, PathBuf};

/// The version every executable reports. One number, from the workspace.
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// The agent runbook, embedded at build time so all five executables print
/// the same bytes. Python read it from disk and a test compared five copies;
/// `include_str!` makes the comparison unnecessary.
pub const SKILL_MD: &str = include_str!("../../../.claude/skills/ox-review/SKILL.md");

pub const SKILL_NAME: &str = "ox-review";

/// The path the runbook uses to name its own scripts. It is written for a
/// checkout, where the skill sits where Claude Code looks for it; `--skill`
/// rewrites it to wherever this installation actually keeps the skill.
pub const SKILL_PATH_IN_TEXT: &str = ".claude/skills/ox-review";

/// The runbook with LF endings whatever git checked out. `include_str!`
/// embeds the file byte for byte, and a Windows checkout with
/// `core.autocrlf` hands it over with CRLF -- which is exactly what the
/// Python tools avoided by reading the file in text mode, and what guardtest
/// asserts against: the document leaves as UTF-8 with LF on every platform.
pub fn skill_text() -> String {
    SKILL_MD.replace("\r\n", "\n")
}

/// The `sys.platform` name the Python tools used, kept because the jail hands
/// it to jailtest as `OXBOX_PLATFORM` and the probes branch on it.
pub const PLATFORM: &str = if cfg!(target_os = "macos") {
    "darwin"
} else if cfg!(target_os = "linux") {
    "linux"
} else if cfg!(windows) {
    "win32"
} else {
    "unknown"
};

/// Write a diagnosis to stderr with the program's prefix on every line.
pub fn diagnose(prog: &str, message: &str) {
    let mut err = io::stderr().lock();
    for line in message.lines() {
        let _ = writeln!(err, "{prog}: {line}");
    }
}

/// The directory holding the running executable, unresolved.
pub fn exe_dir() -> PathBuf {
    env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| PathBuf::from("."))
}

/// The same, with symlinks resolved. Homebrew links `bin/oxbox` into its
/// prefix but never `libexec/`, so anything looking for a sibling directory
/// of `bin` has to start from where the file really is.
pub fn real_exe_dir() -> PathBuf {
    let dir = exe_dir();
    canonicalize_lenient(&dir)
}

/// `canonicalize` that tolerates a path which does not exist yet: the longest
/// existing ancestor is resolved and the rest appended, the way Python's
/// `os.path.realpath` behaves. Windows verbatim prefixes are stripped so the
/// result prints and compares like the path the user typed.
pub fn canonicalize_lenient(path: &Path) -> PathBuf {
    let mut existing = path.to_path_buf();
    let mut tail: Vec<std::ffi::OsString> = Vec::new();
    loop {
        if let Ok(resolved) = fs::canonicalize(&existing) {
            let mut out = strip_verbatim(resolved);
            for part in tail.iter().rev() {
                out.push(part);
            }
            return out;
        }
        match (existing.file_name(), existing.parent()) {
            (Some(name), Some(parent)) => {
                tail.push(name.to_os_string());
                existing = parent.to_path_buf();
            }
            _ => return path.to_path_buf(),
        }
    }
}

fn strip_verbatim(path: PathBuf) -> PathBuf {
    if cfg!(windows) {
        let text = path.to_string_lossy();
        if let Some(rest) = text.strip_prefix(r"\\?\UNC\") {
            return PathBuf::from(format!(r"\\{rest}"));
        }
        if let Some(rest) = text.strip_prefix(r"\\?\") {
            return PathBuf::from(rest);
        }
    }
    path
}

/// The home directory, the way `os.path.expanduser("~")` finds it.
pub fn home_dir() -> PathBuf {
    if cfg!(windows) {
        env::var_os("USERPROFILE")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    } else {
        env::var_os("HOME")
            .map(PathBuf::from)
            .unwrap_or_else(|| PathBuf::from("."))
    }
}

fn expand_tilde(value: &str) -> PathBuf {
    if value == "~" {
        home_dir()
    } else if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        home_dir().join(rest)
    } else {
        PathBuf::from(value)
    }
}

// ── the runbook ─────────────────────────────────────────────────────────────

/// Where the ox-review skill directory is, for this installation.
///
/// A source checkout carries it at `.claude/skills/ox-review` beside the
/// tools, where Claude Code finds it on its own; a package installs `oxbox`
/// into `<prefix>/bin`, the other executables into `<prefix>/libexec/bin`
/// (the .deb: `<prefix>/libexec/oxbox/bin`) and the skill into
/// `<prefix>/share/oxbox/ox-review`, one, two or three levels up. A build
/// tree puts the executables in `target/debug`, two levels below the
/// checkout. Every one of those is "walk up from the executable and look for
/// either spelling", so that is the rule.
pub fn find_skill_dir() -> Result<PathBuf, Vec<PathBuf>> {
    let mut candidates = Vec::new();
    for start in [exe_dir(), real_exe_dir()] {
        let mut base = Some(start);
        for _ in 0..4 {
            let Some(dir) = base else { break };
            for candidate in [
                dir.join(".claude").join("skills").join(SKILL_NAME),
                dir.join("share").join("oxbox").join(SKILL_NAME),
            ] {
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
            base = dir.parent().map(Path::to_path_buf);
        }
    }
    for candidate in &candidates {
        if candidate.join("SKILL.md").is_file() {
            return Ok(candidate.clone());
        }
    }
    Err(candidates)
}

/// Print the runbook, with the paths this installation actually uses.
///
/// An agent finds this through `--help`, so the copy it reads has to be
/// runnable where it is standing. The text names its scripts by their
/// checkout path; an installed tool keeps them under a prefix instead, and a
/// runbook whose commands do not exist is worse than no runbook. Provenance
/// goes to stderr and the document to stdout, the same split these tools use
/// everywhere else, so piping this into a file yields the document alone.
/// The bytes are written as UTF-8 with LF endings on every platform.
pub fn print_skill(prog: &str) -> i32 {
    let directory = match find_skill_dir() {
        Ok(directory) => directory,
        Err(candidates) => {
            let mut message = format!("the {SKILL_NAME} skill was not found; looked in:\n");
            for candidate in candidates {
                message.push_str(&format!("  {}\n", candidate.display()));
            }
            message.push_str(
                "a Homebrew install may predate the skill; reinstall or read it at \
                 https://github.com/curtisgalloway/oxbox",
            );
            diagnose(prog, &message);
            return 1;
        }
    };
    let path = directory.join("SKILL.md");
    eprintln!("{prog}: skill -> {}", path.display());
    let body = skill_text().replace(SKILL_PATH_IN_TEXT, &directory.to_string_lossy());
    let mut out = io::stdout().lock();
    if out.write_all(body.as_bytes()).is_err() || out.flush().is_err() {
        return 1;
    }
    0
}

// ── where sandboxes live ────────────────────────────────────────────────────

pub const CONFIG_FILE: &str = "config.ini";

/// `~/.config/oxbox/config.ini` (`XDG_CONFIG_HOME` honored), or
/// `%APPDATA%\oxbox\config.ini` on Windows.
pub fn config_path() -> PathBuf {
    let base = if cfg!(windows) {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join(".config"))
    };
    base.join("oxbox").join(CONFIG_FILE)
}

/// One value out of an INI file: `key` under `[section]`.
///
/// Enough of configparser's grammar for a config that holds one setting:
/// `[section]` headers, `key = value` or `key: value`, blank lines, and
/// comments starting with `#` or `;`. Keys compare case-insensitively, as
/// configparser's do. Anything else is a parse error, reported rather than
/// guessed at. `Ok(None)` when the file is absent or has no such key.
pub fn ini_get(path: &Path, section: &str, key: &str) -> Result<Option<String>, String> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(format!("cannot read {}: {error}", path.display())),
    };
    let mut current = String::new();
    let mut found = None;
    for (number, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = inner.trim().to_string();
            continue;
        }
        let split = line.find('=').into_iter().chain(line.find(':')).min();
        let Some(at) = split else {
            return Err(format!(
                "cannot parse {}: line {} is not a section, a key = value, or a comment",
                path.display(),
                number + 1
            ));
        };
        let name = line[..at].trim();
        let value = line[at + 1..].trim();
        if current == section && name.eq_ignore_ascii_case(key) {
            found = Some(value.to_string());
        }
    }
    Ok(found)
}

/// Where sandboxes live, and where that setting came from.
pub struct SandboxRoot {
    pub path: PathBuf,
    pub origin: String,
}

/// Every sandbox is `<root>/NAME`, NAME defaulting to `work`, so the layout
/// with nothing configured is `./sandbox/work`, as it always was. The root is
/// the first of `OXBOX_SANDBOX_ROOT` in the environment, `root` under
/// `[sandbox]` in the config file, and `./sandbox`. A relative value resolves
/// against the working directory, and `~` expands.
pub fn sandbox_root() -> Result<SandboxRoot, String> {
    let mut value = env::var("OXBOX_SANDBOX_ROOT")
        .ok()
        .filter(|value| !value.is_empty());
    let mut origin = String::from("OXBOX_SANDBOX_ROOT");
    if value.is_none() {
        let path = config_path();
        value = ini_get(&path, "sandbox", "root")?.filter(|value| !value.is_empty());
        origin = path.to_string_lossy().into_owned();
    }
    let value = match value {
        Some(value) => value,
        None => {
            origin = String::from("default");
            String::from("sandbox")
        }
    };
    let cwd = env::current_dir()
        .map_err(|error| format!("cannot read the working directory: {error}"))?;
    let joined = cwd.join(expand_tilde(&value));
    Ok(SandboxRoot {
        path: canonicalize_lenient(&joined),
        origin,
    })
}

/// A sandbox name is one plain path component: no separators, no traversal,
/// no leading dot (dot-names are the root's own bookkeeping).
pub fn sandbox_name(name: &str) -> Result<String, String> {
    let bad = name.is_empty()
        || name == "."
        || name == ".."
        || name.starts_with('.')
        || name.contains('/')
        || name.contains('\\')
        || (name.len() > 1 && name.as_bytes()[1] == b':');
    if bad {
        return Err(format!(
            "not a sandbox name: {name:?} (one plain path component)"
        ));
    }
    Ok(name.to_string())
}

/// Whether `path` is `root` or lies under it, textually, after both have been
/// resolved. The Python tools compared strings with a separator appended;
/// comparing components is the same test without the trailing-slash edge.
pub fn is_within(root: &Path, path: &Path) -> bool {
    path == root || path.starts_with(root)
}

// ── the other executables ───────────────────────────────────────────────────

/// Where the executables live, in resolution order: beside this one with
/// symlinks resolved (a checkout or a build tree), `<prefix>/libexec/bin`
/// (Homebrew keg, macOS tarball, MSI), `<prefix>/libexec/oxbox/bin` (the
/// .deb), then `/usr/libexec/oxbox/bin` outright. Never the working
/// directory: the project you are standing in is untrusted input.
pub fn helper_dirs() -> Vec<PathBuf> {
    let real_here = real_exe_dir();
    let prefix = real_here
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| real_here.clone());
    let candidates = [
        real_here.clone(),
        prefix.join("libexec").join("bin"),
        prefix.join("libexec").join("oxbox").join("bin"),
        PathBuf::from("/usr/libexec/oxbox/bin"),
    ];
    let mut dirs: Vec<PathBuf> = Vec::new();
    for candidate in candidates {
        if !dirs.contains(&candidate) {
            dirs.push(candidate);
        }
    }
    dirs
}

/// Candidate file names for an executable in a directory: Windows wants the
/// `.exe`, every other platform the bare name.
fn executable_names(name: &str) -> Vec<String> {
    if cfg!(windows) && !name.ends_with(".exe") {
        vec![format!("{name}.exe"), name.to_string()]
    } else {
        vec![name.to_string()]
    }
}

/// Find one of the other executables: the helper directories first, then
/// PATH as a fallback for a copy someone put there by hand.
pub fn find_helper(name: &str) -> Option<PathBuf> {
    let names = executable_names(name);
    for dir in helper_dirs() {
        for candidate in &names {
            let path = dir.join(candidate);
            if path.is_file() {
                return Some(path);
            }
        }
    }
    which(name)
}

/// A PATH lookup, the way `shutil.which` does it.
pub fn which(name: &str) -> Option<PathBuf> {
    let names = executable_names(name);
    let path = env::var_os("PATH")?;
    for dir in env::split_paths(&path) {
        for candidate in &names {
            let full = dir.join(candidate);
            if full.is_file() {
                return Some(full);
            }
        }
    }
    None
}

/// `..` anywhere in a relative path, on either separator.
pub fn has_parent_traversal(rel: &str) -> bool {
    rel.replace('\\', "/").split('/').any(|part| part == "..")
        || Path::new(rel)
            .components()
            .any(|part| matches!(part, Component::ParentDir))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_runbook_leaves_with_lf_endings() {
        assert!(!skill_text().contains('\r'));
        assert!(skill_text().starts_with("---\n"));
    }

    #[test]
    fn names_are_one_component() {
        assert!(sandbox_name("work").is_ok());
        assert!(sandbox_name("alt-2").is_ok());
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "c:x"] {
            assert!(sandbox_name(bad).is_err(), "{bad:?} should be refused");
        }
    }

    #[test]
    fn ini_reads_one_key() {
        let dir = env::temp_dir().join(format!("oxbox-core-ini-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("config.ini");
        fs::write(
            &path,
            "# comment\n[other]\nroot = nope\n[sandbox]\nRoot = /x/y\n",
        )
        .unwrap();
        assert_eq!(
            ini_get(&path, "sandbox", "root").unwrap(),
            Some("/x/y".to_string())
        );
        assert_eq!(ini_get(&path, "sandbox", "missing").unwrap(), None);
        assert_eq!(
            ini_get(&dir.join("absent.ini"), "sandbox", "root").unwrap(),
            None
        );
        fs::write(&path, "[sandbox]\nthis is not a setting\n").unwrap();
        assert!(ini_get(&path, "sandbox", "root").is_err());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn traversal_is_seen_on_both_separators() {
        assert!(has_parent_traversal("../x"));
        assert!(has_parent_traversal("a\\..\\b"));
        assert!(!has_parent_traversal("a/b..c"));
    }
}
