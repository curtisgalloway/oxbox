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
    normalize_newlines(SKILL_MD)
}

/// Text with every line ending as LF, the way Python's text mode reads a
/// file: CRLF and a lone CR both become LF. Context sent to the model, a task
/// read from stdin and a diff to apply all go through this, so a CRLF
/// checkout produces the same bytes on the wire and the same patch as an LF
/// one, and the two implementations agree byte for byte.
pub fn normalize_newlines(text: &str) -> String {
    text.replace("\r\n", "\n").replace('\r', "\n")
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
    // The executable itself is resolved, then its parent taken: Homebrew's
    // symlink is on the file (/opt/homebrew/bin/oxbox -> ../Cellar/...),
    // and resolving the directory alone would leave it in /opt/homebrew/bin,
    // beside a libexec that is not there. os.path.realpath(__file__) in the
    // reference did the same.
    env::current_exe()
        .ok()
        .map(|exe| canonicalize_lenient(&exe))
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
        .unwrap_or_else(|| canonicalize_lenient(&exe_dir()))
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

/// The home directory, the way `os.path.expanduser("~")` finds it: the
/// platform variable first (`HOME`, `USERPROFILE`), then the account
/// database. None when neither knows. Never the working directory: that is
/// the project being reviewed, which is untrusted input, and a config file
/// found there could point the sandbox root anywhere.
pub fn home_dir() -> Option<PathBuf> {
    #[allow(deprecated)]
    env::home_dir().filter(|home| !home.as_os_str().is_empty())
}

/// `~` and `~/rest` through the home directory; left as written when there
/// is no home, as `expanduser` leaves them.
fn expand_tilde(value: &str) -> PathBuf {
    if value == "~" {
        home_dir().unwrap_or_else(|| PathBuf::from(value))
    } else if let Some(rest) = value
        .strip_prefix("~/")
        .or_else(|| value.strip_prefix("~\\"))
    {
        match home_dir() {
            Some(home) => home.join(rest),
            None => PathBuf::from(value),
        }
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
/// `%APPDATA%\oxbox\config.ini` on Windows. None when there is no home to
/// anchor it: then there is no config file, and the defaults apply.
pub fn config_path() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        env::var_os("APPDATA")
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|home| home.join("AppData").join("Roaming")))
    } else {
        env::var_os("XDG_CONFIG_HOME")
            .filter(|value| !value.is_empty())
            .map(PathBuf::from)
            .or_else(|| home_dir().map(|home| home.join(".config")))
    };
    base.map(|base| base.join("oxbox").join(CONFIG_FILE))
}

/// One value out of an INI file: `key` under `[section]`.
///
/// Enough of configparser's grammar for a config of a few settings:
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

/// One setting from the config file, with the file it came from, or None
/// when there is no config file, no such key, or an empty value. A file
/// that cannot be read or parsed is an error, reported rather than
/// treated as absent: a typo in a setting should not silently mean
/// "unset".
pub fn config_get(section: &str, key: &str) -> Result<Option<(String, PathBuf)>, String> {
    let Some(path) = config_path() else {
        return Ok(None);
    };
    Ok(ini_get(&path, section, key)?
        .filter(|value| !value.is_empty())
        .map(|value| (value, path)))
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
    if value.is_none()
        && let Some(path) = config_path()
    {
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
    use std::sync::{Mutex, MutexGuard};

    /// Tests that set environment variables take this, because the
    /// environment is process-wide and the test runner is multi-threaded.
    static ENV: Mutex<()> = Mutex::new(());

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("oxbox-core-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Set variables for the duration of a closure, restoring the previous
    /// values afterwards, even if the closure panics.
    fn with_env<T>(vars: &[(&str, Option<&str>)], body: impl FnOnce() -> T) -> T {
        let _guard = env_lock();
        let saved: Vec<(String, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(key, _)| (key.to_string(), env::var_os(key)))
            .collect();
        for (key, value) in vars {
            match value {
                Some(value) => unsafe { env::set_var(key, value) },
                None => unsafe { env::remove_var(key) },
            }
        }
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        for (key, value) in saved {
            match value {
                Some(value) => unsafe { env::set_var(&key, value) },
                None => unsafe { env::remove_var(&key) },
            }
        }
        result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    }

    #[test]
    fn the_version_is_the_workspace_version() {
        assert_eq!(VERSION, env!("CARGO_PKG_VERSION"));
        assert!(VERSION.split('.').count() == 3);
    }

    #[test]
    fn the_platform_name_is_pythons() {
        assert!(["darwin", "linux", "win32", "unknown"].contains(&PLATFORM));
    }

    #[test]
    fn the_runbook_leaves_with_lf_endings() {
        assert!(!skill_text().contains('\r'));
        assert!(skill_text().starts_with("---\n"));
        assert!(skill_text().contains(SKILL_PATH_IN_TEXT));
    }

    /// Whether the checkout is within the lookup's reach from this test
    /// binary. Under `cargo test` it sits in target/debug/deps, three levels
    /// down, which is the build-tree case the lookup promises; a coverage
    /// build nests it one level deeper, past the walk, and those cases are
    /// about the release layouts rather than this one.
    fn checkout_in_reach() -> bool {
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .map(Path::to_path_buf)
            .unwrap();
        exe_dir().ancestors().take(4).any(|dir| dir == checkout)
    }

    #[test]
    fn the_skill_dir_is_found_from_a_build_tree() {
        if !checkout_in_reach() {
            eprintln!("skipped: the build tree is deeper than the lookup walks");
            return;
        }
        let dir = find_skill_dir().expect("the checkout carries the skill");
        assert!(dir.join("SKILL.md").is_file());
        assert!(dir.ends_with(Path::new(".claude").join("skills").join(SKILL_NAME)));
    }

    #[test]
    fn print_skill_returns_zero_here() {
        if !checkout_in_reach() {
            eprintln!("skipped: the build tree is deeper than the lookup walks");
            return;
        }
        assert_eq!(print_skill("test"), 0);
    }

    #[test]
    fn canonicalize_lenient_resolves_the_existing_prefix() {
        let dir = scratch("canon");
        // On Windows `fs::canonicalize` answers with a \\?\ verbatim prefix,
        // which the lenient form strips so results print and compare like
        // what the user typed; the expectation goes through the same strip.
        let real = strip_verbatim(fs::canonicalize(&dir).unwrap());
        assert!(!real.to_string_lossy().starts_with(r"\\?\"), "{real:?}");
        let missing = dir.join("not").join("yet");
        assert_eq!(canonicalize_lenient(&missing), real.join("not").join("yet"));
        assert_eq!(canonicalize_lenient(&dir), real);
        // A relative path that exists resolves through the working directory.
        assert!(canonicalize_lenient(Path::new(".")).is_absolute());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn canonicalize_lenient_follows_symlinks_in_the_prefix() {
        let dir = scratch("canon-link");
        fs::create_dir_all(dir.join("real")).unwrap();
        std::os::unix::fs::symlink(dir.join("real"), dir.join("link")).unwrap();
        let resolved = canonicalize_lenient(&dir.join("link").join("later"));
        assert!(
            resolved.ends_with(Path::new("real").join("later")),
            "{resolved:?}"
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn strip_verbatim_only_touches_windows_prefixes() {
        let plain = PathBuf::from("/usr/local/bin");
        assert_eq!(strip_verbatim(plain.clone()), plain);
    }

    #[test]
    fn home_and_tilde_follow_the_environment() {
        with_env(
            &[
                ("HOME", Some("/tmp/oxbox-home")),
                ("USERPROFILE", Some("/tmp/oxbox-home")),
            ],
            || {
                assert_eq!(home_dir(), Some(PathBuf::from("/tmp/oxbox-home")));
                assert_eq!(expand_tilde("~"), PathBuf::from("/tmp/oxbox-home"));
                assert_eq!(
                    expand_tilde("~/x/y"),
                    PathBuf::from("/tmp/oxbox-home").join("x/y")
                );
                assert_eq!(expand_tilde("plain"), PathBuf::from("plain"));
                assert_eq!(expand_tilde("~user/x"), PathBuf::from("~user/x"));
            },
        );
    }

    #[test]
    fn home_never_falls_back_to_the_working_directory() {
        with_env(&[("HOME", None), ("USERPROFILE", None)], || {
            // The account database may still know a home; the working
            // directory is never the answer.
            let home = home_dir();
            assert!(home.as_deref().is_none_or(Path::is_absolute), "{home:?}");
            assert_eq!(
                expand_tilde("~/x"),
                home_dir().map_or(PathBuf::from("~/x"), |h| h.join("x"))
            );
        });
    }

    #[test]
    fn newlines_normalize_the_way_python_text_mode_reads() {
        assert_eq!(normalize_newlines("a\r\nb\rc\n"), "a\nb\nc\n");
        assert_eq!(normalize_newlines("plain\n"), "plain\n");
        assert_eq!(normalize_newlines(""), "");
    }

    #[test]
    fn config_path_honors_the_platform_variable() {
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some("/tmp/oxbox-xdg")),
                ("APPDATA", Some("/tmp/oxbox-xdg")),
                ("HOME", Some("/tmp/oxbox-home")),
                ("USERPROFILE", Some("/tmp/oxbox-home")),
            ],
            || {
                assert_eq!(
                    config_path().unwrap(),
                    PathBuf::from("/tmp/oxbox-xdg")
                        .join("oxbox")
                        .join(CONFIG_FILE)
                );
            },
        );
        with_env(
            &[
                ("XDG_CONFIG_HOME", None),
                ("APPDATA", None),
                ("HOME", Some("/tmp/oxbox-home")),
                ("USERPROFILE", Some("/tmp/oxbox-home")),
            ],
            || {
                let path = config_path().unwrap();
                assert!(path.starts_with("/tmp/oxbox-home"), "{path:?}");
                assert!(path.ends_with(Path::new("oxbox").join(CONFIG_FILE)));
            },
        );
        // An empty XDG_CONFIG_HOME means unset, as the spec says.
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some("")),
                ("HOME", Some("/tmp/oxbox-home")),
            ],
            || {
                if !cfg!(windows) {
                    assert!(config_path().unwrap().starts_with("/tmp/oxbox-home"));
                }
            },
        );
    }

    #[test]
    fn ini_reads_one_key() {
        let dir = scratch("ini");
        let path = dir.join("config.ini");
        fs::write(
            &path,
            "# comment\n; another\n[other]\nroot = nope\n\n[sandbox]\nRoot = /x/y\nkey: with colon\n",
        )
        .unwrap();
        assert_eq!(
            ini_get(&path, "sandbox", "root").unwrap(),
            Some("/x/y".to_string())
        );
        assert_eq!(
            ini_get(&path, "sandbox", "key").unwrap(),
            Some("with colon".to_string())
        );
        assert_eq!(
            ini_get(&path, "other", "root").unwrap(),
            Some("nope".to_string())
        );
        assert_eq!(ini_get(&path, "sandbox", "missing").unwrap(), None);
        assert_eq!(ini_get(&path, "absent", "root").unwrap(), None);
        assert_eq!(
            ini_get(&dir.join("absent.ini"), "sandbox", "root").unwrap(),
            None
        );
        fs::write(&path, "[sandbox]\nthis is not a setting\n").unwrap();
        let error = ini_get(&path, "sandbox", "root").unwrap_err();
        assert!(error.contains("line 2"), "{error}");
        // A key before any section header belongs to no section.
        fs::write(&path, "root = early\n[sandbox]\nroot = late\n").unwrap();
        assert_eq!(
            ini_get(&path, "sandbox", "root").unwrap(),
            Some("late".to_string())
        );
        assert_eq!(
            ini_get(&path, "", "root").unwrap(),
            Some("early".to_string())
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn config_get_reads_a_named_setting_from_the_config_file() {
        let dir = scratch("config-get");
        let cfg = dir.join("oxbox");
        fs::create_dir_all(&cfg).unwrap();
        let dir_text = dir.to_string_lossy().into_owned();
        with_env(
            &[
                ("XDG_CONFIG_HOME", Some(&dir_text)),
                ("APPDATA", Some(&dir_text)),
            ],
            || {
                assert_eq!(config_get("send", "manifest").unwrap(), None, "no file");
                fs::write(
                    cfg.join(CONFIG_FILE),
                    "[send]\nmanifest = https://x/m.json\n",
                )
                .unwrap();
                let (value, path) = config_get("send", "manifest").unwrap().unwrap();
                assert_eq!(value, "https://x/m.json");
                assert_eq!(path, cfg.join(CONFIG_FILE));
                assert_eq!(config_get("sandbox", "root").unwrap(), None);
                fs::write(cfg.join(CONFIG_FILE), "[send]\nmanifest =\n").unwrap();
                assert_eq!(
                    config_get("send", "manifest").unwrap(),
                    None,
                    "empty is unset"
                );
                fs::write(cfg.join(CONFIG_FILE), "[send]\nnot a setting\n").unwrap();
                assert!(
                    config_get("send", "manifest").is_err(),
                    "a typo is an error"
                );
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn ini_reports_an_unreadable_file() {
        let dir = scratch("ini-dir");
        // A directory where a file is expected is neither absent nor readable.
        let error = ini_get(&dir, "sandbox", "root").unwrap_err();
        assert!(error.contains("cannot read"), "{error}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_sandbox_root_resolves_env_then_config_then_default() {
        let dir = scratch("root");
        let cfg = dir.join("cfg");
        fs::create_dir_all(cfg.join("oxbox")).unwrap();
        let cfg_root = dir.join("from-config");
        fs::write(
            cfg.join("oxbox").join(CONFIG_FILE),
            format!("[sandbox]\nroot = {}\n", cfg_root.display()),
        )
        .unwrap();
        let env_root = dir.join("from-env");
        let cfg_text = cfg.to_string_lossy().into_owned();
        let env_text = env_root.to_string_lossy().into_owned();
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", Some(env_text.as_str())),
                ("XDG_CONFIG_HOME", Some(cfg_text.as_str())),
                ("APPDATA", Some(cfg_text.as_str())),
            ],
            || {
                let root = sandbox_root().unwrap();
                assert_eq!(root.origin, "OXBOX_SANDBOX_ROOT");
                assert_eq!(root.path, canonicalize_lenient(&env_root));
            },
        );
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", None),
                ("XDG_CONFIG_HOME", Some(cfg_text.as_str())),
                ("APPDATA", Some(cfg_text.as_str())),
            ],
            || {
                let root = sandbox_root().unwrap();
                assert!(root.origin.ends_with(CONFIG_FILE), "{}", root.origin);
                assert_eq!(root.path, canonicalize_lenient(&cfg_root));
            },
        );
        // An empty variable counts as unset.
        let empty_cfg = dir.join("empty-cfg");
        fs::create_dir_all(&empty_cfg).unwrap();
        let empty_text = empty_cfg.to_string_lossy().into_owned();
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", Some("")),
                ("XDG_CONFIG_HOME", Some(empty_text.as_str())),
                ("APPDATA", Some(empty_text.as_str())),
            ],
            || {
                let root = sandbox_root().unwrap();
                assert_eq!(root.origin, "default");
                assert!(root.path.ends_with("sandbox"), "{:?}", root.path);
                assert!(root.path.is_absolute());
            },
        );
        // A relative value resolves against the working directory, and ~ expands.
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", Some("rel/boxes")),
                ("XDG_CONFIG_HOME", Some(empty_text.as_str())),
            ],
            || {
                let root = sandbox_root().unwrap();
                assert!(
                    root.path.ends_with(Path::new("rel").join("boxes")),
                    "{:?}",
                    root.path
                );
            },
        );
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", Some("~/boxes")),
                ("HOME", Some(dir.to_str().unwrap())),
                ("USERPROFILE", Some(dir.to_str().unwrap())),
            ],
            || {
                let root = sandbox_root().unwrap();
                assert_eq!(root.path, canonicalize_lenient(&dir.join("boxes")));
            },
        );
        // A malformed config file is an error, not a silent default.
        fs::write(
            cfg.join("oxbox").join(CONFIG_FILE),
            "[sandbox]\nbroken line\n",
        )
        .unwrap();
        with_env(
            &[
                ("OXBOX_SANDBOX_ROOT", None),
                ("XDG_CONFIG_HOME", Some(cfg_text.as_str())),
                ("APPDATA", Some(cfg_text.as_str())),
            ],
            || {
                assert!(sandbox_root().is_err());
            },
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn names_are_one_component() {
        assert_eq!(sandbox_name("work").unwrap(), "work");
        assert!(sandbox_name("alt-2").is_ok());
        for bad in ["", ".", "..", ".hidden", "a/b", "a\\b", "c:x", "../x"] {
            let error = sandbox_name(bad).unwrap_err();
            assert!(error.contains("not a sandbox name"), "{bad:?}: {error}");
        }
    }

    #[test]
    fn within_means_equal_or_below() {
        let root = Path::new("/a/b");
        assert!(is_within(root, Path::new("/a/b")));
        assert!(is_within(root, Path::new("/a/b/c/d")));
        assert!(!is_within(root, Path::new("/a/bc")));
        assert!(!is_within(root, Path::new("/a")));
        assert!(!is_within(root, Path::new("/x/a/b")));
    }

    #[test]
    fn helper_dirs_start_beside_the_executable_and_never_repeat() {
        let dirs = helper_dirs();
        assert_eq!(dirs[0], real_exe_dir());
        assert!(
            dirs.iter()
                .any(|d| d.ends_with(Path::new("libexec").join("bin")))
        );
        assert!(
            dirs.iter()
                .any(|d| d.ends_with(Path::new("libexec").join("oxbox").join("bin")))
        );
        let mut unique = dirs.clone();
        unique.dedup();
        assert_eq!(unique.len(), dirs.len());
        assert!(
            !dirs.contains(&env::current_dir().unwrap())
                || real_exe_dir() == env::current_dir().unwrap()
        );
    }

    #[test]
    fn executables_are_named_per_platform() {
        let names = executable_names("oxbox-send");
        if cfg!(windows) {
            assert_eq!(
                names,
                vec!["oxbox-send.exe".to_string(), "oxbox-send".to_string()]
            );
            assert_eq!(executable_names("x.exe"), vec!["x.exe".to_string()]);
        } else {
            assert_eq!(names, vec!["oxbox-send".to_string()]);
        }
    }

    #[test]
    fn which_and_find_helper_search_path() {
        let dir = scratch("path");
        let name = if cfg!(windows) {
            "oxbox-fake-helper.exe"
        } else {
            "oxbox-fake-helper"
        };
        fs::write(dir.join(name), b"").unwrap();
        let path_text = dir.to_string_lossy().into_owned();
        with_env(&[("PATH", Some(path_text.as_str()))], || {
            assert_eq!(which("oxbox-fake-helper"), Some(dir.join(name)));
            assert_eq!(find_helper("oxbox-fake-helper"), Some(dir.join(name)));
            assert_eq!(which("oxbox-no-such-helper"), None);
            assert_eq!(find_helper("oxbox-no-such-helper"), None);
        });
        with_env(&[("PATH", None)], || {
            assert_eq!(which("oxbox-fake-helper"), None);
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn traversal_is_seen_on_both_separators() {
        assert!(has_parent_traversal("../x"));
        assert!(has_parent_traversal("a\\..\\b"));
        assert!(has_parent_traversal("a/../b"));
        assert!(!has_parent_traversal("a/b..c"));
        assert!(!has_parent_traversal("..a/b"));
        assert!(!has_parent_traversal("plain"));
    }

    #[test]
    fn diagnose_prefixes_every_line() {
        // Writes to the real stderr; the property under test is that it does
        // not panic on an empty message or a multi-line one.
        diagnose("test", "");
        diagnose("test", "one\ntwo");
    }
}
