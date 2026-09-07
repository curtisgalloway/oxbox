// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! Extract a diff from a model's answer and apply it ONLY inside the sandbox.
//!
//! Refuses absolute paths, parent-directory traversal, and anything that
//! would land outside the work tree. Never touches a real repository.
//!
//! This is the executable `oxbox patch` runs. It lives in a libexec directory
//! rather than on PATH; oxbox finds it from its own location. Standard
//! library only: this is the patch quarantine.
//!
//! Every refusal is a value (`Fail`) returned to `main`, which prints and
//! exits; nothing below it touches the process. That is what lets the unit
//! tests drive the whole path against a scratch sandbox.

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{self, Command};
use std::time::{SystemTime, UNIX_EPOCH};

use oxbox_core as core;

const PROG: &str = "oxbox-patch";

const USAGE: &str = "\
usage: oxbox patch (--log DIR | --diff FILE) [--sandbox NAME | --work DIR] [--commit]

Extract a diff from a model's answer and apply it ONLY inside the sandbox.
Refuses absolute paths, parent-directory traversal, symlink-creating hunks,
and anything that would land outside the work tree.

  --log DIR       an oxbox send log dir containing content.md
  --diff FILE     a file containing a raw diff
  --sandbox NAME  the sandbox to patch: <root>/NAME (default: work)
  --work DIR      a work dir to patch instead; must be inside the sandbox root
  --commit        commit the applied patch in the sandbox git repo
  --skill         print the ox-review agent skill and exit
  --version       print the version and exit
  --help          print this and exit

exit status: 0; 2 for a usage error or a refused patch; 3 when the patch
does not apply.
";

/// How a run ends other than by applying: the text for stderr, already in
/// its final form, and the exit code.
#[derive(Debug, PartialEq)]
struct Fail {
    code: i32,
    text: String,
}

impl Fail {
    /// A diagnosis in the tool's own voice: every line prefixed.
    fn diag(code: i32, message: &str) -> Fail {
        let text = message
            .lines()
            .map(|line| format!("{PROG}: {line}\n"))
            .collect();
        Fail { code, text }
    }

    /// An argparse-style usage error: the usage line, then the reason.
    fn usage(message: &str) -> Fail {
        Fail {
            code: 2,
            text: format!("{USAGE}oxbox patch: error: {message}\n"),
        }
    }
}

/// The diff inside a model's answer: every ```diff or ```patch fence joined,
/// or the whole text if it already starts like a diff, or nothing.
fn extract(text: &str) -> Option<String> {
    let mut blocks = Vec::new();
    let mut rest = text;
    while let Some(start) = rest.find("```") {
        let after = &rest[start + 3..];
        let Some(tag_end) = after.find('\n') else {
            break;
        };
        let tag = after[..tag_end].trim_end();
        if tag == "diff" || tag == "patch" {
            let body = &after[tag_end + 1..];
            let Some(close) = body.find("```") else { break };
            blocks.push(body[..close].trim_end().to_string());
            rest = &body[close + 3..];
        } else {
            rest = after;
        }
    }
    if !blocks.is_empty() {
        return Some(blocks.join("\n") + "\n");
    }
    let trimmed = text.trim_start();
    if trimmed.starts_with("--- ") || trimmed.starts_with("diff --git") {
        return Some(text.to_string());
    }
    None
}

/// Every path token a patch names, from ---/+++ lines AND extended headers.
///
/// ---/+++ lines are not the only place a patch names a target. git also
/// honors extended headers, so validating only ---/+++ lets a
/// "rename to ../../x" slip past while the operator is reassured with
/// "targets (0)".
fn candidate_paths(patch: &str) -> Vec<String> {
    let mut found = Vec::new();
    for line in patch.lines() {
        if let Some(rest) = line
            .strip_prefix("---")
            .or_else(|| line.strip_prefix("+++"))
        {
            if !rest.starts_with(char::is_whitespace) {
                continue;
            }
            if let Some(token) = rest.split_whitespace().next() {
                found.push(strip_prefix_ab(token).to_string());
            }
            continue;
        }
        let header = if let Some(rest) = line.strip_prefix("diff --git") {
            (rest.starts_with(char::is_whitespace)).then_some(rest)
        } else {
            let mut words = line.split_whitespace();
            match (words.next(), words.next()) {
                (Some("rename" | "copy"), Some("from" | "to")) => {
                    let head_len = line.len() - words.remainder_len(line);
                    Some(&line[head_len..])
                }
                _ => None,
            }
        };
        if let Some(raw) = header {
            for token in raw.split_whitespace() {
                let token = token.trim().trim_matches('"');
                let token = strip_prefix_ab(token);
                if !token.is_empty() {
                    found.push(token.to_string());
                }
            }
        }
    }
    found
}

fn strip_prefix_ab(token: &str) -> &str {
    token
        .strip_prefix("a/")
        .or_else(|| token.strip_prefix("b/"))
        .unwrap_or(token)
}

/// What is left of `line` after the words an iterator has consumed.
trait RemainderLen {
    fn remainder_len(&self, line: &str) -> usize;
}

impl RemainderLen for std::str::SplitWhitespace<'_> {
    fn remainder_len(&self, line: &str) -> usize {
        // SplitWhitespace has no `remainder` in stable std; recover it from
        // the next word's position instead.
        let mut probe = self.clone();
        match probe.next() {
            Some(word) => {
                let offset = word.as_ptr() as usize - line.as_ptr() as usize;
                line.len() - offset
            }
            None => 0,
        }
    }
}

/// A patch can create a symlink (mode 12xxxx) whose body is an absolute or
/// ../ target, turning a later in-sandbox write into a write anywhere.
/// Containment should not rest on git's internal symlink checks.
fn is_symlink_mode_line(line: &str) -> bool {
    let words: Vec<&str> = line.split_whitespace().collect();
    let mode = match words.as_slice() {
        ["new" | "old", "mode", mode] => mode,
        ["new" | "deleted", "file", "mode", mode] => mode,
        _ => return false,
    };
    mode.len() == 6 && mode.starts_with("12") && mode.bytes().all(|b| b.is_ascii_digit())
}

fn unsafe_paths(patch: &str) -> Vec<String> {
    let mut bad = Vec::new();
    for raw in candidate_paths(patch) {
        if raw == "/dev/null" {
            continue;
        }
        // Textual checks, not Path::is_absolute: on Windows "/etc/passwd"
        // has a root but no drive and reports false, and a crafted patch
        // could name a drive letter or UNC path outright.
        if raw.starts_with('~')
            || raw.starts_with('/')
            || raw.starts_with('\\')
            || (raw.len() > 1 && raw.as_bytes()[1] == b':')
        {
            bad.push(format!("absolute path: {raw}"));
        } else if core::has_parent_traversal(&raw) {
            bad.push(format!("parent traversal: {raw}"));
        }
    }
    for line in patch.lines() {
        if is_symlink_mode_line(line) {
            bad.push(format!("symlink mode: {}", line.trim()));
        }
    }
    bad
}

/// A fresh `pending-*.patch` beside the work tree, created exclusively.
///
/// Unique per run: --check and --apply are separate git invocations that
/// each re-read this file, so a fixed name would let a concurrent run swap
/// in a patch that was never the one validated.
fn pending_patch(dir: &Path, patch: &str) -> Result<PathBuf, Fail> {
    let seed = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0)
        ^ (process::id() as u128);
    for attempt in 0..100u128 {
        let path = dir.join(format!("pending-{:x}.patch", seed.wrapping_add(attempt)));
        let created = fs::File::options().write(true).create_new(true).open(&path);
        match created {
            Ok(mut file) => {
                // Bytes as given: no line-ending translation, so an LF patch
                // stays LF on Windows and git compares like with like.
                file.write_all(patch.as_bytes()).map_err(|error| {
                    Fail::diag(1, &format!("cannot write {}: {error}", path.display()))
                })?;
                return Ok(path);
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(Fail::diag(
                    1,
                    &format!("cannot create a patch file in {}: {error}", dir.display()),
                ));
            }
        }
    }
    Err(Fail::diag(
        1,
        &format!("cannot create a patch file in {}", dir.display()),
    ))
}

#[derive(Debug, Default, PartialEq)]
struct Options {
    log: Option<PathBuf>,
    diff: Option<PathBuf>,
    sandbox: Option<String>,
    work: Option<PathBuf>,
    commit: bool,
}

/// What a command line asks for.
#[derive(Debug, PartialEq)]
enum Parsed {
    Run(Options),
    Help,
    Version,
    Skill,
}

fn parse(args: &[String]) -> Result<Parsed, Fail> {
    let mut options = Options::default();
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let value = |index: usize| -> Result<&String, Fail> {
            args.get(index + 1)
                .ok_or_else(|| Fail::usage(&format!("argument {arg}: expected one argument")))
        };
        match arg {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--version" => return Ok(Parsed::Version),
            "--skill" => return Ok(Parsed::Skill),
            "--log" => {
                options.log = Some(PathBuf::from(value(index)?));
                index += 1;
            }
            "--diff" => {
                options.diff = Some(PathBuf::from(value(index)?));
                index += 1;
            }
            "--sandbox" => {
                options.sandbox = Some(value(index)?.clone());
                index += 1;
            }
            "--work" => {
                options.work = Some(PathBuf::from(value(index)?));
                index += 1;
            }
            "--commit" => options.commit = true,
            _ => return Err(Fail::usage(&format!("unrecognized arguments: {arg}"))),
        }
        index += 1;
    }
    match (&options.log, &options.diff) {
        (Some(_), Some(_)) => Err(Fail::usage(
            "argument --diff: not allowed with argument --log",
        )),
        (None, None) => Err(Fail::usage("one of the arguments --log --diff is required")),
        _ => Ok(Parsed::Run(options)),
    }
}

/// The patch text an invocation names: extracted from a log's content.md,
/// or read raw from a file.
fn load_patch(options: &Options) -> Result<String, Fail> {
    if let Some(log) = &options.log {
        let content_path = log.join("content.md");
        if !content_path.is_file() {
            return Err(Fail::diag(
                1,
                &format!("no content.md in {}", log.display()),
            ));
        }
        let text = fs::read_to_string(&content_path).map_err(|error| {
            Fail::diag(
                1,
                &format!("cannot read {}: {error}", content_path.display()),
            )
        })?;
        return extract(&core::normalize_newlines(&text))
            .ok_or_else(|| Fail::diag(1, "no diff block found in the response"));
    }
    let diff = options.diff.as_ref().expect("one source is required");
    // Text, not bytes: a diff saved by a Windows editor carries CRLF, and
    // the sandbox tree it applies to was seeded from an LF checkout.
    fs::read_to_string(diff)
        .map(|text| core::normalize_newlines(&text))
        .map_err(|error| Fail::diag(1, &format!("cannot read {}: {error}", diff.display())))
}

/// The work tree an invocation names, checked to be a git repo inside the
/// sandbox root.
fn resolve_work(options: &Options) -> Result<PathBuf, Fail> {
    let root = core::sandbox_root().map_err(|message| Fail::diag(1, &message))?;
    if options.work.is_some() && options.sandbox.is_some() {
        return Err(Fail::diag(
            1,
            "--work and --sandbox name the same thing; pass one",
        ));
    }
    let work = match &options.work {
        Some(work) => core::canonicalize_lenient(work),
        None => {
            let name = options.sandbox.as_deref().unwrap_or("work");
            root.path
                .join(core::sandbox_name(name).map_err(|message| Fail::diag(2, &message))?)
        }
    };
    if !work.is_dir() {
        return Err(Fail::diag(
            1,
            &format!("work dir does not exist: {}", work.display()),
        ));
    }
    let work = core::canonicalize_lenient(&work);

    // A --work outside the sandbox root is refused because whatever --work
    // names is what gets written to: a pasted or mistyped path would apply a
    // model-produced patch straight into a real checkout. unsafe_paths
    // cannot stand in for this: it constrains where a patch may write
    // *relative to* the work dir, and says nothing about where the work dir
    // itself is.
    if !core::is_within(&root.path, &work) {
        return Err(Fail::diag(
            2,
            &format!(
                "REFUSING --work {}\n\
                 it lies outside {} (the sandbox root,\n\
                 from {}), so applying a model-produced patch\n\
                 there would touch a real tree. Run oxbox sandbox --create\n\
                 first, or name a --work inside the sandbox root.",
                work.display(),
                root.path.display(),
                root.origin
            ),
        ));
    }
    if !work.join(".git").exists() {
        return Err(Fail::diag(
            1,
            &format!(
                "{} is not a git repo (run oxbox sandbox --create first)",
                work.display()
            ),
        ));
    }
    Ok(work)
}

fn git(work: &Path, args: &[&str]) -> Result<process::Output, Fail> {
    Command::new("git")
        .arg("-C")
        .arg(work)
        .args(args)
        .output()
        .map_err(|error| Fail::diag(1, &format!("cannot run git: {error}")))
}

/// Apply a validated patch, trying strict first and relaxing hunk matching
/// only with a warning. Returns what went to stdout (git's --stat).
fn apply(work: &Path, patch: &str, patch_path: &Path, commit: bool) -> Result<String, Fail> {
    let mut targets: Vec<String> = candidate_paths(patch)
        .into_iter()
        .filter(|path| path != "/dev/null")
        .collect();
    targets.sort();
    targets.dedup();
    core::diagnose(PROG, &format!("patch -> {}", patch_path.display()));
    core::diagnose(
        PROG,
        &format!("targets ({}): {}", targets.len(), targets.join(", ")),
    );

    let strategies: [(&str, &[&str]); 3] = [
        ("strict", &[]),
        ("recount", &["--recount"]),
        ("recount+C1", &["--recount", "-C1"]),
    ];
    let mut chosen: Option<(&str, &[&str])> = None;
    let mut last_error = String::new();
    let patch_arg = patch_path.to_string_lossy().into_owned();
    for (name, flags) in strategies {
        let mut args = vec!["apply", "--check"];
        args.extend_from_slice(flags);
        args.push(&patch_arg);
        let check = git(work, &args)?;
        if check.status.success() {
            chosen = Some((name, flags));
            break;
        }
        last_error = String::from_utf8_lossy(&check.stderr).into_owned();
    }
    let Some((name, flags)) = chosen else {
        return Err(Fail {
            code: 3,
            text: format!("{PROG}: patch does not apply at any strictness level:\n{last_error}"),
        });
    };
    if name != "strict" {
        core::diagnose(
            PROG,
            &format!(
                "WARNING - patch only applied with '{name}'. The model emitted a\n\
                 malformed hunk (usually wrong line counts or missing trailing\n\
                 context). Re-read the resulting diff carefully."
            ),
        );
    }

    let mut args = vec!["apply", "--stat", "--apply"];
    args.extend_from_slice(flags);
    args.push(&patch_arg);
    let applied = git(work, &args)?;
    let stdout = String::from_utf8_lossy(&applied.stdout).into_owned();
    if !applied.status.success() {
        return Err(Fail {
            code: 3,
            text: String::from_utf8_lossy(&applied.stderr).into_owned(),
        });
    }

    if commit {
        for step in [
            vec!["add", "-A"],
            vec![
                "-c",
                "user.email=ox@sandbox.invalid",
                "-c",
                "user.name=ox-alpha",
                "commit",
                "-q",
                "-m",
                "ox patch",
            ],
        ] {
            let done = git(work, &step)?;
            if !done.status.success() {
                return Err(Fail::diag(1, &format!("git {} failed", step.join(" "))));
            }
        }
    }

    core::diagnose(PROG, "applied inside sandbox only");
    core::diagnose(
        PROG,
        &format!("review with: git -C {} diff HEAD", work.display()),
    );
    Ok(stdout)
}

/// The whole run after parsing: load the patch, find the work tree, refuse
/// unsafe targets, apply. Returns what belongs on stdout.
fn run(options: &Options) -> Result<String, Fail> {
    let patch = load_patch(options)?;
    let work = resolve_work(options)?;

    let bad = unsafe_paths(&patch);
    if !bad.is_empty() {
        let mut text = format!("{PROG}: REFUSING - patch targets paths outside the sandbox:\n");
        for item in bad {
            text.push_str(&format!("  {item}\n"));
        }
        return Err(Fail { code: 2, text });
    }

    let patch_dir = work
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| work.clone());
    let patch_path = pending_patch(&patch_dir, &patch)?;
    let outcome = apply(&work, &patch, &patch_path, options.commit);
    // The pending file holds the model's raw output; it is removed on every
    // exit path rather than left for an archive to pick up.
    if let Err(error) = fs::remove_file(&patch_path) {
        core::diagnose(
            PROG,
            &format!("could not remove {}: {error}", patch_path.display()),
        );
    }
    outcome
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match parse(&args) {
        Ok(Parsed::Help) => {
            print!("{USAGE}");
            0
        }
        Ok(Parsed::Version) => {
            println!("{PROG} {}", core::VERSION);
            0
        }
        Ok(Parsed::Skill) => core::print_skill(PROG),
        Ok(Parsed::Run(options)) => match run(&options) {
            Ok(stdout) => {
                let mut out = std::io::stdout().lock();
                let _ = out.write_all(stdout.as_bytes());
                let _ = out.flush();
                0
            }
            Err(fail) => {
                eprint!("{}", fail.text);
                fail.code
            }
        },
        Err(fail) => {
            eprint!("{}", fail.text);
            fail.code
        }
    };
    process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, MutexGuard};

    static ENV: Mutex<()> = Mutex::new(());

    fn env_lock() -> MutexGuard<'static, ()> {
        ENV.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("oxbox-patch-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    const VALID: &str =
        "--- a/mod.py\n+++ b/mod.py\n@@ -1,2 +1,2 @@\n def f():\n-    return 1\n+    return 2\n";

    /// A sandbox root holding one git work tree with mod.py committed.
    fn seeded(root: &Path, name: &str) -> PathBuf {
        let work = root.join(name);
        fs::create_dir_all(&work).unwrap();
        fs::write(work.join("mod.py"), "def f():\n    return 1\n").unwrap();
        for step in [
            vec!["init", "-q"],
            vec!["add", "-A"],
            vec![
                "-c",
                "user.email=t@t",
                "-c",
                "user.name=t",
                "commit",
                "-q",
                "-m",
                "seed",
            ],
        ] {
            let status = Command::new("git")
                .arg("-C")
                .arg(&work)
                .args(&step)
                .status()
                .unwrap();
            assert!(status.success(), "git {step:?}");
        }
        work
    }

    /// Run with OXBOX_SANDBOX_ROOT pointed at `root`, restoring it after.
    fn with_root<T>(root: &Path, body: impl FnOnce() -> T) -> T {
        let _guard = env_lock();
        let saved = env::var_os("OXBOX_SANDBOX_ROOT");
        unsafe { env::set_var("OXBOX_SANDBOX_ROOT", root) };
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(body));
        match saved {
            Some(value) => unsafe { env::set_var("OXBOX_SANDBOX_ROOT", value) },
            None => unsafe { env::remove_var("OXBOX_SANDBOX_ROOT") },
        }
        result.unwrap_or_else(|payload| std::panic::resume_unwind(payload))
    }

    #[test]
    fn fences_are_extracted_and_joined() {
        let text = "hello\n```diff\n--- a/x\n+++ b/x\n```\nmore\n```patch\n@@ -1 +1 @@\n```\n";
        assert_eq!(extract(text).unwrap(), "--- a/x\n+++ b/x\n@@ -1 +1 @@\n");
        assert_eq!(
            extract("--- a/x\n+++ b/x\n"),
            Some("--- a/x\n+++ b/x\n".to_string())
        );
        assert_eq!(
            extract("  diff --git a/x b/x\n"),
            Some("  diff --git a/x b/x\n".to_string())
        );
        assert_eq!(extract("no diff here"), None);
        // An unclosed fence and a fence of another language are not diffs.
        assert_eq!(extract("```diff\n--- a/x\n"), None);
        assert_eq!(extract("```python\nprint(1)\n```\n"), None);
        // A fence with trailing spaces on the tag line still counts.
        assert_eq!(
            extract("```diff   \n--- a/x\n```"),
            Some("--- a/x\n".to_string())
        );
    }

    #[test]
    fn every_header_kind_names_a_target() {
        let patch = "diff --git a/src/one.py b/src/one.py\nrename from old/name.py\nrename to ../../escape.py\ncopy from \"a/quoted name.py\"\n--- a/src/one.py\n+++ b/src/one.py\n--- /dev/null\n+++ b/new.py\n---not-a-header\n";
        let paths = candidate_paths(patch);
        for expected in [
            "src/one.py",
            "old/name.py",
            "../../escape.py",
            "quoted",
            "name.py",
            "/dev/null",
            "new.py",
        ] {
            assert!(
                paths.contains(&expected.to_string()),
                "{expected} missing from {paths:?}"
            );
        }
        assert!(
            !paths.iter().any(|p| p.contains("not-a-header")),
            "{paths:?}"
        );
        assert_eq!(strip_prefix_ab("a/x"), "x");
        assert_eq!(strip_prefix_ab("b/x"), "x");
        assert_eq!(strip_prefix_ab("c/x"), "c/x");
    }

    #[test]
    fn symlink_mode_lines_are_recognized_in_every_spelling() {
        for line in [
            "new file mode 120000",
            "deleted file mode 120755",
            "old mode 120000",
            "new mode 120000",
            "  new mode 120000  ",
        ] {
            assert!(is_symlink_mode_line(line), "{line:?}");
        }
        for line in [
            "new file mode 100644",
            "new mode 12000",
            "mode 120000",
            "new file mode 12x000",
        ] {
            assert!(!is_symlink_mode_line(line), "{line:?}");
        }
    }

    #[test]
    fn unsafe_forms_are_refused() {
        let bad = unsafe_paths(
            "--- a/../x\n+++ /etc/passwd\n+++ C:\\boot.ini\n+++ ~/x\n+++ \\\\server\\share\nnew file mode 120000\n--- /dev/null\n",
        );
        assert_eq!(bad.len(), 6, "{bad:?}");
        assert!(
            bad.iter().any(|b| b.starts_with("parent traversal: ../x")),
            "{bad:?}"
        );
        assert!(
            bad.iter().any(|b| b == "absolute path: /etc/passwd"),
            "{bad:?}"
        );
        assert!(
            bad.iter().any(|b| b.starts_with("symlink mode:")),
            "{bad:?}"
        );
        assert!(unsafe_paths("--- a/ok.py\n+++ b/ok.py\nnew file mode 100644\n").is_empty());
    }

    #[test]
    fn parsing_matches_argparse() {
        assert_eq!(parse(&args(&["--help"])), Ok(Parsed::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Parsed::Help));
        assert_eq!(parse(&args(&["--version"])), Ok(Parsed::Version));
        assert_eq!(parse(&args(&["--skill"])), Ok(Parsed::Skill));
        assert_eq!(
            parse(&args(&[
                "--diff",
                "x.patch",
                "--sandbox",
                "alt",
                "--commit"
            ])),
            Ok(Parsed::Run(Options {
                diff: Some(PathBuf::from("x.patch")),
                sandbox: Some("alt".into()),
                commit: true,
                ..Options::default()
            }))
        );
        assert_eq!(
            parse(&args(&["--log", "logs/x", "--work", "w"])),
            Ok(Parsed::Run(Options {
                log: Some(PathBuf::from("logs/x")),
                work: Some(PathBuf::from("w")),
                ..Options::default()
            }))
        );
        for bad in [
            vec!["--log", "a", "--diff", "b"],
            vec![],
            vec!["--commit"],
            vec!["--diff"],
            vec!["--nope"],
            vec!["--diff", "x", "extra"],
        ] {
            let fail = parse(&args(&bad)).unwrap_err();
            assert_eq!(fail.code, 2, "{bad:?}");
            assert!(
                fail.text.contains("oxbox patch: error:"),
                "{bad:?}: {}",
                fail.text
            );
            assert!(fail.text.starts_with("usage:"), "{bad:?}");
        }
    }

    #[test]
    fn diagnoses_carry_the_prefix_on_every_line() {
        let fail = Fail::diag(3, "one\ntwo");
        assert_eq!(fail.code, 3);
        assert_eq!(fail.text, "oxbox-patch: one\noxbox-patch: two\n");
    }

    #[test]
    fn pending_patch_files_are_unique_and_hold_the_bytes() {
        let dir = scratch("pending");
        let first = pending_patch(&dir, "one\n").unwrap();
        let second = pending_patch(&dir, "two\r\n").unwrap();
        assert_ne!(first, second);
        assert_eq!(fs::read(&first).unwrap(), b"one\n");
        assert_eq!(fs::read(&second).unwrap(), b"two\r\n");
        assert!(
            first
                .file_name()
                .unwrap()
                .to_string_lossy()
                .starts_with("pending-")
        );
        let missing = dir.join("no-such-dir");
        assert_eq!(pending_patch(&missing, "x").unwrap_err().code, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn loading_a_patch_from_a_log_or_a_file() {
        let dir = scratch("load");
        let log = dir.join("log");
        fs::create_dir_all(&log).unwrap();
        let from_log = Options {
            log: Some(log.clone()),
            ..Options::default()
        };
        assert_eq!(load_patch(&from_log).unwrap_err().code, 1);
        fs::write(
            log.join("content.md"),
            "Explanation.\n\n```diff\n--- a/x\n+++ b/x\n```\n",
        )
        .unwrap();
        assert_eq!(load_patch(&from_log).unwrap(), "--- a/x\n+++ b/x\n");
        fs::write(log.join("content.md"), "no diff at all").unwrap();
        let fail = load_patch(&from_log).unwrap_err();
        assert!(fail.text.contains("no diff block"), "{}", fail.text);
        let diff = dir.join("raw.patch");
        fs::write(&diff, VALID).unwrap();
        let from_file = Options {
            diff: Some(diff),
            ..Options::default()
        };
        assert_eq!(load_patch(&from_file).unwrap(), VALID);
        let absent = Options {
            diff: Some(dir.join("absent.patch")),
            ..Options::default()
        };
        assert_eq!(load_patch(&absent).unwrap_err().code, 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_work_tree_must_be_a_repo_inside_the_root() {
        let dir = scratch("resolve");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let outside = dir.join("outside");
        fs::create_dir_all(&outside).unwrap();
        with_root(&root, || {
            let default = Options::default();
            assert_eq!(
                resolve_work(&default).unwrap(),
                core::canonicalize_lenient(&work)
            );
            let named = Options {
                sandbox: Some("work".into()),
                ..Options::default()
            };
            assert_eq!(
                resolve_work(&named).unwrap(),
                core::canonicalize_lenient(&work)
            );
            let both = Options {
                sandbox: Some("work".into()),
                work: Some(work.clone()),
                ..Options::default()
            };
            assert!(resolve_work(&both).unwrap_err().text.contains("pass one"));
            let bad_name = Options {
                sandbox: Some("../x".into()),
                ..Options::default()
            };
            assert_eq!(resolve_work(&bad_name).unwrap_err().code, 2);
            let missing = Options {
                sandbox: Some("alt".into()),
                ..Options::default()
            };
            assert!(
                resolve_work(&missing)
                    .unwrap_err()
                    .text
                    .contains("does not exist")
            );
            let escape = Options {
                work: Some(outside.clone()),
                ..Options::default()
            };
            let fail = resolve_work(&escape).unwrap_err();
            assert_eq!(fail.code, 2);
            assert!(fail.text.contains("REFUSING --work"), "{}", fail.text);
            assert!(fail.text.contains("OXBOX_SANDBOX_ROOT"), "{}", fail.text);
            let plain = root.join("plain");
            fs::create_dir_all(&plain).unwrap();
            let no_git = Options {
                sandbox: Some("plain".into()),
                ..Options::default()
            };
            assert!(
                resolve_work(&no_git)
                    .unwrap_err()
                    .text
                    .contains("not a git repo")
            );
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_valid_patch_applies_and_an_invalid_one_does_not() {
        let dir = scratch("apply");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let valid = dir.join("valid.patch");
        fs::write(&valid, VALID).unwrap();
        with_root(&root, || {
            let options = Options {
                diff: Some(valid.clone()),
                ..Options::default()
            };
            let stdout = run(&options).unwrap();
            assert!(stdout.contains("mod.py"), "{stdout}");
            assert!(
                fs::read_to_string(work.join("mod.py"))
                    .unwrap()
                    .contains("return 2")
            );
            assert!(
                fs::read_dir(&root)
                    .unwrap()
                    .filter_map(Result::ok)
                    .all(|e| !e.file_name().to_string_lossy().starts_with("pending-")),
                "the pending patch file was removed"
            );
            // The same hunk no longer applies: exit 3, no traceback.
            let fail = run(&options).unwrap_err();
            assert_eq!(fail.code, 3);
            assert!(fail.text.contains("does not apply"), "{}", fail.text);
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_crlf_diff_applies_like_an_lf_one() {
        let dir = scratch("crlf");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let crlf = dir.join("crlf.patch");
        fs::write(&crlf, VALID.replace('\n', "\r\n")).unwrap();
        with_root(&root, || {
            let options = Options {
                diff: Some(crlf.clone()),
                ..Options::default()
            };
            run(&options).unwrap();
            // Only that it applied: on a Windows runner git's autocrlf
            // writes the tree back with CRLF, which is git's business.
            let text = fs::read_to_string(work.join("mod.py")).unwrap();
            assert!(text.contains("return 2"), "{text}");
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_patch_that_escapes_is_refused_before_git_sees_it() {
        let dir = scratch("escape");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let evil = dir.join("evil.patch");
        fs::write(
            &evil,
            "--- a/../../etc/passwd\n+++ b/../../etc/passwd\n@@ -1 +1 @@\n-x\n+y\n",
        )
        .unwrap();
        with_root(&root, || {
            let options = Options {
                diff: Some(evil.clone()),
                ..Options::default()
            };
            let fail = run(&options).unwrap_err();
            assert_eq!(fail.code, 2);
            assert!(
                fail.text.contains("REFUSING - patch targets paths outside"),
                "{}",
                fail.text
            );
            assert!(fail.text.contains("parent traversal"), "{}", fail.text);
        });
        assert!(
            fs::read_to_string(work.join("mod.py"))
                .unwrap()
                .contains("return 1")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_malformed_hunk_applies_with_recount_and_a_warning() {
        let dir = scratch("recount");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        // Wrong line counts in the hunk header: strict fails, --recount fixes.
        let sloppy = dir.join("sloppy.patch");
        fs::write(&sloppy, "--- a/mod.py\n+++ b/mod.py\n@@ -1,9 +1,9 @@\n def f():\n-    return 1\n+    return 2\n").unwrap();
        with_root(&root, || {
            let options = Options {
                diff: Some(sloppy.clone()),
                ..Options::default()
            };
            run(&options).unwrap();
            assert!(
                fs::read_to_string(work.join("mod.py"))
                    .unwrap()
                    .contains("return 2")
            );
        });
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn commit_records_the_patch_in_the_sandbox_repo() {
        let dir = scratch("commit");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let valid = dir.join("valid.patch");
        fs::write(&valid, VALID).unwrap();
        with_root(&root, || {
            let options = Options {
                diff: Some(valid.clone()),
                commit: true,
                ..Options::default()
            };
            run(&options).unwrap();
        });
        let log = Command::new("git")
            .arg("-C")
            .arg(&work)
            .args(["log", "--oneline"])
            .output()
            .unwrap();
        let text = String::from_utf8_lossy(&log.stdout);
        assert!(text.contains("ox patch"), "{text}");
        assert_eq!(text.lines().count(), 2, "{text}");
        let status = Command::new("git")
            .arg("-C")
            .arg(&work)
            .args(["status", "--porcelain"])
            .output()
            .unwrap();
        assert!(status.stdout.is_empty(), "the tree is clean after --commit");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_patch_from_a_log_directory_round_trips() {
        let dir = scratch("fromlog");
        let root = dir.join("root");
        let work = seeded(&root, "work");
        let log = dir.join("logs").join("2026-09-06T00-00-00Z");
        fs::create_dir_all(&log).unwrap();
        fs::write(
            log.join("content.md"),
            format!("Changed the return value.\n\n```diff\n{VALID}```\n"),
        )
        .unwrap();
        with_root(&root, || {
            let options = Options {
                log: Some(log.clone()),
                ..Options::default()
            };
            run(&options).unwrap();
        });
        assert!(
            fs::read_to_string(work.join("mod.py"))
                .unwrap()
                .contains("return 2")
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
