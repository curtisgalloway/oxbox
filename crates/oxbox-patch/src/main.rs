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

fn say(message: &str) {
    core::diagnose(PROG, message);
}

fn fail(code: i32, message: &str) -> ! {
    say(message);
    process::exit(code);
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
fn pending_patch(dir: &Path, patch: &str) -> PathBuf {
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
                if let Err(error) = file.write_all(patch.as_bytes()) {
                    fail(1, &format!("cannot write {}: {error}", path.display()));
                }
                return path;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => fail(
                1,
                &format!("cannot create a patch file in {}: {error}", dir.display()),
            ),
        }
    }
    fail(
        1,
        &format!("cannot create a patch file in {}", dir.display()),
    );
}

struct Options {
    log: Option<PathBuf>,
    diff: Option<PathBuf>,
    sandbox: Option<String>,
    work: Option<PathBuf>,
    commit: bool,
}

fn usage_error(message: &str) -> ! {
    eprint!("{USAGE}");
    eprintln!("oxbox patch: error: {message}");
    process::exit(2);
}

fn parse(args: &[String]) -> Options {
    let mut options = Options {
        log: None,
        diff: None,
        sandbox: None,
        work: None,
        commit: false,
    };
    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        let value = |index: usize| -> &String {
            args.get(index + 1)
                .unwrap_or_else(|| usage_error(&format!("argument {arg}: expected one argument")))
        };
        match arg {
            "--help" | "-h" => {
                print!("{USAGE}");
                process::exit(0);
            }
            "--version" => {
                println!("{PROG} {}", core::VERSION);
                process::exit(0);
            }
            "--skill" => process::exit(core::print_skill(PROG)),
            "--log" => {
                options.log = Some(PathBuf::from(value(index)));
                index += 1;
            }
            "--diff" => {
                options.diff = Some(PathBuf::from(value(index)));
                index += 1;
            }
            "--sandbox" => {
                options.sandbox = Some(value(index).clone());
                index += 1;
            }
            "--work" => {
                options.work = Some(PathBuf::from(value(index)));
                index += 1;
            }
            "--commit" => options.commit = true,
            _ => usage_error(&format!("unrecognized arguments: {arg}")),
        }
        index += 1;
    }
    match (&options.log, &options.diff) {
        (Some(_), Some(_)) => usage_error("argument --diff: not allowed with argument --log"),
        (None, None) => usage_error("one of the arguments --log --diff is required"),
        _ => {}
    }
    options
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let options = parse(&args);

    let patch = if let Some(log) = &options.log {
        let content_path = log.join("content.md");
        if !content_path.is_file() {
            fail(1, &format!("no content.md in {}", log.display()));
        }
        let text = fs::read_to_string(&content_path).unwrap_or_else(|error| {
            fail(
                1,
                &format!("cannot read {}: {error}", content_path.display()),
            )
        });
        extract(&text).unwrap_or_else(|| fail(1, "no diff block found in the response"))
    } else {
        let diff = options.diff.as_ref().expect("one source is required");
        fs::read_to_string(diff)
            .unwrap_or_else(|error| fail(1, &format!("cannot read {}: {error}", diff.display())))
    };

    let root = match core::sandbox_root() {
        Ok(root) => root,
        Err(message) => fail(1, &message),
    };
    if options.work.is_some() && options.sandbox.is_some() {
        fail(1, "--work and --sandbox name the same thing; pass one");
    }
    let work = match &options.work {
        Some(work) => core::canonicalize_lenient(work),
        None => {
            let name = options.sandbox.as_deref().unwrap_or("work");
            match core::sandbox_name(name) {
                Ok(name) => root.path.join(name),
                Err(message) => fail(2, &message),
            }
        }
    };
    if !work.is_dir() {
        fail(1, &format!("work dir does not exist: {}", work.display()));
    }
    let work = core::canonicalize_lenient(&work);

    // A --work outside the sandbox root is refused because whatever --work
    // names is what gets written to: a pasted or mistyped path would apply a
    // model-produced patch straight into a real checkout. unsafe_paths below
    // cannot stand in for this: it constrains where a patch may write
    // *relative to* the work dir, and says nothing about where the work dir
    // itself is.
    if !core::is_within(&root.path, &work) {
        say(&format!(
            "REFUSING --work {}\n\
             it lies outside {} (the sandbox root,\n\
             from {}), so applying a model-produced patch\n\
             there would touch a real tree. Run oxbox sandbox --create\n\
             first, or name a --work inside the sandbox root.",
            work.display(),
            root.path.display(),
            root.origin
        ));
        process::exit(2);
    }
    if !work.join(".git").exists() {
        fail(
            1,
            &format!(
                "{} is not a git repo (run oxbox sandbox --create first)",
                work.display()
            ),
        );
    }

    let bad = unsafe_paths(&patch);
    if !bad.is_empty() {
        eprintln!("{PROG}: REFUSING - patch targets paths outside the sandbox:");
        for item in bad {
            eprintln!("  {item}");
        }
        process::exit(2);
    }

    let patch_dir = work
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| work.clone());
    let patch_path = pending_patch(&patch_dir, &patch);
    let code = apply(&work, &patch, &patch_path, options.commit);
    // The pending file holds the model's raw output; it is removed on every
    // exit path rather than left for an archive to pick up.
    if let Err(error) = fs::remove_file(&patch_path) {
        say(&format!(
            "could not remove {}: {error}",
            patch_path.display()
        ));
    }
    process::exit(code);
}

fn apply(work: &Path, patch: &str, patch_path: &Path, commit: bool) -> i32 {
    let mut targets: Vec<String> = candidate_paths(patch)
        .into_iter()
        .filter(|path| path != "/dev/null")
        .collect();
    targets.sort();
    targets.dedup();
    say(&format!("patch -> {}", patch_path.display()));
    say(&format!(
        "targets ({}): {}",
        targets.len(),
        targets.join(", ")
    ));

    let strategies: [(&str, &[&str]); 3] = [
        ("strict", &[]),
        ("recount", &["--recount"]),
        ("recount+C1", &["--recount", "-C1"]),
    ];
    let mut chosen: Option<(&str, &[&str])> = None;
    let mut last_error = String::new();
    for (name, flags) in strategies {
        let check = Command::new("git")
            .arg("-C")
            .arg(work)
            .args(["apply", "--check"])
            .args(flags)
            .arg(patch_path)
            .output();
        match check {
            Ok(output) if output.status.success() => {
                chosen = Some((name, flags));
                break;
            }
            Ok(output) => last_error = String::from_utf8_lossy(&output.stderr).into_owned(),
            Err(error) => fail(1, &format!("cannot run git: {error}")),
        }
    }
    let Some((name, flags)) = chosen else {
        eprintln!("{PROG}: patch does not apply at any strictness level:");
        eprint!("{last_error}");
        return 3;
    };
    if name != "strict" {
        say(&format!(
            "WARNING - patch only applied with '{name}'. The model emitted a\n\
             malformed hunk (usually wrong line counts or missing trailing\n\
             context). Re-read the resulting diff carefully."
        ));
    }

    let applied = Command::new("git")
        .arg("-C")
        .arg(work)
        .args(["apply", "--stat", "--apply"])
        .args(flags)
        .arg(patch_path)
        .output();
    let applied = match applied {
        Ok(output) => output,
        Err(error) => fail(1, &format!("cannot run git: {error}")),
    };
    let mut out = std::io::stdout().lock();
    let _ = out.write_all(&applied.stdout);
    let _ = out.flush();
    if !applied.status.success() {
        eprint!("{}", String::from_utf8_lossy(&applied.stderr));
        return 3;
    }

    if commit {
        for args in [
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
            let status = Command::new("git").arg("-C").arg(work).args(&args).status();
            if !matches!(status, Ok(status) if status.success()) {
                fail(1, &format!("git {} failed", args.join(" ")));
            }
        }
    }

    say("applied inside sandbox only");
    say(&format!("review with: git -C {} diff HEAD", work.display()));
    0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fences_are_extracted_and_joined() {
        let text = "hello\n```diff\n--- a/x\n+++ b/x\n```\nmore\n```patch\n@@ -1 +1 @@\n```\n";
        assert_eq!(extract(text).unwrap(), "--- a/x\n+++ b/x\n@@ -1 +1 @@\n");
        assert_eq!(
            extract("--- a/x\n+++ b/x\n"),
            Some("--- a/x\n+++ b/x\n".to_string())
        );
        assert_eq!(extract("no diff here"), None);
    }

    #[test]
    fn every_header_kind_names_a_target() {
        let patch = "diff --git a/src/one.py b/src/one.py\nrename from old/name.py\nrename to ../../escape.py\n--- a/src/one.py\n+++ b/src/one.py\n--- /dev/null\n+++ b/new.py\n";
        let paths = candidate_paths(patch);
        for expected in [
            "src/one.py",
            "old/name.py",
            "../../escape.py",
            "/dev/null",
            "new.py",
        ] {
            assert!(
                paths.contains(&expected.to_string()),
                "{expected} missing from {paths:?}"
            );
        }
    }

    #[test]
    fn unsafe_forms_are_refused() {
        let bad = unsafe_paths(
            "--- a/../x\n+++ /etc/passwd\n+++ C:\\boot.ini\nnew file mode 120000\n--- /dev/null\n",
        );
        assert_eq!(bad.len(), 4, "{bad:?}");
        assert!(unsafe_paths("--- a/ok.py\n+++ b/ok.py\nnew file mode 100644\n").is_empty());
    }
}
