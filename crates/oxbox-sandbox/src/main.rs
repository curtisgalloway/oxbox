// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! Build and tend a disposable sandbox tree: a copy of chosen files from a
//! real repo, made a git repo so patches can be applied and diffed without
//! ever touching the original.
//!
//! This is the executable `oxbox sandbox` runs. It lives in a libexec
//! directory rather than on PATH; oxbox finds it from its own location.
//! Standard library only.
//!
//! Every refusal is a value (`Fail`) returned to `main`, which prints and
//! exits, and the operations take their input and output streams as
//! parameters. Nothing below `main` touches the process, which is what lets
//! the unit tests drive every operation against a scratch root.

use std::env;
use std::fs;
use std::io::{self, IsTerminal, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command};

use oxbox_core as core;

const PROG: &str = "oxbox-sandbox";

const USAGE: &str = "\
usage: oxbox sandbox [--sandbox NAME] --create /path/to/repo file1 [file2 ...]
       oxbox sandbox [--sandbox NAME] --add file1 [file2 ...]
       oxbox sandbox [--sandbox NAME] --remove file1 [file2 ...]
       oxbox sandbox [--sandbox NAME] --list
       oxbox sandbox [--sandbox NAME] --read file
       oxbox sandbox [--sandbox NAME] --write file   < content
       oxbox sandbox [--sandbox NAME] --destroy [--all]
       oxbox sandbox --status

Build and tend disposable sandbox trees: a copy of chosen files from a real
repo, made a git repo so patches can be applied and diffed without ever
touching the original.

Sandboxes live under a root -- OXBOX_SANDBOX_ROOT, else `root` under
[sandbox] in ~/.config/oxbox/config.ini, else ./sandbox -- as <root>/NAME.
--sandbox NAME picks one (default: work); --status lists them all.

Baseline operations commit, so `git -C <root>/NAME diff HEAD` keeps meaning
\"what changed since the operator set the baseline\":
  --create REPO FILE...   wipe the sandbox and copy FILEs from REPO into it,
                          recording REPO as the source for --add
  --add FILE...           copy more files from the recorded source
  --remove FILE...        delete files from the sandbox
  --destroy               remove this sandbox; with --all, every sandbox and
                          the root itself

Working-tree operations do not commit; they read and edit the tree as the
model's patch would:
  --list                  print every file in the sandbox, one per line
  --read FILE             print a sandbox file to stdout, bytes unchanged
  --write FILE            replace a sandbox file with stdin, bytes unchanged
  --status                one line per sandbox under the root: name, file
                          count, clean or modified, and source

  --skill                 print the ox-review agent skill and exit
  --version               print the version and exit
  --help                  print this and exit

Paths are relative to the sandbox; anything absolute, traversing upward,
through a symlink, or into .git is refused. exit status: 0; 1 when --list or
--status finds nothing; 2 for a usage error; 3 when there is no sandbox, no
recorded source, or a named file does not exist; 78 for a refused path.
";

const EX_CONFIG: i32 = 78;

/// How a run ends other than by succeeding: the text for stderr, already in
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

    /// A refused path: exit 78, like the jail's refusals.
    fn refuse(message: &str) -> Fail {
        Fail::diag(EX_CONFIG, message)
    }

    /// An argparse-style usage error.
    fn usage(message: &str) -> Fail {
        Fail {
            code: 2,
            text: format!("oxbox sandbox: error: {message}\n"),
        }
    }
}

fn say(message: &str) {
    core::diagnose(PROG, message);
}

/// The selected sandbox: its tree, and the record of where --create copied
/// from, so --add can copy more from the same place. The record sits beside
/// the tree, not inside it: the jail writes only into the tree, so nothing
/// that ran in it can redirect the next --add at a directory of its choosing.
struct Sandbox {
    root: PathBuf,
    root_origin: String,
    work: PathBuf,
    source_record: PathBuf,
}

impl Sandbox {
    fn select(root: core::SandboxRoot, name: &str) -> Sandbox {
        Sandbox {
            work: root.path.join(name),
            source_record: root.path.join(".sources").join(name),
            root: root.path,
            root_origin: root.origin,
        }
    }

    fn git(&self, args: &[&str]) -> Result<(), Fail> {
        let status = Command::new("git")
            .arg("-C")
            .arg(&self.work)
            .args(args)
            .status();
        match status {
            Ok(status) if status.success() => Ok(()),
            Ok(status) => Err(Fail::diag(
                1,
                &format!("git {} failed: {status}", args.join(" ")),
            )),
            Err(error) => Err(Fail::diag(1, &format!("cannot run git: {error}"))),
        }
    }

    /// Record a baseline change: everything after --create, or only the named
    /// paths after --add and --remove, so an uncommitted --write (or the
    /// model's applied patch) elsewhere in the tree stays out of the baseline.
    fn commit(&self, message: &str, paths: &[String]) -> Result<(), Fail> {
        if paths.is_empty() {
            self.git(&["add", "-A"])?;
        } else {
            let mut args = vec!["add", "-A", "--"];
            args.extend(paths.iter().map(String::as_str));
            self.git(&args)?;
        }
        self.git(&[
            "-c",
            "user.email=seed@sandbox.invalid",
            "-c",
            "user.name=oxbox-sandbox",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            message,
        ])
    }

    fn require(&self) -> Result<(), Fail> {
        if self.work.join(".git").is_dir() {
            Ok(())
        } else {
            Err(Fail::diag(
                3,
                "no sandbox here; create one with oxbox sandbox --create /path/to/repo file...",
            ))
        }
    }

    /// A path inside the work tree, or a refusal.
    ///
    /// The same textual rules as `validate`, because the same tricks apply:
    /// an absolute path, a parent traversal or a drive letter would name
    /// something outside the sandbox, and a symlink component would reach
    /// outside it through a link the model's patch could have created. .git
    /// is refused because it is the baseline's bookkeeping, not a sandbox
    /// file.
    fn work_path(&self, rel: &str, must_exist: bool) -> Result<PathBuf, Fail> {
        if is_rooted(rel) {
            return Err(Fail::refuse(&format!("REFUSING absolute path: {rel}")));
        }
        if core::has_parent_traversal(rel) {
            return Err(Fail::refuse(&format!("REFUSING parent traversal: {rel}")));
        }
        let first = rel.replace('\\', "/");
        if first.split('/').next() == Some(".git") {
            return Err(Fail::refuse(&format!("REFUSING a path inside .git: {rel}")));
        }
        let full = self.work.join(rel);
        if must_exist && fs::symlink_metadata(&full).is_err() {
            return Err(Fail::diag(
                3,
                &format!("no such file in the sandbox: {rel}"),
            ));
        }
        // Resolve every existing component and require the result to stay
        // under the work tree -- a symlink anywhere on the way would put it
        // elsewhere.
        let mut probe = full.clone();
        while fs::symlink_metadata(&probe).is_err() && probe != self.work {
            match probe.parent() {
                Some(parent) => probe = parent.to_path_buf(),
                None => break,
            }
        }
        let unresolvable = |error: io::Error| {
            Fail::refuse(&format!("REFUSING unresolvable path: {rel} ({error})"))
        };
        let root = fs::canonicalize(&self.work).map_err(unresolvable)?;
        let resolved = fs::canonicalize(&probe).map_err(unresolvable)?;
        if !core::is_within(&root, &resolved) {
            return Err(Fail::refuse(&format!(
                "REFUSING path resolving outside the sandbox: {rel} -> {}",
                resolved.display()
            )));
        }
        Ok(full)
    }

    /// Every sandbox under the root, by name.
    fn sandboxes(&self) -> Vec<String> {
        let Ok(entries) = fs::read_dir(&self.root) else {
            return Vec::new();
        };
        let mut names: Vec<String> = entries
            .filter_map(Result::ok)
            .filter(|entry| {
                entry
                    .file_type()
                    .map(|kind| kind.is_dir() && !kind.is_symlink())
                    .unwrap_or(false)
            })
            .map(|entry| entry.file_name().to_string_lossy().into_owned())
            .filter(|name| !name.starts_with('.'))
            .collect();
        names.sort();
        names
    }
}

/// POSIX root, Windows root, UNC, drive letter, or home expansion. Textual,
/// because `Path::is_absolute` on Windows says `/etc/hosts` has a root but no
/// drive and reports false.
fn is_rooted(rel: &str) -> bool {
    Path::new(rel).is_absolute()
        || rel.starts_with('~')
        || rel.starts_with('/')
        || rel.starts_with('\\')
        || (rel.len() > 1 && rel.as_bytes()[1] == b':')
}

/// `shutil.rmtree`, but able to remove git's read-only object files.
///
/// Git marks objects in .git/objects read-only. On Windows that makes the
/// unlink fail with "Access is denied", so re-seeding an existing sandbox
/// blows up half-deleted. POSIX does not care -- permission to unlink comes
/// from the directory there -- which is why this only ever shows up on
/// Windows.
fn rmtree_force(path: &Path) -> Result<(), Fail> {
    if fs::remove_dir_all(path).is_ok() {
        return Ok(());
    }
    make_writable(path);
    fs::remove_dir_all(path)
        .map_err(|error| Fail::diag(1, &format!("cannot remove {}: {error}", path.display())))
}

fn make_writable(path: &Path) {
    if let Ok(meta) = fs::symlink_metadata(path) {
        let mut permissions = meta.permissions();
        #[allow(clippy::permissions_set_readonly_false)]
        permissions.set_readonly(false);
        let _ = fs::set_permissions(path, permissions);
        if meta.is_dir()
            && !meta.file_type().is_symlink()
            && let Ok(entries) = fs::read_dir(path)
        {
            for entry in entries.filter_map(Result::ok) {
                make_writable(&entry.path());
            }
        }
    }
}

/// Reject anything that would land outside the sandbox.
///
/// The traversal class oxbox-patch refuses in patches applies just as much
/// to seed arguments, which would otherwise copy straight past the boundary.
fn validate(source: &Path, rel: &str) -> Result<(), Fail> {
    if is_rooted(rel) {
        return Err(Fail::refuse(&format!("REFUSING absolute path: {rel}")));
    }
    if core::has_parent_traversal(rel) {
        return Err(Fail::refuse(&format!("REFUSING parent traversal: {rel}")));
    }
    let full = source.join(rel);
    let Ok(meta) = fs::symlink_metadata(&full) else {
        return Err(Fail::diag(3, &format!("missing in source: {rel}")));
    };
    // A copied symlink aimed at ~/.ssh or /etc would put a live handle to the
    // outside inside the work tree, for anything that touches it outside the
    // jail.
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&full)
            .map(|t| t.to_string_lossy().into_owned())
            .unwrap_or_default();
        return Err(Fail::refuse(&format!(
            "REFUSING symlink: {rel} -> {target}"
        )));
    }
    // The named path is not the only place a link can hide. An intermediate
    // component does the same job: seeding "gate/creds.txt" where gate is a
    // link to /elsewhere passes every check above, because `full` is itself
    // neither a symlink nor a directory, and a copy reads straight through
    // it. Resolving the whole chain and requiring it to stay under the source
    // root is the check that closes that, and every variant like it.
    let unresolvable =
        |error: io::Error| Fail::refuse(&format!("REFUSING unresolvable path: {rel} ({error})"));
    let root = fs::canonicalize(source).map_err(unresolvable)?;
    let resolved = fs::canonicalize(&full).map_err(unresolvable)?;
    if !core::is_within(&root, &resolved) {
        return Err(Fail::refuse(&format!(
            "REFUSING path resolving outside the source: {rel} -> {}",
            resolved.display()
        )));
    }
    if meta.is_dir() {
        // Directories matter as much as files: a symlinked directory inside a
        // tree would be dereferenced by the copy and its target's contents
        // copied into the sandbox.
        if let Some(name) = first_symlink_within(&full) {
            return Err(Fail::refuse(&format!(
                "REFUSING {rel}: contains symlink {name}"
            )));
        }
    }
    Ok(())
}

fn first_symlink_within(dir: &Path) -> Option<String> {
    let entries = fs::read_dir(dir).ok()?;
    for entry in entries.filter_map(Result::ok) {
        let kind = entry.file_type().ok()?;
        if kind.is_symlink() {
            return Some(entry.file_name().to_string_lossy().into_owned());
        }
        if kind.is_dir()
            && let Some(found) = first_symlink_within(&entry.path())
        {
            return Some(found);
        }
    }
    None
}

/// Copy a file with its modification time, the way `shutil.copy2` does.
fn copy_file(from: &Path, to: &Path) -> io::Result<()> {
    fs::copy(from, to)?;
    if let Ok(modified) = fs::metadata(from).and_then(|meta| meta.modified()) {
        let _ = fs::File::options()
            .write(true)
            .open(to)
            .and_then(|file| file.set_modified(modified));
    }
    Ok(())
}

/// `shutil.copytree(symlinks=False)` on a tree `validate` has already checked
/// holds no symlinks.
fn copy_tree(from: &Path, to: &Path) -> io::Result<()> {
    fs::create_dir_all(to)?;
    for entry in fs::read_dir(from)? {
        let entry = entry?;
        let target = to.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_tree(&entry.path(), &target)?;
        } else {
            copy_file(&entry.path(), &target)?;
        }
    }
    Ok(())
}

/// Copy validated files from the source repo into the work tree.
fn copy_in(sandbox: &Sandbox, source: &Path, relatives: &[String]) -> Result<(), Fail> {
    for rel in relatives {
        let destination = sandbox.work.join(rel);
        if let Some(parent) = destination.parent() {
            fs::create_dir_all(parent).map_err(|error| {
                Fail::diag(1, &format!("cannot create {}: {error}", parent.display()))
            })?;
        }
        let origin = source.join(rel);
        let result = if origin.is_dir() {
            if destination.exists() {
                rmtree_force(&destination)?;
            }
            copy_tree(&origin, &destination)
        } else {
            copy_file(&origin, &destination)
        };
        result.map_err(|error| Fail::diag(1, &format!("cannot copy {rel}: {error}")))?;
        say(&format!("seeded {rel}"));
    }
    Ok(())
}

/// Every file under a tree, skipping .git and .oxtmp, as sandbox-relative
/// POSIX paths, sorted.
fn files_within(tree: &Path) -> Vec<String> {
    fn walk(dir: &Path, base: &Path, out: &mut Vec<String>) {
        let Ok(entries) = fs::read_dir(dir) else {
            return;
        };
        for entry in entries.filter_map(Result::ok) {
            let name = entry.file_name().to_string_lossy().into_owned();
            let path = entry.path();
            let Ok(kind) = entry.file_type() else {
                continue;
            };
            if kind.is_dir() {
                if name != ".git" && name != ".oxtmp" {
                    walk(&path, base, out);
                }
            } else if let Ok(rel) = path.strip_prefix(base) {
                let text = rel
                    .components()
                    .map(|part| part.as_os_str().to_string_lossy().into_owned())
                    .collect::<Vec<_>>()
                    .join("/");
                out.push(text);
            }
        }
    }
    let mut found = Vec::new();
    walk(tree, tree, &mut found);
    found.sort();
    found
}

fn op_create(sandbox: &Sandbox, paths: &[String]) -> Result<i32, Fail> {
    let Some((repo, relatives)) = paths.split_first() else {
        return Err(Fail::diag(
            2,
            "--create needs the repo and at least one file",
        ));
    };
    if relatives.is_empty() {
        return Err(Fail::diag(
            2,
            "--create needs the repo and at least one file",
        ));
    }
    let Ok(source) = fs::canonicalize(repo) else {
        return Err(Fail::diag(3, &format!("not a directory: {repo}")));
    };
    let source = core::canonicalize_lenient(&source);
    if !source.is_dir() {
        return Err(Fail::diag(3, &format!("not a directory: {repo}")));
    }
    // Validate everything BEFORE destroying anything: refusing partway
    // through would still have wiped the existing sandbox on the way to
    // saying no.
    for rel in relatives {
        validate(&source, rel)?;
    }
    if sandbox.work.exists() {
        rmtree_force(&sandbox.work)?;
    }
    fs::create_dir_all(&sandbox.work).map_err(|error| {
        Fail::diag(
            1,
            &format!("cannot create {}: {error}", sandbox.work.display()),
        )
    })?;
    if let Some(parent) = sandbox.source_record.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&sandbox.source_record, format!("{}\n", source.display()))
        .map_err(|error| Fail::diag(1, &format!("cannot record the source: {error}")))?;
    copy_in(sandbox, &source, relatives)?;
    sandbox.git(&["init", "-q"])?;
    sandbox.commit(&format!("pristine seed from {}", source.display()), &[])?;
    say(&format!(
        "work={} (pristine commit recorded)",
        sandbox.work.display()
    ));
    say(&format!("source untouched: {}", source.display()));
    Ok(0)
}

fn op_add(sandbox: &Sandbox, relatives: &[String]) -> Result<i32, Fail> {
    sandbox.require()?;
    if relatives.is_empty() {
        return Err(Fail::diag(2, "--add needs at least one file"));
    }
    let Ok(recorded) = fs::read_to_string(&sandbox.source_record) else {
        return Err(Fail::diag(
            3,
            "no recorded source; this sandbox predates --add, so --create it again",
        ));
    };
    let source = PathBuf::from(recorded.trim());
    if !source.is_dir() {
        return Err(Fail::diag(
            3,
            &format!("recorded source is not a directory: {}", source.display()),
        ));
    }
    for rel in relatives {
        validate(&source, rel)?;
    }
    copy_in(sandbox, &source, relatives)?;
    sandbox.commit(&format!("seed {}", relatives.join(" ")), relatives)?;
    say(&format!(
        "added from {} (baseline commit recorded)",
        source.display()
    ));
    Ok(0)
}

fn op_remove(sandbox: &Sandbox, relatives: &[String]) -> Result<i32, Fail> {
    sandbox.require()?;
    if relatives.is_empty() {
        return Err(Fail::diag(2, "--remove needs at least one file"));
    }
    let mut targets = Vec::new();
    for rel in relatives {
        targets.push(sandbox.work_path(rel, true)?);
    }
    for (rel, full) in relatives.iter().zip(&targets) {
        if full.is_dir() {
            rmtree_force(full)?;
        } else {
            fs::remove_file(full)
                .map_err(|error| Fail::diag(1, &format!("cannot remove {rel}: {error}")))?;
        }
        say(&format!("removed {rel}"));
    }
    sandbox.commit(&format!("remove {}", relatives.join(" ")), relatives)?;
    say("baseline commit recorded");
    Ok(0)
}

fn op_destroy(sandbox: &Sandbox, everything: bool) -> Result<i32, Fail> {
    if everything {
        if sandbox.root.exists() {
            rmtree_force(&sandbox.root)?;
        }
        say(&format!(
            "removed {} and every sandbox in it",
            sandbox.root.display()
        ));
        return Ok(0);
    }
    if sandbox.work.exists() {
        rmtree_force(&sandbox.work)?;
    }
    if sandbox.source_record.exists() {
        let _ = fs::remove_file(&sandbox.source_record);
    }
    say(&format!("removed {}", sandbox.work.display()));
    // Leave no empty root behind, so the single-sandbox case ends the way it
    // always did: ./sandbox is gone.
    if sandbox.root.exists() && sandbox.sandboxes().is_empty() {
        rmtree_force(&sandbox.root)?;
    }
    Ok(0)
}

fn op_status(sandbox: &Sandbox, out: &mut dyn Write) -> Result<i32, Fail> {
    let _ = writeln!(
        out,
        "root {}  (from {})",
        sandbox.root.display(),
        sandbox.root_origin
    );
    let names = sandbox.sandboxes();
    for name in &names {
        let tree = sandbox.root.join(name);
        let count = files_within(&tree).len();
        let state = if tree.join(".git").is_dir() {
            let porcelain = Command::new("git")
                .arg("-C")
                .arg(&tree)
                .args(["status", "--porcelain"])
                .output();
            match porcelain {
                Ok(output) if !String::from_utf8_lossy(&output.stdout).trim().is_empty() => {
                    "modified"
                }
                _ => "clean",
            }
        } else {
            "no-git"
        };
        let source = fs::read_to_string(sandbox.root.join(".sources").join(name))
            .map(|text| text.trim().to_string())
            .unwrap_or_else(|_| "?".to_string());
        let _ = writeln!(out, "{name}  {count} files  {state}  {source}");
    }
    Ok(if names.is_empty() { 1 } else { 0 })
}

fn op_list(sandbox: &Sandbox, out: &mut dyn Write) -> Result<i32, Fail> {
    sandbox.require()?;
    let found = files_within(&sandbox.work);
    for rel in &found {
        let _ = writeln!(out, "{rel}");
    }
    Ok(if found.is_empty() { 1 } else { 0 })
}

fn op_read(sandbox: &Sandbox, relatives: &[String], out: &mut dyn Write) -> Result<i32, Fail> {
    sandbox.require()?;
    let [rel] = relatives else {
        return Err(Fail::diag(2, "--read takes exactly one file"));
    };
    let full = sandbox.work_path(rel, true)?;
    if full.is_dir() {
        return Err(Fail::diag(
            2,
            &format!("{rel} is a directory; --list shows it"),
        ));
    }
    // Bytes through, unchanged: no re-encoding and no line-ending rewrite.
    let data =
        fs::read(&full).map_err(|error| Fail::diag(1, &format!("cannot read {rel}: {error}")))?;
    out.write_all(&data)
        .and_then(|_| out.flush())
        .map_err(|error| Fail::diag(1, &format!("cannot write stdout: {error}")))?;
    Ok(0)
}

fn op_write(
    sandbox: &Sandbox,
    relatives: &[String],
    stdin_is_terminal: bool,
    input: &mut dyn Read,
) -> Result<i32, Fail> {
    sandbox.require()?;
    let [rel] = relatives else {
        return Err(Fail::diag(2, "--write takes exactly one file"));
    };
    if stdin_is_terminal {
        return Err(Fail::diag(
            2,
            "--write reads the content from stdin; redirect or pipe it in",
        ));
    }
    let full = sandbox.work_path(rel, false)?;
    if full.is_dir() {
        return Err(Fail::diag(2, &format!("{rel} is a directory")));
    }
    let mut data = Vec::new();
    input
        .read_to_end(&mut data)
        .map_err(|error| Fail::diag(1, &format!("cannot read stdin: {error}")))?;
    if let Some(parent) = full.parent() {
        let _ = fs::create_dir_all(parent);
    }
    fs::write(&full, &data)
        .map_err(|error| Fail::diag(1, &format!("cannot write {rel}: {error}")))?;
    say(&format!(
        "wrote {} bytes to {rel} (not committed; git diff HEAD shows it)",
        data.len()
    ));
    Ok(0)
}

const OPERATIONS: [&str; 8] = [
    "create", "add", "remove", "destroy", "list", "read", "write", "status",
];

/// What a command line asks for.
#[derive(Debug, PartialEq)]
enum Parsed {
    Help,
    Version,
    Skill,
    Run {
        name: String,
        all: bool,
        op: &'static str,
        paths: Vec<String>,
    },
}

fn parse(args: &[String]) -> Result<Parsed, Fail> {
    let mut name = String::from("work");
    let mut all = false;
    let mut op: Option<&'static str> = None;
    let mut paths: Vec<String> = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--help" | "-h" => return Ok(Parsed::Help),
            "--version" => return Ok(Parsed::Version),
            "--skill" => return Ok(Parsed::Skill),
            "--sandbox" => {
                let Some(value) = args.get(index + 1) else {
                    return Err(Fail::usage("argument --sandbox: expected one argument"));
                };
                name = value.clone();
                index += 2;
                continue;
            }
            "--all" => all = true,
            _ if arg.starts_with("--") => {
                let word = &arg[2..];
                let Some(found) = OPERATIONS.iter().find(|&&candidate| candidate == word) else {
                    return Err(Fail::usage(&format!("unrecognized arguments: {arg}")));
                };
                if let Some(previous) = op
                    && previous != *found
                {
                    return Err(Fail::usage(&format!(
                        "argument --{found}: not allowed with argument --{previous}"
                    )));
                }
                op = Some(found);
            }
            _ => paths.push(arg.to_string()),
        }
        index += 1;
    }
    let Some(op) = op else {
        return Err(Fail::usage(&format!(
            "one of the arguments {} is required",
            OPERATIONS
                .iter()
                .map(|word| format!("--{word}"))
                .collect::<Vec<_>>()
                .join(" ")
        )));
    };
    Ok(Parsed::Run {
        name,
        all,
        op,
        paths,
    })
}

/// Carry out one operation against the selected sandbox.
fn execute(
    sandbox: &Sandbox,
    op: &str,
    all: bool,
    paths: &[String],
    stdin_is_terminal: bool,
    input: &mut dyn Read,
    out: &mut dyn Write,
) -> Result<i32, Fail> {
    if all && op != "destroy" {
        return Err(Fail::diag(2, "--all goes with --destroy only"));
    }
    match op {
        "create" => op_create(sandbox, paths),
        "add" => op_add(sandbox, paths),
        "remove" => op_remove(sandbox, paths),
        "read" => op_read(sandbox, paths, out),
        "write" => op_write(sandbox, paths, stdin_is_terminal, input),
        _ if !paths.is_empty() => Err(Fail::diag(2, &format!("--{op} takes no paths"))),
        "destroy" => op_destroy(sandbox, all),
        "status" => op_status(sandbox, out),
        _ => op_list(sandbox, out),
    }
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
        Ok(Parsed::Run {
            name,
            all,
            op,
            paths,
        }) => {
            let outcome = core::sandbox_root()
                .map_err(|message| Fail::diag(1, &message))
                .and_then(|root| {
                    let name =
                        core::sandbox_name(&name).map_err(|message| Fail::diag(2, &message))?;
                    let sandbox = Sandbox::select(root, &name);
                    let stdin = io::stdin();
                    let is_terminal = stdin.is_terminal();
                    let mut input = stdin.lock();
                    let mut out = io::stdout().lock();
                    execute(&sandbox, op, all, &paths, is_terminal, &mut input, &mut out)
                });
            match outcome {
                Ok(code) => code,
                Err(fail) => {
                    eprint!("{}", fail.text);
                    fail.code
                }
            }
        }
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
    use std::io::Cursor;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("oxbox-sandbox-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn sandbox_at(dir: &Path, name: &str) -> Sandbox {
        Sandbox::select(
            core::SandboxRoot {
                path: dir.join("root"),
                origin: "test".into(),
            },
            name,
        )
    }

    /// A source repo with a.py, pkg/b.py and c.py.
    fn source_at(dir: &Path) -> PathBuf {
        let src = dir.join("src");
        fs::create_dir_all(src.join("pkg")).unwrap();
        fs::write(src.join("a.py"), b"a = 1\n").unwrap();
        fs::write(src.join("pkg").join("b.py"), b"b = 2\n").unwrap();
        fs::write(src.join("c.py"), b"c = 3\n").unwrap();
        src
    }

    fn run_op(
        sandbox: &Sandbox,
        op: &str,
        all: bool,
        paths: &[&str],
        stdin: &[u8],
    ) -> (Result<i32, Fail>, String) {
        let mut out = Vec::new();
        let mut input = Cursor::new(stdin.to_vec());
        let result = execute(sandbox, op, all, &args(paths), false, &mut input, &mut out);
        (result, String::from_utf8_lossy(&out).into_owned())
    }

    fn git_changed(work: &Path) -> Vec<String> {
        let output = Command::new("git")
            .arg("-C")
            .arg(work)
            .args(["diff", "--name-only", "HEAD"])
            .output()
            .unwrap();
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn parsing_matches_argparse() {
        assert_eq!(parse(&args(&["--help"])), Ok(Parsed::Help));
        assert_eq!(parse(&args(&["-h"])), Ok(Parsed::Help));
        assert_eq!(parse(&args(&["--version"])), Ok(Parsed::Version));
        assert_eq!(parse(&args(&["--skill"])), Ok(Parsed::Skill));
        assert_eq!(
            parse(&args(&[
                "--sandbox",
                "alt",
                "--create",
                "/repo",
                "a.py",
                "pkg"
            ])),
            Ok(Parsed::Run {
                name: "alt".into(),
                all: false,
                op: "create",
                paths: args(&["/repo", "a.py", "pkg"]),
            })
        );
        assert_eq!(
            parse(&args(&["--destroy", "--all"])),
            Ok(Parsed::Run {
                name: "work".into(),
                all: true,
                op: "destroy",
                paths: vec![],
            })
        );
        // Repeating the same operation is fine; two different ones are not.
        assert!(parse(&args(&["--list", "--list"])).is_ok());
        for (bad, needle) in [
            (
                vec!["--list", "--destroy"],
                "not allowed with argument --list",
            ),
            (vec![], "one of the arguments"),
            (vec!["a.py"], "one of the arguments"),
            (vec!["--sandbox"], "expected one argument"),
            (vec!["--frobnicate"], "unrecognized arguments: --frobnicate"),
        ] {
            let fail = parse(&args(&bad)).unwrap_err();
            assert_eq!(fail.code, 2, "{bad:?}");
            assert!(fail.text.starts_with("oxbox sandbox: error:"), "{bad:?}");
            assert!(fail.text.contains(needle), "{bad:?}: {}", fail.text);
        }
    }

    #[test]
    fn rooted_paths_are_recognized_in_every_spelling() {
        for bad in [
            "/etc/hosts",
            "\\server\\share",
            "~/x",
            "C:\\boot.ini",
            "c:x",
        ] {
            assert!(is_rooted(bad), "{bad}");
        }
        assert!(!is_rooted("a.py"));
        assert!(!is_rooted("pkg/b.py"));
        assert!(!is_rooted("..hidden"));
    }

    #[test]
    fn diagnoses_refusals_and_usage_errors_have_their_shapes() {
        assert_eq!(
            Fail::diag(3, "a\nb").text,
            "oxbox-sandbox: a\noxbox-sandbox: b\n"
        );
        assert_eq!(Fail::refuse("x").code, 78);
        let usage = Fail::usage("bad");
        assert_eq!(usage.code, 2);
        assert_eq!(usage.text, "oxbox sandbox: error: bad\n");
    }

    #[test]
    fn the_full_lifecycle_of_one_sandbox() {
        let dir = scratch("life");
        let src = source_at(&dir);
        let sandbox = sandbox_at(&dir, "work");

        let (result, _) = run_op(
            &sandbox,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py", "pkg"],
            b"",
        );
        assert_eq!(result, Ok(0));
        assert!(sandbox.work.join(".git").is_dir());
        assert_eq!(
            fs::read_to_string(&sandbox.source_record).unwrap().trim(),
            core::canonicalize_lenient(&src).to_string_lossy(),
            "the record holds the resolved source, without a Windows verbatim prefix"
        );

        let (result, out) = run_op(&sandbox, "list", false, &[], b"");
        assert_eq!(result, Ok(0));
        assert_eq!(out, "a.py\npkg/b.py\n");

        let (result, _) = run_op(&sandbox, "add", false, &["c.py"], b"");
        assert_eq!(result, Ok(0));
        assert!(git_changed(&sandbox.work).is_empty(), "add commits");

        let (result, out) = run_op(&sandbox, "read", false, &["c.py"], b"");
        assert_eq!(result, Ok(0));
        assert_eq!(out, "c = 3\n");

        let (result, _) = run_op(&sandbox, "write", false, &["c.py"], b"c = 4\r\n");
        assert_eq!(result, Ok(0));
        assert_eq!(fs::read(sandbox.work.join("c.py")).unwrap(), b"c = 4\r\n");
        assert_eq!(
            git_changed(&sandbox.work),
            vec!["c.py".to_string()],
            "write does not commit"
        );

        // A write can create a new file in a new directory.
        let (result, _) = run_op(&sandbox, "write", false, &["new/dir/d.py"], b"d = 5\n");
        assert_eq!(result, Ok(0));
        assert!(sandbox.work.join("new").join("dir").join("d.py").is_file());

        let (result, _) = run_op(&sandbox, "remove", false, &["pkg/b.py"], b"");
        assert_eq!(result, Ok(0));
        assert!(!sandbox.work.join("pkg").join("b.py").exists());
        assert_eq!(
            git_changed(&sandbox.work),
            vec!["c.py".to_string()],
            "remove commits only itself"
        );

        let (result, out) = run_op(&sandbox, "list", false, &[], b"");
        assert_eq!(result, Ok(0));
        assert_eq!(out, "a.py\nc.py\nnew/dir/d.py\n");

        let (result, out) = run_op(&sandbox, "status", false, &[], b"");
        assert_eq!(result, Ok(0));
        let lines: Vec<&str> = out.lines().collect();
        assert!(lines[0].starts_with("root "), "{out}");
        assert!(lines[0].ends_with("(from test)"), "{out}");
        assert!(lines[1].starts_with("work  3 files  modified  "), "{out}");

        // Re-creating wipes the tree, and a tracked directory can be removed.
        let (result, _) = run_op(
            &sandbox,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py", "pkg"],
            b"",
        );
        assert_eq!(result, Ok(0));
        let (_, out) = run_op(&sandbox, "list", false, &[], b"");
        assert_eq!(out, "a.py\npkg/b.py\n");
        let (result, _) = run_op(&sandbox, "remove", false, &["pkg"], b"");
        assert_eq!(result, Ok(0));
        let (_, out) = run_op(&sandbox, "list", false, &[], b"");
        assert_eq!(out, "a.py\n");

        let (result, _) = run_op(&sandbox, "destroy", false, &[], b"");
        assert_eq!(result, Ok(0));
        assert!(!sandbox.work.exists());
        assert!(!sandbox.root.exists(), "the empty root goes too");
        let (result, _) = run_op(&sandbox, "list", false, &[], b"");
        assert_eq!(result.unwrap_err().code, 3);
        let (result, out) = run_op(&sandbox, "status", false, &[], b"");
        assert_eq!(result, Ok(1));
        assert_eq!(out.lines().count(), 1);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn several_sandboxes_share_a_root_and_destroy_all_removes_it() {
        let dir = scratch("many");
        let src = source_at(&dir);
        let work = sandbox_at(&dir, "work");
        let alt = sandbox_at(&dir, "alt");
        run_op(
            &work,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py"],
            b"",
        )
        .0
        .unwrap();
        run_op(&alt, "create", false, &[src.to_str().unwrap(), "c.py"], b"")
            .0
            .unwrap();
        assert_eq!(
            work.sandboxes(),
            vec!["alt".to_string(), "work".to_string()]
        );
        // Dot directories are the root's bookkeeping, not sandboxes.
        assert!(work.root.join(".sources").is_dir());
        run_op(&alt, "destroy", false, &[], b"").0.unwrap();
        assert!(!alt.work.exists());
        assert!(work.work.exists(), "destroying one leaves the other");
        assert!(!alt.source_record.exists());
        run_op(&work, "destroy", true, &[], b"").0.unwrap();
        assert!(!work.root.exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn create_refuses_bad_paths_before_touching_anything() {
        let dir = scratch("refuse");
        let src = source_at(&dir);
        let sandbox = sandbox_at(&dir, "work");
        let repo = src.to_str().unwrap();
        for (bad, code, needle) in [
            ("../../etc/hosts", 78, "parent traversal"),
            ("/etc/hosts", 78, "absolute path"),
            ("C:/Windows/System32/drivers/etc/hosts", 78, "absolute path"),
            ("\\\\server\\share\\payload", 78, "absolute path"),
            ("..\\..\\payload", 78, "parent traversal"),
            ("missing.py", 3, "missing in source"),
        ] {
            let (result, _) = run_op(&sandbox, "create", false, &[repo, bad], b"");
            let fail = result.unwrap_err();
            assert_eq!(fail.code, code, "{bad}");
            assert!(fail.text.contains(needle), "{bad}: {}", fail.text);
            assert!(!sandbox.work.exists(), "{bad}: nothing was created");
        }
        let (result, _) = run_op(&sandbox, "create", false, &[repo], b"");
        assert_eq!(result.unwrap_err().code, 2);
        let (result, _) = run_op(&sandbox, "create", false, &[], b"");
        assert_eq!(result.unwrap_err().code, 2);
        let (result, _) = run_op(
            &sandbox,
            "create",
            false,
            &[dir.join("nope").to_str().unwrap(), "a.py"],
            b"",
        );
        assert_eq!(result.unwrap_err().code, 3);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn symlinks_in_the_source_are_refused_wherever_they_hide() {
        use std::os::unix::fs::symlink;
        let dir = scratch("links");
        let src = source_at(&dir);
        let secret = dir.join("secret");
        fs::create_dir_all(&secret).unwrap();
        fs::write(secret.join("key.txt"), b"k").unwrap();
        symlink(&secret, src.join("gate")).unwrap();
        symlink(secret.join("key.txt"), src.join("key.link")).unwrap();
        fs::create_dir_all(src.join("tree")).unwrap();
        symlink(&secret, src.join("tree").join("inner")).unwrap();
        let sandbox = sandbox_at(&dir, "work");
        let repo = src.to_str().unwrap();
        for bad in ["key.link", "gate/key.txt", "tree", "gate"] {
            let (result, _) = run_op(&sandbox, "create", false, &[repo, bad], b"");
            let fail = result.unwrap_err();
            assert_eq!(fail.code, 78, "{bad}: {}", fail.text);
            assert!(fail.text.contains("REFUSING"), "{bad}: {}", fail.text);
        }
        // A tree without links is fine.
        let (result, _) = run_op(&sandbox, "create", false, &[repo, "pkg"], b"");
        assert_eq!(result, Ok(0));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn working_tree_operations_refuse_the_same_paths() {
        let dir = scratch("tend-refuse");
        let src = source_at(&dir);
        let sandbox = sandbox_at(&dir, "work");
        run_op(
            &sandbox,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py"],
            b"",
        )
        .0
        .unwrap();
        for (op, path, code, needle) in [
            ("read", "../src/c.py", 78, "parent traversal"),
            ("read", "/etc/passwd", 78, "absolute path"),
            ("write", ".git/config", 78, "inside .git"),
            ("remove", "~/x", 78, "absolute path"),
            ("read", "nope.py", 3, "no such file"),
            ("remove", "nope.py", 3, "no such file"),
        ] {
            let (result, _) = run_op(&sandbox, op, false, &[path], b"x");
            let fail = result.unwrap_err();
            assert_eq!(fail.code, code, "{op} {path}: {}", fail.text);
            assert!(fail.text.contains(needle), "{op} {path}: {}", fail.text);
        }
        // Arity and terminal checks.
        assert_eq!(
            run_op(&sandbox, "read", false, &[], b"")
                .0
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "read", false, &["a.py", "b.py"], b"")
                .0
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "write", false, &[], b"")
                .0
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "add", false, &[], b"").0.unwrap_err().code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "remove", false, &[], b"")
                .0
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "list", false, &["a.py"], b"")
                .0
                .unwrap_err()
                .code,
            2
        );
        assert_eq!(
            run_op(&sandbox, "list", true, &[], b"").0.unwrap_err().code,
            2
        );
        let mut out = Vec::new();
        let mut input = Cursor::new(Vec::new());
        let fail = execute(
            &sandbox,
            "write",
            false,
            &args(&["a.py"]),
            true,
            &mut input,
            &mut out,
        )
        .unwrap_err();
        assert!(
            fail.text.contains("reads the content from stdin"),
            "{}",
            fail.text
        );
        // Reading a directory is redirected to --list; writing one is refused.
        fs::create_dir_all(sandbox.work.join("d")).unwrap();
        assert!(
            run_op(&sandbox, "read", false, &["d"], b"")
                .0
                .unwrap_err()
                .text
                .contains("--list")
        );
        assert!(
            run_op(&sandbox, "write", false, &["d"], b"x")
                .0
                .unwrap_err()
                .text
                .contains("is a directory")
        );
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlink_planted_in_the_tree_cannot_lead_a_write_out() {
        use std::os::unix::fs::symlink;
        let dir = scratch("planted");
        let src = source_at(&dir);
        let sandbox = sandbox_at(&dir, "work");
        run_op(
            &sandbox,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py"],
            b"",
        )
        .0
        .unwrap();
        let outside = dir.join("outside");
        fs::create_dir_all(&outside).unwrap();
        symlink(&outside, sandbox.work.join("escape")).unwrap();
        let (result, _) = run_op(&sandbox, "write", false, &["escape/pwned.txt"], b"x");
        let fail = result.unwrap_err();
        assert_eq!(fail.code, 78);
        assert!(
            fail.text.contains("resolving outside the sandbox"),
            "{}",
            fail.text
        );
        assert!(!outside.join("pwned.txt").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn add_needs_a_recorded_source_that_still_exists() {
        let dir = scratch("add-source");
        let src = source_at(&dir);
        let sandbox = sandbox_at(&dir, "work");
        run_op(
            &sandbox,
            "create",
            false,
            &[src.to_str().unwrap(), "a.py"],
            b"",
        )
        .0
        .unwrap();
        fs::remove_file(&sandbox.source_record).unwrap();
        let fail = run_op(&sandbox, "add", false, &["c.py"], b"")
            .0
            .unwrap_err();
        assert_eq!(fail.code, 3);
        assert!(fail.text.contains("no recorded source"), "{}", fail.text);
        fs::write(
            &sandbox.source_record,
            dir.join("gone").to_string_lossy().as_bytes(),
        )
        .unwrap();
        let fail = run_op(&sandbox, "add", false, &["c.py"], b"")
            .0
            .unwrap_err();
        assert_eq!(fail.code, 3);
        assert!(fail.text.contains("not a directory"), "{}", fail.text);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn operations_on_a_missing_sandbox_say_so() {
        let dir = scratch("missing");
        let sandbox = sandbox_at(&dir, "work");
        for (op, paths) in [
            ("add", vec!["a.py"]),
            ("remove", vec!["a.py"]),
            ("list", vec![]),
            ("read", vec!["a.py"]),
            ("write", vec!["a.py"]),
        ] {
            let (result, _) = run_op(&sandbox, op, false, &paths, b"x");
            let fail = result.unwrap_err();
            assert_eq!(fail.code, 3, "{op}");
            assert!(fail.text.contains("no sandbox here"), "{op}: {}", fail.text);
        }
        // Destroying what is not there is fine.
        assert_eq!(run_op(&sandbox, "destroy", false, &[], b"").0, Ok(0));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn rmtree_force_removes_read_only_files() {
        let dir = scratch("rmtree");
        let tree = dir.join("tree").join("nested");
        fs::create_dir_all(&tree).unwrap();
        let file = tree.join("ro.txt");
        fs::write(&file, b"x").unwrap();
        let mut perms = fs::metadata(&file).unwrap().permissions();
        perms.set_readonly(true);
        fs::set_permissions(&file, perms).unwrap();
        rmtree_force(&dir.join("tree")).unwrap();
        assert!(!dir.join("tree").exists());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn copies_keep_modification_times_and_files_within_skips_bookkeeping() {
        let dir = scratch("copy");
        let src = source_at(&dir);
        let dest = dir.join("dest");
        copy_tree(&src, &dest).unwrap();
        let before = fs::metadata(src.join("a.py")).unwrap().modified().unwrap();
        let after = fs::metadata(dest.join("a.py")).unwrap().modified().unwrap();
        assert_eq!(before, after);
        fs::create_dir_all(dest.join(".git")).unwrap();
        fs::write(dest.join(".git").join("HEAD"), b"ref").unwrap();
        fs::create_dir_all(dest.join(".oxtmp")).unwrap();
        fs::write(dest.join(".oxtmp").join("tmp"), b"t").unwrap();
        assert_eq!(files_within(&dest), vec!["a.py", "c.py", "pkg/b.py"]);
        assert!(files_within(&dir.join("absent")).is_empty());
        fs::remove_dir_all(&dir).unwrap();
    }
}
