// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! Build and tend a disposable sandbox tree: a copy of chosen files from a
//! real repo, made a git repo so patches can be applied and diffed without
//! ever touching the original.
//!
//! This is the executable `oxbox sandbox` runs. It lives in a libexec
//! directory rather than on PATH; oxbox finds it from its own location.
//! Standard library only.

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

fn say(message: &str) {
    core::diagnose(PROG, message);
}

fn refuse(message: &str) -> ! {
    say(message);
    process::exit(EX_CONFIG);
}

fn fail(code: i32, message: &str) -> ! {
    say(message);
    process::exit(code);
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

    fn git(&self, args: &[&str]) {
        let status = Command::new("git")
            .arg("-C")
            .arg(&self.work)
            .args(args)
            .status();
        match status {
            Ok(status) if status.success() => {}
            Ok(status) => fail(1, &format!("git {} failed: {status}", args.join(" "))),
            Err(error) => fail(1, &format!("cannot run git: {error}")),
        }
    }

    /// Record a baseline change: everything after --create, or only the named
    /// paths after --add and --remove, so an uncommitted --write (or the
    /// model's applied patch) elsewhere in the tree stays out of the baseline.
    fn commit(&self, message: &str, paths: &[String]) {
        if paths.is_empty() {
            self.git(&["add", "-A"]);
        } else {
            let mut args = vec!["add", "-A", "--"];
            args.extend(paths.iter().map(String::as_str));
            self.git(&args);
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
        ]);
    }

    fn require(&self) {
        if !self.work.join(".git").is_dir() {
            fail(
                3,
                "no sandbox here; create one with oxbox sandbox --create /path/to/repo file...",
            );
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
    fn work_path(&self, rel: &str, must_exist: bool) -> PathBuf {
        if is_rooted(rel) {
            refuse(&format!("REFUSING absolute path: {rel}"));
        }
        if core::has_parent_traversal(rel) {
            refuse(&format!("REFUSING parent traversal: {rel}"));
        }
        let first = rel.replace('\\', "/");
        if first.split('/').next() == Some(".git") {
            refuse(&format!("REFUSING a path inside .git: {rel}"));
        }
        let full = self.work.join(rel);
        if must_exist && fs::symlink_metadata(&full).is_err() {
            fail(3, &format!("no such file in the sandbox: {rel}"));
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
        let root = fs::canonicalize(&self.work).unwrap_or_else(|error| {
            refuse(&format!("REFUSING unresolvable path: {rel} ({error})"))
        });
        let resolved = fs::canonicalize(&probe).unwrap_or_else(|error| {
            refuse(&format!("REFUSING unresolvable path: {rel} ({error})"))
        });
        if !core::is_within(&root, &resolved) {
            refuse(&format!(
                "REFUSING path resolving outside the sandbox: {rel} -> {}",
                resolved.display()
            ));
        }
        full
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
fn rmtree_force(path: &Path) {
    if fs::remove_dir_all(path).is_ok() {
        return;
    }
    make_writable(path);
    if let Err(error) = fs::remove_dir_all(path) {
        fail(1, &format!("cannot remove {}: {error}", path.display()));
    }
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
fn validate(source: &Path, rel: &str) {
    if is_rooted(rel) {
        refuse(&format!("REFUSING absolute path: {rel}"));
    }
    if core::has_parent_traversal(rel) {
        refuse(&format!("REFUSING parent traversal: {rel}"));
    }
    let full = source.join(rel);
    let Ok(meta) = fs::symlink_metadata(&full) else {
        fail(3, &format!("missing in source: {rel}"));
    };
    // A copied symlink aimed at ~/.ssh or /etc would put a live handle to the
    // outside inside the work tree, for anything that touches it outside the
    // jail.
    if meta.file_type().is_symlink() {
        let target = fs::read_link(&full)
            .map(|t| t.to_string_lossy().into_owned())
            .unwrap_or_default();
        refuse(&format!("REFUSING symlink: {rel} -> {target}"));
    }
    // The named path is not the only place a link can hide. An intermediate
    // component does the same job: seeding "gate/creds.txt" where gate is a
    // link to /elsewhere passes every check above, because `full` is itself
    // neither a symlink nor a directory, and a copy reads straight through
    // it. Resolving the whole chain and requiring it to stay under the source
    // root is the check that closes that, and every variant like it.
    let root = fs::canonicalize(source)
        .unwrap_or_else(|error| refuse(&format!("REFUSING unresolvable path: {rel} ({error})")));
    let resolved = fs::canonicalize(&full)
        .unwrap_or_else(|error| refuse(&format!("REFUSING unresolvable path: {rel} ({error})")));
    if !core::is_within(&root, &resolved) {
        refuse(&format!(
            "REFUSING path resolving outside the source: {rel} -> {}",
            resolved.display()
        ));
    }
    if meta.is_dir() {
        // Directories matter as much as files: a symlinked directory inside a
        // tree would be dereferenced by the copy and its target's contents
        // copied into the sandbox.
        if let Some(name) = first_symlink_within(&full) {
            refuse(&format!("REFUSING {rel}: contains symlink {name}"));
        }
    }
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
fn copy_in(sandbox: &Sandbox, source: &Path, relatives: &[String]) {
    for rel in relatives {
        let destination = sandbox.work.join(rel);
        if let Some(parent) = destination.parent()
            && let Err(error) = fs::create_dir_all(parent)
        {
            fail(1, &format!("cannot create {}: {error}", parent.display()));
        }
        let origin = source.join(rel);
        let result = if origin.is_dir() {
            if destination.exists() {
                rmtree_force(&destination);
            }
            copy_tree(&origin, &destination)
        } else {
            copy_file(&origin, &destination)
        };
        if let Err(error) = result {
            fail(1, &format!("cannot copy {rel}: {error}"));
        }
        say(&format!("seeded {rel}"));
    }
}

/// Every file under a tree, skipping .git and .oxtmp, as sandbox-relative
/// POSIX paths.
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

fn op_create(sandbox: &Sandbox, paths: &[String]) -> i32 {
    let Some((repo, relatives)) = paths.split_first() else {
        say("--create needs the repo and at least one file");
        return 2;
    };
    if relatives.is_empty() {
        say("--create needs the repo and at least one file");
        return 2;
    }
    let Ok(source) = fs::canonicalize(repo) else {
        say(&format!("not a directory: {repo}"));
        return 3;
    };
    let source = core::canonicalize_lenient(&source);
    if !source.is_dir() {
        say(&format!("not a directory: {repo}"));
        return 3;
    }
    // Validate everything BEFORE destroying anything: refusing partway
    // through would still have wiped the existing sandbox on the way to
    // saying no.
    for rel in relatives {
        validate(&source, rel);
    }
    if sandbox.work.exists() {
        rmtree_force(&sandbox.work);
    }
    if let Err(error) = fs::create_dir_all(&sandbox.work) {
        fail(
            1,
            &format!("cannot create {}: {error}", sandbox.work.display()),
        );
    }
    if let Some(parent) = sandbox.source_record.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(error) = fs::write(&sandbox.source_record, format!("{}\n", source.display())) {
        fail(1, &format!("cannot record the source: {error}"));
    }
    copy_in(sandbox, &source, relatives);
    sandbox.git(&["init", "-q"]);
    sandbox.commit(&format!("pristine seed from {}", source.display()), &[]);
    say(&format!(
        "work={} (pristine commit recorded)",
        sandbox.work.display()
    ));
    say(&format!("source untouched: {}", source.display()));
    0
}

fn op_add(sandbox: &Sandbox, relatives: &[String]) -> i32 {
    sandbox.require();
    if relatives.is_empty() {
        say("--add needs at least one file");
        return 2;
    }
    let Ok(recorded) = fs::read_to_string(&sandbox.source_record) else {
        say("no recorded source; this sandbox predates --add, so --create it again");
        return 3;
    };
    let source = PathBuf::from(recorded.trim());
    if !source.is_dir() {
        say(&format!(
            "recorded source is not a directory: {}",
            source.display()
        ));
        return 3;
    }
    for rel in relatives {
        validate(&source, rel);
    }
    copy_in(sandbox, &source, relatives);
    sandbox.commit(&format!("seed {}", relatives.join(" ")), relatives);
    say(&format!(
        "added from {} (baseline commit recorded)",
        source.display()
    ));
    0
}

fn op_remove(sandbox: &Sandbox, relatives: &[String]) -> i32 {
    sandbox.require();
    if relatives.is_empty() {
        say("--remove needs at least one file");
        return 2;
    }
    let targets: Vec<PathBuf> = relatives
        .iter()
        .map(|rel| sandbox.work_path(rel, true))
        .collect();
    for (rel, full) in relatives.iter().zip(&targets) {
        let result = if full.is_dir() {
            rmtree_force(full);
            Ok(())
        } else {
            fs::remove_file(full)
        };
        if let Err(error) = result {
            fail(1, &format!("cannot remove {rel}: {error}"));
        }
        say(&format!("removed {rel}"));
    }
    sandbox.commit(&format!("remove {}", relatives.join(" ")), relatives);
    say("baseline commit recorded");
    0
}

fn op_destroy(sandbox: &Sandbox, everything: bool) -> i32 {
    if everything {
        if sandbox.root.exists() {
            rmtree_force(&sandbox.root);
        }
        say(&format!(
            "removed {} and every sandbox in it",
            sandbox.root.display()
        ));
        return 0;
    }
    if sandbox.work.exists() {
        rmtree_force(&sandbox.work);
    }
    if sandbox.source_record.exists() {
        let _ = fs::remove_file(&sandbox.source_record);
    }
    say(&format!("removed {}", sandbox.work.display()));
    // Leave no empty root behind, so the single-sandbox case ends the way it
    // always did: ./sandbox is gone.
    if sandbox.root.exists() && sandbox.sandboxes().is_empty() {
        rmtree_force(&sandbox.root);
    }
    0
}

fn op_status(sandbox: &Sandbox) -> i32 {
    println!(
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
        println!("{name}  {count} files  {state}  {source}");
    }
    if names.is_empty() { 1 } else { 0 }
}

fn op_list(sandbox: &Sandbox) -> i32 {
    sandbox.require();
    let found = files_within(&sandbox.work);
    for rel in &found {
        println!("{rel}");
    }
    if found.is_empty() { 1 } else { 0 }
}

fn op_read(sandbox: &Sandbox, relatives: &[String]) -> i32 {
    sandbox.require();
    let [rel] = relatives else {
        say("--read takes exactly one file");
        return 2;
    };
    let full = sandbox.work_path(rel, true);
    if full.is_dir() {
        say(&format!("{rel} is a directory; --list shows it"));
        return 2;
    }
    // Bytes through, unchanged: no re-encoding and no line-ending rewrite.
    let data = match fs::read(&full) {
        Ok(data) => data,
        Err(error) => fail(1, &format!("cannot read {rel}: {error}")),
    };
    let mut out = io::stdout().lock();
    if out.write_all(&data).is_err() || out.flush().is_err() {
        return 1;
    }
    0
}

fn op_write(sandbox: &Sandbox, relatives: &[String]) -> i32 {
    sandbox.require();
    let [rel] = relatives else {
        say("--write takes exactly one file");
        return 2;
    };
    if io::stdin().is_terminal() {
        say("--write reads the content from stdin; redirect or pipe it in");
        return 2;
    }
    let full = sandbox.work_path(rel, false);
    if full.is_dir() {
        say(&format!("{rel} is a directory"));
        return 2;
    }
    let mut data = Vec::new();
    if let Err(error) = io::stdin().lock().read_to_end(&mut data) {
        fail(1, &format!("cannot read stdin: {error}"));
    }
    if let Some(parent) = full.parent() {
        let _ = fs::create_dir_all(parent);
    }
    if let Err(error) = fs::write(&full, &data) {
        fail(1, &format!("cannot write {rel}: {error}"));
    }
    say(&format!(
        "wrote {} bytes to {rel} (not committed; git diff HEAD shows it)",
        data.len()
    ));
    0
}

const OPERATIONS: [&str; 8] = [
    "create", "add", "remove", "destroy", "list", "read", "write", "status",
];

fn usage_error(message: &str) -> i32 {
    eprintln!("oxbox sandbox: error: {message}");
    2
}

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    let mut name = String::from("work");
    let mut all = false;
    let mut op: Option<&str> = None;
    let mut paths: Vec<String> = Vec::new();

    let mut index = 0;
    while index < args.len() {
        let arg = args[index].as_str();
        match arg {
            "--help" | "-h" => {
                print!("{USAGE}");
                return 0;
            }
            "--version" => {
                println!("{PROG} {}", core::VERSION);
                return 0;
            }
            "--skill" => return core::print_skill(PROG),
            "--sandbox" => {
                let Some(value) = args.get(index + 1) else {
                    return usage_error("argument --sandbox: expected one argument");
                };
                name = value.clone();
                index += 2;
                continue;
            }
            "--all" => all = true,
            _ if arg.starts_with("--") => {
                let word = &arg[2..];
                let Some(found) = OPERATIONS.iter().find(|&&candidate| candidate == word) else {
                    return usage_error(&format!("unrecognized arguments: {arg}"));
                };
                if let Some(previous) = op
                    && previous != *found
                {
                    return usage_error(&format!(
                        "argument --{found}: not allowed with argument --{previous}"
                    ));
                }
                op = Some(found);
            }
            _ => paths.push(arg.to_string()),
        }
        index += 1;
    }

    let Some(op) = op else {
        return usage_error(&format!(
            "one of the arguments {} is required",
            OPERATIONS
                .iter()
                .map(|word| format!("--{word}"))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    };

    let root = match core::sandbox_root() {
        Ok(root) => root,
        Err(message) => fail(1, &message),
    };
    let name = match core::sandbox_name(&name) {
        Ok(name) => name,
        Err(message) => {
            say(&message);
            return 2;
        }
    };
    let sandbox = Sandbox::select(root, &name);

    if all && op != "destroy" {
        say("--all goes with --destroy only");
        return 2;
    }
    match op {
        "create" => op_create(&sandbox, &paths),
        "add" => op_add(&sandbox, &paths),
        "remove" => op_remove(&sandbox, &paths),
        "read" => op_read(&sandbox, &paths),
        "write" => op_write(&sandbox, &paths),
        _ if !paths.is_empty() => {
            say(&format!("--{op} takes no paths"));
            2
        }
        "destroy" => op_destroy(&sandbox, all),
        "status" => op_status(&sandbox),
        _ => op_list(&sandbox),
    }
}
