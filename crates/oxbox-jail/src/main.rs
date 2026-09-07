// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! Run a command inside a jail: no network, no writes outside the work dir.
//!
//! Backends:
//!   macOS   sandbox-exec (seatbelt) with profiles/jail.sb
//!   Linux   bubblewrap, everything read-only except the work dir
//!   else    refuse
//!
//! Refusing is the point. A harness that appears to sandbox but doesn't is
//! worse than none, because you would trust it. There is no "best effort"
//! mode.
//!
//! This is the executable `oxbox jail` runs (and the bare `oxbox -- cmd`). It
//! lives in a libexec directory rather than on PATH; oxbox finds it from its
//! own location. Standard library only: this is the execution boundary, and
//! it should be readable in full with nothing to audit beneath it.
//!
//! The work splits into `parse` (the command line), `plan` (every check and
//! the argument vector and environment the backend gets) and `main`, which
//! is the only place that prints, exits or execs. Tests drive the first two.

use std::env;
use std::path::{Path, PathBuf};
use std::process;

use oxbox_core as core;

const PROG: &str = "oxbox-jail";

const USAGE: &str = "\
usage: oxbox jail [--sandbox NAME | --work DIR] [--allow-external-output] -- command args...
       oxbox      [--sandbox NAME | --work DIR] [--allow-external-output] -- command args...

Run a command in a jail with no network and no writes outside the work dir.

  --sandbox NAME            the sandbox to run in: <root>/NAME (default: work)
  --work DIR                the directory the command may write to instead;
                            must be inside the sandbox root
  --allow-external-output   permit stdout/stderr already redirected outside
                            the sandbox; refused by default, because an
                            inherited descriptor writes straight past the jail
  --skill                   print the ox-review agent skill and exit
  --version                 print the version and exit
  --help                    print this and exit

The sandbox root is OXBOX_SANDBOX_ROOT, else `root` under [sandbox] in
~/.config/oxbox/config.ini, else ./sandbox.

exit status: the command's own; 2 for a usage error; 78 when the jail refuses
(no backend on this platform, or a work dir or output file outside the
sandbox root).
";

const WINDOWS_HELP: &str = "\
oxbox: no supported sandbox on this platform.

Windows has no unprivileged sandbox reachable from a stdlib script that can
restrict both the filesystem and the network. Job Objects cap CPU and memory
but not file or network access; AppContainer needs Win32 API work plus fragile
ACLs. Windows Sandbox is a real boundary, but it needs Pro/Enterprise, cannot
run without a writable share back to the host, and will not start at all from a
non-interactive session -- so it reaches fewer machines than WSL2 does and
guards less once it gets there. AGENTS.md records the full evaluation, measured
on real hardware, under \"Rejected alternatives\".

Running model-generated code unsandboxed is exactly what this tool exists to
prevent, so oxbox refuses rather than pretending.

Use WSL2, where the Linux backend works unchanged. It runs on every Windows
edition, Home included -- it needs only the Virtual Machine Platform feature,
not the full Hyper-V that Windows Sandbox requires:

    wsl --install -d Ubuntu
    wsl
    sudo apt install bubblewrap
    oxbox jail -- python3 jailtest.py

Better, give it a distro of its own, so an escape from the jail lands somewhere
holding nothing of yours:

    wsl --export Ubuntu \"$env:TEMP\\rootfs.tar\"
    wsl --import oxbox \"$env:LOCALAPPDATA\\WSL\\oxbox\" \"$env:TEMP\\rootfs.tar\"

Then, inside it, cut the two routes back to Windows in /etc/wsl.conf --
[automount] enabled=false and [interop] enabled=false -- and keep the checkout
on ext4 rather than under /mnt/c, so the work dir never becomes a Windows
share. The README carries the full recipe and what it does and does not buy.

The rest of the toolkit runs natively on Windows: oxbox send (talk to the
model), oxbox sandbox (build a disposable copy), and oxbox patch (quarantined patch
application). Only executing the model's output needs the jail.
";

/// The jail refuses with this, the way `sysexits.h` spells "configuration".
const EX_CONFIG: i32 = 78;

/// How a run ends other than by launching: the text for stderr, already
/// prefixed line by line, and the exit code.
#[derive(Debug, PartialEq)]
struct Fail {
    code: i32,
    text: String,
}

impl Fail {
    fn diag(code: i32, message: &str) -> Fail {
        let text = message
            .lines()
            .map(|line| format!("{PROG}: {line}\n"))
            .collect();
        Fail { code, text }
    }
}

/// What a command line asks for.
#[derive(Debug, PartialEq)]
enum Request {
    Help,
    Version,
    Skill,
    Launch {
        work: PathBuf,
        allow_external: bool,
        command: Vec<String>,
    },
}

fn parse(args: &[String], root: &core::SandboxRoot) -> Result<Request, Fail> {
    let mut work = root.path.join("work");
    let mut allow_external = false;
    let mut rest = args;
    while let Some(head) = rest.first() {
        // `--work=DIR` and `--sandbox=NAME` as well as the two-word forms,
        // so the four tools take flags the same way.
        let (flag, inline) = match head.split_once('=') {
            Some((flag, value)) if matches!(flag, "--work" | "--sandbox") => (flag, Some(value)),
            _ => (head.as_str(), None),
        };
        // The flag's value and how many words it took.
        let take = |missing: &str| -> Result<(String, usize), Fail> {
            match inline {
                Some(value) => Ok((value.to_string(), 1)),
                None => rest
                    .get(1)
                    .map(|value| (value.clone(), 2))
                    .ok_or_else(|| Fail::diag(2, missing)),
            }
        };
        match flag {
            "--help" | "-h" => return Ok(Request::Help),
            "--version" => return Ok(Request::Version),
            "--skill" => return Ok(Request::Skill),
            "--work" => {
                let (dir, taken) = take("--work needs a directory")?;
                work = PathBuf::from(dir);
                rest = &rest[taken..];
            }
            "--sandbox" => {
                let (name, taken) = take("--sandbox needs a name")?;
                let name = core::sandbox_name(&name).map_err(|message| Fail::diag(2, &message))?;
                work = root.path.join(name);
                rest = &rest[taken..];
            }
            "--allow-external-output" => {
                allow_external = true;
                rest = &rest[1..];
            }
            "--" => {
                rest = &rest[1..];
                break;
            }
            other => {
                return Err(Fail::diag(
                    2,
                    &format!(
                        "unexpected argument {other}; the command goes after --  (see oxbox jail --help)"
                    ),
                ));
            }
        }
    }
    if rest.is_empty() {
        return Err(Fail {
            code: 2,
            text: format!("{PROG}: no command given (use: oxbox jail -- pytest -q)\n{USAGE}"),
        });
    }
    Ok(Request::Launch {
        work,
        allow_external,
        command: rest.to_vec(),
    })
}

#[cfg(unix)]
/// The seatbelt profile, wherever this oxbox is installed.
///
/// A source checkout carries it at `profiles/jail.sb` beside the tools; a
/// package installs this executable into `<prefix>/libexec/bin` (the .deb:
/// `<prefix>/libexec/oxbox/bin`) and the profile into
/// `<prefix>/share/oxbox/jail.sb`; a build tree keeps it two levels above
/// `target/debug`. Refusing when none exists is deliberate: there is no jail
/// without the profile, and no jail means no run.
fn find_profile() -> Result<PathBuf, Fail> {
    let mut candidates = Vec::new();
    for start in [core::exe_dir(), core::real_exe_dir()] {
        let mut base = Some(start);
        for _ in 0..4 {
            let Some(dir) = base else { break };
            for candidate in [
                dir.join("profiles").join("jail.sb"),
                dir.join("share").join("oxbox").join("jail.sb"),
            ] {
                if !candidates.contains(&candidate) {
                    candidates.push(candidate);
                }
            }
            base = dir.parent().map(Path::to_path_buf);
        }
    }
    for candidate in &candidates {
        if candidate.is_file() {
            return Ok(candidate.clone());
        }
    }
    let mut message = String::from("seatbelt profile jail.sb not found; looked in:\n");
    for candidate in candidates {
        message.push_str(&format!("  {}\n", candidate.display()));
    }
    Err(Fail::diag(1, message.trim_end()))
}

#[cfg(unix)]
/// Paths jailtest should try to read, per platform. Existence is decided
/// HERE, outside the jail: inside, `stat()` is denied, so every hidden path
/// looks absent and a probe that checks for itself would skip rather than
/// test.
fn sensitive_paths(real_home: &Path, project_root: &Path) -> Vec<PathBuf> {
    let mut names = vec![
        ".ssh",
        ".aws",
        ".gnupg",
        ".config/gh",
        ".netrc",
        ".git-credentials",
    ];
    if cfg!(target_os = "macos") {
        names.extend([".zsh_history", ".claude", "Library/Keychains"]);
    } else {
        names.extend([
            ".bash_history",
            ".claude",
            ".kube/config",
            ".docker/config.json",
        ]);
    }
    let mut paths: Vec<PathBuf> = names.iter().map(|name| real_home.join(name)).collect();
    paths.push(project_root.join(".env"));
    if !cfg!(target_os = "macos") {
        paths.push(PathBuf::from("/etc/shadow"));
    }
    paths
}

#[cfg(unix)]
/// Whether this host can route to the internet at all, decided outside the
/// jail like the sensitive-path list is. Inside the jail a blocked connect
/// and an offline host fail the same way -- bubblewrap's `--unshare-net`
/// gives ENETUNREACH, exactly what a laptop with Wi-Fi off gives -- so on
/// such a host jailtest's network probes would pass without testing
/// anything. A UDP connect sends no packet; it only asks the kernel whether
/// a route exists.
fn host_has_route() -> bool {
    std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|socket| socket.connect("1.1.1.1:53"))
        .is_ok()
}

/// Absolute path a descriptor points at, or None if it is not a regular file.
///
/// Pipes, ttys and /dev/null cannot be steered to a location of anyone's
/// choosing, so they are not escapes.
#[cfg(unix)]
fn descriptor_target(fd: i32) -> Option<PathBuf> {
    use std::mem::ManuallyDrop;
    use std::os::fd::FromRawFd;

    // Borrow the descriptor for a metadata call without ever closing it.
    let file = ManuallyDrop::new(unsafe { std::fs::File::from_raw_fd(fd) });
    let info = file.metadata().ok()?;
    if !info.file_type().is_file() {
        return None;
    }
    let path = descriptor_path(fd)?;
    Some(core::canonicalize_lenient(&path))
}

#[cfg(target_os = "linux")]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    std::fs::read_link(format!("/proc/self/fd/{fd}")).ok()
}

#[cfg(target_os = "macos")]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    use std::ffi::{CStr, c_char, c_int};
    use std::os::unix::ffi::OsStrExt;

    // fcntl(F_GETPATH) resolves a descriptor back to its path. Declared here
    // rather than through a crate: it is one libSystem call, and this
    // executable stays standard-library only on purpose.
    const F_GETPATH: c_int = 50;
    const MAXPATHLEN: usize = 1024;
    unsafe extern "C" {
        fn fcntl(fd: c_int, cmd: c_int, ...) -> c_int;
    }
    let mut buffer = [0 as c_char; MAXPATHLEN];
    let result = unsafe { fcntl(fd, F_GETPATH, buffer.as_mut_ptr()) };
    if result == -1 {
        return None;
    }
    let text = unsafe { CStr::from_ptr(buffer.as_ptr()) };
    if text.to_bytes().is_empty() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(text.to_bytes())))
}

#[cfg(all(unix, not(target_os = "linux"), not(target_os = "macos")))]
fn descriptor_path(_fd: i32) -> Option<PathBuf> {
    None
}

/// Where stdout and stderr point, if at regular files.
#[cfg(unix)]
fn probe_descriptors() -> Vec<(&'static str, Option<PathBuf>)> {
    vec![
        ("stdout", descriptor_target(1)),
        ("stderr", descriptor_target(2)),
    ]
}

#[cfg(unix)]
/// The named descriptors that point at regular files outside the sandbox
/// root.
///
/// Neither backend can help here: the shell opened those files before the
/// jail existed, so the descriptor is already live. `oxbox -- cmd > ~/notes.md`
/// would let jailed code write whatever it likes there.
fn escaping_descriptors(root: &Path, descriptors: &[(&str, Option<PathBuf>)]) -> Vec<String> {
    descriptors
        .iter()
        .filter_map(|(name, target)| {
            target.as_ref().and_then(|target| {
                (!core::is_within(root, target)).then(|| format!("{name} -> {}", target.display()))
            })
        })
        .collect()
}

#[cfg(unix)]
/// The environment the jailed command sees: a fresh one, not the caller's.
/// The parent shell routinely holds OPENROUTER_API_KEY (via `op run`), and
/// inheriting it would hand jailed code the key.
fn jail_env(
    work: &Path,
    real_home: &Path,
    project_root: &Path,
    existing: &[String],
    has_route: bool,
) -> Vec<(String, String)> {
    vec![
        ("HOME".into(), work.to_string_lossy().into_owned()),
        ("REAL_HOME".into(), real_home.to_string_lossy().into_owned()),
        (
            "REPO_ROOT".into(),
            project_root.to_string_lossy().into_owned(),
        ),
        ("OXBOX_EXISTING_PATHS".into(), existing.join("\n")),
        (
            "OXBOX_HOST_HAS_ROUTE".into(),
            if has_route { "1" } else { "0" }.into(),
        ),
        ("OXBOX_PLATFORM".into(), core::PLATFORM.into()),
        (
            "TMPDIR".into(),
            work.join(".oxtmp").to_string_lossy().into_owned(),
        ),
        (
            "PATH".into(),
            "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin".into(),
        ),
        (
            "TERM".into(),
            env::var("TERM").unwrap_or_else(|_| "dumb".into()),
        ),
        (
            "LANG".into(),
            env::var("LANG").unwrap_or_else(|_| "en_US.UTF-8".into()),
        ),
        ("PYTHONDONTWRITEBYTECODE".into(), "1".into()),
    ]
}

#[cfg(unix)]
/// `sandbox-exec -f <profile> -D WORK=<work> <command...>`.
fn macos_argv(profile: &Path, work: &Path, command: &[String]) -> Vec<String> {
    let mut argv = vec![
        String::from("/usr/bin/sandbox-exec"),
        String::from("-f"),
        profile.to_string_lossy().into_owned(),
        String::from("-D"),
        format!("WORK={}", work.display()),
    ];
    argv.extend(command.iter().cloned());
    argv
}

#[cfg(unix)]
/// The bubblewrap invocation: every namespace unshared, the system bound
/// read-only, the work dir bound writable, the environment cleared and
/// rebuilt from `env` inside.
fn linux_argv(
    bwrap: &Path,
    work: &Path,
    command: &[String],
    env: &[(String, String)],
) -> Vec<String> {
    let mut argv: Vec<String> = vec![
        bwrap.to_string_lossy().into_owned(),
        // Namespaces: --unshare-all includes the network, which is the
        // guarantee that matters most. Nothing is bound in unless named
        // below, so the user's home simply does not exist inside.
        "--unshare-all".into(),
        "--die-with-parent".into(),
        // Blocks TIOCSTI-style injection back into the controlling terminal.
        "--new-session".into(),
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
        "--tmpfs".into(),
        "/tmp".into(),
    ];
    // /bin, /lib, /sbin are symlinks into /usr on merged-usr distributions;
    // binding a symlink's path would fail, so reproduce the link instead.
    for path in [
        "/usr",
        "/bin",
        "/lib",
        "/lib32",
        "/lib64",
        "/sbin",
        "/etc",
        "/opt",
        "/usr/local",
    ] {
        let Ok(meta) = std::fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            if let Ok(target) = std::fs::read_link(path) {
                argv.extend([
                    "--symlink".into(),
                    target.to_string_lossy().into_owned(),
                    path.into(),
                ]);
            }
        } else {
            argv.extend(["--ro-bind".into(), path.into(), path.into()]);
        }
    }
    let work_text = work.to_string_lossy().into_owned();
    argv.extend([
        "--bind".into(),
        work_text.clone(),
        work_text.clone(),
        "--chdir".into(),
        work_text,
        "--clearenv".into(),
    ]);
    // bwrap --clearenv wipes what execve passes, so set it inside instead.
    for (key, value) in env {
        argv.extend(["--setenv".into(), key.clone(), value.clone()]);
    }
    argv.extend(command.iter().cloned());
    argv
}

#[cfg(unix)]
/// Everything decided before the backend starts.
#[derive(Debug)]
struct Plan {
    work: PathBuf,
    backend: &'static str,
    argv: Vec<String>,
    env: Vec<(String, String)>,
    /// Lines for stderr that are not refusals (an allowed external output).
    warnings: Vec<String>,
}

#[cfg(unix)]
/// Every check, then the argument vector and environment. `descriptors` is
/// where stdout and stderr point, passed in so the check can be exercised
/// without redirecting the test runner's own streams.
fn plan(
    root: &core::SandboxRoot,
    work: &Path,
    allow_external: bool,
    command: &[String],
    descriptors: &[(&str, Option<PathBuf>)],
) -> Result<Plan, Fail> {
    if !work.is_dir() {
        return Err(Fail::diag(
            1,
            &format!("work dir does not exist: {}", work.display()),
        ));
    }
    let work = core::canonicalize_lenient(work);

    // The backend grants write access to whatever --work names, so a work
    // dir outside the sandbox is not a jail at all.
    if !core::is_within(&root.path, &work) {
        return Err(Fail::diag(
            EX_CONFIG,
            &format!(
                "REFUSING --work {}\n\
                 the backend grants write access to whatever --work names, so a\n\
                 work dir outside {} is not a jail at all.\n\
                 (the sandbox root comes from {})",
                work.display(),
                root.path.display(),
                root.origin
            ),
        ));
    }

    let escaping = escaping_descriptors(&root.path, descriptors);
    let mut warnings = Vec::new();
    if !escaping.is_empty() && !allow_external {
        let mut message = String::from("REFUSING - output is redirected outside the sandbox:\n");
        for item in &escaping {
            message.push_str(&format!("  {item}\n"));
        }
        message.push_str(&format!(
            "the shell opened that file before the jail existed, so jailed\n\
             code can write whatever it likes through the inherited handle.\n\
             redirect inside {}, or pass --allow-external-output.",
            work.display()
        ));
        return Err(Fail::diag(EX_CONFIG, &message));
    }
    if !escaping.is_empty() {
        warnings.push("WARNING - output redirected outside the sandbox (allowed):".into());
        for item in &escaping {
            warnings.push(format!("  {item}"));
        }
    }

    let Some(real_home) = core::home_dir() else {
        return Err(Fail::diag(
            1,
            "cannot determine the home directory (HOME is unset and the account \
             database has none); the jail needs to know it to hide it",
        ));
    };
    let project_root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let tmpdir = work.join(".oxtmp");
    std::fs::create_dir_all(&tmpdir)
        .map_err(|error| Fail::diag(1, &format!("cannot create {}: {error}", tmpdir.display())))?;

    let existing: Vec<String> = sensitive_paths(&real_home, &project_root)
        .into_iter()
        .filter(|path| std::fs::symlink_metadata(path).is_ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();
    let env = jail_env(
        &work,
        &real_home,
        &project_root,
        &existing,
        host_has_route(),
    );

    let (argv, backend) = if cfg!(target_os = "macos") {
        if !Path::new("/usr/bin/sandbox-exec").exists() {
            return Err(Fail::diag(
                1,
                "/usr/bin/sandbox-exec not found; cannot jail on this macOS",
            ));
        }
        (macos_argv(&find_profile()?, &work, command), "seatbelt")
    } else {
        let Some(bwrap) = core::which("bwrap") else {
            return Err(Fail::diag(
                1,
                "bubblewrap (bwrap) not found.\n\
                 it is the sandbox on Linux; without it there is no jail.\n\
                   Debian/Ubuntu  sudo apt install bubblewrap\n\
                   Fedora/RHEL    sudo dnf install bubblewrap\n\
                   Arch           sudo pacman -S bubblewrap\n\
                   Alpine         sudo apk add bubblewrap",
            ));
        };
        (linux_argv(&bwrap, &work, command, &env), "bubblewrap")
    };

    Ok(Plan {
        work,
        backend,
        argv,
        env,
        warnings,
    })
}

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    process::exit(run(&args));
}

fn run(args: &[String]) -> i32 {
    let root = match core::sandbox_root() {
        Ok(root) => root,
        Err(message) => {
            eprint!("{}", Fail::diag(1, &message).text);
            return 1;
        }
    };
    let request = match parse(args, &root) {
        Ok(request) => request,
        Err(fail) => {
            eprint!("{}", fail.text);
            return fail.code;
        }
    };
    let (work, allow_external, command) = match request {
        Request::Help => {
            print!("{USAGE}");
            return 0;
        }
        Request::Version => {
            println!("{PROG} {}", core::VERSION);
            return 0;
        }
        Request::Skill => return core::print_skill(PROG),
        Request::Launch {
            work,
            allow_external,
            command,
        } => (work, allow_external, command),
    };

    if cfg!(windows) || !cfg!(any(target_os = "macos", target_os = "linux")) {
        if cfg!(windows) {
            eprint!("{WINDOWS_HELP}");
        } else {
            eprint!(
                "{}",
                Fail::diag(
                    1,
                    &format!(
                        "no sandbox backend for platform {:?}; refusing",
                        core::PLATFORM
                    )
                )
                .text
            );
        }
        return EX_CONFIG;
    }

    launch(&root, &work, allow_external, &command)
}

#[cfg(unix)]
fn launch(root: &core::SandboxRoot, work: &Path, allow_external: bool, command: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    let planned = match plan(root, work, allow_external, command, &probe_descriptors()) {
        Ok(planned) => planned,
        Err(fail) => {
            eprint!("{}", fail.text);
            return fail.code;
        }
    };
    for line in &planned.warnings {
        eprintln!("{PROG}: {line}");
    }
    eprintln!(
        "{PROG}: backend={} work={}",
        planned.backend,
        planned.work.display()
    );
    eprintln!(
        "{PROG}: network=DENIED writes={} only",
        planned.work.display()
    );
    eprintln!("{PROG}: env=CLEARED (nothing from the parent shell crosses in)");

    let mut child = process::Command::new(&planned.argv[0]);
    child
        .args(&planned.argv[1..])
        .current_dir(&planned.work)
        .env_clear();
    for (key, value) in &planned.env {
        child.env(key, value);
    }
    let error = child.exec();
    eprint!(
        "{}",
        Fail::diag(1, &format!("failed to start {}: {error}", planned.argv[0])).text
    );
    1
}

#[cfg(not(unix))]
fn launch(
    _root: &core::SandboxRoot,
    _work: &Path,
    _allow_external: bool,
    _command: &[String],
) -> i32 {
    eprint!("{WINDOWS_HELP}");
    EX_CONFIG
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("oxbox-jail-{name}-{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn root_at(dir: &Path) -> core::SandboxRoot {
        core::SandboxRoot {
            path: core::canonicalize_lenient(dir),
            origin: "test".into(),
        }
    }

    #[test]
    fn parsing_the_command_line() {
        let dir = scratch("parse");
        let root = root_at(&dir);
        assert_eq!(parse(&args(&["--help"]), &root), Ok(Request::Help));
        assert_eq!(parse(&args(&["-h"]), &root), Ok(Request::Help));
        assert_eq!(parse(&args(&["--version"]), &root), Ok(Request::Version));
        assert_eq!(parse(&args(&["--skill"]), &root), Ok(Request::Skill));
        assert_eq!(
            parse(&args(&["--", "pytest", "-q"]), &root),
            Ok(Request::Launch {
                work: root.path.join("work"),
                allow_external: false,
                command: args(&["pytest", "-q"]),
            })
        );
        assert_eq!(
            parse(
                &args(&["--sandbox", "alt", "--allow-external-output", "--", "true"]),
                &root
            ),
            Ok(Request::Launch {
                work: root.path.join("alt"),
                allow_external: true,
                command: args(&["true"]),
            })
        );
        assert_eq!(
            parse(&args(&["--work", "/elsewhere", "--", "true"]), &root),
            Ok(Request::Launch {
                work: PathBuf::from("/elsewhere"),
                allow_external: false,
                command: args(&["true"]),
            })
        );
        assert_eq!(
            parse(
                &args(&["--sandbox=alt", "--work=/elsewhere", "--", "true"]),
                &root
            ),
            Ok(Request::Launch {
                work: PathBuf::from("/elsewhere"),
                allow_external: false,
                command: args(&["true"]),
            })
        );
        // Flags after -- belong to the command.
        assert_eq!(
            parse(&args(&["--", "--help"]), &root),
            Ok(Request::Launch {
                work: root.path.join("work"),
                allow_external: false,
                command: args(&["--help"]),
            })
        );
        for (bad, needle) in [
            (vec!["--work"], "--work needs a directory"),
            (vec!["--sandbox"], "--sandbox needs a name"),
            (vec!["--sandbox=", "--", "true"], "not a sandbox name"),
            (
                vec!["--sandbox", "../x", "--", "true"],
                "not a sandbox name",
            ),
            (vec!["--nope", "--", "true"], "unexpected argument --nope"),
            (vec!["pytest"], "unexpected argument pytest"),
            (vec![], "no command given"),
            (vec!["--"], "no command given"),
        ] {
            let fail = parse(&args(&bad), &root).unwrap_err();
            assert_eq!(fail.code, 2, "{bad:?}");
            assert!(fail.text.contains(needle), "{bad:?}: {}", fail.text);
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_profile_is_found_from_a_build_tree() {
        // Under `cargo test` the binary sits three levels below the checkout,
        // within the lookup's walk; a coverage build nests it one deeper.
        let checkout = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .and_then(Path::parent)
            .unwrap();
        if !core::exe_dir()
            .ancestors()
            .take(4)
            .any(|dir| dir == checkout)
        {
            eprintln!("skipped: the build tree is deeper than the lookup walks");
            return;
        }
        let profile = find_profile().unwrap();
        assert!(
            profile.ends_with(Path::new("profiles").join("jail.sb")),
            "{profile:?}"
        );
        assert!(profile.is_file());
    }

    #[cfg(unix)]
    #[test]
    fn the_sensitive_list_matches_the_platform_and_ends_with_the_projects_env() {
        let home = Path::new("/h");
        let project = Path::new("/p");
        let paths = sensitive_paths(home, project);
        assert!(paths.contains(&PathBuf::from("/h/.ssh")));
        assert!(paths.contains(&PathBuf::from("/h/.aws")));
        assert!(paths.contains(&PathBuf::from("/h/.claude")));
        assert!(paths.contains(&PathBuf::from("/p/.env")));
        if cfg!(target_os = "macos") {
            assert!(paths.contains(&PathBuf::from("/h/Library/Keychains")));
            assert!(!paths.contains(&PathBuf::from("/etc/shadow")));
        } else {
            assert!(paths.contains(&PathBuf::from("/etc/shadow")));
            assert!(paths.contains(&PathBuf::from("/h/.kube/config")));
        }
    }

    #[cfg(unix)]
    #[test]
    fn the_route_probe_answers_without_sending() {
        // Either answer is right for some host; the property is that the
        // probe completes and reports a bool rather than hanging or failing.
        let _ = host_has_route();
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_descriptor_resolves_and_a_pipe_does_not() {
        use std::os::fd::AsRawFd;
        let dir = scratch("fd");
        let path = dir.join("out.txt");
        let file = fs::File::create(&path).unwrap();
        let target = descriptor_target(file.as_raw_fd()).expect("a regular file has a path");
        assert_eq!(target, core::canonicalize_lenient(&path));
        let (reader, _writer) = std::io::pipe().unwrap();
        assert_eq!(descriptor_target(reader.as_raw_fd()), None);
        assert_eq!(descriptor_target(9999), None);
        drop(file);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn escapes_are_files_outside_the_root() {
        let root = Path::new("/r");
        let descriptors = vec![
            ("stdout", Some(PathBuf::from("/r/work/log.txt"))),
            ("stderr", Some(PathBuf::from("/elsewhere/notes.md"))),
            ("other", None),
        ];
        assert_eq!(
            escaping_descriptors(root, &descriptors),
            vec!["stderr -> /elsewhere/notes.md".to_string()]
        );
        assert!(escaping_descriptors(root, &[("stdout", None)]).is_empty());
    }

    #[cfg(unix)]
    #[test]
    fn the_jailed_environment_is_exactly_what_jailtest_expects() {
        let env = jail_env(
            Path::new("/r/work"),
            Path::new("/home/me"),
            Path::new("/proj"),
            &["/home/me/.ssh".into(), "/proj/.env".into()],
            true,
        );
        let get = |key: &str| env.iter().find(|(k, _)| k == key).map(|(_, v)| v.as_str());
        assert_eq!(get("HOME"), Some("/r/work"));
        assert_eq!(get("REAL_HOME"), Some("/home/me"));
        assert_eq!(get("REPO_ROOT"), Some("/proj"));
        assert_eq!(
            get("OXBOX_EXISTING_PATHS"),
            Some("/home/me/.ssh\n/proj/.env")
        );
        assert_eq!(get("OXBOX_HOST_HAS_ROUTE"), Some("1"));
        assert_eq!(get("OXBOX_PLATFORM"), Some(core::PLATFORM));
        assert_eq!(get("TMPDIR"), Some("/r/work/.oxtmp"));
        assert_eq!(get("PYTHONDONTWRITEBYTECODE"), Some("1"));
        assert!(get("PATH").unwrap().starts_with("/opt/homebrew/bin:"));
        assert!(get("TERM").is_some() && get("LANG").is_some());
        assert!(get("OPENROUTER_API_KEY").is_none());
        let offline = jail_env(
            Path::new("/w"),
            Path::new("/h"),
            Path::new("/p"),
            &[],
            false,
        );
        assert_eq!(
            offline
                .iter()
                .find(|(k, _)| k == "OXBOX_HOST_HAS_ROUTE")
                .map(|(_, v)| v.as_str()),
            Some("0")
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_seatbelt_argument_vector() {
        let argv = macos_argv(
            Path::new("/p/jail.sb"),
            Path::new("/r/work"),
            &args(&["pytest", "-q"]),
        );
        assert_eq!(
            argv,
            args(&[
                "/usr/bin/sandbox-exec",
                "-f",
                "/p/jail.sb",
                "-D",
                "WORK=/r/work",
                "pytest",
                "-q"
            ])
        );
    }

    #[cfg(unix)]
    #[test]
    fn the_bubblewrap_argument_vector() {
        let env = vec![("HOME".to_string(), "/r/work".to_string())];
        let argv = linux_argv(
            Path::new("/usr/bin/bwrap"),
            Path::new("/r/work"),
            &args(&["pytest", "-q"]),
            &env,
        );
        assert_eq!(argv[0], "/usr/bin/bwrap");
        for required in [
            "--unshare-all",
            "--die-with-parent",
            "--new-session",
            "--clearenv",
        ] {
            assert!(
                argv.contains(&required.to_string()),
                "{required} missing: {argv:?}"
            );
        }
        let clear = argv.iter().position(|a| a == "--clearenv").unwrap();
        assert_eq!(
            &argv[clear + 1..clear + 4],
            &args(&["--setenv", "HOME", "/r/work"])[..]
        );
        assert_eq!(&argv[argv.len() - 2..], &args(&["pytest", "-q"])[..]);
        let bind = argv.iter().position(|a| a == "--bind").unwrap();
        assert_eq!(
            &argv[bind..bind + 5],
            &args(&["--bind", "/r/work", "/r/work", "--chdir", "/r/work"])[..]
        );
        // The work dir is the only writable bind; the system is read-only.
        assert_eq!(argv.iter().filter(|a| *a == "--bind").count(), 1);
        assert!(argv.iter().any(|a| a == "--ro-bind" || a == "--symlink"));
    }

    #[cfg(unix)]
    #[test]
    fn the_plan_refuses_a_work_dir_outside_the_root_and_a_missing_one() {
        let dir = scratch("plan-refuse");
        let root = root_at(&dir.join("root"));
        fs::create_dir_all(root.path.join("work")).unwrap();
        let outside = dir.join("outside");
        fs::create_dir_all(&outside).unwrap();
        let fail = plan(&root, &outside, false, &args(&["true"]), &[]).unwrap_err();
        assert_eq!(fail.code, EX_CONFIG);
        assert!(fail.text.contains("REFUSING --work"), "{}", fail.text);
        assert!(fail.text.contains("comes from test"), "{}", fail.text);
        let fail = plan(
            &root,
            &root.path.join("absent"),
            false,
            &args(&["true"]),
            &[],
        )
        .unwrap_err();
        assert_eq!(fail.code, 1);
        assert!(fail.text.contains("does not exist"), "{}", fail.text);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_plan_refuses_an_escaping_descriptor_unless_allowed() {
        let dir = scratch("plan-fd");
        let root = root_at(&dir.join("root"));
        let work = root.path.join("work");
        fs::create_dir_all(&work).unwrap();
        let outside = Some(PathBuf::from("/elsewhere/out.txt"));
        let inside = Some(work.join("log.txt"));
        let fail = plan(
            &root,
            &work,
            false,
            &args(&["true"]),
            &[("stdout", outside.clone())],
        )
        .unwrap_err();
        assert_eq!(fail.code, EX_CONFIG);
        assert!(
            fail.text
                .contains("REFUSING - output is redirected outside"),
            "{}",
            fail.text
        );
        assert!(
            fail.text.contains("stdout -> /elsewhere/out.txt"),
            "{}",
            fail.text
        );
        let ok_inside = plan(&root, &work, false, &args(&["true"]), &[("stdout", inside)]);
        let ok_allowed = plan(&root, &work, true, &args(&["true"]), &[("stdout", outside)]);
        // Both need a backend on this host; when there is none the refusal
        // is about the backend, not the descriptor, and the case is moot.
        // On macOS the backend needs the profile too, which a build tree
        // deeper than the lookup walks (a coverage build) cannot supply.
        let backend_here = (cfg!(target_os = "macos") && find_profile().is_ok())
            || (!cfg!(target_os = "macos") && core::which("bwrap").is_some());
        if backend_here {
            let planned = ok_inside.unwrap();
            assert!(planned.warnings.is_empty());
            let planned = ok_allowed.unwrap();
            assert!(
                planned.warnings.iter().any(|w| w.contains("(allowed)")),
                "{:?}",
                planned.warnings
            );
            assert!(
                planned
                    .warnings
                    .iter()
                    .any(|w| w.contains("stdout -> /elsewhere/out.txt"))
            );
            assert_eq!(planned.work, core::canonicalize_lenient(&work));
            assert!(work.join(".oxtmp").is_dir());
            assert!(planned.env.iter().any(|(k, _)| k == "OXBOX_EXISTING_PATHS"));
            assert!(planned.argv.ends_with(&args(&["true"])));
            assert!(["seatbelt", "bubblewrap"].contains(&planned.backend));
        } else {
            let text = ok_inside.unwrap_err().text;
            assert!(text.contains("bwrap") || text.contains("jail.sb"), "{text}");
        }
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn run_answers_the_informational_flags_without_a_root_on_disk() {
        assert_eq!(run(&args(&["--version"])), 0);
        assert_eq!(run(&args(&["--help"])), 0);
        assert_eq!(run(&args(&["--nope"])), 2);
        assert_eq!(run(&[]), 2);
    }

    #[test]
    fn diagnoses_carry_the_prefix_on_every_line() {
        assert_eq!(
            Fail::diag(78, "a\nb").text,
            "oxbox-jail: a\noxbox-jail: b\n"
        );
    }
}
