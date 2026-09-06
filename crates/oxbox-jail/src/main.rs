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

use std::env;
#[cfg(unix)]
use std::fs;
#[cfg(unix)]
use std::path::Path;
use std::path::PathBuf;
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

fn refuse(message: &str) -> ! {
    core::diagnose(PROG, message);
    process::exit(1);
}

/// The seatbelt profile, wherever this oxbox is installed.
///
/// A source checkout carries it at `profiles/jail.sb` beside the tools; a
/// package installs this executable into `<prefix>/libexec/bin` (the .deb:
/// `<prefix>/libexec/oxbox/bin`) and the profile into
/// `<prefix>/share/oxbox/jail.sb`; a build tree keeps it two levels above
/// `target/debug`. Refusing when none exists is deliberate: there is no jail
/// without the profile, and no jail means no run.
#[cfg(unix)]
fn find_profile() -> PathBuf {
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
            return candidate.clone();
        }
    }
    let mut message = String::from("seatbelt profile jail.sb not found; looked in:\n");
    for candidate in candidates {
        message.push_str(&format!("  {}\n", candidate.display()));
    }
    refuse(message.trim_end());
}

/// Paths jailtest should try to read, per platform. Existence is decided
/// HERE, outside the jail: inside, `stat()` is denied, so every hidden path
/// looks absent and a probe that checks for itself would skip rather than
/// test.
#[cfg(unix)]
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

/// Whether this host can route to the internet at all, decided outside the
/// jail like the sensitive-path list is. Inside the jail a blocked connect
/// and an offline host fail the same way -- bubblewrap's `--unshare-net`
/// gives ENETUNREACH, exactly what a laptop with Wi-Fi off gives -- so on
/// such a host jailtest's network probes would pass without testing
/// anything. A UDP connect sends no packet; it only asks the kernel whether
/// a route exists.
#[cfg(unix)]
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
    let file = ManuallyDrop::new(unsafe { fs::File::from_raw_fd(fd) });
    let info = file.metadata().ok()?;
    if !info.file_type().is_file() {
        return None;
    }
    let path = descriptor_path(fd)?;
    Some(core::canonicalize_lenient(&path))
}

#[cfg(target_os = "linux")]
fn descriptor_path(fd: i32) -> Option<PathBuf> {
    fs::read_link(format!("/proc/self/fd/{fd}")).ok()
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

/// stdout/stderr that point at regular files outside the sandbox root.
///
/// Neither backend can help here: the shell opened those files before the
/// jail existed, so the descriptor is already live. `oxbox -- cmd > ~/notes.md`
/// would let jailed code write whatever it likes there.
#[cfg(unix)]
fn escaping_descriptors(root: &Path) -> Vec<String> {
    let mut found = Vec::new();
    for (fd, name) in [(1, "stdout"), (2, "stderr")] {
        if let Some(target) = descriptor_target(fd)
            && !core::is_within(root, &target)
        {
            found.push(format!("{name} -> {}", target.display()));
        }
    }
    found
}

#[cfg(unix)]
fn macos_argv(work: &Path, command: &[String]) -> Vec<String> {
    if !Path::new("/usr/bin/sandbox-exec").exists() {
        refuse("/usr/bin/sandbox-exec not found; cannot jail on this macOS");
    }
    let profile = find_profile();
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
fn linux_argv(work: &Path, command: &[String], env: &[(String, String)]) -> Vec<String> {
    let Some(bwrap) = core::which("bwrap") else {
        refuse(
            "bubblewrap (bwrap) not found.\n\
             it is the sandbox on Linux; without it there is no jail.\n\
               Debian/Ubuntu  sudo apt install bubblewrap\n\
               Fedora/RHEL    sudo dnf install bubblewrap\n\
               Arch           sudo pacman -S bubblewrap\n\
               Alpine         sudo apk add bubblewrap",
        );
    };
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
        let Ok(meta) = fs::symlink_metadata(path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            if let Ok(target) = fs::read_link(path) {
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

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    let root = match core::sandbox_root() {
        Ok(root) => root,
        Err(message) => refuse(&message),
    };
    let mut work = root.path.join("work");
    let mut allow_external = false;
    let mut rest = args.as_slice();

    while let Some(head) = rest.first() {
        match head.as_str() {
            "--help" | "-h" => {
                print!("{USAGE}");
                return 0;
            }
            "--version" => {
                println!("{PROG} {}", core::VERSION);
                return 0;
            }
            "--skill" => return core::print_skill(PROG),
            "--work" => {
                let Some(dir) = rest.get(1) else {
                    core::diagnose(PROG, "--work needs a directory");
                    return 2;
                };
                work = PathBuf::from(dir);
                rest = &rest[2..];
            }
            "--sandbox" => {
                let Some(name) = rest.get(1) else {
                    core::diagnose(PROG, "--sandbox needs a name");
                    return 2;
                };
                match core::sandbox_name(name) {
                    Ok(name) => work = root.path.join(name),
                    Err(message) => {
                        core::diagnose(PROG, &message);
                        return 2;
                    }
                }
                rest = &rest[2..];
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
                core::diagnose(
                    PROG,
                    &format!(
                        "unexpected argument {other}; the command goes after --  (see oxbox jail --help)"
                    ),
                );
                return 2;
            }
        }
    }

    let command: Vec<String> = rest.to_vec();
    if command.is_empty() {
        core::diagnose(PROG, "no command given (use: oxbox jail -- pytest -q)");
        eprint!("{USAGE}");
        return 2;
    }

    if cfg!(windows) {
        eprint!("{WINDOWS_HELP}");
        return EX_CONFIG;
    }
    if !cfg!(any(target_os = "macos", target_os = "linux")) {
        refuse(&format!(
            "no sandbox backend for platform {:?}; refusing",
            core::PLATFORM
        ));
    }

    jail(&root, work, allow_external, &command)
}

#[cfg(unix)]
fn jail(root: &core::SandboxRoot, work: PathBuf, allow_external: bool, command: &[String]) -> i32 {
    use std::os::unix::process::CommandExt;

    if !work.is_dir() {
        refuse(&format!("work dir does not exist: {}", work.display()));
    }
    let work = core::canonicalize_lenient(&work);

    // The backend grants write access to whatever --work names, so a work
    // dir outside the sandbox is not a jail at all.
    if !core::is_within(&root.path, &work) {
        core::diagnose(
            PROG,
            &format!(
                "REFUSING --work {}\n\
                 the backend grants write access to whatever --work names, so a\n\
                 work dir outside {} is not a jail at all.\n\
                 (the sandbox root comes from {})",
                work.display(),
                root.path.display(),
                root.origin
            ),
        );
        return EX_CONFIG;
    }

    let escaping = escaping_descriptors(&root.path);
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
        core::diagnose(PROG, &message);
        return EX_CONFIG;
    }
    if !escaping.is_empty() {
        let mut message =
            String::from("WARNING - output redirected outside the sandbox (allowed):\n");
        for item in &escaping {
            message.push_str(&format!("  {item}\n"));
        }
        core::diagnose(PROG, message.trim_end());
    }

    let real_home = core::home_dir();
    let project_root = env::current_dir().unwrap_or_else(|_| PathBuf::from("."));
    let tmpdir = work.join(".oxtmp");
    if let Err(error) = fs::create_dir_all(&tmpdir) {
        refuse(&format!("cannot create {}: {error}", tmpdir.display()));
    }

    let existing: Vec<String> = sensitive_paths(&real_home, &project_root)
        .into_iter()
        .filter(|path| fs::symlink_metadata(path).is_ok())
        .map(|path| path.to_string_lossy().into_owned())
        .collect();

    // A fresh environment, not the caller's. The parent shell routinely
    // holds OPENROUTER_API_KEY (via `op run`), and inheriting it would hand
    // jailed code the key.
    let jail_env: Vec<(String, String)> = vec![
        ("HOME".into(), work.to_string_lossy().into_owned()),
        ("REAL_HOME".into(), real_home.to_string_lossy().into_owned()),
        (
            "REPO_ROOT".into(),
            project_root.to_string_lossy().into_owned(),
        ),
        ("OXBOX_EXISTING_PATHS".into(), existing.join("\n")),
        (
            "OXBOX_HOST_HAS_ROUTE".into(),
            if host_has_route() { "1" } else { "0" }.into(),
        ),
        ("OXBOX_PLATFORM".into(), core::PLATFORM.into()),
        ("TMPDIR".into(), tmpdir.to_string_lossy().into_owned()),
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
    ];

    let (argv, backend) = if cfg!(target_os = "macos") {
        (macos_argv(&work, command), "seatbelt")
    } else {
        (linux_argv(&work, command, &jail_env), "bubblewrap")
    };

    eprintln!("{PROG}: backend={backend} work={}", work.display());
    eprintln!("{PROG}: network=DENIED writes={} only", work.display());
    eprintln!("{PROG}: env=CLEARED (nothing from the parent shell crosses in)");

    let mut child = process::Command::new(&argv[0]);
    child.args(&argv[1..]).current_dir(&work).env_clear();
    for (key, value) in &jail_env {
        child.env(key, value);
    }
    let error = child.exec();
    refuse(&format!("failed to start {}: {error}", argv[0]));
}

#[cfg(not(unix))]
fn jail(
    _root: &core::SandboxRoot,
    _work: PathBuf,
    _allow_external: bool,
    _command: &[String],
) -> i32 {
    eprint!("{WINDOWS_HELP}");
    EX_CONFIG
}
