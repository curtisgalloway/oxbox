// SPDX-FileCopyrightText: 2026 Curtis Galloway
// SPDX-License-Identifier: Apache-2.0

//! The one command: `oxbox <subcommand>`, handed to the executable that does
//! it.
//!
//!     oxbox sandbox ...   -> oxbox-sandbox   build and tend the disposable copy
//!     oxbox send ...      -> oxbox-send      send files to a model; text comes back
//!     oxbox patch ...     -> oxbox-patch     apply its patch into the sandbox only
//!     oxbox jail -- cmd   -> oxbox-jail      run cmd with no network, no escape
//!
//! The four executables live in a libexec directory rather than on PATH --
//! the paniolo pattern: one command installs to bin, its helpers install
//! beside it where nothing else finds them, and each subcommand execs the
//! executable by name. A process listing then says which piece is running.
//! The bare `oxbox -- cmd` form is still the jail, so nothing that already
//! worked stops. Standard library only.

use std::env;
use std::process::{self, Command};

use oxbox_core as core;

const PROG: &str = "oxbox";
const SUBCOMMANDS: [&str; 4] = ["sandbox", "send", "patch", "jail"];

const USAGE: &str = "\
usage: oxbox <command> [args...]
       oxbox [--work DIR] [--allow-external-output] -- command args...

A supervised harness for pointing an untrusted LLM at your code: one command
in front of four scripts. Each step is a subcommand, handed to the script
that does it; the bare form is the jail.

  sandbox --create REPO FILE...  copy files into a disposable sandbox
          --add | --remove FILE  tend the copy; --list, --read, --write it;
          --destroy, --status    burn it down; list them all   (oxbox-sandbox)
  send    [flags] \"task\"         send it to a model; nothing is applied
                                                               (oxbox-send)
  patch   --log logs/<ts>        apply its patch into the sandbox only
                                                               (oxbox-patch)
  jail    [flags] -- cmd...      run cmd with no network and no writes
                                 outside ./sandbox/work        (oxbox-jail)
  helper  [NAME] [args...]       list the scripts with the path each resolved
                                 to, or run one directly
  skill                          print the ox-review agent skill

Every subcommand answers --help. Sandboxes live under OXBOX_SANDBOX_ROOT,
else `root` under [sandbox] in ~/.config/oxbox/config.ini, else ./sandbox;
sandbox, patch and jail take --sandbox NAME to pick one (default: work).

  --skill                   print the ox-review agent skill and exit
  --version                 print the version and exit
  --help                    print this and exit

exit status: a subcommand's own, passed through unchanged; 2 for a usage
error here; 3 when a script cannot be found.
";

/// Which subcommand owns a flag, so `oxbox --manifest` can say whose it is
/// instead of "unknown flag". The project is called oxbox, so oxbox is what
/// a reader types first; the first thing one typed was --manifest.
fn owner_of(flag: &str) -> Option<&'static str> {
    const SEND: [&str; 18] = [
        "--files",
        "--mode",
        "--venue",
        "--manifest",
        "--allow-paid",
        "--failover",
        "--base-url",
        "--api-key-env",
        "--model",
        "--effort",
        "--max-tokens",
        "--temperature",
        "--stdin",
        "--log-dir",
        "--output",
        "--status-file",
        "--force",
        "--dry-run",
    ];
    const SANDBOX: [&str; 9] = [
        "--create",
        "--add",
        "--remove",
        "--destroy",
        "--list",
        "--read",
        "--write",
        "--status",
        "--all",
    ];
    const PATCH: [&str; 3] = ["--log", "--diff", "--commit"];
    if SEND.contains(&flag) {
        Some("send")
    } else if SANDBOX.contains(&flag) {
        Some("sandbox")
    } else if PATCH.contains(&flag) {
        Some("patch")
    } else {
        None
    }
}

/// The jail's flags are accepted here too, ahead of `--`, because that is
/// the command line the jail has always taken.
const JAIL_FLAGS: [&str; 3] = ["--work", "--sandbox", "--allow-external-output"];

/// Hand off to a script: in place on POSIX, as a child on Windows.
///
/// The environment is passed through untouched -- oxbox-send needs its
/// venue key, and oxbox-jail clears it for the jailed command itself -- and
/// the exit status is the script's own.
fn run_helper(name: &str, args: &[String]) -> i32 {
    let Some(path) = core::find_helper(name) else {
        let mut message = format!("{name} not found; looked in:\n");
        for dir in core::helper_dirs() {
            message.push_str(&format!("  {}\n", dir.display()));
        }
        message.push_str("  and on PATH");
        core::diagnose(PROG, &message);
        return 3;
    };
    let mut command = Command::new(&path);
    command.args(args);
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        let error = command.exec();
        core::diagnose(
            PROG,
            &format!("failed to start {}: {error}", path.display()),
        );
        1
    }
    #[cfg(not(unix))]
    {
        match command.status() {
            Ok(status) => status.code().unwrap_or(1),
            Err(error) => {
                core::diagnose(
                    PROG,
                    &format!("failed to start {}: {error}", path.display()),
                );
                1
            }
        }
    }
}

/// `oxbox helper send` and `oxbox helper oxbox-send` name the same script.
fn helper_name(word: &str) -> Option<String> {
    let word = word.strip_prefix("oxbox-").unwrap_or(word);
    SUBCOMMANDS.contains(&word).then(|| format!("oxbox-{word}"))
}

/// `oxbox helper` with no name: each script and where it was found.
fn list_helpers() -> i32 {
    let mut missing = 0;
    for sub in SUBCOMMANDS {
        let name = format!("oxbox-{sub}");
        match core::find_helper(&name) {
            Some(path) => println!("{name:<14} {}", path.display()),
            None => {
                missing += 1;
                println!("{name:<14} (not found)");
            }
        }
    }
    if missing > 0 { 3 } else { 0 }
}

fn main() {
    process::exit(run());
}

fn run() -> i32 {
    let args: Vec<String> = env::args().skip(1).collect();
    let Some(head) = args.first() else {
        print!("{USAGE}");
        return 2;
    };
    let head = head.as_str();
    if SUBCOMMANDS.contains(&head) {
        return run_helper(&format!("oxbox-{head}"), &args[1..]);
    }
    match head {
        "helper" => {
            let Some(word) = args.get(1) else {
                return list_helpers();
            };
            let Some(name) = helper_name(word) else {
                core::diagnose(
                    PROG,
                    &format!(
                        "no script named {word:?}; they are {}",
                        SUBCOMMANDS
                            .iter()
                            .map(|sub| format!("oxbox-{sub}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                );
                return 2;
            };
            return run_helper(&name, &args[2..]);
        }
        "--help" | "-h" => {
            print!("{USAGE}");
            return 0;
        }
        "--version" => {
            println!("{PROG} {}", core::VERSION);
            return 0;
        }
        "--skill" | "skill" => return core::print_skill(PROG),
        _ => {}
    }
    let flag = head.split('=').next().unwrap_or(head);
    if head == "--" || JAIL_FLAGS.contains(&flag) {
        return run_helper("oxbox-jail", &args);
    }
    if head.starts_with('-') {
        match owner_of(flag) {
            Some(owner) => {
                let shown = match args.get(1) {
                    Some(value) if !value.starts_with('-') => format!("{flag} {value}"),
                    _ => flag.to_string(),
                };
                core::diagnose(
                    PROG,
                    &format!(
                        "{flag} is a flag of `oxbox {owner}`; use:\n  oxbox {owner} {shown} ..."
                    ),
                );
            }
            None => core::diagnose(PROG, &format!("unknown flag {flag} (see oxbox --help)")),
        }
        return 2;
    }
    core::diagnose(
        PROG,
        &format!(
            "unknown command {head:?}; the commands are {}\n\
             to jail a command, put it after --:  oxbox -- {head} ...",
            SUBCOMMANDS
                .iter()
                .copied()
                .chain(["helper", "skill"])
                .collect::<Vec<_>>()
                .join(", ")
        ),
    );
    2
}
