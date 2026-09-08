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
//!
//! `decide` turns a command line into an `Action` without touching the
//! process; `main` carries the action out. That split is what makes the
//! dispatch table testable.

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
  skill                          print the oxbox-review agent skill

Every subcommand answers --help. Sandboxes live under OXBOX_SANDBOX_ROOT,
else `root` under [sandbox] in ~/.config/oxbox/config.ini, else ./sandbox;
sandbox, patch and jail take --sandbox NAME to pick one (default: work).

  --skill                   print the oxbox-review agent skill and exit
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

/// What a command line asks for. Everything that leaves the process --
/// printing, exiting, exec -- happens in `main`, on one of these.
#[derive(Debug, PartialEq)]
enum Action {
    /// Print to stdout and exit with the code.
    Stdout(String, i32),
    /// Print to stderr, prefixed line by line, and exit with the code.
    Stderr(String, i32),
    /// Print the runbook.
    Skill,
    /// List the scripts and where each resolved to.
    ListHelpers,
    /// Hand off to the named executable with these arguments.
    Run(String, Vec<String>),
}

/// `oxbox helper send` and `oxbox helper oxbox-send` name the same script.
fn helper_name(word: &str) -> Option<String> {
    let word = word.strip_prefix("oxbox-").unwrap_or(word);
    SUBCOMMANDS.contains(&word).then(|| format!("oxbox-{word}"))
}

fn decide(args: &[String]) -> Action {
    let Some(head) = args.first() else {
        return Action::Stdout(USAGE.to_string(), 2);
    };
    let head = head.as_str();
    if SUBCOMMANDS.contains(&head) {
        return Action::Run(format!("oxbox-{head}"), args[1..].to_vec());
    }
    match head {
        "helper" => {
            let Some(word) = args.get(1) else {
                return Action::ListHelpers;
            };
            return match helper_name(word) {
                Some(name) => Action::Run(name, args[2..].to_vec()),
                None => Action::Stderr(
                    format!(
                        "no script named {word:?}; they are {}",
                        SUBCOMMANDS
                            .iter()
                            .map(|sub| format!("oxbox-{sub}"))
                            .collect::<Vec<_>>()
                            .join(", ")
                    ),
                    2,
                ),
            };
        }
        "--help" | "-h" => return Action::Stdout(USAGE.to_string(), 0),
        "--version" => return Action::Stdout(format!("{PROG} {}\n", core::VERSION), 0),
        "--skill" | "skill" => return Action::Skill,
        _ => {}
    }
    let flag = head.split('=').next().unwrap_or(head);
    if head == "--" || JAIL_FLAGS.contains(&flag) {
        return Action::Run("oxbox-jail".to_string(), args.to_vec());
    }
    if head.starts_with('-') {
        return match owner_of(flag) {
            Some(owner) => {
                let shown = match args.get(1) {
                    Some(value) if !value.starts_with('-') => format!("{flag} {value}"),
                    _ => flag.to_string(),
                };
                Action::Stderr(
                    format!(
                        "{flag} is a flag of `oxbox {owner}`; use:\n  oxbox {owner} {shown} ..."
                    ),
                    2,
                )
            }
            None => Action::Stderr(format!("unknown flag {flag} (see oxbox --help)"), 2),
        };
    }
    Action::Stderr(
        format!(
            "unknown command {head:?}; the commands are {}\n\
             to jail a command, put it after --:  oxbox -- {head} ...",
            SUBCOMMANDS
                .iter()
                .copied()
                .chain(["helper", "skill"])
                .collect::<Vec<_>>()
                .join(", ")
        ),
        2,
    )
}

/// `oxbox helper` with no name: each script and where it was found. Returns
/// the lines to print and the exit code, 3 when any is missing.
fn helper_listing() -> (String, i32) {
    let mut lines = String::new();
    let mut missing = 0;
    for sub in SUBCOMMANDS {
        let name = format!("oxbox-{sub}");
        match core::find_helper(&name) {
            Some(path) => lines.push_str(&format!("{name:<14} {}\n", path.display())),
            None => {
                missing += 1;
                lines.push_str(&format!("{name:<14} (not found)\n"));
            }
        }
    }
    (lines, if missing > 0 { 3 } else { 0 })
}

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

fn main() {
    let args: Vec<String> = env::args().skip(1).collect();
    let code = match decide(&args) {
        Action::Stdout(text, code) => {
            print!("{text}");
            code
        }
        Action::Stderr(text, code) => {
            core::diagnose(PROG, &text);
            code
        }
        Action::Skill => core::print_skill(PROG),
        Action::ListHelpers => {
            let (text, code) = helper_listing();
            print!("{text}");
            code
        }
        Action::Run(name, rest) => run_helper(&name, &rest),
    };
    process::exit(code);
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    static ENV: Mutex<()> = Mutex::new(());

    fn args(words: &[&str]) -> Vec<String> {
        words.iter().map(|w| w.to_string()).collect()
    }

    #[test]
    fn subcommands_run_their_script_with_the_rest_of_the_line() {
        for sub in SUBCOMMANDS {
            assert_eq!(
                decide(&args(&[sub, "--flag", "value"])),
                Action::Run(format!("oxbox-{sub}"), args(&["--flag", "value"]))
            );
        }
    }

    #[test]
    fn helper_lists_or_runs_by_either_spelling() {
        assert_eq!(decide(&args(&["helper"])), Action::ListHelpers);
        assert_eq!(
            decide(&args(&["helper", "send", "--version"])),
            Action::Run("oxbox-send".into(), args(&["--version"]))
        );
        assert_eq!(
            decide(&args(&["helper", "oxbox-jail", "--", "true"])),
            Action::Run("oxbox-jail".into(), args(&["--", "true"]))
        );
        match decide(&args(&["helper", "python3"])) {
            Action::Stderr(text, 2) => assert!(text.contains("no script named \"python3\"")),
            other => panic!("{other:?}"),
        }
        assert_eq!(helper_name("patch"), Some("oxbox-patch".into()));
        assert_eq!(helper_name("oxbox-patch"), Some("oxbox-patch".into()));
        assert_eq!(helper_name("oxbox-nope"), None);
        assert_eq!(helper_name(""), None);
    }

    #[test]
    fn the_informational_flags_print_and_exit_zero() {
        assert_eq!(decide(&args(&["--help"])), Action::Stdout(USAGE.into(), 0));
        assert_eq!(decide(&args(&["-h"])), Action::Stdout(USAGE.into(), 0));
        assert_eq!(
            decide(&args(&["--version"])),
            Action::Stdout(format!("oxbox {}\n", core::VERSION), 0)
        );
        assert_eq!(decide(&args(&["--skill"])), Action::Skill);
        assert_eq!(decide(&args(&["skill"])), Action::Skill);
    }

    #[test]
    fn no_arguments_is_a_usage_error_with_the_usage() {
        assert_eq!(decide(&[]), Action::Stdout(USAGE.into(), 2));
    }

    #[test]
    fn the_bare_form_and_the_jail_flags_reach_the_jail_unchanged() {
        for line in [
            vec!["--", "pytest", "-q"],
            vec!["--work", "sandbox/work", "--", "true"],
            vec!["--sandbox", "alt", "--", "true"],
            vec!["--allow-external-output", "--", "true"],
            vec!["--sandbox=alt", "--", "true"],
        ] {
            assert_eq!(
                decide(&args(&line)),
                Action::Run("oxbox-jail".into(), args(&line)),
                "{line:?}"
            );
        }
    }

    #[test]
    fn a_subcommands_flag_typed_here_names_the_subcommand() {
        match decide(&args(&["--manifest", "https://x/latest.json"])) {
            Action::Stderr(text, 2) => {
                assert!(
                    text.contains("--manifest is a flag of `oxbox send`"),
                    "{text}"
                );
                assert!(
                    text.contains("oxbox send --manifest https://x/latest.json ..."),
                    "{text}"
                );
            }
            other => panic!("{other:?}"),
        }
        // The value is not echoed when the next word is another flag.
        match decide(&args(&["--create", "--all"])) {
            Action::Stderr(text, 2) => {
                assert!(text.contains("`oxbox sandbox`"), "{text}");
                assert!(text.contains("oxbox sandbox --create ..."), "{text}");
            }
            other => panic!("{other:?}"),
        }
        match decide(&args(&["--log=logs/x"])) {
            Action::Stderr(text, 2) => assert!(text.contains("`oxbox patch`"), "{text}"),
            other => panic!("{other:?}"),
        }
        match decide(&args(&["--nope"])) {
            Action::Stderr(text, 2) => assert!(text.contains("unknown flag --nope"), "{text}"),
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn an_unknown_word_lists_the_commands_and_the_dash_dash_form() {
        match decide(&args(&["pytest", "-q"])) {
            Action::Stderr(text, 2) => {
                assert!(text.contains("unknown command \"pytest\""), "{text}");
                assert!(
                    text.contains("sandbox, send, patch, jail, helper, skill"),
                    "{text}"
                );
                assert!(text.contains("oxbox -- pytest ..."), "{text}");
            }
            other => panic!("{other:?}"),
        }
    }

    #[test]
    fn every_owned_flag_maps_to_its_subcommand_and_nothing_else() {
        assert_eq!(owner_of("--manifest"), Some("send"));
        assert_eq!(owner_of("--dry-run"), Some("send"));
        assert_eq!(owner_of("--status"), Some("sandbox"));
        assert_eq!(owner_of("--all"), Some("sandbox"));
        assert_eq!(owner_of("--commit"), Some("patch"));
        assert_eq!(owner_of("--diff"), Some("patch"));
        assert_eq!(owner_of("--work"), None);
        assert_eq!(owner_of("--sandbox"), None);
        assert_eq!(owner_of("--frobnicate"), None);
    }

    #[test]
    fn the_listing_names_every_script_and_says_when_one_is_missing() {
        let _guard = ENV.lock().unwrap_or_else(|p| p.into_inner());
        let dir = env::temp_dir().join(format!("oxbox-dispatch-{}", process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let suffix = if cfg!(windows) { ".exe" } else { "" };
        for sub in ["sandbox", "send", "patch"] {
            std::fs::write(dir.join(format!("oxbox-{sub}{suffix}")), b"").unwrap();
        }
        let saved = env::var_os("PATH");
        unsafe { env::set_var("PATH", &dir) };
        let (text, code) = helper_listing();
        match saved {
            Some(path) => unsafe { env::set_var("PATH", path) },
            None => unsafe { env::remove_var("PATH") },
        }
        assert_eq!(code, 3, "{text}");
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines.len(), 4);
        assert!(lines[0].starts_with("oxbox-sandbox "), "{text}");
        assert!(
            lines[3].starts_with("oxbox-jail ") && lines[3].ends_with("(not found)"),
            "{text}"
        );
        assert!(
            lines[1].contains(&dir.to_string_lossy().into_owned()),
            "{text}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
