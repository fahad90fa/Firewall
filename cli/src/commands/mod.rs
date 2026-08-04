//! Subcommand dispatch.
//!
//! Every command is a function from parsed arguments and a [`Transport`] to a
//! string. Taking the transport as a parameter rather than opening a socket
//! inside each command is what lets the whole CLI be tested against a scripted
//! daemon.

pub mod debug;
pub mod identity;
pub mod logs;
pub mod policy;
pub mod rules;
pub mod status;

use crate::client::Transport;
use crate::{CliError, CliResult, GlobalOptions};

/// Run a subcommand.
pub fn dispatch(
    command: &str,
    args: &[String],
    options: &GlobalOptions,
    transport: &mut dyn Transport,
) -> CliResult {
    match command {
        "status" => status::run(args, options, transport),
        "policy" => policy::run(args, options, transport),
        "rules" => rules::run(args, options, transport),
        "identity" => identity::run(args, options, transport),
        "logs" => logs::run(args, options, transport),
        "debug" => debug::run(args, options, transport),
        "shutdown" => status::shutdown(options, transport),
        other => Err(CliError::Usage(format!("unknown command `{other}`"))),
    }
}

/// Every command name the CLI accepts.
pub const COMMANDS: [&str; 7] = [
    "status", "policy", "rules", "identity", "logs", "debug", "shutdown",
];

/// Reject an unknown command before anything opens a socket.
///
/// [`dispatch`] catches this too, but only after `main` has already connected,
/// which reports a typo as "cannot reach the daemon" — the wrong diagnosis, and
/// the wrong exit code for a script to branch on.
pub fn check_command(command: &str) -> Result<(), CliError> {
    if COMMANDS.contains(&command) {
        return Ok(());
    }
    Err(CliError::Usage(
        match ufw_policy_lang::error::closest_match(command, COMMANDS) {
            Some(near) => format!("unknown command `{command}` (did you mean `{near}`?)"),
            None => format!("unknown command `{command}`, try `ufwctl --help`"),
        },
    ))
}

/// The help text for a command, so `ufwctl logs --help` answers without a
/// daemon. Help that requires a running service is help you cannot read when
/// you most need it.
pub fn help_for(command: &str) -> Option<&'static str> {
    Some(match command {
        "status" => status::HELP,
        "policy" => policy::HELP,
        "rules" => rules::HELP,
        "identity" => identity::HELP,
        "logs" => logs::HELP,
        "debug" => debug::HELP,
        "shutdown" => {
            "ufwctl shutdown\n\nAsk the daemon to exit. \
                       The kernel module keeps enforcing the installed policy.\n"
        }
        _ => return None,
    })
}

/// Whether the first argument asks for help.
pub fn wants_help(args: &[String]) -> bool {
    matches!(
        args.first().map(String::as_str),
        Some("-h" | "--help" | "help")
    )
}

/// Commands that never talk to the daemon, so `main` can run them without
/// opening a socket. `ufwctl policy validate` has to work on a build machine.
pub fn is_offline(command: &str, args: &[String]) -> bool {
    if wants_help(args) {
        return true;
    }
    matches!(
        (command, args.first().map(String::as_str)),
        ("policy", Some("validate")) | ("policy", Some("compile")) | ("policy", Some("explain"))
    )
}

/// Run an offline command.
pub fn dispatch_offline(command: &str, args: &[String], options: &GlobalOptions) -> CliResult {
    if wants_help(args) {
        if let Some(help) = help_for(command) {
            return Ok(help.to_string());
        }
    }
    match (command, args.first().map(String::as_str)) {
        ("policy", Some("validate")) => policy::validate_offline(&args[1..], options),
        ("policy", Some("compile")) => policy::compile_offline(&args[1..], options),
        ("policy", Some("explain")) => policy::explain_offline(&args[1..], options),
        _ => Err(CliError::Usage(format!(
            "`{command}` needs a running daemon"
        ))),
    }
}

/// Pull `--flag value` out of an argument list, returning the value.
pub fn take_option(args: &[String], flag: &str) -> Option<String> {
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if arg == flag {
            return it.next().cloned();
        }
        if let Some(rest) = arg.strip_prefix(&format!("{flag}=")) {
            return Some(rest.to_string());
        }
    }
    None
}

/// Whether a boolean flag is present.
pub fn has_flag(args: &[String], flag: &str) -> bool {
    args.iter().any(|a| a == flag)
}

/// Positional arguments: everything that is not a flag or a flag's value.
pub fn positionals(args: &[String], value_flags: &[&str]) -> Vec<String> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }
        if arg.starts_with('-') {
            if value_flags.contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }
        out.push(arg.clone());
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    #[test]
    fn options_are_found_in_both_forms() {
        let a = args(&["--filter", "dns", "--output=json"]);
        assert_eq!(take_option(&a, "--filter").as_deref(), Some("dns"));
        assert_eq!(take_option(&a, "--output").as_deref(), Some("json"));
        assert_eq!(take_option(&a, "--missing"), None);
    }

    #[test]
    fn flags_are_detected() {
        let a = args(&["--follow", "list"]);
        assert!(has_flag(&a, "--follow"));
        assert!(!has_flag(&a, "--json"));
    }

    #[test]
    fn positionals_skip_flags_and_their_values() {
        let a = args(&["list", "--filter", "dns", "--follow", "extra"]);
        assert_eq!(positionals(&a, &["--filter"]), vec!["list", "extra"]);
    }

    #[test]
    fn offline_commands_are_recognized() {
        assert!(is_offline("policy", &args(&["validate", "p.yaml"])));
        assert!(is_offline("policy", &args(&["compile"])));
        assert!(!is_offline("policy", &args(&["reload"])));
        assert!(!is_offline("status", &[]));
    }

    #[test]
    fn help_is_offline_for_every_command() {
        for command in COMMANDS {
            assert!(help_for(command).is_some(), "{command} has no help");
            assert!(is_offline(command, &args(&["--help"])), "{command} --help");
            let help = dispatch_offline(command, &args(&["--help"]), &GlobalOptions::default())
                .unwrap_or_else(|e| panic!("{command} --help: {e}"));
            assert!(help.contains("ufwctl"), "{command}: {help}");
        }
    }

    #[test]
    fn an_unknown_command_is_a_usage_error() {
        let mut t = crate::client::testing::ScriptedTransport::default();
        let err = dispatch("teleport", &[], &GlobalOptions::default(), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn an_unknown_command_is_rejected_before_a_socket_is_opened() {
        let err = check_command("teleport").unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(check_command("status").is_ok());
    }

    #[test]
    fn a_near_miss_command_suggests_the_real_one() {
        let err = check_command("polciy").unwrap_err();
        assert!(err.to_string().contains("did you mean `policy`"), "{err}");
    }
}
