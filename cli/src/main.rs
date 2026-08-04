//! `ufwctl` — the Unified Firewall management CLI.

use std::process::ExitCode;

use ufw_cli::commands;
use ufw_cli::output::Format;
use ufw_cli::{CliError, GlobalOptions};
use ufw_shared::constants;

const HELP: &str = "\
ufwctl — Unified Firewall management

USAGE:
    ufwctl [GLOBAL OPTIONS] <COMMAND> [ARGS]

COMMANDS:
    status                 Daemon health, installed policy and traffic counters
    policy <SUB>           Compile, validate, install, diff and roll back policy
    rules <SUB>            List and inspect the installed rule set
    identity <SUB>         Resolve application identity; inspect the trust database
    logs                   Read and filter the event log
    debug <SUB>            Kernel counters, a diagnostic dump, and enforcement mode
    shutdown               Ask the daemon to exit

GLOBAL OPTIONS:
    -s, --socket <PATH>    Daemon control socket
    -o, --output <FORMAT>  table | json | yaml [default: table]
    -t, --timeout <SECS>   How long to wait for the daemon [default: 10]
    -q, --quiet            Suppress non-essential output
    -V, --version          Print the version and exit
    -h, --help             Print this help and exit

`policy validate`, `policy compile` and `policy explain` run entirely locally,
so they work in CI with no daemon, no kernel module and no privileges.

EXIT CODES:
    0  success
    1  the operation failed
    2  usage error
    3  the daemon could not be reached
";

fn main() -> ExitCode {
    match run() {
        Ok(Some(output)) => {
            print!("{output}");
            ExitCode::SUCCESS
        }
        Ok(None) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("ufwctl: {e}");
            ExitCode::from(e.exit_code())
        }
    }
}

fn run() -> Result<Option<String>, CliError> {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let (options, rest) = parse_globals(&argv)?;

    let Some(command) = rest.first().map(String::as_str) else {
        print!("{HELP}");
        return Ok(None);
    };
    let args = &rest[1..];

    match command {
        "-h" | "--help" | "help" => {
            print!("{HELP}");
            return Ok(None);
        }
        "-V" | "--version" => {
            println!("ufwctl {}", constants::VERSION);
            return Ok(None);
        }
        _ => {}
    }

    // A typo is a usage error, not an unreachable daemon. Deciding that here
    // keeps `ufwctl teleport` from failing with the wrong exit code on a host
    // where the daemon happens to be down.
    commands::check_command(command)?;

    // Local-only commands must work without a daemon: that is what makes
    // `ufwctl policy validate` usable in CI, and `ufwctl logs --help` readable
    // when the daemon is the thing you are trying to fix.
    if commands::is_offline(command, args) {
        return commands::dispatch_offline(command, args, &options).map(Some);
    }

    // Connects on first request, so a bad argument is still a usage error on a
    // host where the daemon is down.
    let mut transport = ufw_cli::client::LazyTransport::new(&options);
    commands::dispatch(command, args, &options, &mut transport).map(Some)
}

/// Consume global options from the front of the argument list.
fn parse_globals(argv: &[String]) -> Result<(GlobalOptions, Vec<String>), CliError> {
    let mut options = GlobalOptions::default();
    let mut rest = Vec::new();
    let mut it = argv.iter().peekable();

    while let Some(arg) = it.next() {
        match arg.as_str() {
            "-s" | "--socket" => {
                options.socket = it
                    .next()
                    .ok_or_else(|| CliError::Usage("--socket needs a path".into()))?
                    .into();
            }
            "-o" | "--output" => {
                let value = it
                    .next()
                    .ok_or_else(|| CliError::Usage("--output needs a format".into()))?;
                options.format = Format::parse(value).ok_or_else(|| {
                    CliError::Usage(format!("`{value}` is not a format (table, json, yaml)"))
                })?;
            }
            "-t" | "--timeout" => {
                let value = it
                    .next()
                    .ok_or_else(|| CliError::Usage("--timeout needs a number".into()))?;
                options.timeout_secs = value
                    .parse()
                    .map_err(|_| CliError::Usage("--timeout needs a number of seconds".into()))?;
            }
            "-q" | "--quiet" => options.quiet = true,
            _ => {
                // The first non-global argument ends global parsing; the rest
                // belongs to the subcommand, which has its own flags.
                rest.push(arg.clone());
                rest.extend(it.cloned());
                break;
            }
        }
    }

    Ok((options, rest))
}
