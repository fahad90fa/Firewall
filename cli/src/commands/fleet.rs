//! `ufwctl fleet` — the fleet roster and member enrolment.
//!
//! A daemon with `api.fleet_secret` set is a distribution point: it holds the
//! members that have checked in and authenticates the policy bundles pushed to
//! them. This command reads that roster and enrols members. Authenticating and
//! applying a *signed bundle* (`fleet-verify`) is a machine-to-machine
//! operation driven by a distribution tool over the REST API, not something
//! typed by hand, so it is not surfaced here.

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{emit, number, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl fleet <SUBCOMMAND>

SUBCOMMANDS:
    status                       The fleet roster and rollout state
    enroll <HOST_ID> <REVISION>  Record a member reporting a revision
    distribute <POLICY> --revision <N> --to <a:port,b:port> [--canary-percent P] [--canary-seconds S]
                                 Sign the policy as a bundle and push it to each
                                 member's fleet endpoint

Fleet control is enabled only when `api.fleet_secret` is configured; otherwise
`status` reports the surface as disabled, and `distribute` is refused.
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    match args.first().map(String::as_str) {
        None | Some("status") => status(options, transport),
        Some("enroll") => enroll(&args[1..], options, transport),
        Some("distribute") => distribute(&args[1..], options, transport),
        Some("-h") | Some("--help") | Some("help") => Ok(HELP.to_string()),
        Some(other) => Err(CliError::Usage(format!(
            "unknown fleet subcommand `{other}`"
        ))),
    }
}

fn distribute(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let positionals = super::positionals(args, &["--revision", "--to", "--canary-percent", "--canary-seconds"]);
    let policy = positionals
        .first()
        .ok_or_else(|| CliError::Usage("fleet distribute needs a <POLICY> file".into()))?;
    let revision: u64 = super::take_option(args, "--revision")
        .ok_or_else(|| CliError::Usage("fleet distribute needs --revision <N>".into()))?
        .parse()
        .map_err(|_| CliError::Usage("--revision must be a number".into()))?;
    let members: Vec<String> = super::take_option(args, "--to")
        .ok_or_else(|| CliError::Usage("fleet distribute needs --to <a:port,b:port>".into()))?
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();
    if members.is_empty() {
        return Err(CliError::Usage("--to must list at least one member".into()));
    }
    let canary_percent: u64 = super::take_option(args, "--canary-percent")
        .map(|v| v.parse().unwrap_or(100))
        .unwrap_or(100);
    let canary_seconds: u64 = super::take_option(args, "--canary-seconds")
        .map(|v| v.parse().unwrap_or(0))
        .unwrap_or(0);

    let source = std::fs::read_to_string(policy)
        .map_err(|e| CliError::Local(format!("cannot read {policy}: {e}")))?;

    let raw = client::call(
        transport,
        RequestBuilder::new("fleet-distribute")
            .num("revision", revision)
            .str("source", &source)
            .str_list("members", &members)
            .num("canary_percent", canary_percent)
            .num("canary_seconds", canary_seconds)
            .finish(),
    )?;

    Ok(emit(options.format, &raw, |v| {
        let mut out = format!(
            "revision {} distributed to {} member(s), {} accepted\n\n",
            number(v, "revision"),
            number(v, "members"),
            number(v, "accepted"),
        );
        let mut t = Table::new(["MEMBER", "OK", "STATUS", "DETAIL"]);
        if let Some(list) = v.get("results").and_then(|r| r.as_array()) {
            for m in list {
                t.push([
                    text(m, "member"),
                    if m.get("ok").and_then(|b| b.as_bool()).unwrap_or(false) {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                    number(m, "status").to_string(),
                    text(m, "detail"),
                ]);
            }
        }
        out.push_str(&t.render());
        out
    }))
}

fn status(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("fleet-status").finish())?;
    Ok(emit(options.format, &raw, |v| {
        let enabled = v
            .get("enabled")
            .and_then(|b| b.as_bool())
            .unwrap_or(false);
        let mut out = String::new();
        out.push_str(&format!(
            "fleet control: {}\n",
            if enabled { "enabled" } else { "disabled (set api.fleet_secret)" }
        ));
        out.push_str(&format!(
            "target revision {} · canary {}% · {} member(s), {} converged\n\n",
            number(v, "target_revision"),
            number(v, "target_canary_percent"),
            number(v, "members"),
            number(v, "converged"),
        ));
        let mut t = Table::new(["HOST", "REVISION", "CANARY", "LAST SEEN"]);
        if let Some(roster) = v.get("roster").and_then(|r| r.as_array()) {
            for m in roster {
                t.push([
                    text(m, "host_id"),
                    number(m, "revision").to_string(),
                    if m.get("in_canary").and_then(|b| b.as_bool()).unwrap_or(false) {
                        "yes".into()
                    } else {
                        "no".into()
                    },
                    number(m, "last_seen").to_string(),
                ]);
            }
        }
        out.push_str(&t.render());
        out
    }))
}

fn enroll(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let host = args
        .first()
        .ok_or_else(|| CliError::Usage("fleet enroll needs a <HOST_ID>".into()))?;
    let revision: u64 = args
        .get(1)
        .ok_or_else(|| CliError::Usage("fleet enroll needs a <REVISION>".into()))?
        .parse()
        .map_err(|_| CliError::Usage("<REVISION> must be a number".into()))?;

    let raw = client::call(
        transport,
        RequestBuilder::new("fleet-enroll")
            .str("host_id", host)
            .num("revision", revision)
            .finish(),
    )?;
    Ok(emit(options.format, &raw, |v| {
        format!("{}\n", text(v, "message"))
    }))
}
