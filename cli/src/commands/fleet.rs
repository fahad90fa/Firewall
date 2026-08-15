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

Fleet control is enabled only when `api.fleet_secret` is configured; otherwise
`status` reports the surface as disabled.
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    match args.first().map(String::as_str) {
        None | Some("status") => status(options, transport),
        Some("enroll") => enroll(&args[1..], options, transport),
        Some("-h") | Some("--help") | Some("help") => Ok(HELP.to_string()),
        Some(other) => Err(CliError::Usage(format!(
            "unknown fleet subcommand `{other}`"
        ))),
    }
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
