//! `ufwctl identity` — application identity queries and the trust database.

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{emit, field, number, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl identity <SUBCOMMAND>

SUBCOMMANDS:
    resolve <PID>   Resolve a running process the way the kernel module would
    trust           Show the trust database and identity cache statistics

`resolve` asks the daemon to run the platform resolver against a live process,
which is the same path a cache miss from the kernel module takes. It is the
fastest way to answer \"why does this binary not match my rule?\".
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let Some(sub) = args.first().map(String::as_str) else {
        return Ok(HELP.to_string());
    };
    match sub {
        "-h" | "--help" | "help" => Ok(HELP.to_string()),
        "resolve" => {
            let pid = super::positionals(&args[1..], &[])
                .first()
                .ok_or_else(|| CliError::Usage("resolve needs a pid".into()))?
                .parse::<u64>()
                .map_err(|_| CliError::Usage("the pid must be a number".into()))?;
            resolve(pid, options, transport)
        }
        "trust" => trust(options, transport),
        other => Err(CliError::Usage(format!(
            "unknown identity subcommand `{other}`"
        ))),
    }
}

fn resolve(pid: u64, options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(
        transport,
        RequestBuilder::new("resolve-identity")
            .num("pid", pid)
            .finish(),
    )?;

    Ok(emit(options.format, &raw, |v| {
        let id = field(v, "identity");
        let mut t = Table::new(["", ""]);
        t.push(["pid", &text(id, "pid")]);
        t.push(["path", &text(id, "path")]);
        t.push(["sha256", &text(id, "sha256")]);
        t.push(["signature", &text(id, "signature_type")]);
        t.push(["signature valid", &text(id, "signature_valid")]);
        t.push(["signer", &text(id, "signer")]);
        t.push(["team id", &text(id, "team_id")]);
        t.push(["bundle id", &text(id, "bundle_id")]);
        t.push(["trust", &text(id, "trust")]);
        t.push(["user", &text(id, "user")]);

        let mut out = t.render();

        if let Some(ufw_shared::json::Json::Object(meta)) = id.get("platform") {
            out.push_str("\nplatform detail:\n");
            let mut m = Table::new(["", ""]);
            for (key, value) in meta {
                m.push([key.clone(), value.as_str().unwrap_or_default().to_string()]);
            }
            out.push_str(&m.render());
        }

        // The two facts most likely to explain a rule not matching.
        let trust = text(id, "trust");
        if trust == "untrusted" {
            out.push_str(
                "\nnote: `untrusted` means a signature was present and failed, or the process \
                 could not be inspected at all. It is not the same as unsigned.\n",
            );
        } else if trust == "unknown" && text(id, "signature_type") == "none" {
            out.push_str(
                "\nnote: this binary is unsigned, so it can only match rules that accept \
                 `trust: [unknown]` or constrain it by path or hash.\n",
            );
        }
        out
    }))
}

fn trust(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("list-trust").finish())?;
    Ok(emit(options.format, &raw, |v| {
        let cache = field(v, "cache");
        let mut t = Table::new(["", ""]);
        t.push(["resolver".to_string(), text(v, "resolver")]);
        t.push(["trust anchors".to_string(), text(v, "anchors")]);
        t.push([
            "cache".to_string(),
            format!(
                "{} of {} entries",
                number(cache, "entries"),
                number(cache, "capacity")
            ),
        ]);
        t.push([
            "cache activity".to_string(),
            format!(
                "{} hits, {} misses, {} evictions ({:.0}% hit rate)",
                number(cache, "hits"),
                number(cache, "misses"),
                number(cache, "evictions"),
                cache
                    .get("hit_rate")
                    .and_then(|r| r.as_f64())
                    .unwrap_or(0.0)
                    * 100.0
            ),
        ]);
        t.render()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::ScriptedTransport;
    use crate::output::Format;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn options(format: Format) -> GlobalOptions {
        GlobalOptions {
            format,
            ..Default::default()
        }
    }

    const SIGNED: &str = r#"{"ok":true,"identity":{
        "pid":4242,"path":"/usr/lib/contoso/browser","sha256":"ab12",
        "signature_type":"elf-hash","signature_valid":true,"signer":"Contoso Ltd",
        "team_id":null,"bundle_id":null,"trust":"trusted","user":"1000:1000",
        "platform":{"packaged_prefix":"true"}}}"#;

    #[test]
    fn resolve_renders_the_identity_and_platform_detail() {
        let mut t = ScriptedTransport::new([SIGNED]);
        let out = run(&args(&["resolve", "4242"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("path             /usr/lib/contoso/browser"));
        assert!(out.contains("trust            trusted"));
        assert!(out.contains("platform detail:"));
        assert!(out.contains("packaged_prefix"));
        assert_eq!(
            t.last_request(),
            Some(r#"{"op":"resolve-identity","pid":4242}"#)
        );
    }

    #[test]
    fn an_untrusted_result_explains_what_that_means() {
        // The distinction between "signature failed" and "unsigned" is the
        // one operators get wrong, so the CLI says it explicitly.
        let untrusted = SIGNED
            .replace("\"trust\":\"trusted\"", "\"trust\":\"untrusted\"")
            .replace("\"signature_valid\":true", "\"signature_valid\":false");
        let mut t = ScriptedTransport::new([untrusted]);
        let out = run(&args(&["resolve", "1"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("It is not the same as unsigned"), "{out}");
    }

    #[test]
    fn an_unsigned_result_says_which_rules_can_still_match_it() {
        let unsigned = SIGNED
            .replace("\"trust\":\"trusted\"", "\"trust\":\"unknown\"")
            .replace(
                "\"signature_type\":\"elf-hash\"",
                "\"signature_type\":\"none\"",
            );
        let mut t = ScriptedTransport::new([unsigned]);
        let out = run(&args(&["resolve", "1"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("trust: [unknown]"), "{out}");
    }

    #[test]
    fn resolve_requires_a_numeric_pid() {
        let mut t = ScriptedTransport::default();
        for bad in [args(&["resolve"]), args(&["resolve", "self"])] {
            assert_eq!(
                run(&bad, &options(Format::Table), &mut t)
                    .unwrap_err()
                    .exit_code(),
                2
            );
        }
    }

    #[test]
    fn trust_shows_the_database_and_cache() {
        let response = r#"{"ok":true,"resolver":"linux-procfs","anchors":3,
          "cache":{"entries":9,"capacity":4096,"hits":80,"misses":20,"evictions":0,
                   "hit_rate":0.8}}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(&args(&["trust"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("linux-procfs"));
        assert!(out.contains("9 of 4096 entries"));
        assert!(out.contains("80% hit rate"));
    }

    #[test]
    fn help_is_shown_without_a_subcommand() {
        let mut t = ScriptedTransport::default();
        let out = run(&[], &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("SUBCOMMANDS"));
    }
}
