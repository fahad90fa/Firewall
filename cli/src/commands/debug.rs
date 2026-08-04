//! `ufwctl debug` — kernel module state and enforcement controls.
//!
//! Everything here can change what the firewall does, so every subcommand
//! either reports state or requires an explicit confirmation flag. `mode
//! emergency-allow` in particular turns enforcement off entirely; it exists
//! because a firewall that cannot be turned off during an outage gets turned
//! off by uninstalling it, which is worse.

use ufw_shared::protocol::EnforcementMode;

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{emit, field, number, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl debug <SUBCOMMAND>

SUBCOMMANDS:
    stats               Kernel module counters
    signatures          Loaded DPI signatures, and any the policy names in vain
    dump                Everything the daemon knows, for a bug report
    mode <MODE>         Change enforcement: enforce | monitor | emergency-allow

`mode emergency-allow` stops all filtering. It requires --yes, and the daemon
records it at critical severity.
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let Some(sub) = args.first().map(String::as_str) else {
        return Ok(HELP.to_string());
    };
    let rest = &args[1..];

    match sub {
        "-h" | "--help" | "help" => Ok(HELP.to_string()),
        "stats" => stats(options, transport),
        "signatures" => signatures(rest, options, transport),
        "dump" => dump(options, transport),
        "mode" => mode(rest, options, transport),
        other => Err(CliError::Usage(format!("unknown debug subcommand `{other}`"))),
    }
}

/// The signature set, and the references that resolve to nothing.
///
/// The dangling list is the reason this command exists. A DPI rule naming a
/// signature no file defines compiles, installs and never fires, so the only
/// symptom is traffic that was supposed to be inspected and silently was not.
fn signatures(
    args: &[String],
    options: &GlobalOptions,
    transport: &mut dyn Transport,
) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("list-signatures").finish())?;
    let validate_only = super::has_flag(args, "--validate");

    Ok(emit(options.format, &raw, |v| {
        let dangling = v
            .get("dangling_references")
            .and_then(|d| d.as_array())
            .map(|a| a.len())
            .unwrap_or(0);

        let mut out = String::new();
        if !validate_only {
            let mut t = Table::new(["SIGNATURE", "PROTOCOL", "SEVERITY", "CONDITIONS"]);
            if let Some(list) = v.get("signatures").and_then(|s| s.as_array()) {
                for sig in list {
                    t.push([
                        text(sig, "name"),
                        text(sig, "protocol"),
                        text(sig, "severity"),
                        sig.get("conditions")
                            .and_then(|c| c.as_array())
                            .map(|c| c.len())
                            .unwrap_or(0)
                            .to_string(),
                    ]);
                }
            }
            out.push_str(&t.render());
            out.push('\n');
        }

        out.push_str(&format!(
            "{} signature(s) loaded\n",
            number(v, "count")
        ));
        if dangling > 0 {
            out.push_str(&format!(
                "\nwarning: {dangling} DPI reference(s) in the installed policy match no \
                 loaded signature.\nThose rules can never fire. Either the signature file \
                 was not deployed, or the\nname in the policy is misspelled — ids are \
                 derived from the name, so the two\nmust match exactly.\n"
            ));
        }
        out
    }))
}

fn stats(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("stats").finish())?;
    Ok(emit(options.format, &raw, |v| {
        let mut t = Table::new(["COUNTER", "VALUE"]);
        for key in [
            "packets_seen",
            "packets_allowed",
            "packets_denied",
            "flows_seen",
            "flows_allowed",
            "flows_denied",
            "identity_cache_hits",
            "identity_cache_misses",
            "identity_queries_timed_out",
            "dpi_scans",
            "dpi_hits",
            "reassembly_contexts",
            "reassembly_truncated",
            "conntrack_entries",
            "log_events_dropped",
            "ebpf_fastpath_decisions",
        ] {
            t.push([key.replace('_', " "), number(v, key).to_string()]);
        }
        let mut out = t.render();

        // Two counters that mean something is wrong rather than something is
        // busy, so they get called out instead of sitting in the list.
        let timeouts = number(v, "identity_queries_timed_out");
        if timeouts > 0 {
            out.push_str(&format!(
                "\nwarning: {timeouts} identity query(ies) timed out. Flows for those \
                 processes fell back to the unresolved-identity path, which is untrusted.\n"
            ));
        }
        let truncated = number(v, "reassembly_truncated");
        if truncated > 0 {
            out.push_str(&format!(
                "\nnote: {truncated} stream(s) exceeded the reassembly budget. A signature that \
                 did not match one of those was not necessarily absent.\n"
            ));
        }
        out
    }))
}

/// Everything at once, for pasting into a bug report.
fn dump(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let status = client::call(transport, RequestBuilder::new("status").finish())?;
    let stats = client::call(transport, RequestBuilder::new("stats").finish())?;
    let rules = client::call(transport, RequestBuilder::new("list-rules").finish())?;
    let revisions = client::call(transport, RequestBuilder::new("list-revisions").finish())?;
    let trust = client::call(transport, RequestBuilder::new("list-trust").finish())?;

    let mut w = ufw_shared::json::JsonWriter::with_capacity(8192);
    w.begin_object();
    w.bool_field("ok", true);
    w.str_field("cli_version", ufw_shared::constants::VERSION);
    w.str_field("collected_at", &ufw_shared::log_types::format_rfc3339_micros(
        ufw_shared::now_us(),
    ));
    w.raw_field("status", &status);
    w.raw_field("stats", &stats);
    w.raw_field("rules", &rules);
    w.raw_field("revisions", &revisions);
    w.raw_field("trust", &trust);
    w.end_object();
    let combined = w.finish();

    Ok(emit(options.format, &combined, |v| {
        let status = field(v, "status");
        let mut out = String::new();
        out.push_str(&format!(
            "collected {}\n\n",
            text(v, "collected_at")
        ));
        out.push_str(&format!(
            "host {} | {} | version {} | mode {}\n",
            text(status, "host_id"),
            text(status, "health"),
            text(status, "version"),
            text(status, "mode")
        ));
        out.push_str(
            "\nRun with `--output json` to capture the full dump for a bug report.\n",
        );
        out
    }))
}

fn mode(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let requested = super::positionals(args, &[])
        .first()
        .cloned()
        .ok_or_else(|| CliError::Usage("mode needs a value".into()))?;
    let mode = EnforcementMode::parse(&requested).ok_or_else(|| {
        CliError::Usage(format!(
            "`{requested}` is not a mode (enforce, monitor, emergency-allow)"
        ))
    })?;

    // Turning enforcement off is a decision, not a typo. Requiring the flag
    // means it cannot happen by autocomplete.
    if mode == EnforcementMode::EmergencyAllow && !super::has_flag(args, "--yes") {
        return Err(CliError::Usage(
            "emergency-allow stops all filtering on this host.\n\
             Re-run with --yes if that is what you intend."
                .into(),
        ));
    }

    let raw = client::call(
        transport,
        RequestBuilder::new("set-mode").str("mode", mode.as_str()).finish(),
    )?;

    Ok(emit(options.format, &raw, |v| {
        let mut out = format!("{}\n", text(v, "message"));
        if mode == EnforcementMode::EmergencyAllow {
            out.push_str(
                "\nEnforcement is OFF. Every flow is permitted and logged as an emergency \
                 allow.\nRestore it with `ufwctl debug mode enforce`.\n",
            );
        } else if mode == EnforcementMode::Monitor {
            out.push_str(
                "\nDecisions are computed and logged but not applied. Nothing is being \
                 blocked.\n",
            );
        }
        out
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
        GlobalOptions { format, ..Default::default() }
    }

    const STATS: &str = r#"{"ok":true,"packets_seen":100,"packets_allowed":90,"packets_denied":10,
      "flows_seen":50,"flows_allowed":45,"flows_denied":5,"identity_cache_hits":80,
      "identity_cache_misses":20,"identity_queries_timed_out":0,"dpi_scans":10,"dpi_hits":1,
      "reassembly_contexts":3,"reassembly_truncated":0,"conntrack_entries":40,
      "log_events_dropped":0,"ebpf_fastpath_decisions":70,"rule_hits":[]}"#;

    #[test]
    fn signatures_lists_what_is_loaded() {
        let response = r#"{"ok":true,"count":2,"complete":true,
          "signatures":[
            {"name":"dns-tunnel-long-label","protocol":"dns","severity":"high",
             "conditions":[{"kind":"field"},{"kind":"field"}]},
            {"name":"http-exploit-post","protocol":"http","severity":"high",
             "conditions":[{"kind":"field"}]}],
          "dangling_references":[]}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(&args(&["signatures"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("dns-tunnel-long-label"), "{out}");
        assert!(out.contains("2 signature(s) loaded"), "{out}");
        assert!(!out.contains("warning"), "{out}");
        assert_eq!(t.last_request(), Some(r#"{"op":"list-signatures"}"#));
    }

    #[test]
    fn a_dangling_reference_is_called_out_because_nothing_else_would() {
        // A DPI rule naming a signature nobody shipped installs cleanly and
        // never fires. This message is the only symptom an operator gets.
        let response = r#"{"ok":true,"count":1,"complete":false,
          "signatures":[{"name":"a","protocol":"dns","severity":"low","conditions":[]}],
          "dangling_references":[4242,9999]}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(&args(&["signatures"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("2 DPI reference(s)"), "{out}");
        assert!(out.contains("can never fire"), "{out}");
    }

    #[test]
    fn validate_reports_without_listing() {
        let response = r#"{"ok":true,"count":9,"complete":true,
          "signatures":[{"name":"a","protocol":"dns","severity":"low","conditions":[]}],
          "dangling_references":[]}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(
            &args(&["signatures", "--validate"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert!(!out.contains("SIGNATURE"), "the table is suppressed: {out}");
        assert!(out.contains("9 signature(s) loaded"), "{out}");
    }

    #[test]
    fn stats_render_every_counter() {
        let mut t = ScriptedTransport::new([STATS]);
        let out = run(&args(&["stats"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("flows denied"));
        assert!(out.contains("ebpf fastpath decisions"));
        assert!(out.contains("70"));
    }

    #[test]
    fn identity_timeouts_are_called_out_as_a_problem() {
        let lossy = STATS.replace("\"identity_queries_timed_out\":0", "\"identity_queries_timed_out\":5");
        let mut t = ScriptedTransport::new([lossy]);
        let out = run(&args(&["stats"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("5 identity query(ies) timed out"), "{out}");
        assert!(out.contains("untrusted"));
    }

    #[test]
    fn truncated_reassembly_is_explained_rather_than_buried() {
        let truncated = STATS.replace("\"reassembly_truncated\":0", "\"reassembly_truncated\":2");
        let mut t = ScriptedTransport::new([truncated]);
        let out = run(&args(&["stats"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("not necessarily absent"), "{out}");
    }

    #[test]
    fn emergency_allow_requires_an_explicit_confirmation() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"mode is now emergency-allow"}"#]);
        let err = run(
            &args(&["mode", "emergency-allow"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap_err();
        assert_eq!(err.exit_code(), 2);
        assert!(err.to_string().contains("stops all filtering"));
        // Crucially, nothing was sent.
        assert!(t.last_request().is_none());
    }

    #[test]
    fn emergency_allow_with_yes_goes_through_and_says_what_it_did() {
        let mut t =
            ScriptedTransport::new([r#"{"ok":true,"message":"enforcement mode is now emergency-allow"}"#]);
        let out = run(
            &args(&["mode", "emergency-allow", "--yes"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert!(out.contains("Enforcement is OFF"));
        assert!(out.contains("ufwctl debug mode enforce"));
        assert_eq!(
            t.last_request(),
            Some(r#"{"op":"set-mode","mode":"emergency-allow"}"#)
        );
    }

    #[test]
    fn monitor_mode_explains_that_nothing_is_blocked() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"mode is now monitor"}"#]);
        let out = run(&args(&["mode", "monitor"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("Nothing is being blocked"));
    }

    #[test]
    fn enforce_needs_no_confirmation() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"mode is now enforce"}"#]);
        assert!(run(&args(&["mode", "enforce"]), &options(Format::Table), &mut t).is_ok());
    }

    #[test]
    fn an_unknown_mode_is_a_usage_error() {
        let mut t = ScriptedTransport::default();
        let err = run(&args(&["mode", "sideways"]), &options(Format::Table), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn dump_collects_every_surface_into_one_document() {
        let mut t = ScriptedTransport::new([
            r#"{"host_id":"web-01","health":"enforcing","version":"0.1.0","mode":"enforce"}"#,
            STATS,
            r#"{"ok":true,"revision":1,"rules":[]}"#,
            r#"{"ok":true,"revisions":[]}"#,
            r#"{"ok":true,"resolver":"linux-procfs","anchors":0,"cache":{}}"#,
        ]);
        let out = run(&args(&["dump"]), &options(Format::Json), &mut t).unwrap();
        let v = ufw_shared::json::parse(&out).expect("the dump must be valid JSON");
        for section in ["status", "stats", "rules", "revisions", "trust"] {
            assert!(v.get(section).is_some(), "{section} missing");
        }
        assert_eq!(
            v.get("status").unwrap().get("host_id").unwrap().as_str(),
            Some("web-01")
        );
    }
}
