//! `ufwctl status` — what the daemon is doing right now.

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{self, duration, emit, number, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl status [OPTIONS]

Show daemon health, the installed policy, and traffic counters.

OPTIONS:
    --watch <SECONDS>   Refresh every N seconds until interrupted
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    if super::has_flag(args, "--help") || super::has_flag(args, "-h") {
        return Ok(HELP.to_string());
    }

    let watch = super::take_option(args, "--watch")
        .map(|v| {
            v.parse::<u64>()
                .map_err(|_| CliError::Usage("--watch needs a number of seconds".into()))
        })
        .transpose()?;

    match watch {
        None => once(options, transport),
        Some(interval) => {
            // A watch loop prints and sleeps; the operator interrupts it.
            // Bounded here only by the daemon going away.
            let interval = std::time::Duration::from_secs(interval.max(1));
            loop {
                let rendered = once(options, transport)?;
                println!("\x1b[2J\x1b[H{rendered}");
                std::thread::sleep(interval);
            }
        }
    }
}

fn once(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("status").finish())?;
    Ok(emit(options.format, &raw, render))
}

fn render(v: &ufw_shared::json::Json) -> String {
    let kernel = output::field(v, "kernel");
    let policy = output::field(v, "policy");
    let identity = output::field(v, "identity");
    let logging = output::field(v, "logging");
    let traffic = output::field(v, "traffic");

    let mut out = String::new();
    let health = text(v, "health");
    out.push_str(&format!(
        "{}  {}  version {}  up {}\n",
        text(v, "host_id"),
        // The one line an operator scans for. `degraded` means the daemon is
        // running and nothing is being filtered, so it is worth shouting.
        match health.as_str() {
            "enforcing" => "ENFORCING".to_string(),
            "degraded" => "DEGRADED — NOT FILTERING".to_string(),
            other => other.to_uppercase(),
        },
        text(v, "version"),
        duration(number(v, "uptime_secs")),
    ));
    out.push_str(&format!("mode: {}\n\n", text(v, "mode")));

    let mut t = Table::new(["", ""]);
    t.push([
        "kernel module",
        &if kernel.get("connected").and_then(|c| c.as_bool()) == Some(true) {
            format!(
                "{} on {} via {}",
                text(kernel, "module_version"),
                text(kernel, "platform"),
                text(kernel, "endpoint")
            )
        } else {
            format!(
                "disconnected after {} attempt(s): {}",
                number(kernel, "reconnect_attempts"),
                text(kernel, "last_error")
            )
        },
    ]);
    if let Some(caps) = kernel.get("capabilities").and_then(|c| c.as_array()) {
        let names: Vec<&str> = caps.iter().filter_map(|c| c.as_str()).collect();
        t.push(["capabilities", &names.join(", ")]);
    }
    t.push([
        "policy",
        &format!(
            "revision {}, {} rules, from {}",
            number(policy, "revision"),
            number(policy, "rules"),
            text(policy, "origin")
        ),
    ]);
    t.push([
        "reloads",
        &format!(
            "{} ok, {} failed",
            number(policy, "reloads"),
            number(policy, "failed_reloads")
        ),
    ]);
    t.push([
        "identity",
        &format!(
            "{}, {} anchors, {} cached ({:.0}% hit rate)",
            text(identity, "resolver"),
            number(identity, "trust_anchors"),
            number(identity, "cache_entries"),
            identity
                .get("cache_hit_rate")
                .and_then(|r| r.as_f64())
                .unwrap_or(0.0)
                * 100.0
        ),
    ]);
    t.push([
        "logging",
        &format!(
            "{} written, {} filtered, {} dropped, {} correlations",
            number(logging, "written"),
            number(logging, "filtered"),
            number(logging, "dropped_queue_full"),
            number(logging, "correlations")
        ),
    ]);
    t.push([
        "flows",
        &format!(
            "{} seen, {} allowed, {} denied",
            number(traffic, "flows_seen"),
            number(traffic, "flows_allowed"),
            number(traffic, "flows_denied")
        ),
    ]);
    t.push([
        "inspection",
        &format!(
            "{} scans, {} signature hits, {} fast-path decisions",
            number(traffic, "dpi_scans"),
            number(traffic, "dpi_hits"),
            number(traffic, "ebpf_fastpath_decisions")
        ),
    ]);
    out.push_str(&t.render());

    let dropped = number(logging, "dropped_queue_full") + number(traffic, "log_events_dropped");
    if dropped > 0 {
        out.push_str(&format!(
            "\nwarning: {dropped} log event(s) were dropped under load; \
             decisions were still enforced but are not all recorded\n"
        ));
    }
    out
}

/// `ufwctl shutdown`
pub fn shutdown(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("shutdown").finish())?;
    Ok(emit(options.format, &raw, |v| {
        format!("{}\n", text(v, "message"))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::ScriptedTransport;
    use crate::output::Format;

    const STATUS: &str = r#"{
      "host_id":"web-01","version":"0.1.0","health":"enforcing","mode":"enforce",
      "uptime_secs":93784,
      "kernel":{"connected":true,"endpoint":"/dev/ufw-control","module_version":"0.1.0",
                "platform":"linux","capabilities":["dpi","conntrack"],
                "installed_revision":7,"reconnect_attempts":0,"last_error":null},
      "policy":{"revision":7,"rules":12,"reloads":3,"failed_reloads":1,
                "origin":"base.yaml","activated_at":"2024-01-01T00:00:00.000000Z"},
      "identity":{"resolver":"linux-procfs","trust_anchors":2,"queries":40,
                  "cache_entries":9,"cache_hits":80,"cache_misses":20,"cache_hit_rate":0.8},
      "logging":{"received":100,"written":90,"filtered":10,"dropped_queue_full":0,
                 "sink_errors":0,"correlations":2},
      "traffic":{"flows_seen":500,"flows_allowed":480,"flows_denied":20,"packets_seen":9000,
                 "dpi_scans":30,"dpi_hits":1,"conntrack_entries":50,
                 "ebpf_fastpath_decisions":400,"log_events_dropped":0}
    }"#;

    fn options(format: Format) -> GlobalOptions {
        GlobalOptions {
            format,
            ..Default::default()
        }
    }

    #[test]
    fn the_table_leads_with_what_an_operator_scans_for() {
        let mut t = ScriptedTransport::new([STATUS]);
        let out = run(&[], &options(Format::Table), &mut t).unwrap();
        let first = out.lines().next().unwrap();
        assert!(first.contains("web-01"));
        assert!(first.contains("ENFORCING"));
        assert!(first.contains("1d 2h 3m"));
        assert!(out.contains("revision 7, 12 rules"));
        assert!(out.contains("80% hit rate"));
    }

    #[test]
    fn a_degraded_daemon_says_it_is_not_filtering() {
        let degraded = STATUS
            .replace("\"health\":\"enforcing\"", "\"health\":\"degraded\"")
            .replace("\"connected\":true", "\"connected\":false")
            .replace("\"last_error\":null", "\"last_error\":\"module unloaded\"");
        let mut t = ScriptedTransport::new([degraded]);
        let out = run(&[], &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("DEGRADED — NOT FILTERING"), "{out}");
        assert!(out.contains("module unloaded"));
    }

    #[test]
    fn dropped_log_events_are_called_out() {
        let lossy = STATUS.replace("\"dropped_queue_full\":0", "\"dropped_queue_full\":42");
        let mut t = ScriptedTransport::new([lossy]);
        let out = run(&[], &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("42 log event(s) were dropped"), "{out}");
        assert!(out.contains("decisions were still enforced"));
    }

    #[test]
    fn json_output_is_the_response_verbatim() {
        let mut t = ScriptedTransport::new([STATUS]);
        let out = run(&[], &options(Format::Json), &mut t).unwrap();
        assert_eq!(out, STATUS);
    }

    #[test]
    fn yaml_output_is_readable() {
        let mut t = ScriptedTransport::new([STATUS]);
        let out = run(&[], &options(Format::Yaml), &mut t).unwrap();
        assert!(out.contains("host_id: web-01"));
        assert!(out.contains("policy:"));
    }

    #[test]
    fn a_bad_watch_interval_is_a_usage_error() {
        let mut t = ScriptedTransport::new([STATUS]);
        let args = vec!["--watch".to_string(), "soon".to_string()];
        assert_eq!(
            run(&args, &options(Format::Table), &mut t)
                .unwrap_err()
                .exit_code(),
            2
        );
    }

    #[test]
    fn shutdown_reports_what_the_daemon_said() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"shutting down"}"#]);
        let out = shutdown(&options(Format::Table), &mut t).unwrap();
        assert_eq!(out.trim(), "shutting down");
        assert_eq!(t.last_request(), Some(r#"{"op":"shutdown"}"#));
    }
}
