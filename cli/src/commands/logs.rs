//! `ufwctl logs` — read and filter the event log.
//!
//! The daemon writes structured events to its configured sinks; this command
//! reads the JSONL file sink back. It deliberately does *not* stream through
//! the control socket: a log tail that competes with policy operations on the
//! same socket is a log tail that can stall a rollback.

use std::io::{BufRead, BufReader, Seek, SeekFrom};
use std::path::PathBuf;
use std::time::Duration;

use ufw_shared::json::{self, Json};

use crate::client::Transport;
use crate::output::{Format, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl logs [OPTIONS]

Read the event log written by the daemon's file sink.

OPTIONS:
    --file <PATH>       Log file [default: /var/log/unified-firewall/events.jsonl]
    --tail <N>          Show the last N events [default: 50]
    --follow            Keep reading as new events arrive
    --decision <D>      Only allow or deny
    --rule <NAME>       Only events attributed to this rule
    --app <TEXT>        Only events whose application path contains this text
    --kind <KIND>       flow-decision, alert, dpi-match, policy-change, system-fault
    --since <TS>        Only events at or after this RFC 3339 timestamp
";

/// A parsed filter set.
#[derive(Debug, Default, Clone)]
pub struct Filter {
    pub decision: Option<String>,
    pub rule: Option<String>,
    pub app: Option<String>,
    pub kind: Option<String>,
    pub since: Option<String>,
}

impl Filter {
    pub fn from_args(args: &[String]) -> Self {
        Filter {
            decision: super::take_option(args, "--decision"),
            rule: super::take_option(args, "--rule"),
            app: super::take_option(args, "--app"),
            kind: super::take_option(args, "--kind"),
            since: super::take_option(args, "--since"),
        }
    }

    pub fn is_empty(&self) -> bool {
        self.decision.is_none()
            && self.rule.is_none()
            && self.app.is_none()
            && self.kind.is_none()
            && self.since.is_none()
    }

    /// Whether an event survives the filter.
    pub fn admits(&self, event: &Json) -> bool {
        if let Some(want) = &self.decision {
            if event.get("decision").and_then(|d| d.as_str()) != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.kind {
            if event.get("kind").and_then(|d| d.as_str()) != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.rule {
            if event.get("rule").and_then(|d| d.as_str()) != Some(want.as_str()) {
                return false;
            }
        }
        if let Some(want) = &self.app {
            let path = event
                .get("app")
                .and_then(|a| a.get("path"))
                .and_then(|p| p.as_str())
                .unwrap_or("");
            if !path.contains(want.as_str()) {
                return false;
            }
        }
        if let Some(since) = &self.since {
            // Timestamps are RFC 3339 with fixed-width fields, so lexical
            // comparison is chronological. That is the whole reason the log
            // format uses that shape.
            let ts = event.get("ts").and_then(|t| t.as_str()).unwrap_or("");
            if ts < since.as_str() {
                return false;
            }
        }
        true
    }
}

pub fn run(args: &[String], options: &GlobalOptions, _transport: &mut dyn Transport) -> CliResult {
    if super::has_flag(args, "--help") || super::has_flag(args, "-h") {
        return Ok(HELP.to_string());
    }

    let path = super::take_option(args, "--file")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(ufw_shared::constants::DEFAULT_LOG_PATH_UNIX));
    let tail = super::take_option(args, "--tail")
        .map(|v| {
            v.parse::<usize>()
                .map_err(|_| CliError::Usage("--tail needs a number".into()))
        })
        .transpose()?
        .unwrap_or(50);
    let filter = Filter::from_args(args);

    if super::has_flag(args, "--follow") {
        return follow(&path, &filter, options);
    }

    let events = read_tail(&path, tail, &filter)?;
    Ok(render(&events, options.format, &filter))
}

/// Read the last `tail` matching events.
///
/// The whole file is scanned rather than seeked backwards: a JSONL file has no
/// index, lines vary in length, and the log is size-capped by the daemon's
/// rotation anyway. Correctness over cleverness on a path an operator uses
/// while something is on fire.
pub fn read_tail(path: &PathBuf, tail: usize, filter: &Filter) -> Result<Vec<Json>, CliError> {
    let file = std::fs::File::open(path).map_err(|e| {
        CliError::Local(format!(
            "{}: {e}\n\nIs the file sink enabled? See `logging.file` in the daemon configuration.",
            path.display()
        ))
    })?;

    let mut kept: std::collections::VecDeque<Json> = std::collections::VecDeque::new();
    for line in BufReader::new(file).lines() {
        let Ok(line) = line else { continue };
        if line.trim().is_empty() {
            continue;
        }
        // A partially-written final line is normal when tailing a live log.
        let Ok(event) = json::parse(&line) else {
            continue;
        };
        if !filter.admits(&event) {
            continue;
        }
        kept.push_back(event);
        while kept.len() > tail {
            kept.pop_front();
        }
    }
    Ok(kept.into_iter().collect())
}

fn follow(path: &PathBuf, filter: &Filter, options: &GlobalOptions) -> CliResult {
    let mut file = std::fs::File::open(path)
        .map_err(|e| CliError::Local(format!("{}: {e}", path.display())))?;
    let mut position = file
        .seek(SeekFrom::End(0))
        .map_err(|e| CliError::Local(e.to_string()))?;

    loop {
        file.seek(SeekFrom::Start(position))
            .map_err(|e| CliError::Local(e.to_string()))?;
        let mut reader = BufReader::new(&file);
        let mut line = String::new();
        loop {
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) => break,
                Ok(n) => {
                    // Only advance past a complete line; a partial write is
                    // re-read on the next pass.
                    if !line.ends_with('\n') {
                        break;
                    }
                    position += n as u64;
                    if let Ok(event) = json::parse(line.trim()) {
                        if filter.admits(&event) {
                            print!("{}", render(&[event], options.format, filter));
                        }
                    }
                }
                Err(_) => break,
            }
        }
        std::thread::sleep(Duration::from_millis(250));

        // Rotation: the file we hold shrank or was replaced.
        if let Ok(meta) = std::fs::metadata(path) {
            if meta.len() < position {
                file = std::fs::File::open(path).map_err(|e| CliError::Local(e.to_string()))?;
                position = 0;
            }
        }
    }
}

fn render(events: &[Json], format: Format, filter: &Filter) -> String {
    match format {
        Format::Json => {
            let mut out = String::new();
            for event in events {
                // One JSON object per line, the same shape the daemon wrote.
                out.push_str(&crate::output::to_yaml(event, 0));
                out.push('\n');
            }
            // For JSON output, re-emit compact objects rather than YAML.
            let mut compact = String::new();
            for event in events {
                compact.push_str(&compact_json(event));
                compact.push('\n');
            }
            compact
        }
        Format::Yaml => {
            let mut out = String::new();
            for event in events {
                out.push_str("---");
                out.push_str(&crate::output::to_yaml(event, 0));
                out.push('\n');
            }
            out
        }
        Format::Table => {
            if events.is_empty() {
                return if filter.is_empty() {
                    "no events\n".into()
                } else {
                    "no events matched the filter\n".into()
                };
            }
            let mut t = Table::new(["TIME", "DECISION", "DIR", "FLOW", "APP", "RULE", "ZONE"]);
            for event in events {
                let flow = event.get("flow");
                let app = event.get("app");
                t.push([
                    string(event, "ts"),
                    string(event, "decision").to_uppercase(),
                    string(event, "direction"),
                    match flow {
                        Some(f) => format!(
                            "{} {}:{} -> {}:{}",
                            string(f, "protocol"),
                            string(f, "src_ip"),
                            string(f, "src_port"),
                            string(f, "dst_ip"),
                            string(f, "dst_port")
                        ),
                        None => "-".into(),
                    },
                    match app {
                        Some(Json::Object(_)) => {
                            let path = string(app.unwrap(), "path");
                            let name = path
                                .rsplit(['/', '\\'])
                                .next()
                                .filter(|s| !s.is_empty())
                                .unwrap_or("-")
                                .to_string();
                            format!("{name}[{}]", string(app.unwrap(), "pid"))
                        }
                        _ => "-".into(),
                    },
                    string(event, "rule"),
                    event
                        .get("network")
                        .map(|n| string(n, "remote_zone"))
                        .unwrap_or_else(|| "-".into()),
                ]);
            }
            t.render()
        }
    }
}

fn string(value: &Json, key: &str) -> String {
    match value.get(key) {
        Some(Json::String(s)) => s.clone(),
        Some(Json::Number(n)) if n.fract() == 0.0 => format!("{}", *n as i64),
        Some(Json::Number(n)) => n.to_string(),
        Some(Json::Bool(b)) => b.to_string(),
        _ => "-".into(),
    }
}

fn compact_json(value: &Json) -> String {
    match value {
        Json::Null => "null".into(),
        Json::Bool(b) => b.to_string(),
        Json::Number(n) => {
            if n.fract() == 0.0 && n.abs() < 1e15 {
                format!("{}", *n as i64)
            } else {
                n.to_string()
            }
        }
        Json::String(s) => ufw_shared::json::escape(s),
        Json::Array(items) => format!(
            "[{}]",
            items.iter().map(compact_json).collect::<Vec<_>>().join(",")
        ),
        Json::Object(map) => format!(
            "{{{}}}",
            map.iter()
                .map(|(k, v)| format!("{}:{}", ufw_shared::json::escape(k), compact_json(v)))
                .collect::<Vec<_>>()
                .join(",")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::ScriptedTransport;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn options(format: Format) -> GlobalOptions {
        GlobalOptions {
            format,
            ..Default::default()
        }
    }

    fn event(ts: &str, decision: &str, rule: &str, app: &str, kind: &str) -> String {
        format!(
            r#"{{"schema":1,"ts":"{ts}","host":"h","seq":1,"kind":"{kind}","severity":"notice",
               "policy_revision":1,"rule_id":1,"rule":"{rule}","layer":"packet",
               "decision":"{decision}","direction":"outbound",
               "flow":{{"protocol":"tcp","src_ip":"10.0.0.1","src_port":40000,
                        "dst_ip":"8.8.8.8","dst_port":443}},
               "network":{{"remote_zone":"external","perimeter_crossing":true}},
               "app":{{"pid":42,"path":"{app}","sha256":null,"signer":null,"trust":"unknown"}},
               "dpi":null,"latency_ns":100,"message":null,"tags":[],"correlation_key":"k"}}"#
        )
        .replace('\n', "")
    }

    struct LogFile {
        path: PathBuf,
    }

    impl LogFile {
        fn new(lines: &[String]) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ufwctl-logs-{}-{}",
                std::process::id(),
                ufw_shared::now_us()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("events.jsonl");
            std::fs::write(&path, lines.join("\n") + "\n").unwrap();
            LogFile { path }
        }
    }

    impl Drop for LogFile {
        fn drop(&mut self) {
            if let Some(dir) = self.path.parent() {
                let _ = std::fs::remove_dir_all(dir);
            }
        }
    }

    fn sample() -> LogFile {
        LogFile::new(&[
            event(
                "2024-01-01T00:00:01.000000Z",
                "allow",
                "allow-dns",
                "/usr/bin/curl",
                "flow-decision",
            ),
            event(
                "2024-01-01T00:00:02.000000Z",
                "deny",
                "block-telnet",
                "/tmp/dropper",
                "flow-decision",
            ),
            event(
                "2024-01-01T00:00:03.000000Z",
                "deny",
                "block-telnet",
                "/tmp/dropper",
                "alert",
            ),
            event(
                "2024-01-02T00:00:00.000000Z",
                "allow",
                "allow-dns",
                "/usr/bin/curl",
                "flow-decision",
            ),
        ])
    }

    #[test]
    fn events_render_as_a_readable_table() {
        let f = sample();
        let mut t = ScriptedTransport::default();
        let out = run(
            &args(&["--file", f.path.to_str().unwrap()]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert!(out.contains("DECISION"));
        assert!(out.contains("ALLOW"));
        assert!(out.contains("DENY"));
        assert!(out.contains("curl[42]"));
        assert!(out.contains("tcp 10.0.0.1:40000 -> 8.8.8.8:443"));
    }

    #[test]
    fn the_tail_limit_keeps_the_most_recent_events() {
        let f = sample();
        let mut t = ScriptedTransport::default();
        let out = run(
            &args(&["--file", f.path.to_str().unwrap(), "--tail", "2"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        // Header plus two rows.
        assert_eq!(out.lines().count(), 3);
        assert!(out.contains("2024-01-02"));
        assert!(!out.contains("00:00:01"));
    }

    #[test]
    fn every_filter_narrows_the_set() {
        let f = sample();
        let path = f.path.to_str().unwrap().to_string();
        let mut t = ScriptedTransport::default();

        let cases: [(Vec<&str>, usize); 5] = [
            (vec!["--decision", "deny"], 2),
            (vec!["--rule", "allow-dns"], 2),
            (vec!["--app", "dropper"], 2),
            (vec!["--kind", "alert"], 1),
            (vec!["--since", "2024-01-02T00:00:00.000000Z"], 1),
        ];
        for (flags, expected) in cases {
            let mut argv = vec!["--file", &path];
            argv.extend(flags.iter());
            let out = run(&args(&argv), &options(Format::Table), &mut t).unwrap();
            assert_eq!(
                out.lines().count(),
                expected + 1,
                "filter {flags:?} returned:\n{out}"
            );
        }
    }

    #[test]
    fn an_empty_result_says_whether_a_filter_was_applied() {
        let f = sample();
        let mut t = ScriptedTransport::default();
        let out = run(
            &args(&["--file", f.path.to_str().unwrap(), "--rule", "nonexistent"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert_eq!(out, "no events matched the filter\n");
    }

    #[test]
    fn a_missing_log_file_points_at_the_configuration() {
        let mut t = ScriptedTransport::default();
        let err = run(
            &args(&["--file", "/nonexistent/events.jsonl"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap_err();
        assert!(err.to_string().contains("logging.file"), "{err}");
    }

    #[test]
    fn a_partial_final_line_is_skipped_not_fatal() {
        // A live log always has a chance of a half-written last line.
        let mut lines = vec![event(
            "2024-01-01T00:00:01.000000Z",
            "allow",
            "r",
            "/usr/bin/x",
            "flow-decision",
        )];
        lines.push("{\"ts\":\"2024".to_string());
        let f = LogFile::new(&lines);
        let mut t = ScriptedTransport::default();
        let out = run(
            &args(&["--file", f.path.to_str().unwrap()]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert_eq!(out.lines().count(), 2);
    }

    #[test]
    fn json_output_is_one_compact_object_per_line() {
        let f = sample();
        let mut t = ScriptedTransport::default();
        let out = run(
            &args(&["--file", f.path.to_str().unwrap(), "--tail", "1"]),
            &options(Format::Json),
            &mut t,
        )
        .unwrap();
        assert_eq!(out.lines().count(), 1);
        assert!(json::parse(out.trim()).is_ok());
    }

    #[test]
    fn a_bad_tail_value_is_a_usage_error() {
        let mut t = ScriptedTransport::default();
        let err = run(&args(&["--tail", "lots"]), &options(Format::Table), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn timestamp_ordering_is_lexical_because_the_format_allows_it() {
        let filter = Filter {
            since: Some("2024-01-01T12:00:00.000000Z".into()),
            ..Default::default()
        };
        let before = json::parse(&event(
            "2024-01-01T11:59:59.999999Z",
            "deny",
            "r",
            "/x",
            "flow-decision",
        ))
        .unwrap();
        let after = json::parse(&event(
            "2024-01-01T12:00:00.000000Z",
            "deny",
            "r",
            "/x",
            "flow-decision",
        ))
        .unwrap();
        assert!(!filter.admits(&before));
        assert!(filter.admits(&after));
    }
}
