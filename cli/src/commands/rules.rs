//! `ufwctl rules` — list and inspect the installed rule set.

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{emit, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl rules <SUBCOMMAND>

SUBCOMMANDS:
    list [--filter <TEXT>]   List installed rules
    show <NAME|ID>           Show one rule in full
    hits                     Per-rule match counters from the kernel module

The filter matches a substring of the rule name, an exact tag, or a rule id.
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let sub = args.first().map(String::as_str).unwrap_or("list");
    let rest = if args.is_empty() { args } else { &args[1..] };

    match sub {
        "-h" | "--help" | "help" => Ok(HELP.to_string()),
        "list" => list(rest, options, transport),
        "show" => {
            let key = super::positionals(rest, &[])
                .first()
                .cloned()
                .ok_or_else(|| CliError::Usage("show needs a rule name or id".into()))?;
            show(&key, options, transport)
        }
        "hits" => hits(options, transport),
        // `ufwctl rules --filter dns` with no subcommand is the common case.
        _ if sub.starts_with('-') => list(args, options, transport),
        other => Err(CliError::Usage(format!(
            "unknown rules subcommand `{other}`"
        ))),
    }
}

fn list(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let filter = super::take_option(args, "--filter");
    let raw = client::call(
        transport,
        RequestBuilder::new("list-rules")
            .opt_str("filter", filter.as_deref())
            .finish(),
    )?;

    Ok(emit(options.format, &raw, |v| {
        let mut t = Table::new([
            "ID", "NAME", "PRI", "LAYER", "DIR", "ACTION", "PROTO", "SOURCE", "DEST", "PORTS",
            "FLAGS",
        ]);
        if let Some(rules) = v.get("rules").and_then(|r| r.as_array()) {
            for rule in rules {
                let mut flags = Vec::new();
                if rule.get("has_identity_predicate").and_then(|b| b.as_bool()) == Some(true) {
                    flags.push("app");
                }
                if rule.get("has_dpi_predicate").and_then(|b| b.as_bool()) == Some(true) {
                    flags.push("dpi");
                }
                if rule.get("ebpf_eligible").and_then(|b| b.as_bool()) == Some(true) {
                    flags.push("fast");
                }
                if rule.get("log").and_then(|b| b.as_bool()) == Some(false) {
                    flags.push("nolog");
                }
                t.push([
                    text(rule, "id"),
                    text(rule, "name"),
                    text(rule, "priority"),
                    text(rule, "layer"),
                    text(rule, "direction"),
                    text(rule, "action"),
                    text(rule, "protocol"),
                    text(rule, "source"),
                    text(rule, "dest"),
                    text(rule, "dest_ports"),
                    flags.join(","),
                ]);
            }
        }
        if t.is_empty() {
            let suffix = filter
                .as_deref()
                .map(|f| format!(" matching `{f}`"))
                .unwrap_or_default();
            return format!("no rules installed{suffix}\n");
        }
        format!(
            "{}\n{} rule(s) at revision {}\n",
            t.render(),
            t.len(),
            text(v, "revision")
        )
    }))
}

fn show(key: &str, options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(
        transport,
        RequestBuilder::new("get-rule").str("key", key).finish(),
    )?;
    Ok(emit(options.format, &raw, |v| {
        let rule = crate::output::field(v, "rule");
        let mut t = Table::new(["", ""]);
        for (label, key) in [
            ("id", "id"),
            ("name", "name"),
            ("priority", "priority"),
            ("layer", "layer"),
            ("direction", "direction"),
            ("action", "action"),
            ("protocol", "protocol"),
            ("source", "source"),
            ("source ports", "source_ports"),
            ("destination", "dest"),
            ("dest ports", "dest_ports"),
        ] {
            t.push([label.to_string(), text(rule, key)]);
        }
        t.push([
            "identity".to_string(),
            if rule.get("has_identity_predicate").and_then(|b| b.as_bool()) == Some(true) {
                "constrained".into()
            } else {
                "any".into()
            },
        ]);
        t.push([
            "inspection".to_string(),
            if rule.get("has_dpi_predicate").and_then(|b| b.as_bool()) == Some(true) {
                "payload inspected".into()
            } else {
                "none".into()
            },
        ]);
        if let Some(tags) = rule.get("tags").and_then(|t| t.as_array()) {
            let names: Vec<&str> = tags.iter().filter_map(|t| t.as_str()).collect();
            if !names.is_empty() {
                t.push(["tags".to_string(), names.join(", ")]);
            }
        }
        t.render()
    }))
}

fn hits(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("stats").finish())?;
    Ok(emit(options.format, &raw, |v| {
        let mut rows: Vec<(u64, String, u64)> = Vec::new();
        if let Some(items) = v.get("rule_hits").and_then(|r| r.as_array()) {
            for item in items {
                rows.push((
                    item.get("rule_id").and_then(|x| x.as_u64()).unwrap_or(0),
                    text(item, "rule"),
                    item.get("hits").and_then(|x| x.as_u64()).unwrap_or(0),
                ));
            }
        }
        if rows.is_empty() {
            return "no rule has matched yet\n".into();
        }
        // Busiest first: the question is usually "what is this policy actually
        // doing?", not "what is rule 4 doing?".
        rows.sort_by_key(|r| std::cmp::Reverse(r.2));

        let mut t = Table::new(["HITS", "ID", "RULE"]);
        for (id, name, hits) in rows {
            t.push([hits.to_string(), id.to_string(), name]);
        }
        t.render()
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::ScriptedTransport;
    use crate::output::Format;

    const RULES: &str = r#"{"ok":true,"revision":7,"rules":[
      {"id":101,"name":"allow-dns","priority":100,"layer":"packet","direction":"outbound",
       "action":"allow","protocol":"udp","source":"any","source_ports":"any",
       "dest":"1.1.1.1/32","dest_ports":"53","has_identity_predicate":false,
       "has_dpi_predicate":false,"ebpf_eligible":true,"log":true,"tags":["baseline"]},
      {"id":202,"name":"browser-web","priority":200,"layer":"identity","direction":"outbound",
       "action":"allow-inspect","protocol":"tcp","source":"any","source_ports":"any",
       "dest":"any","dest_ports":"80,443","has_identity_predicate":true,
       "has_dpi_predicate":false,"ebpf_eligible":false,"log":true,"tags":[]}]}"#;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn options(format: Format) -> GlobalOptions {
        GlobalOptions {
            format,
            ..Default::default()
        }
    }

    #[test]
    fn list_renders_a_table_with_flags() {
        let mut t = ScriptedTransport::new([RULES]);
        let out = run(&args(&["list"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("allow-dns"));
        assert!(out.contains("browser-web"));
        // The identity rule is flagged; the header-only one is fast-path.
        let dns_line = out.lines().find(|l| l.contains("allow-dns")).unwrap();
        let web_line = out.lines().find(|l| l.contains("browser-web")).unwrap();
        assert!(dns_line.trim_end().ends_with("fast"));
        assert!(web_line.trim_end().ends_with("app"));
        assert!(out.contains("2 rule(s) at revision 7"));
    }

    #[test]
    fn list_is_the_default_subcommand() {
        let mut t = ScriptedTransport::new([RULES]);
        let out = run(&[], &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("allow-dns"));
        assert_eq!(t.last_request(), Some(r#"{"op":"list-rules"}"#));
    }

    #[test]
    fn a_bare_filter_flag_still_lists() {
        let mut t = ScriptedTransport::new([RULES]);
        run(&args(&["--filter", "dns"]), &options(Format::Table), &mut t).unwrap();
        assert_eq!(
            t.last_request(),
            Some(r#"{"op":"list-rules","filter":"dns"}"#)
        );
    }

    #[test]
    fn an_empty_result_says_so_rather_than_printing_a_bare_header() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"revision":1,"rules":[]}"#]);
        let out = run(
            &args(&["list", "--filter", "nope"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert_eq!(out, "no rules installed matching `nope`\n");
    }

    #[test]
    fn show_needs_a_key() {
        let mut t = ScriptedTransport::default();
        let err = run(&args(&["show"]), &options(Format::Table), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn show_renders_one_rule_in_full() {
        let response = r#"{"ok":true,"rule":{"id":101,"name":"allow-dns","priority":100,
          "layer":"packet","direction":"outbound","action":"allow","protocol":"udp",
          "source":"any","source_ports":"any","dest":"1.1.1.1/32","dest_ports":"53",
          "has_identity_predicate":false,"has_dpi_predicate":false,"ebpf_eligible":true,
          "log":true,"tags":["baseline"]}}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(
            &args(&["show", "allow-dns"]),
            &options(Format::Table),
            &mut t,
        )
        .unwrap();
        assert!(out.contains("name          allow-dns"));
        assert!(out.contains("identity      any"));
        assert!(out.contains("tags          baseline"));
        assert_eq!(
            t.last_request(),
            Some(r#"{"op":"get-rule","key":"allow-dns"}"#)
        );
    }

    #[test]
    fn hits_are_sorted_busiest_first() {
        let response = r#"{"ok":true,"rule_hits":[
          {"rule_id":1,"rule":"quiet","hits":3},
          {"rule_id":2,"rule":"busy","hits":9000},
          {"rule_id":3,"rule":"middling","hits":42}]}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(&args(&["hits"]), &options(Format::Table), &mut t).unwrap();
        let names: Vec<&str> = out
            .lines()
            .skip(1)
            .filter(|l| !l.trim().is_empty())
            .map(|l| l.split_whitespace().last().unwrap())
            .collect();
        assert_eq!(names, vec!["busy", "middling", "quiet"]);
    }

    #[test]
    fn hits_with_no_matches_says_so() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"rule_hits":[]}"#]);
        let out = run(&args(&["hits"]), &options(Format::Table), &mut t).unwrap();
        assert_eq!(out, "no rule has matched yet\n");
    }

    #[test]
    fn json_output_is_verbatim() {
        let mut t = ScriptedTransport::new([RULES]);
        let out = run(&args(&["list"]), &options(Format::Json), &mut t).unwrap();
        assert_eq!(out, RULES);
    }
}
