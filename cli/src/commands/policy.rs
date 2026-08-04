//! `ufwctl policy` — compile, validate, install, diff and roll back.
//!
//! Three of these subcommands never touch the daemon. `validate`, `compile`
//! and `explain` link the compiler directly, so a policy can be checked in CI
//! on a machine with no daemon, no kernel module and no privileges — which is
//! where a policy mistake is cheapest to catch.

use std::path::{Path, PathBuf};

use ufw_policy_lang::compiler;
use ufw_policy_lang::{CompileOptions, Compilation};
use ufw_shared::policy_types::{Decision, Direction, FlowContext, Protocol};
use ufw_shared::Platform;

use crate::client::{self, RequestBuilder, Transport};
use crate::output::{emit, text, Table};
use crate::{CliError, CliResult, GlobalOptions};

pub const HELP: &str = "\
ufwctl policy <SUBCOMMAND>

SUBCOMMANDS:
    validate <FILE>        Compile a policy file and report problems (no daemon needed)
    compile <FILE>         Compile and write platform artifacts (no daemon needed)
    explain <FILE> <FLOW>  Show which rule decides a flow (no daemon needed)
    reload                 Recompile from the daemon's policy directory and install
    diff                   Compare the on-disk policy against what is installed
    revisions              List retained revisions
    rollback <REVISION>    Reinstall a retained revision
    flush                  Remove every rule, leaving the default action

VALIDATE/COMPILE OPTIONS:
    --deny-warnings        Treat warnings as errors
    --no-verify            Skip the cross-platform equivalence check
    --platform <NAME>      Restrict artifacts to windows|linux|macos
    --out <DIR>            Where `compile` writes artifacts [default: ./build/generated]

EXPLAIN FLOW SYNTAX:
    <proto>:<dst-ip>:<port>[:in|:out]      e.g. tcp:8.8.8.8:443:out
";

pub fn run(args: &[String], options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let Some(sub) = args.first().map(String::as_str) else {
        return Ok(HELP.to_string());
    };
    let rest = &args[1..];
    match sub {
        "-h" | "--help" | "help" => Ok(HELP.to_string()),
        "validate" => validate_offline(rest, options),
        "compile" => compile_offline(rest, options),
        "explain" => explain_offline(rest, options),
        "reload" => simple(options, transport, "reload-policy"),
        "diff" => simple(options, transport, "diff-policy"),
        "flush" => simple(options, transport, "flush-policy"),
        "revisions" => revisions(options, transport),
        "rollback" => {
            let revision = super::positionals(rest, &[])
                .first()
                .ok_or_else(|| CliError::Usage("rollback needs a revision number".into()))?
                .parse::<u64>()
                .map_err(|_| CliError::Usage("the revision must be a number".into()))?;
            let raw = client::call(
                transport,
                RequestBuilder::new("rollback").num("revision", revision).finish(),
            )?;
            Ok(emit(options.format, &raw, |v| {
                format!("{}\n", text(v, "message"))
            }))
        }
        other => Err(CliError::Usage(format!("unknown policy subcommand `{other}`"))),
    }
}

fn simple(options: &GlobalOptions, transport: &mut dyn Transport, op: &str) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new(op).finish())?;
    Ok(emit(options.format, &raw, |v| {
        format!("{}\n", text(v, "message"))
    }))
}

fn revisions(options: &GlobalOptions, transport: &mut dyn Transport) -> CliResult {
    let raw = client::call(transport, RequestBuilder::new("list-revisions").finish())?;
    Ok(emit(options.format, &raw, |v| {
        let mut t = Table::new(["REVISION", "RULES", "ORIGIN", "ACTIVATED", "ACTIVE"]);
        if let Some(items) = v.get("revisions").and_then(|r| r.as_array()) {
            for item in items {
                t.push([
                    text(item, "revision"),
                    text(item, "rules"),
                    text(item, "origin"),
                    text(item, "activated_at"),
                    if item.get("active").and_then(|a| a.as_bool()) == Some(true) {
                        "*".into()
                    } else {
                        String::new()
                    },
                ]);
            }
        }
        if t.is_empty() {
            return "no revisions retained\n".into();
        }
        t.render()
    }))
}

// ===========================================================================
// Offline
// ===========================================================================

fn compile_options(args: &[String]) -> Result<(CompileOptions, PathBuf), CliError> {
    let mut opts = CompileOptions {
        deny_warnings: super::has_flag(args, "--deny-warnings"),
        verify_equivalence: !super::has_flag(args, "--no-verify"),
        ..Default::default()
    };
    if let Some(name) = super::take_option(args, "--platform") {
        let platform = Platform::parse(&name)
            .ok_or_else(|| CliError::Usage(format!("`{name}` is not a platform")))?;
        opts.platforms = vec![platform];
        // Equivalence is a statement about three backends agreeing; with one
        // backend there is nothing to compare.
        opts.verify_equivalence = false;
    }
    let out = super::take_option(args, "--out")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("build/generated"));
    Ok((opts, out))
}

fn policy_path(args: &[String]) -> Result<PathBuf, CliError> {
    super::positionals(args, &["--platform", "--out"])
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Usage("a policy file is required".into()))
}

fn compile(path: &Path, options: &CompileOptions) -> Result<Compilation, CliError> {
    ufw_policy_lang::compile_file(path, options)
        .map_err(|e| CliError::Local(format!("{}: {e}", path.display())))
}

/// `ufwctl policy validate <FILE>`
pub fn validate_offline(args: &[String], options: &GlobalOptions) -> CliResult {
    let path = policy_path(args)?;
    let (compile_options, _) = compile_options(args)?;
    let result = compile(&path, &compile_options)?;

    let rendered = result.render();
    let Some(policy) = &result.policy else {
        return Err(CliError::Local(format!(
            "{}\n{} failed to compile",
            rendered,
            path.display()
        )));
    };

    if options.format != crate::output::Format::Table {
        // Machine-readable validation output, for CI.
        let mut w = ufw_shared::json::JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.str_field("file", &path.display().to_string());
        w.u64_field("rules", policy.rules.len() as u64);
        w.u64_field("warnings", result.diagnostics.warning_count() as u64);
        w.str_field("ruleset_sha256", &ufw_shared::hash::hex(&policy.ruleset_hash));
        w.u64_field(
            "equivalence_scenarios",
            result
                .equivalence
                .as_ref()
                .map(|e| e.scenarios_checked as u64)
                .unwrap_or(0),
        );
        w.end_object();
        return Ok(emit(options.format, &w.finish(), |_| String::new()));
    }

    let mut out = String::new();
    if !rendered.is_empty() {
        out.push_str(&rendered);
        out.push('\n');
    }
    out.push_str(&format!(
        "{} is valid: {} rules, {} warning(s)\n",
        path.display(),
        policy.rules.len(),
        result.diagnostics.warning_count()
    ));
    out.push_str(&format!(
        "  ruleset      sha256:{}\n",
        ufw_shared::hash::hex(&policy.ruleset_hash)
    ));
    out.push_str(&format!(
        "  optimizer    {} rule(s) removed, {} eligible for the eBPF fast path\n",
        result.optimization.rules_removed(),
        result.optimization.ebpf_eligible
    ));
    match &result.equivalence {
        Some(eq) => out.push_str(&format!(
            "  equivalence  verified across {} scenarios on {}\n",
            eq.scenarios_checked,
            Platform::ALL
                .iter()
                .map(|p| p.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        )),
        None => out.push_str("  equivalence  not checked\n"),
    }
    Ok(out)
}

/// `ufwctl policy compile <FILE> --out <DIR>`
pub fn compile_offline(args: &[String], options: &GlobalOptions) -> CliResult {
    let path = policy_path(args)?;
    let (compile_options, out_dir) = compile_options(args)?;
    let result = compile(&path, &compile_options)?;

    let Some(policy) = &result.policy else {
        return Err(CliError::Local(format!(
            "{}\n{} failed to compile",
            result.render(),
            path.display()
        )));
    };

    let mut written = Vec::new();
    for artifact in &result.artifacts {
        for file in &artifact.files {
            let target = out_dir.join(&file.path);
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)
                    .map_err(|e| CliError::Local(format!("{}: {e}", parent.display())))?;
            }
            std::fs::write(&target, &file.contents)
                .map_err(|e| CliError::Local(format!("{}: {e}", target.display())))?;
            written.push((artifact.platform, target, file.contents.len()));
        }
    }

    if options.format != crate::output::Format::Table {
        let mut w = ufw_shared::json::JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.u64_field("rules", policy.rules.len() as u64);
        w.begin_array_field("artifacts");
        for (platform, target, size) in &written {
            w.begin_object();
            w.str_field("platform", platform.as_str());
            w.str_field("path", &target.display().to_string());
            w.u64_field("bytes", *size as u64);
            w.end_object();
        }
        w.end_array();
        w.end_object();
        return Ok(emit(options.format, &w.finish(), |_| String::new()));
    }

    let mut t = Table::new(["PLATFORM", "ARTIFACT", "SIZE"]);
    for (platform, target, size) in &written {
        t.push([
            platform.as_str().to_string(),
            target.display().to_string(),
            crate::output::bytes(*size as u64),
        ]);
    }
    Ok(format!(
        "{}\n{} rules compiled for {} platform(s)\n",
        t.render(),
        policy.rules.len(),
        result.artifacts.len()
    ))
}

/// `ufwctl policy explain <FILE> <FLOW>`
///
/// The question an operator actually asks — "why was this blocked?" — answered
/// against a policy file without needing to reproduce the traffic.
pub fn explain_offline(args: &[String], options: &GlobalOptions) -> CliResult {
    let positionals = super::positionals(args, &["--platform", "--out"]);
    let path = positionals
        .first()
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Usage("a policy file is required".into()))?;
    let flow = positionals
        .get(1)
        .ok_or_else(|| CliError::Usage("a flow is required, e.g. tcp:8.8.8.8:443:out".into()))?;

    let (compile_options, _) = compile_options(args)?;
    let result = compile(&path, &compile_options)?;
    let Some(policy) = result.policy.clone() else {
        return Err(CliError::Local(format!(
            "{}\n{} failed to compile",
            result.render(),
            path.display()
        )));
    };

    let spec = parse_flow(flow)?;
    let ctx = FlowContext::new(
        &policy.network_profile,
        spec.direction,
        spec.protocol,
        ("10.0.0.1".parse().unwrap(), 40000),
        (spec.dst, spec.port),
    );
    let evaluation = policy.evaluate(&ctx);

    if options.format != crate::output::Format::Table {
        let mut w = ufw_shared::json::JsonWriter::new();
        w.begin_object();
        w.bool_field("ok", true);
        w.str_field("flow", flow);
        w.str_field("decision", evaluation.decision.as_str());
        w.u64_field("rule_id", evaluation.rule_id as u64);
        w.opt_str_field(
            "rule",
            policy.find(evaluation.rule_id).map(|r| r.name.as_str()),
        );
        w.str_field("layer", evaluation.layer.as_str());
        w.str_field("remote_zone", ctx.remote_zone().as_str());
        w.end_object();
        return Ok(emit(options.format, &w.finish(), |_| String::new()));
    }

    let mut out = String::new();
    out.push_str(&format!(
        "{} {} -> {}:{}\n",
        spec.protocol.as_str(),
        spec.direction.as_str(),
        spec.dst,
        spec.port
    ));
    out.push_str(&format!(
        "  decision   {}\n",
        evaluation.decision.as_str().to_uppercase()
    ));
    match policy.find(evaluation.rule_id) {
        Some(rule) => {
            out.push_str(&format!("  rule       {} (id {})\n", rule.name, rule.id));
            out.push_str(&format!(
                "  layer      {} at priority {}\n",
                rule.layer.as_str(),
                rule.priority
            ));
            if rule.app.is_some() {
                out.push_str(
                    "  note       this rule also constrains application identity, which was \
                     not supplied here\n",
                );
            }
        }
        None => out.push_str("  rule       (policy default; no rule matched)\n"),
    }
    out.push_str(&format!("  zone       {}\n", ctx.remote_zone().as_str()));
    if !evaluation.alerts.is_empty() {
        out.push_str(&format!("  alerts     {:?}\n", evaluation.alerts));
    }

    // The same question asked of each backend, which is what proves the answer
    // is not platform-specific.
    out.push_str("\nper-platform verdict:\n");
    let mut t = Table::new(["PLATFORM", "DECISION", "RULE"]);
    for artifact in compiler::compile_all(&policy) {
        let (decision, rule_id) = artifact.model.evaluate(&ctx);
        t.push([
            artifact.platform.as_str().to_string(),
            decision.as_str().to_string(),
            policy
                .find(rule_id)
                .map(|r| r.name.clone())
                .unwrap_or_else(|| "(default)".into()),
        ]);
    }
    out.push_str(&t.render());
    if evaluation.decision == Decision::Deny {
        out.push('\n');
    }
    Ok(out)
}

#[derive(Debug)]
struct FlowSpec {
    protocol: Protocol,
    dst: std::net::IpAddr,
    port: u16,
    direction: Direction,
}

fn parse_flow(text: &str) -> Result<FlowSpec, CliError> {
    // `proto:addr:port[:direction]`, with IPv6 addresses in brackets.
    let (protocol_text, rest) = text
        .split_once(':')
        .ok_or_else(|| CliError::Usage("a flow looks like tcp:8.8.8.8:443:out".into()))?;
    let protocol = Protocol::parse(protocol_text)
        .ok_or_else(|| CliError::Usage(format!("`{protocol_text}` is not a protocol")))?;

    let (addr_text, rest) = if let Some(stripped) = rest.strip_prefix('[') {
        let end = stripped
            .find(']')
            .ok_or_else(|| CliError::Usage("unterminated IPv6 literal".into()))?;
        (&stripped[..end], stripped[end + 1..].trim_start_matches(':'))
    } else {
        rest.split_once(':')
            .ok_or_else(|| CliError::Usage("a flow needs a port".into()))?
    };

    let dst = addr_text
        .parse::<std::net::IpAddr>()
        .map_err(|_| CliError::Usage(format!("`{addr_text}` is not an IP address")))?;

    let (port_text, direction_text) = match rest.split_once(':') {
        Some((p, d)) => (p, Some(d)),
        None => (rest, None),
    };
    let port = port_text
        .parse::<u16>()
        .map_err(|_| CliError::Usage(format!("`{port_text}` is not a port")))?;
    let direction = match direction_text {
        None => Direction::Outbound,
        Some(d) => Direction::parse(d)
            .ok_or_else(|| CliError::Usage(format!("`{d}` is not a direction")))?,
    };

    Ok(FlowSpec { protocol, dst, port, direction })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::testing::ScriptedTransport;
    use crate::output::Format;

    const POLICY: &str = "\
version: 1
defaults:
  action: deny
network_profile:
  internal: [10.0.0.0/8]
rules:
  - id: allow-dns
    priority: 100
    action: allow
    protocol: udp
    destination:
      ports: [53]
  - id: block-telnet
    priority: 50
    action: deny
    protocol: tcp
    destination:
      ports: [23]
";

    struct Fixture {
        dir: PathBuf,
    }

    impl Fixture {
        fn new(name: &str) -> Self {
            let dir = std::env::temp_dir().join(format!(
                "ufwctl-{}-{}-{name}",
                std::process::id(),
                ufw_shared::now_us()
            ));
            std::fs::create_dir_all(&dir).unwrap();
            Fixture { dir }
        }
        fn write(&self, name: &str, text: &str) -> PathBuf {
            let path = self.dir.join(name);
            std::fs::write(&path, text).unwrap();
            path
        }
    }

    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|s| s.to_string()).collect()
    }

    fn options(format: Format) -> GlobalOptions {
        GlobalOptions { format, ..Default::default() }
    }

    #[test]
    fn validate_works_without_a_daemon() {
        let f = Fixture::new("validate");
        let path = f.write("p.yaml", POLICY);
        let out =
            validate_offline(&args(&[path.to_str().unwrap()]), &options(Format::Table)).unwrap();
        assert!(out.contains("is valid: 2 rules"));
        assert!(out.contains("equivalence  verified across"));
    }

    #[test]
    fn validate_reports_compiler_diagnostics_and_fails() {
        let f = Fixture::new("invalid");
        let path = f.write("p.yaml", "version: 1\nrules:\n  - id: a\n");
        let err =
            validate_offline(&args(&[path.to_str().unwrap()]), &options(Format::Table)).unwrap_err();
        let text = err.to_string();
        assert!(text.contains("E0201"), "{text}");
        assert_eq!(err.exit_code(), 1);
    }

    #[test]
    fn deny_warnings_makes_a_lint_fail_the_build() {
        let f = Fixture::new("lint");
        let path = f.write(
            "p.yaml",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n",
        );
        let p = path.to_str().unwrap();
        assert!(validate_offline(&args(&[p]), &options(Format::Table)).is_ok());
        assert!(validate_offline(&args(&[p, "--deny-warnings"]), &options(Format::Table)).is_err());
    }

    #[test]
    fn validate_emits_machine_readable_output_for_ci() {
        let f = Fixture::new("ci");
        let path = f.write("p.yaml", POLICY);
        let out =
            validate_offline(&args(&[path.to_str().unwrap()]), &options(Format::Json)).unwrap();
        let v = ufw_shared::json::parse(&out).unwrap();
        assert_eq!(v.get("rules").unwrap().as_u64(), Some(2));
        assert!(v.get("equivalence_scenarios").unwrap().as_u64().unwrap() > 0);
    }

    #[test]
    fn compile_writes_artifacts_for_every_platform() {
        let f = Fixture::new("compile");
        let path = f.write("p.yaml", POLICY);
        let out_dir = f.dir.join("out");
        let out = compile_offline(
            &args(&[path.to_str().unwrap(), "--out", out_dir.to_str().unwrap()]),
            &options(Format::Table),
        )
        .unwrap();

        assert!(out.contains("3 platform(s)"));
        for expected in [
            "windows/ufw_filters.json",
            "linux/ufw_ebpf_rules.h",
            "macos/UFWPolicy.generated.swift",
        ] {
            assert!(out_dir.join(expected).exists(), "{expected} was not written");
        }
    }

    #[test]
    fn compile_can_target_one_platform() {
        let f = Fixture::new("single");
        let path = f.write("p.yaml", POLICY);
        let out_dir = f.dir.join("out");
        compile_offline(
            &args(&[
                path.to_str().unwrap(),
                "--platform",
                "linux",
                "--out",
                out_dir.to_str().unwrap(),
            ]),
            &options(Format::Table),
        )
        .unwrap();
        assert!(out_dir.join("linux/ufw_policy.json").exists());
        assert!(!out_dir.join("windows").exists());
    }

    #[test]
    fn explain_answers_why_a_flow_was_decided() {
        let f = Fixture::new("explain");
        let path = f.write("p.yaml", POLICY);

        let allowed = explain_offline(
            &args(&[path.to_str().unwrap(), "udp:8.8.8.8:53:out"]),
            &options(Format::Table),
        )
        .unwrap();
        assert!(allowed.contains("decision   ALLOW"));
        assert!(allowed.contains("allow-dns"));

        let denied = explain_offline(
            &args(&[path.to_str().unwrap(), "tcp:8.8.8.8:23:out"]),
            &options(Format::Table),
        )
        .unwrap();
        assert!(denied.contains("decision   DENY"));
        assert!(denied.contains("block-telnet"));

        let defaulted = explain_offline(
            &args(&[path.to_str().unwrap(), "tcp:8.8.8.8:443:out"]),
            &options(Format::Table),
        )
        .unwrap();
        assert!(defaulted.contains("policy default"));
    }

    #[test]
    fn explain_shows_that_every_platform_agrees() {
        let f = Fixture::new("agree");
        let path = f.write("p.yaml", POLICY);
        let out = explain_offline(
            &args(&[path.to_str().unwrap(), "udp:8.8.8.8:53:out"]),
            &options(Format::Table),
        )
        .unwrap();
        for platform in ["windows", "linux", "macos"] {
            assert!(out.contains(platform), "{platform} missing from:\n{out}");
        }
    }

    #[test]
    fn flow_syntax_covers_ipv6_and_direction() {
        let spec = parse_flow("tcp:[2001:db8::1]:443:in").unwrap();
        assert_eq!(spec.protocol, Protocol::Tcp);
        assert_eq!(spec.port, 443);
        assert_eq!(spec.direction, Direction::Inbound);
        assert!(spec.dst.is_ipv6());

        // Direction defaults to outbound, which is the common case.
        assert_eq!(parse_flow("udp:1.1.1.1:53").unwrap().direction, Direction::Outbound);
    }

    #[test]
    fn malformed_flows_are_usage_errors() {
        for bad in ["", "tcp", "tcp:notanip:443", "tcp:1.1.1.1:notaport", "zz:1.1.1.1:1"] {
            assert_eq!(parse_flow(bad).unwrap_err().exit_code(), 2, "for {bad:?}");
        }
    }

    #[test]
    fn rollback_requires_a_numeric_revision() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"done"}"#]);
        let err = run(&args(&["rollback", "soon"]), &options(Format::Table), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn rollback_sends_the_revision() {
        let mut t = ScriptedTransport::new([r#"{"ok":true,"message":"rolled back"}"#]);
        let out = run(&args(&["rollback", "4"]), &options(Format::Table), &mut t).unwrap();
        assert_eq!(t.last_request(), Some(r#"{"op":"rollback","revision":4}"#));
        assert_eq!(out.trim(), "rolled back");
    }

    #[test]
    fn revisions_render_as_a_table_with_the_active_one_marked() {
        let response = r#"{"ok":true,"revisions":[
            {"revision":2,"name":"p","rules":5,"origin":"base.yaml",
             "activated_at":"2024-01-01T00:00:00.000000Z","ruleset_sha256":"ab","active":true},
            {"revision":1,"name":"p","rules":4,"origin":"base.yaml",
             "activated_at":"2023-12-31T00:00:00.000000Z","ruleset_sha256":"cd","active":false}]}"#;
        let mut t = ScriptedTransport::new([response]);
        let out = run(&args(&["revisions"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("REVISION"));
        let active_line = out.lines().find(|l| l.starts_with("2 ")).unwrap();
        assert!(active_line.trim_end().ends_with('*'));
    }

    #[test]
    fn an_unknown_subcommand_is_a_usage_error() {
        let mut t = ScriptedTransport::default();
        let err = run(&args(&["teleport"]), &options(Format::Table), &mut t).unwrap_err();
        assert_eq!(err.exit_code(), 2);
    }

    #[test]
    fn help_is_available_without_a_daemon() {
        let mut t = ScriptedTransport::default();
        let out = run(&args(&["--help"]), &options(Format::Table), &mut t).unwrap();
        assert!(out.contains("SUBCOMMANDS"));
    }
}
