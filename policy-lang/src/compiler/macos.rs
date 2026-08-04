//! macOS backend: Network Extension configuration and rule table.
//!
//! # One engine, two entry points
//!
//! Unlike Windows and Linux, macOS gives no choice of hook: `NEFilterDataProvider`
//! is the only supported network filter on modern macOS, and it delivers
//! decisions through `handleNewFlow` for connection-oriented traffic and
//! `handleNewPacket` (in a separate `NEFilterPacketProvider`) for everything
//! else. Both call into the same `RuleEngine`, which walks one ordered table,
//! so evaluation order here is simply reference order and there is no
//! layer-interleaving hazard to reason about.
//!
//! The rules are still split across the two entry points for the same reason
//! as on Windows: `handleNewFlow` never fires for ICMP. A rule that could match
//! both is installed at both, scoped so the two copies are disjoint.
//!
//! # Constraints this backend has to respect
//!
//! * **A verdict is due within a system timeout.** The generated configuration
//!   carries the compiler's own budget ([`constants::FLOW_VERDICT_BUDGET_MS`]),
//!   which the provider uses to bail out to the policy default rather than let
//!   the system time the flow out and drop it.
//! * **Reassembly memory is scarce.** The extension runs sandboxed, so the DPI
//!   buffer budget emitted here is [`constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS`],
//!   an order of magnitude below the other two platforms. A scan that hits the
//!   ceiling reports `truncated`, and the reference semantics already say a DPI
//!   predicate is not satisfied without evidence — so a truncated scan fails
//!   closed onto whatever the flow-level rules decided, it does not silently
//!   allow.
//! * **Flow data is readable but not modifiable.** Nothing in the policy
//!   language asks for modification, so this costs nothing today; it is why
//!   there is no `redirect` action.

use std::fmt::Write as _;

use ufw_shared::json::JsonWriter;
use ufw_shared::policy_types::*;
use ufw_shared::{constants, Platform};

use crate::compiler::{
    evaluation_order_key, Artifact, Backend, DecisionModel, Engine, GeneratedFile, ModelRule,
    ProtocolScope,
};
use crate::error::{codes, Diagnostic, Diagnostics, Span};

pub struct MacOsBackend;

/// Protocols delivered through `handleNewFlow`.
const FLOW_PROTOCOLS: [Protocol; 2] = [Protocol::Tcp, Protocol::Udp];

impl Backend for MacOsBackend {
    fn platform(&self) -> Platform {
        Platform::MacOS
    }

    fn generate(&self, policy: &CompiledPolicy) -> Artifact {
        let mut notes = Diagnostics::new();
        let placements = plan(policy, &mut notes);
        let model = DecisionModel {
            platform: Platform::MacOS,
            default_action: policy.default_action,
            profile: policy.network_profile.clone(),
            rules: placements
                .iter()
                .map(|p| {
                    let mut m = ModelRule::new(p.rule, p.engine);
                    m.order_key = evaluation_order_key(p.rule);
                    m.scope = p.scope.clone();
                    m
                })
                .collect(),
        };

        let files = vec![
            GeneratedFile::new("macos/ufw-policy.json", emit_json(policy, &placements)),
            GeneratedFile::new(
                "macos/UFWPolicy.generated.swift",
                emit_swift(policy, &placements),
            ),
        ];

        Artifact {
            platform: Platform::MacOS,
            files,
            model,
            notes,
        }
    }
}

struct Placement<'a> {
    rule: &'a CompiledRule,
    engine: Engine,
    scope: ProtocolScope,
}

fn plan<'a>(policy: &'a CompiledPolicy, notes: &mut Diagnostics) -> Vec<Placement<'a>> {
    let mut ordered: Vec<&CompiledRule> = policy.rules.iter().collect();
    ordered.sort_by_key(|r| evaluation_order_key(r));

    let mut out = Vec::new();
    let mut dpi_rules = 0usize;

    for rule in ordered {
        if rule.dpi.is_some() {
            dpi_rules += 1;
        }
        match rule.layer {
            Layer::AppDpi | Layer::Stream => {
                // Payload inspection only exists for flows.
                out.push(Placement {
                    rule,
                    engine: Engine::NeFlow,
                    scope: ProtocolScope::Only(FLOW_PROTOCOLS.to_vec()),
                });
            }
            _ => {
                if rule.protocol == Protocol::Any || FLOW_PROTOCOLS.contains(&rule.protocol) {
                    out.push(Placement {
                        rule,
                        engine: Engine::NeFlow,
                        scope: ProtocolScope::Only(FLOW_PROTOCOLS.to_vec()),
                    });
                }
                if rule.protocol == Protocol::Any || !FLOW_PROTOCOLS.contains(&rule.protocol) {
                    if rule.app.is_some() {
                        // `handleNewPacket` has no `sourceAppAuditToken`, so an
                        // identity predicate cannot be evaluated there. The
                        // reference semantics agree: an identity predicate
                        // without an identity never matches.
                        notes.push(Diagnostic::note(
                            codes::EBPF_OFFLOAD,
                            Span::default(),
                            format!(
                                "rule `{}` is identity-scoped and is installed only on the flow \
                                 provider; the packet provider has no audit token to match on",
                                rule.name
                            ),
                        ));
                    } else {
                        out.push(Placement {
                            rule,
                            engine: Engine::NePacket,
                            scope: ProtocolScope::Excluding(FLOW_PROTOCOLS.to_vec()),
                        });
                    }
                }
            }
        }
    }

    if dpi_rules > 0 {
        notes.push(
            Diagnostic::note(
                codes::DPI_BUFFER_BUDGET,
                Span::default(),
                format!(
                    "{dpi_rules} rule(s) need payload inspection; the Network Extension sandbox \
                     buffers at most {} KiB per flow, and a scan that hits that ceiling is \
                     reported as truncated rather than as a clean miss",
                    constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS / 1024
                ),
            )
            .with_help(
                "keep signatures anchored near the start of a stream so they resolve inside the \
                 buffer budget",
            ),
        );
    }

    out
}

/// The `NEFilterNewFlowVerdict` a rule maps to.
///
/// `allow-inspect` becomes `filterDataVerdict`, which permits the flow while
/// keeping the provider subscribed to its data — exactly the semantics the
/// action was introduced for. A plain `allow` becomes `allow()`, which detaches
/// the provider from the flow entirely and is therefore cheaper.
fn ne_verdict(action: Action) -> &'static str {
    match action {
        Action::Allow => "NEFilterNewFlowVerdict.allow()",
        Action::Deny => "NEFilterNewFlowVerdict.drop()",
        Action::AllowInspect => {
            "NEFilterNewFlowVerdict.filterDataVerdict(withFilterInbound:true, peekInboundBytes:Int.max, filterOutbound:true, peekOutboundBytes:Int.max)"
        }
        Action::Alert | Action::Continue => "nil",
    }
}

fn swift_action_case(action: Action) -> &'static str {
    match action {
        Action::Allow => ".allow",
        Action::Deny => ".deny",
        Action::AllowInspect => ".allowInspect",
        Action::Alert => ".alert",
        Action::Continue => ".continueEvaluation",
    }
}

// ===========================================================================
// JSON payload (shipped to the extension over XPC)
// ===========================================================================

fn emit_json(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> String {
    let mut w = JsonWriter::with_capacity(4096);
    w.begin_object();
    w.str_field("format", "ufw-macos-policy");
    w.u64_field("format_version", 1);
    w.str_field("policy", &policy.name);
    w.u64_field("revision", policy.revision);
    w.str_field(
        "ruleset_sha256",
        &ufw_shared::hash::hex(&policy.ruleset_hash),
    );
    w.str_field("default_action", policy.default_action.as_str());
    w.str_field("xpc_service", constants::MACOS_XPC_SERVICE);
    w.str_field("app_group", constants::MACOS_APP_GROUP);
    w.u64_field("verdict_budget_ms", constants::FLOW_VERDICT_BUDGET_MS);
    w.u64_field(
        "reassembly_budget_bytes",
        constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS as u64,
    );

    w.begin_object_field("network_profile");
    let internal: Vec<String> = policy
        .network_profile
        .internal
        .iter()
        .map(|c| c.to_string())
        .collect();
    let perimeter: Vec<String> = policy
        .network_profile
        .perimeter
        .iter()
        .map(|c| c.to_string())
        .collect();
    w.str_array_field("internal", internal.iter().map(|s| s.as_str()));
    w.str_array_field("perimeter", perimeter.iter().map(|s| s.as_str()));
    w.bool_field(
        "perimeter_crossing_requires_dpi",
        policy.network_profile.perimeter_crossing_requires_dpi,
    );
    w.end_object();

    w.begin_array_field("rules");
    for p in placements {
        let r = p.rule;
        w.begin_object();
        w.u64_field("id", r.id as u64);
        w.str_field("name", &r.name);
        w.str_field("stage", r.layer.as_str());
        w.u64_field("priority", r.priority as u64);
        w.str_field("provider", p.engine.as_str());
        w.str_field("protocol_scope", &p.scope.describe());
        w.str_field("action", r.effective_action().as_str());
        w.str_field("verdict", ne_verdict(r.effective_action()));
        w.str_field("direction", r.direction.as_str());
        w.str_field("protocol", &r.protocol.as_str());
        w.str_field("source", &render_address(&r.source));
        w.str_field("source_ports", &render_ports(&r.source_ports));
        w.str_field("dest", &render_address(&r.dest));
        w.str_field("dest_ports", &render_ports(&r.dest_ports));

        match &r.app {
            Some(app) => {
                w.begin_object_field("application");
                w.begin_array_field("fingerprints");
                for fp in &app.fingerprints {
                    w.begin_object();
                    let paths: Vec<&str> = fp.paths.iter().map(|p| p.pattern.as_str()).collect();
                    w.str_array_field("paths", paths);
                    let hashes: Vec<String> =
                        fp.sha256.iter().map(|h| ufw_shared::hash::hex(h)).collect();
                    w.str_array_field("sha256", hashes.iter().map(|s| s.as_str()));
                    w.str_array_field("signers", fp.signers.iter().map(|s| s.as_str()));
                    w.str_array_field("team_ids", fp.team_ids.iter().map(|s| s.as_str()));
                    w.str_array_field("bundle_ids", fp.bundle_ids.iter().map(|s| s.as_str()));
                    w.end_object();
                }
                w.end_array();
                let trust: Vec<&str> = app.trust.levels().map(|l| l.as_str()).collect();
                w.str_array_field("trust", trust);
                w.bool_field("require_valid_signature", app.require_valid_signature);
                w.bool_field("negate", app.negate);
                w.end_object();
            }
            None => w.null_field("application"),
        }

        match &r.dpi {
            Some(dpi) => {
                w.begin_object_field("dpi");
                w.begin_array_field("signatures");
                for s in &dpi.signatures {
                    w.u64_element(*s as u64);
                }
                w.end_array();
                let l7: Vec<&str> = dpi.l7.iter().map(|p| p.as_str()).collect();
                w.str_array_field("protocols", l7);
                w.str_field("on_match", dpi.on_match.as_str());
                w.end_object();
            }
            None => w.null_field("dpi"),
        }

        w.bool_field("log", r.log);
        w.str_array_field("tags", r.tags.iter().map(|s| s.as_str()));
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.finish()
}

// ===========================================================================
// Swift rule table
// ===========================================================================

fn emit_swift(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> String {
    let mut s = String::with_capacity(8192);
    let _ = write!(
        s,
        "//\n\
         // Generated by the Unified Policy Language compiler. Do not edit.\n\
         //\n\
         // policy   : {}\n\
         // revision : {}\n\
         // ruleset  : sha256:{}\n\
         //\n\
         // Consumed by RuleEngine.swift. In normal operation the daemon pushes the\n\
         // equivalent JSON over XPC; this file exists so a build can ship with a\n\
         // policy compiled in, and so the rule table is reviewable in the same pull\n\
         // request as the policy source.\n\
         //\n\n\
         import Foundation\n\n\
         enum UFWGeneratedPolicy {{\n\
         \x20   static let name = \"{}\"\n\
         \x20   static let revision: UInt64 = {}\n\
         \x20   static let rulesetSHA256 = \"{}\"\n\
         \x20   static let defaultAction: UFWAction = .{}\n\
         \x20   static let verdictBudgetMilliseconds: UInt64 = {}\n\
         \x20   static let reassemblyBudgetBytes = {}\n\n",
        policy.name,
        policy.revision,
        ufw_shared::hash::hex(&policy.ruleset_hash),
        escape_swift(&policy.name),
        policy.revision,
        ufw_shared::hash::hex(&policy.ruleset_hash),
        policy.default_action.as_str(),
        constants::FLOW_VERDICT_BUDGET_MS,
        constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS,
    );

    let _ = write!(
        s,
        "    static let internalNetworks: [String] = [{}]\n\
         \x20   static let perimeterNetworks: [String] = [{}]\n\
         \x20   static let perimeterCrossingRequiresDPI = {}\n\n",
        policy
            .network_profile
            .internal
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", "),
        policy
            .network_profile
            .perimeter
            .iter()
            .map(|c| format!("\"{c}\""))
            .collect::<Vec<_>>()
            .join(", "),
        policy.network_profile.perimeter_crossing_requires_dpi,
    );

    s.push_str("    /// Rules in evaluation order. RuleEngine walks this table top to bottom.\n");
    s.push_str("    static let rules: [UFWRule] = [\n");
    for p in placements {
        let r = p.rule;
        let _ = write!(
            s,
            "        UFWRule(\n\
             \x20           id: {},\n\
             \x20           name: \"{}\",\n\
             \x20           stage: .{},\n\
             \x20           priority: {},\n\
             \x20           provider: .{},\n\
             \x20           protocolScope: .{},\n\
             \x20           action: {},\n\
             \x20           direction: .{},\n\
             \x20           ipProtocol: {},\n\
             \x20           sourceCIDRs: [{}],\n\
             \x20           sourcePorts: [{}],\n\
             \x20           destCIDRs: [{}],\n\
             \x20           destPorts: [{}],\n\
             \x20           sourceZones: [{}],\n\
             \x20           destZones: [{}],\n\
             \x20           application: {},\n\
             \x20           dpi: {},\n\
             \x20           shouldLog: {}\n\
             \x20       ),\n",
            r.id,
            escape_swift(&r.name),
            swift_stage(r.layer),
            r.priority,
            match p.engine {
                Engine::NePacket => "packet",
                _ => "flow",
            },
            match &p.scope {
                ProtocolScope::Any => "any",
                ProtocolScope::Only(_) => "connectionOriented",
                ProtocolScope::Excluding(_) => "connectionless",
            },
            swift_action_case(r.effective_action()),
            r.direction.as_str(),
            r.protocol
                .number()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "nil".into()),
            swift_strings(r.source.cidrs.iter().map(|c| c.to_string())),
            swift_ports(&r.source_ports.ranges),
            swift_strings(r.dest.cidrs.iter().map(|c| c.to_string())),
            swift_ports(&r.dest_ports.ranges),
            swift_strings(r.source.zones.iter().map(|z| z.as_str().to_string())),
            swift_strings(r.dest.zones.iter().map(|z| z.as_str().to_string())),
            swift_app(r.app.as_ref()),
            swift_dpi(r.dpi.as_ref()),
            r.log,
        );
    }
    s.push_str("    ]\n}\n");
    s
}

fn swift_stage(l: Layer) -> &'static str {
    match l {
        Layer::Perimeter => "perimeter",
        Layer::Packet => "packet",
        Layer::Identity => "identity",
        Layer::AppDpi => "appDPI",
        Layer::Stream => "stream",
    }
}

fn swift_strings<I: IntoIterator<Item = String>>(items: I) -> String {
    items
        .into_iter()
        .map(|s| format!("\"{}\"", escape_swift(&s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn swift_ports(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|r| format!("UFWPortRange({}, {})", r.lo, r.hi))
        .collect::<Vec<_>>()
        .join(", ")
}

fn swift_app(app: Option<&AppMatch>) -> String {
    let Some(a) = app else {
        return "nil".into();
    };
    let fingerprints = a
        .fingerprints
        .iter()
        .map(|f| {
            format!(
                "UFWFingerprint(paths: [{}], sha256: [{}], signers: [{}], teamIDs: [{}], \
                 bundleIDs: [{}])",
                swift_strings(f.paths.iter().map(|p| p.pattern.clone())),
                swift_strings(f.sha256.iter().map(|h| ufw_shared::hash::hex(h))),
                swift_strings(f.signers.iter().cloned()),
                swift_strings(f.team_ids.iter().cloned()),
                swift_strings(f.bundle_ids.iter().cloned()),
            )
        })
        .collect::<Vec<_>>()
        .join(", ");
    format!(
        "UFWAppMatch(fingerprints: [{}], trust: [{}], requireValidSignature: {}, negate: {})",
        fingerprints,
        a.trust
            .levels()
            .map(|l| format!(".{}", l.as_str()))
            .collect::<Vec<_>>()
            .join(", "),
        a.require_valid_signature,
        a.negate,
    )
}

fn swift_dpi(dpi: Option<&DpiMatch>) -> String {
    let Some(d) = dpi else {
        return "nil".into();
    };
    format!(
        "UFWDPIMatch(signatures: [{}], protocols: [{}], onMatch: {})",
        d.signatures
            .iter()
            .map(|s| s.to_string())
            .collect::<Vec<_>>()
            .join(", "),
        d.l7.iter()
            .map(|p| format!(".{}", p.as_str()))
            .collect::<Vec<_>>()
            .join(", "),
        swift_action_case(d.on_match),
    )
}

fn escape_swift(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::identity_types::{TrustLevel, TrustMask};
    use ufw_shared::json;

    fn policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("mac", Decision::Deny);
        p.network_profile.internal = vec![Cidr::parse("10.0.0.0/8").unwrap()];

        let mut icmp = CompiledRule::new(1, "block-icmp", Layer::Packet, Action::Deny);
        icmp.priority = 10;
        icmp.protocol = Protocol::Icmp;

        let mut web = CompiledRule::new(2, "web", Layer::Packet, Action::AllowInspect);
        web.priority = 100;
        web.protocol = Protocol::Tcp;

        let mut ident = CompiledRule::new(3, "signed-only", Layer::Identity, Action::Deny);
        ident.priority = 50;
        ident.app = Some(AppMatch {
            fingerprints: vec![AppFingerprint {
                team_ids: vec!["ABCDE12345".into()],
                ..Default::default()
            }],
            trust: TrustMask::from_levels([TrustLevel::Trusted]),
            require_valid_signature: true,
            negate: false,
        });

        let mut dpi = CompiledRule::new(4, "exploit", Layer::Stream, Action::Allow);
        dpi.dpi = Some(DpiMatch {
            signatures: vec![9001],
            l7: vec![L7Protocol::Http],
            on_match: Action::Deny,
        });

        p.rules = vec![icmp, web, ident, dpi];
        p.finalize();
        p
    }

    #[test]
    fn json_payload_is_valid_and_carries_the_sandbox_budgets() {
        let a = MacOsBackend.generate(&policy());
        let v = json::parse(&a.file("macos/ufw-policy.json").unwrap().contents).unwrap();
        assert_eq!(v.get("format").unwrap().as_str(), Some("ufw-macos-policy"));
        assert_eq!(
            v.get("reassembly_budget_bytes").unwrap().as_u64(),
            Some(constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS as u64)
        );
        assert_eq!(
            v.get("verdict_budget_ms").unwrap().as_u64(),
            Some(constants::FLOW_VERDICT_BUDGET_MS)
        );
    }

    #[test]
    fn icmp_goes_to_the_packet_provider_and_tcp_to_the_flow_provider() {
        let a = MacOsBackend.generate(&policy());
        let engine_of = |id: u32| a.model.rules.iter().find(|r| r.id == id).unwrap().engine;
        assert_eq!(engine_of(1), Engine::NePacket);
        assert_eq!(engine_of(2), Engine::NeFlow);
        assert_eq!(engine_of(4), Engine::NeFlow);
    }

    #[test]
    fn identity_rules_never_reach_the_packet_provider() {
        let a = MacOsBackend.generate(&policy());
        assert!(a
            .model
            .rules
            .iter()
            .filter(|r| r.id == 3)
            .all(|r| r.engine == Engine::NeFlow));
        assert!(!a.notes.is_empty());
    }

    #[test]
    fn allow_inspect_maps_to_a_data_verdict_not_a_plain_allow() {
        assert!(ne_verdict(Action::AllowInspect).contains("filterDataVerdict"));
        assert_eq!(ne_verdict(Action::Allow), "NEFilterNewFlowVerdict.allow()");
        assert_eq!(ne_verdict(Action::Deny), "NEFilterNewFlowVerdict.drop()");
    }

    #[test]
    fn swift_output_is_shaped_like_swift() {
        let a = MacOsBackend.generate(&policy());
        let sw = &a.file("macos/UFWPolicy.generated.swift").unwrap().contents;
        assert!(sw.starts_with("//"));
        assert!(sw.contains("import Foundation"));
        assert!(sw.contains("enum UFWGeneratedPolicy {"));
        assert!(sw.contains("static let rules: [UFWRule] = ["));
        assert!(sw.contains("UFWAppMatch(fingerprints:"));
        assert!(sw.contains("UFWFingerprint(paths:"));
        assert!(sw.contains("UFWDPIMatch(signatures: [9001]"));
        assert_eq!(sw.matches('{').count(), sw.matches('}').count());
        assert_eq!(sw.matches('[').count(), sw.matches(']').count());
    }

    #[test]
    fn swift_escapes_quotes_and_backslashes() {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        let mut r = CompiledRule::new(1, r#"a"b\c"#, Layer::Packet, Action::Deny);
        r.protocol = Protocol::Tcp;
        p.rules = vec![r];
        p.finalize();
        let a = MacOsBackend.generate(&p);
        let sw = &a.file("macos/UFWPolicy.generated.swift").unwrap().contents;
        assert!(sw.contains(r#""a\"b\\c""#));
    }

    #[test]
    fn rules_are_emitted_in_evaluation_order() {
        let a = MacOsBackend.generate(&policy());
        let ids: Vec<u32> = a.model.rules.iter().map(|r| r.id).collect();
        // packet stage (icmp p10, web p100) then identity (p50) then stream.
        assert_eq!(ids, vec![1, 2, 3, 4]);
    }

    #[test]
    fn dpi_rules_produce_a_sandbox_budget_note() {
        let a = MacOsBackend.generate(&policy());
        assert!(a.notes.has_code(codes::DPI_BUFFER_BUDGET));
    }
}
