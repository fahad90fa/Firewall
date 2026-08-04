//! Windows backend: WFP filter specification generator.
//!
//! # Layer assignment, and why it is not the obvious one
//!
//! The Windows Filtering Platform does not evaluate a single ordered rule
//! table. It evaluates *layers*, and the layers fire at different points in
//! the stack — in a different relative order depending on direction:
//!
//! ```text
//!   outbound:  ALE_AUTH_CONNECT  ->  OUTBOUND_IPPACKET  ->  STREAM
//!   inbound:   INBOUND_IPPACKET  ->  ALE_AUTH_RECV_ACCEPT -> STREAM
//! ```
//!
//! So a naive mapping — packet-layer rules to the IP packet layers, identity
//! rules to ALE — would evaluate identity *before* packet rules on the way out
//! and *after* them on the way in. The same policy would behave differently
//! per direction, and differently again from Linux and macOS.
//!
//! This backend sidesteps that entirely: **all connection-oriented traffic is
//! decided at the ALE layers**, where the driver evaluates the perimeter,
//! packet and identity stages in one pass in reference order. The IP packet
//! layers carry the same rules but scoped to protocols ALE never sees (ICMP
//! and anything else that is not TCP or UDP), so the two paths are disjoint by
//! construction and exactly one of them can decide any given flow.
//!
//! The stream layer carries the DPI and stream stages. WFP hands it data
//! already reassembled, which is why the Windows driver has no TCP reassembly
//! engine of its own.
//!
//! # Filter weight
//!
//! Within a layer, WFP evaluates filters by descending weight. The weight here
//! is `u64::MAX - evaluation_order_key(rule)`, and the order key puts the
//! *stage* above the priority. Without that, a priority-10 packet rule would
//! outrank a priority-500 perimeter rule inside the shared IP packet layer,
//! which is precisely the divergence the equivalence verifier flagged when
//! this backend derived weight from priority alone.

use ufw_shared::json::JsonWriter;
use ufw_shared::policy_types::*;
use ufw_shared::{constants, Platform};

use crate::compiler::{
    evaluation_order_key, Artifact, Backend, DecisionModel, Engine, GeneratedFile, ModelRule,
    ProtocolScope,
};
use crate::error::{codes, Diagnostic, Diagnostics, Span};

pub struct WindowsBackend;

/// Protocols that reach the ALE layers. Everything else is decided at the IP
/// packet layers.
const ALE_PROTOCOLS: [Protocol; 2] = [Protocol::Tcp, Protocol::Udp];

impl Backend for WindowsBackend {
    fn platform(&self) -> Platform {
        Platform::Windows
    }

    fn generate(&self, policy: &CompiledPolicy) -> Artifact {
        let mut notes = Diagnostics::new();
        let placements = plan(policy, &mut notes);
        let model = build_model(policy, &placements);

        let files = vec![
            GeneratedFile::new("windows/ufw_filters.json", emit_json(policy, &placements)),
            GeneratedFile::new(
                "windows/ufw_policy_generated.h",
                emit_header(policy, &placements),
            ),
            GeneratedFile::new("windows/ufw_filters.txt", emit_text(policy, &placements)),
        ];

        Artifact { platform: Platform::Windows, files, model, notes }
    }
}

/// Where one installed copy of a rule goes.
struct Placement<'a> {
    rule: &'a CompiledRule,
    engine: Engine,
    scope: ProtocolScope,
    /// WFP layer identifiers this copy is installed at (v4 and v6 variants,
    /// plus inbound/outbound where the layer is directional).
    layers: Vec<&'static str>,
    weight: u64,
}

fn plan<'a>(policy: &'a CompiledPolicy, notes: &mut Diagnostics) -> Vec<Placement<'a>> {
    let mut out = Vec::new();

    for rule in &policy.rules {
        let key = evaluation_order_key(rule);
        let weight = u64::MAX - key;

        match rule.layer {
            Layer::Perimeter | Layer::Packet | Layer::Identity => {
                // ALE copy: connection-oriented traffic.
                if rule.protocol == Protocol::Any || ALE_PROTOCOLS.contains(&rule.protocol) {
                    out.push(Placement {
                        rule,
                        engine: Engine::WfpAle,
                        scope: ProtocolScope::Only(ALE_PROTOCOLS.to_vec()),
                        layers: ale_layers(rule.direction),
                        weight,
                    });
                }
                // Packet copy: everything ALE never sees.
                if rule.protocol == Protocol::Any || !ALE_PROTOCOLS.contains(&rule.protocol) {
                    if rule.layer == Layer::Identity {
                        // An identity predicate cannot be evaluated at the IP
                        // packet layer: there is no process context there. The
                        // rule simply does not apply to ICMP, which is the same
                        // answer the reference gives (an identity predicate
                        // never matches without an identity).
                        notes.push(Diagnostic::note(
                            codes::EBPF_OFFLOAD,
                            Span::default(),
                            format!(
                                "rule `{}` is identity-scoped, so it is installed only at the \
                                 ALE layers; non-TCP/UDP traffic is unaffected by it",
                                rule.name
                            ),
                        ));
                    } else {
                        out.push(Placement {
                            rule,
                            engine: Engine::WfpPacket,
                            scope: ProtocolScope::Excluding(ALE_PROTOCOLS.to_vec()),
                            layers: packet_layers(rule.direction),
                            weight,
                        });
                    }
                }
            }
            Layer::AppDpi | Layer::Stream => {
                // TCP payload arrives already reassembled at the stream layer,
                // which is why the Windows driver needs no reassembly engine
                // of its own. UDP payload arrives at the datagram-data layer.
                // Both are installed under one entry because the callout does
                // the matching either way.
                out.push(Placement {
                    rule,
                    engine: Engine::WfpStream,
                    scope: ProtocolScope::Only(vec![Protocol::Tcp, Protocol::Udp]),
                    layers: vec![
                        "FWPM_LAYER_STREAM_V4",
                        "FWPM_LAYER_STREAM_V6",
                        "FWPM_LAYER_DATAGRAM_DATA_V4",
                        "FWPM_LAYER_DATAGRAM_DATA_V6",
                    ],
                    weight,
                });
            }
        }
    }

    // ALE and packet copies interleave by weight; the stream layer always runs
    // after both, so it sorts last regardless of weight.
    out.sort_by_key(|p| (layer_group(p.engine), std::cmp::Reverse(p.weight)));
    out
}

/// Relative order of the WFP layer groups in the stack.
fn layer_group(engine: Engine) -> u8 {
    match engine {
        Engine::WfpAle | Engine::WfpPacket => 0,
        Engine::WfpStream => 1,
        _ => 2,
    }
}

fn ale_layers(direction: Direction) -> Vec<&'static str> {
    match direction {
        Direction::Outbound => vec![
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
        ],
        Direction::Inbound => vec![
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        ],
        Direction::Any => vec![
            "FWPM_LAYER_ALE_AUTH_CONNECT_V4",
            "FWPM_LAYER_ALE_AUTH_CONNECT_V6",
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4",
            "FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6",
        ],
    }
}

fn packet_layers(direction: Direction) -> Vec<&'static str> {
    match direction {
        Direction::Outbound => vec![
            "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
            "FWPM_LAYER_OUTBOUND_IPPACKET_V6",
        ],
        Direction::Inbound => vec![
            "FWPM_LAYER_INBOUND_IPPACKET_V4",
            "FWPM_LAYER_INBOUND_IPPACKET_V6",
        ],
        Direction::Any => vec![
            "FWPM_LAYER_INBOUND_IPPACKET_V4",
            "FWPM_LAYER_INBOUND_IPPACKET_V6",
            "FWPM_LAYER_OUTBOUND_IPPACKET_V4",
            "FWPM_LAYER_OUTBOUND_IPPACKET_V6",
        ],
    }
}

fn build_model(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> DecisionModel {
    DecisionModel {
        platform: Platform::Windows,
        default_action: policy.default_action,
        profile: policy.network_profile.clone(),
        rules: placements
            .iter()
            .map(|p| {
                let mut m = ModelRule::new(p.rule, p.engine);
                m.order_key = p.weight;
                m.scope = p.scope.clone();
                m
            })
            .collect(),
    }
}

/// The WFP action a rule maps to.
///
/// `allow-inspect` becomes `FWP_ACTION_PERMIT` at the ALE layer — the flow is
/// permitted to establish — and the stream-layer filters remain installed, so
/// a later DPI match can still terminate it. `alert` and `continue` become
/// `FWP_ACTION_CONTINUE`, which is WFP's own "I have no opinion, keep
/// evaluating" verdict.
fn wfp_action(action: Action) -> &'static str {
    match action {
        Action::Allow | Action::AllowInspect => "FWP_ACTION_PERMIT",
        Action::Deny => "FWP_ACTION_BLOCK",
        Action::Alert | Action::Continue => "FWP_ACTION_CONTINUE",
    }
}

// ===========================================================================
// JSON filter specification
// ===========================================================================

fn emit_json(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> String {
    let mut w = JsonWriter::with_capacity(4096);
    w.begin_object();
    w.str_field("format", "ufw-wfp-filter-spec");
    w.u64_field("format_version", 1);
    w.str_field("policy", &policy.name);
    w.u64_field("revision", policy.revision);
    w.str_field("ruleset_sha256", &ufw_shared::hash::hex(&policy.ruleset_hash));
    w.str_field("default_action", policy.default_action.as_str());
    w.str_field("provider_key", "UFW_PROVIDER_KEY");
    w.str_field("sublayer_key", "UFW_SUBLAYER_KEY");
    w.u64_field("sublayer_weight", 0x8000);

    w.begin_object_field("network_profile");
    w.str_array_field(
        "internal",
        policy
            .network_profile
            .internal
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .iter()
            .map(|s| s.as_str()),
    );
    w.str_array_field(
        "perimeter",
        policy
            .network_profile
            .perimeter
            .iter()
            .map(|c| c.to_string())
            .collect::<Vec<_>>()
            .iter()
            .map(|s| s.as_str()),
    );
    w.bool_field(
        "perimeter_crossing_requires_dpi",
        policy.network_profile.perimeter_crossing_requires_dpi,
    );
    w.end_object();

    w.begin_array_field("filters");
    for p in placements {
        let r = p.rule;
        w.begin_object();
        w.u64_field("rule_id", r.id as u64);
        w.str_field("name", &r.name);
        w.str_field("engine", p.engine.as_str());
        w.str_field("layer_stage", r.layer.as_str());
        w.u64_field("weight", p.weight);
        w.u64_field("priority", r.priority as u64);
        w.str_field("action", wfp_action(r.effective_action()));
        w.str_field("policy_action", r.effective_action().as_str());
        w.str_field("protocol_scope", &p.scope.describe());
        w.str_array_field("wfp_layers", p.layers.iter().copied());

        w.begin_array_field("conditions");
        emit_conditions(&mut w, r);
        w.end_array();

        w.bool_field("log", r.log);
        w.bool_field("stateful", r.stateful);
        w.str_array_field("tags", r.tags.iter().map(|s| s.as_str()));
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.finish()
}

/// Emit the WFP filter conditions for a rule.
///
/// Each entry names the real `FWPM_CONDITION_*` field so the driver's
/// `wfp_helpers.c` can build `FWPM_FILTER_CONDITION0` structures from this
/// specification without a translation table living in two places.
fn emit_conditions(w: &mut JsonWriter, r: &CompiledRule) {
    if let Some(n) = r.protocol.number() {
        condition(w, "FWPM_CONDITION_IP_PROTOCOL", "equal", &n.to_string());
    }
    for c in &r.source.cidrs {
        condition(
            w,
            if c.is_v4() {
                "FWPM_CONDITION_IP_LOCAL_ADDRESS"
            } else {
                "FWPM_CONDITION_IP_LOCAL_ADDRESS"
            },
            if r.source.negate { "not-equal" } else { "equal" },
            &c.to_string(),
        );
    }
    for c in &r.dest.cidrs {
        condition(
            w,
            "FWPM_CONDITION_IP_REMOTE_ADDRESS",
            if r.dest.negate { "not-equal" } else { "equal" },
            &c.to_string(),
        );
    }
    for range in &r.source_ports.ranges {
        condition(w, "FWPM_CONDITION_IP_LOCAL_PORT", "range", &range.to_string());
    }
    for range in &r.dest_ports.ranges {
        condition(w, "FWPM_CONDITION_IP_REMOTE_PORT", "range", &range.to_string());
    }
    for zone in &r.source.zones {
        // Zones have no native WFP condition; the callout evaluates them from
        // the network profile it holds in kernel memory.
        condition(w, "UFW_CONDITION_LOCAL_ZONE", "equal", zone.as_str());
    }
    for zone in &r.dest.zones {
        condition(w, "UFW_CONDITION_REMOTE_ZONE", "equal", zone.as_str());
    }
    if let Some(app) = &r.app {
        // Fingerprints are alternatives; the index keeps them distinguishable
        // so the callout can OR within an index and AND across kinds.
        for (i, fp) in app.fingerprints.iter().enumerate() {
            for path in &fp.paths {
                // Real Authenticode-aware matching happens in the callout
                // against the resolved AppIdentity; the condition below
                // narrows the set of flows the callout is invoked for.
                condition_alt(w, "FWPM_CONDITION_ALE_APP_ID", "equal", &path.pattern, i);
            }
            for signer in &fp.signers {
                condition_alt(w, "UFW_CONDITION_SIGNER", "equal", signer, i);
            }
            for hash in &fp.sha256 {
                condition_alt(
                    w,
                    "UFW_CONDITION_IMAGE_SHA256",
                    "equal",
                    &ufw_shared::hash::hex(hash),
                    i,
                );
            }
            for team in &fp.team_ids {
                condition_alt(w, "UFW_CONDITION_TEAM_ID", "equal", team, i);
            }
            for bundle in &fp.bundle_ids {
                condition_alt(w, "UFW_CONDITION_BUNDLE_ID", "equal", bundle, i);
            }
        }
        if !app.trust.is_any() {
            let levels: Vec<&str> = app.trust.levels().map(|l| l.as_str()).collect();
            condition(w, "UFW_CONDITION_TRUST_LEVEL", "in", &levels.join("|"));
        }
        if app.require_valid_signature {
            condition(w, "UFW_CONDITION_SIGNATURE_VALID", "equal", "true");
        }
    }
    if let Some(dpi) = &r.dpi {
        for sig in &dpi.signatures {
            condition(w, "UFW_CONDITION_DPI_SIGNATURE", "equal", &sig.to_string());
        }
        for l7 in &dpi.l7 {
            condition(w, "UFW_CONDITION_L7_PROTOCOL", "equal", l7.as_str());
        }
    }
    for iface in &r.interfaces {
        condition(w, "FWPM_CONDITION_INTERFACE_INDEX", "equal", iface);
    }
    if let Some(s) = &r.schedule {
        condition(
            w,
            "UFW_CONDITION_TIME_WINDOW",
            "in",
            &format!("days=0x{:02x};{}-{}", s.days, s.start_minute, s.end_minute),
        );
    }
}

fn condition(w: &mut JsonWriter, field: &str, op: &str, value: &str) {
    w.begin_object();
    w.str_field("field", field);
    w.str_field("op", op);
    w.str_field("value", value);
    w.end_object();
}

/// A condition belonging to one identity alternative. Conditions sharing an
/// `alternative` index are ANDed; the alternatives themselves are ORed.
fn condition_alt(w: &mut JsonWriter, field: &str, op: &str, value: &str, alternative: usize) {
    w.begin_object();
    w.str_field("field", field);
    w.str_field("op", op);
    w.str_field("value", value);
    w.u64_field("alternative", alternative as u64);
    w.end_object();
}

// ===========================================================================
// C header for build-time embedding
// ===========================================================================

fn emit_header(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> String {
    let mut s = String::with_capacity(8192);
    s.push_str(&format!(
        "/*\n\
         \x20* Generated by the Unified Policy Language compiler. Do not edit.\n\
         \x20*\n\
         \x20* policy   : {}\n\
         \x20* revision : {}\n\
         \x20* ruleset  : sha256:{}\n\
         \x20* filters  : {}\n\
         \x20*\n\
         \x20* Consumed by kernel/windows/src/policy_cache.c when the driver is built\n\
         \x20* with a policy baked in. In normal operation the daemon ships the same\n\
         \x20* rules over IOCTL instead, so this header is a build-time convenience\n\
         \x20* and a review artifact, not the primary path.\n\
         \x20*/\n\n",
        policy.name,
        policy.revision,
        ufw_shared::hash::hex(&policy.ruleset_hash),
        placements.len()
    ));
    s.push_str("#pragma once\n\n#include \"ipc_ioctl.h\"\n\n");
    s.push_str(&format!(
        "#define UFW_GENERATED_ABI_REVISION {}\n",
        constants::ABI_REVISION
    ));
    s.push_str(&format!(
        "#define UFW_GENERATED_FILTER_COUNT {}\n",
        placements.len()
    ));
    s.push_str(&format!(
        "#define UFW_GENERATED_DEFAULT_ACTION UFW_ACTION_{}\n\n",
        policy.default_action.as_str().to_uppercase()
    ));

    for (i, p) in placements.iter().enumerate() {
        let r = p.rule;
        if !r.source.cidrs.is_empty() {
            s.push_str(&emit_cidr_array(&format!("kFilter{i}SrcCidr"), &r.source.cidrs));
        }
        if !r.dest.cidrs.is_empty() {
            s.push_str(&emit_cidr_array(&format!("kFilter{i}DstCidr"), &r.dest.cidrs));
        }
        if !r.source_ports.ranges.is_empty() {
            s.push_str(&emit_port_array(
                &format!("kFilter{i}SrcPort"),
                &r.source_ports.ranges,
            ));
        }
        if !r.dest_ports.ranges.is_empty() {
            s.push_str(&emit_port_array(
                &format!("kFilter{i}DstPort"),
                &r.dest_ports.ranges,
            ));
        }
    }
    s.push('\n');

    s.push_str("static const UFW_FILTER_SPEC g_ufwGeneratedFilters[] = {\n");
    for (i, p) in placements.iter().enumerate() {
        let r = p.rule;
        s.push_str(&format!(
            "    {{\n\
             \x20        .ruleId          = {},\n\
             \x20        .name            = \"{}\",\n\
             \x20        .stage           = UFW_STAGE_{},\n\
             \x20        .engine          = UFW_ENGINE_{},\n\
             \x20        .weight          = 0x{:016X}ULL,\n\
             \x20        .action          = {},\n\
             \x20        .direction       = UFW_DIR_{},\n\
             \x20        .protocol        = {},\n\
             \x20        .protocolScope   = UFW_SCOPE_{},\n\
             \x20        .srcCidrs        = {},\n\
             \x20        .srcCidrCount    = {},\n\
             \x20        .dstCidrs        = {},\n\
             \x20        .dstCidrCount    = {},\n\
             \x20        .srcPorts        = {},\n\
             \x20        .srcPortCount    = {},\n\
             \x20        .dstPorts        = {},\n\
             \x20        .dstPortCount    = {},\n\
             \x20        .flags           = {},\n\
             \x20    }},\n",
            r.id,
            escape_c(&r.name),
            r.layer.as_str().to_uppercase().replace('-', "_"),
            p.engine.as_str().to_uppercase().replace('-', "_"),
            p.weight,
            wfp_action(r.effective_action()),
            r.direction.as_str().to_uppercase(),
            r.protocol.number().map(|n| n.to_string()).unwrap_or_else(|| "UFW_PROTO_ANY".into()),
            scope_macro(&p.scope),
            array_ref(&format!("kFilter{i}SrcCidr"), r.source.cidrs.is_empty()),
            r.source.cidrs.len(),
            array_ref(&format!("kFilter{i}DstCidr"), r.dest.cidrs.is_empty()),
            r.dest.cidrs.len(),
            array_ref(&format!("kFilter{i}SrcPort"), r.source_ports.ranges.is_empty()),
            r.source_ports.ranges.len(),
            array_ref(&format!("kFilter{i}DstPort"), r.dest_ports.ranges.is_empty()),
            r.dest_ports.ranges.len(),
            rule_flags(r),
        ));
    }
    s.push_str("};\n");
    s
}

fn array_ref(name: &str, empty: bool) -> String {
    if empty {
        "NULL".into()
    } else {
        name.into()
    }
}

fn scope_macro(scope: &ProtocolScope) -> &'static str {
    match scope {
        ProtocolScope::Any => "ANY",
        ProtocolScope::Only(_) => "CONNECTION_ORIENTED",
        ProtocolScope::Excluding(_) => "CONNECTIONLESS",
    }
}

fn rule_flags(r: &CompiledRule) -> String {
    let mut flags: Vec<&str> = Vec::new();
    if r.log {
        flags.push("UFW_FLAG_LOG");
    }
    if r.stateful {
        flags.push("UFW_FLAG_STATEFUL");
    }
    if r.app.is_some() {
        flags.push("UFW_FLAG_NEEDS_IDENTITY");
    }
    if r.dpi.is_some() {
        flags.push("UFW_FLAG_NEEDS_DPI");
    }
    if r.source.negate || r.dest.negate {
        flags.push("UFW_FLAG_NEGATED");
    }
    if flags.is_empty() {
        "0".into()
    } else {
        flags.join(" | ")
    }
}

fn emit_cidr_array(name: &str, cidrs: &[Cidr]) -> String {
    let mut s = format!("static const UFW_CIDR {name}[] = {{\n");
    for c in cidrs {
        s.push_str(&format!("    {},\n", cidr_initializer(c)));
    }
    s.push_str("};\n");
    s
}

fn cidr_initializer(c: &Cidr) -> String {
    match c.addr() {
        std::net::IpAddr::V4(a) => {
            let o = a.octets();
            format!(
                "{{ .family = 4, .prefix = {}, .addr = {{ {}, {}, {}, {} }} }}",
                c.prefix(),
                o[0],
                o[1],
                o[2],
                o[3]
            )
        }
        std::net::IpAddr::V6(a) => {
            let o = a.octets();
            let bytes: Vec<String> = o.iter().map(|b| format!("0x{b:02x}")).collect();
            format!(
                "{{ .family = 6, .prefix = {}, .addr6 = {{ {} }} }}",
                c.prefix(),
                bytes.join(", ")
            )
        }
    }
}

fn emit_port_array(name: &str, ranges: &[PortRange]) -> String {
    let mut s = format!("static const UFW_PORT_RANGE {name}[] = {{\n");
    for r in ranges {
        s.push_str(&format!("    {{ {}, {} }},\n", r.lo, r.hi));
    }
    s.push_str("};\n");
    s
}

fn escape_c(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ===========================================================================
// Human-readable listing
// ===========================================================================

fn emit_text(policy: &CompiledPolicy, placements: &[Placement<'_>]) -> String {
    let mut s = String::new();
    s.push_str(&format!(
        "# WFP filter plan for policy `{}` (revision {})\n\
         # ruleset sha256:{}\n\
         # default action: {}\n\
         #\n\
         # Filters are listed in the order WFP will evaluate them: the ALE and IP\n\
         # packet layers interleave by weight (they are protocol-disjoint), and the\n\
         # stream layer always runs last.\n\n",
        policy.name,
        policy.revision,
        ufw_shared::hash::hex(&policy.ruleset_hash),
        policy.default_action.as_str(),
    ));
    s.push_str(&format!(
        "{:<4} {:<28} {:<12} {:<10} {:<18} {:<20} {}\n",
        "#", "RULE", "STAGE", "ENGINE", "WEIGHT", "ACTION", "SCOPE"
    ));
    for (i, p) in placements.iter().enumerate() {
        s.push_str(&format!(
            "{:<4} {:<28} {:<12} {:<10} 0x{:016X} {:<20} {}\n",
            i,
            truncate(&p.rule.name, 28),
            p.rule.layer.as_str(),
            p.engine.as_str(),
            p.weight,
            wfp_action(p.rule.effective_action()),
            p.scope.describe()
        ));
        s.push_str(&format!(
            "     layers: {}\n     match : {} {} -> {} {}\n",
            p.layers.join(", "),
            p.rule.protocol.as_str(),
            render_address(&p.rule.source),
            render_address(&p.rule.dest),
            render_ports(&p.rule.dest_ports),
        ));
    }
    s
}

fn truncate(s: &str, n: usize) -> String {
    if s.chars().count() <= n {
        s.to_string()
    } else {
        let mut out: String = s.chars().take(n.saturating_sub(1)).collect();
        out.push('~');
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::json;

    fn policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("win", Decision::Deny);

        let mut perimeter = CompiledRule::new(1, "lan-ok", Layer::Perimeter, Action::Allow);
        perimeter.priority = 60000;
        perimeter.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::Internal],
            negate: false,
        };

        let mut packet = CompiledRule::new(2, "block-icmp", Layer::Packet, Action::Deny);
        packet.priority = 1;
        packet.protocol = Protocol::Icmp;

        let mut ale = CompiledRule::new(3, "web", Layer::Packet, Action::AllowInspect);
        ale.priority = 100;
        ale.protocol = Protocol::Tcp;
        ale.dest_ports = PortMatch { ranges: vec![PortRange::single(443)], negate: false };

        let mut stream = CompiledRule::new(4, "dpi", Layer::Stream, Action::Allow);
        stream.dpi = Some(DpiMatch {
            signatures: vec![7],
            l7: vec![L7Protocol::Tls],
            on_match: Action::Deny,
        });

        p.rules = vec![perimeter, packet, ale, stream];
        p.finalize();
        p
    }

    #[test]
    fn json_specification_is_valid_json() {
        let a = WindowsBackend.generate(&policy());
        let f = a.file("windows/ufw_filters.json").unwrap();
        let v = json::parse(&f.contents).expect("filter spec must be valid JSON");
        assert_eq!(v.get("format").unwrap().as_str(), Some("ufw-wfp-filter-spec"));
        assert!(!v.get("filters").unwrap().as_array().unwrap().is_empty());
    }

    #[test]
    fn stage_outranks_priority_in_the_filter_weight() {
        // `lan-ok` is a perimeter rule at priority 60000; `block-icmp` is a
        // packet rule at priority 1. In WFP both would land in the same layer
        // group, and only a stage-aware weight keeps the perimeter rule first.
        let a = WindowsBackend.generate(&policy());
        let weights: Vec<(u32, u64)> = a
            .model
            .rules
            .iter()
            .map(|r| (r.id, r.order_key))
            .collect();
        let lan = weights.iter().find(|(id, _)| *id == 1).unwrap().1;
        let icmp = weights.iter().find(|(id, _)| *id == 2).unwrap().1;
        assert!(lan > icmp, "higher weight is evaluated first in WFP");
    }

    #[test]
    fn tcp_rules_go_to_ale_and_icmp_rules_to_the_packet_layers() {
        let a = WindowsBackend.generate(&policy());
        let engine_of = |id: u32| {
            a.model
                .rules
                .iter()
                .find(|r| r.id == id)
                .map(|r| r.engine)
                .unwrap()
        };
        assert_eq!(engine_of(3), Engine::WfpAle);
        assert_eq!(engine_of(2), Engine::WfpPacket);
        assert_eq!(engine_of(4), Engine::WfpStream);
    }

    #[test]
    fn a_protocol_any_rule_is_installed_at_both_layers_disjointly() {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        p.rules = vec![CompiledRule::new(1, "any", Layer::Packet, Action::Deny)];
        p.finalize();
        let a = WindowsBackend.generate(&p);
        let copies: Vec<&ModelRule> = a.model.rules.iter().filter(|r| r.id == 1).collect();
        assert_eq!(copies.len(), 2);
        assert!(copies.iter().any(|c| c.engine == Engine::WfpAle));
        assert!(copies.iter().any(|c| c.engine == Engine::WfpPacket));
        // Exactly one admits TCP, exactly one admits ICMP.
        assert_eq!(
            copies.iter().filter(|c| c.scope.admits(Protocol::Tcp)).count(),
            1
        );
        assert_eq!(
            copies.iter().filter(|c| c.scope.admits(Protocol::Icmp)).count(),
            1
        );
    }

    #[test]
    fn identity_rules_are_not_installed_at_the_packet_layer() {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        let mut r = CompiledRule::new(1, "ident", Layer::Identity, Action::Deny);
        r.app = Some(AppMatch::any());
        p.rules = vec![r];
        p.finalize();
        let a = WindowsBackend.generate(&p);
        assert!(a.model.rules.iter().all(|m| m.engine == Engine::WfpAle));
        assert!(!a.notes.is_empty());
    }

    #[test]
    fn allow_inspect_permits_at_ale_so_the_stream_layer_still_runs() {
        assert_eq!(wfp_action(Action::AllowInspect), "FWP_ACTION_PERMIT");
        assert_eq!(wfp_action(Action::Alert), "FWP_ACTION_CONTINUE");
        assert_eq!(wfp_action(Action::Deny), "FWP_ACTION_BLOCK");
    }

    #[test]
    fn generated_header_is_shaped_like_c() {
        let a = WindowsBackend.generate(&policy());
        let h = &a.file("windows/ufw_policy_generated.h").unwrap().contents;
        assert!(h.contains("#pragma once"));
        assert!(h.contains("static const UFW_FILTER_SPEC g_ufwGeneratedFilters[]"));
        assert!(h.contains(".ruleId          = 1,"));
        assert_eq!(h.matches('{').count(), h.matches('}').count());
    }

    #[test]
    fn rule_names_are_escaped_in_generated_c() {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        p.rules = vec![CompiledRule::new(
            1,
            r#"we"ird\name"#,
            Layer::Packet,
            Action::Deny,
        )];
        p.finalize();
        let a = WindowsBackend.generate(&p);
        let h = &a.file("windows/ufw_policy_generated.h").unwrap().contents;
        assert!(h.contains(r#""we\"ird\\name""#));
    }

    #[test]
    fn text_listing_is_ordered_like_the_model() {
        let a = WindowsBackend.generate(&policy());
        let text = &a.file("windows/ufw_filters.txt").unwrap().contents;
        let lan = text.find("lan-ok").unwrap();
        let icmp = text.find("block-icmp").unwrap();
        let dpi = text.find(" dpi ").unwrap_or_else(|| text.find("dpi").unwrap());
        assert!(lan < icmp, "perimeter stage listed before packet stage");
        assert!(icmp < dpi, "stream layer listed last");
    }

    #[test]
    fn ipv6_cidrs_emit_a_16_byte_initializer() {
        let c = Cidr::parse("2001:db8::/32").unwrap();
        let init = cidr_initializer(&c);
        assert!(init.contains(".family = 6"));
        assert_eq!(init.matches("0x").count(), 16);
    }
}
