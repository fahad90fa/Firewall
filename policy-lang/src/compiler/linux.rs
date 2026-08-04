//! Linux backend: eBPF fast-path program plus a netfilter rule table.
//!
//! # The hook-ordering problem
//!
//! Linux runs eBPF at the tc hooks and this project's netfilter hooks inside a
//! kernel module. Their relative order depends on direction:
//!
//! ```text
//!   inbound :  XDP -> tc ingress -> NF_INET_PRE_ROUTING -> NF_INET_LOCAL_IN
//!   outbound:  NF_INET_LOCAL_OUT -> NF_INET_POST_ROUTING -> tc egress
//! ```
//!
//! tc runs *first* on the way in and *last* on the way out. An eBPF fast path
//! carrying an arbitrary subset of rules would therefore decide inbound flows
//! ahead of higher-priority netfilter rules, and would be useless (already
//! decided) on the way out.
//!
//! # The offload rule
//!
//! The netfilter table is always **complete**: every rule in the policy, in
//! reference order. That alone is correct. The eBPF program is a pure
//! short-circuit layered on top, and it is only safe if a match in eBPF is
//! guaranteed to be the same match the full table would have produced.
//!
//! That guarantee comes from a prefix argument:
//!
//! 1. Take the rules in reference evaluation order.
//! 2. Drop rules that can never match an inbound flow (`direction: outbound`).
//!    For an inbound packet those rules are no-ops, so removing them does not
//!    change which rule matches first.
//! 3. From what remains, take the longest **prefix** of rules that are
//!    eBPF-expressible.
//!
//! If a prefix rule matches, every rule that could have matched earlier is
//! also in the prefix and was already tried — so the match is the true first
//! match. If none matches, eBPF returns `TC_ACT_UNSPEC` and the complete
//! netfilter table runs as normal.
//!
//! The prefix is why an ordinary "default deny at priority 65535" policy still
//! offloads its hot rules, while a policy that opens with an identity rule
//! offloads nothing — correctly, because nothing can be decided before that
//! identity rule has had its chance.
//!
//! The egress direction is deliberately not offloaded: netfilter `LOCAL_OUT`
//! already runs before tc egress, so an egress program could only ever
//! re-decide something already decided.

use std::fmt::Write as _;

use ufw_shared::json::JsonWriter;
use ufw_shared::policy_types::*;
use ufw_shared::{constants, Platform};

use crate::compiler::{
    evaluation_order_key, Artifact, Backend, DecisionModel, Engine, GeneratedFile, ModelRule,
};
use crate::error::{codes, Diagnostic, Diagnostics, Span};
use crate::optimizer::is_ebpf_expressible;

pub struct LinuxBackend;

impl Backend for LinuxBackend {
    fn platform(&self) -> Platform {
        Platform::Linux
    }

    fn generate(&self, policy: &CompiledPolicy) -> Artifact {
        let mut notes = Diagnostics::new();
        let ordered = ordered(policy);
        let offloaded = plan_offload(&ordered, &mut notes);

        let model = DecisionModel {
            platform: Platform::Linux,
            default_action: policy.default_action,
            profile: policy.network_profile.clone(),
            rules: ordered
                .iter()
                .map(|r| {
                    let engine = if offloaded.contains(&r.id) {
                        Engine::Ebpf
                    } else {
                        Engine::Netfilter
                    };
                    let mut m = ModelRule::new(r, engine);
                    m.order_key = evaluation_order_key(r);
                    m
                })
                .collect(),
        };

        let files = vec![
            GeneratedFile::new(
                "linux/ufw_ebpf_rules.h",
                emit_ebpf_header(policy, &ordered, &offloaded),
            ),
            GeneratedFile::new("linux/ufw_rules.h", emit_module_header(policy, &ordered)),
            GeneratedFile::new("linux/ufw_policy.json", emit_json(policy, &ordered, &offloaded)),
            GeneratedFile::new("linux/ufw.nft", emit_nftables(policy, &ordered)),
        ];

        Artifact { platform: Platform::Linux, files, model, notes }
    }
}

fn ordered(policy: &CompiledPolicy) -> Vec<CompiledRule> {
    let mut v = policy.rules.clone();
    v.sort_by_key(evaluation_order_key);
    v
}

/// Decide which rules the eBPF program carries. See the module documentation
/// for why this must be a prefix.
fn plan_offload(ordered: &[CompiledRule], notes: &mut Diagnostics) -> Vec<u32> {
    let mut offloaded = Vec::new();
    let mut blocked_by: Option<&CompiledRule> = None;

    for rule in ordered {
        // Outbound-only rules cannot match an inbound packet, so they neither
        // offload nor block the prefix.
        if rule.direction == Direction::Outbound {
            continue;
        }
        if !is_ebpf_expressible(rule) {
            blocked_by = Some(rule);
            break;
        }
        offloaded.push(rule.id);
    }

    if let Some(blocker) = blocked_by {
        let remaining = ordered
            .iter()
            .filter(|r| r.direction != Direction::Outbound && is_ebpf_expressible(r))
            .count()
            - offloaded.len();
        if remaining > 0 {
            notes.push(
                Diagnostic::note(
                    codes::EBPF_OFFLOAD,
                    Span::default(),
                    format!(
                        "{} further rule(s) are eBPF-expressible but sit after `{}`, which is \
                         not; offloading them would let the tc ingress hook decide ahead of it",
                        remaining, blocker.name
                    ),
                )
                .with_help(
                    "give the header-only rules a lower `priority:` so they sort before the \
                     rules that need identity or payload context",
                ),
            );
        }
    }

    notes.push(Diagnostic::note(
        codes::EBPF_OFFLOAD,
        Span::default(),
        format!(
            "{} of {} rules offloaded to the tc ingress fast path",
            offloaded.len(),
            ordered.len()
        ),
    ));

    offloaded
}

// ===========================================================================
// eBPF program header
// ===========================================================================

fn emit_ebpf_header(policy: &CompiledPolicy, ordered: &[CompiledRule], offloaded: &[u32]) -> String {
    let rules: Vec<&CompiledRule> = ordered
        .iter()
        .filter(|r| offloaded.contains(&r.id))
        .collect();

    let mut s = String::with_capacity(4096);
    let _ = write!(
        s,
        "/*\n\
         \x20* Generated by the Unified Policy Language compiler. Do not edit.\n\
         \x20*\n\
         \x20* policy   : {}\n\
         \x20* revision : {}\n\
         \x20* ruleset  : sha256:{}\n\
         \x20*\n\
         \x20* Included by kernel/linux/ebpf/packet_filter.c. Holds the longest prefix\n\
         \x20* of the policy that (a) can match inbound traffic and (b) is expressible\n\
         \x20* with only L3/L4 header fields. A match here is provably the same match\n\
         \x20* the complete netfilter table would produce; anything this table does not\n\
         \x20* decide falls through to it.\n\
         \x20*/\n\n",
        policy.name,
        policy.revision,
        ufw_shared::hash::hex(&policy.ruleset_hash),
    );
    s.push_str("#pragma once\n\n#include \"common.h\"\n\n");
    let _ = writeln!(s, "#define UFW_EBPF_RULE_COUNT {}", rules.len());
    let _ = writeln!(
        s,
        "#define UFW_EBPF_RULESET_REVISION {}ULL\n",
        policy.revision
    );

    if rules.is_empty() {
        s.push_str(
            "/*\n\
             \x20* No rules qualified for the fast path. Either the policy opens with a\n\
             \x20* rule needing identity or payload context, or every rule is outbound.\n\
             \x20* The netfilter table handles everything; this is a performance note,\n\
             \x20* not an error.\n\
             \x20*/\n",
        );
        s.push_str("static const struct ufw_ebpf_rule ufw_ebpf_rules[1] = { { .rule_id = 0 } };\n");
        return s;
    }

    s.push_str("static const struct ufw_ebpf_rule ufw_ebpf_rules[UFW_EBPF_RULE_COUNT] = {\n");
    for r in &rules {
        let _ = write!(
            s,
            "    {{\n\
             \x20        .rule_id     = {},\n\
             \x20        .name        = \"{}\",\n\
             \x20        .action      = {},\n\
             \x20        .direction   = {},\n\
             \x20        .protocol    = {},\n\
             \x20        .src_cidrs   = {{ {} }},\n\
             \x20        .src_n       = {},\n\
             \x20        .dst_cidrs   = {{ {} }},\n\
             \x20        .dst_n       = {},\n\
             \x20        .src_ports   = {{ {} }},\n\
             \x20        .src_port_n  = {},\n\
             \x20        .dst_ports   = {{ {} }},\n\
             \x20        .dst_port_n  = {},\n\
             \x20        .flags       = {},\n\
             \x20    }},\n",
            r.id,
            escape_c(&r.name),
            match r.action {
                Action::Deny => "UFW_VERDICT_DROP",
                _ => "UFW_VERDICT_PASS",
            },
            direction_macro(r.direction),
            r.protocol
                .number()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "UFW_PROTO_ANY".into()),
            cidr_list(&r.source.cidrs),
            r.source.cidrs.len(),
            cidr_list(&r.dest.cidrs),
            r.dest.cidrs.len(),
            port_list(&r.source_ports.ranges),
            r.source_ports.ranges.len(),
            port_list(&r.dest_ports.ranges),
            r.dest_ports.ranges.len(),
            if r.log { "UFW_EBPF_FLAG_LOG" } else { "0" },
        );
    }
    s.push_str("};\n");
    s
}

fn direction_macro(d: Direction) -> &'static str {
    match d {
        Direction::Inbound => "UFW_DIR_INBOUND",
        Direction::Outbound => "UFW_DIR_OUTBOUND",
        Direction::Any => "UFW_DIR_ANY",
    }
}

/// eBPF stack and verifier limits mean the per-rule arrays are fixed size; the
/// compiler already enforces `MAX_CIDRS_PER_RULE`, and this pads to the
/// declared width so the initializer matches the struct.
fn cidr_list(cidrs: &[Cidr]) -> String {
    cidrs
        .iter()
        .map(|c| match c.addr() {
            std::net::IpAddr::V4(a) => format!(
                "{{ .family = 4, .prefix = {}, .v4 = 0x{:08x} }}",
                c.prefix(),
                u32::from(a)
            ),
            std::net::IpAddr::V6(a) => {
                let o = a.octets();
                let bytes: Vec<String> = o.iter().map(|b| format!("0x{b:02x}")).collect();
                format!(
                    "{{ .family = 6, .prefix = {}, .v6 = {{ {} }} }}",
                    c.prefix(),
                    bytes.join(", ")
                )
            }
        })
        .collect::<Vec<_>>()
        .join(", ")
}

fn port_list(ranges: &[PortRange]) -> String {
    ranges
        .iter()
        .map(|r| format!("{{ {}, {} }}", r.lo, r.hi))
        .collect::<Vec<_>>()
        .join(", ")
}

// ===========================================================================
// Kernel module rule table
// ===========================================================================

fn emit_module_header(policy: &CompiledPolicy, ordered: &[CompiledRule]) -> String {
    let mut s = String::with_capacity(8192);
    let _ = write!(
        s,
        "/*\n\
         \x20* Generated by the Unified Policy Language compiler. Do not edit.\n\
         \x20*\n\
         \x20* policy   : {}\n\
         \x20* revision : {}\n\
         \x20* rules    : {}\n\
         \x20*\n\
         \x20* The complete rule table, in reference evaluation order. The kernel\n\
         \x20* module normally receives this over netlink from the daemon; the header\n\
         \x20* exists for builds that bake a policy in and for review.\n\
         \x20*/\n\n",
        policy.name,
        policy.revision,
        ordered.len()
    );
    s.push_str("#pragma once\n\n#include \"policy_structs.h\"\n\n");
    let _ = writeln!(s, "#define UFW_ABI_REVISION_EXPECTED {}", constants::ABI_REVISION);
    let _ = writeln!(s, "#define UFW_RULE_COUNT {}", ordered.len());
    let _ = writeln!(
        s,
        "#define UFW_DEFAULT_VERDICT {}\n",
        match policy.default_action {
            Decision::Allow => "UFW_VERDICT_PASS",
            Decision::Deny => "UFW_VERDICT_DROP",
        }
    );

    s.push_str("static const struct ufw_rule ufw_rules[] = {\n");
    for r in ordered {
        let _ = write!(
            s,
            "    {{ .id = {}, .name = \"{}\", .stage = {}, .priority = {}, .action = {}, \
             .direction = {}, .protocol = {}, .flags = {} }},\n",
            r.id,
            escape_c(&r.name),
            stage_macro(r.layer),
            r.priority,
            action_macro(r.effective_action()),
            direction_macro(r.direction),
            r.protocol
                .number()
                .map(|n| n.to_string())
                .unwrap_or_else(|| "UFW_PROTO_ANY".into()),
            module_flags(r),
        );
    }
    s.push_str("};\n");
    s
}

fn stage_macro(l: Layer) -> &'static str {
    match l {
        Layer::Perimeter => "UFW_STAGE_PERIMETER",
        Layer::Packet => "UFW_STAGE_PACKET",
        Layer::Identity => "UFW_STAGE_IDENTITY",
        Layer::AppDpi => "UFW_STAGE_APP_DPI",
        Layer::Stream => "UFW_STAGE_STREAM",
    }
}

fn action_macro(a: Action) -> &'static str {
    match a {
        Action::Allow => "UFW_ACTION_ALLOW",
        Action::Deny => "UFW_ACTION_DENY",
        Action::AllowInspect => "UFW_ACTION_ALLOW_INSPECT",
        Action::Alert => "UFW_ACTION_ALERT",
        Action::Continue => "UFW_ACTION_CONTINUE",
    }
}

fn module_flags(r: &CompiledRule) -> String {
    let mut f: Vec<&str> = Vec::new();
    if r.log {
        f.push("UFW_FLAG_LOG");
    }
    if r.stateful {
        f.push("UFW_FLAG_STATEFUL");
    }
    if r.ebpf_eligible {
        f.push("UFW_FLAG_EBPF_ELIGIBLE");
    }
    if r.app.is_some() {
        f.push("UFW_FLAG_NEEDS_IDENTITY");
    }
    if r.dpi.is_some() {
        f.push("UFW_FLAG_NEEDS_DPI");
    }
    if f.is_empty() {
        "0".into()
    } else {
        f.join(" | ")
    }
}

fn escape_c(s: &str) -> String {
    s.replace('\\', "\\\\").replace('"', "\\\"")
}

// ===========================================================================
// JSON (netlink payload description)
// ===========================================================================

fn emit_json(policy: &CompiledPolicy, ordered: &[CompiledRule], offloaded: &[u32]) -> String {
    let mut w = JsonWriter::with_capacity(4096);
    w.begin_object();
    w.str_field("format", "ufw-linux-policy");
    w.u64_field("format_version", 1);
    w.str_field("policy", &policy.name);
    w.u64_field("revision", policy.revision);
    w.str_field("ruleset_sha256", &ufw_shared::hash::hex(&policy.ruleset_hash));
    w.str_field("default_action", policy.default_action.as_str());
    w.str_field("genl_family", constants::LINUX_GENL_FAMILY);
    w.str_field("bpf_pin_dir", constants::LINUX_BPF_PIN_DIR);

    w.begin_object_field("fast_path");
    w.str_field("attach", "tc ingress (clsact)");
    w.u64_field("offloaded_rules", offloaded.len() as u64);
    w.begin_array_field("rule_ids");
    for id in offloaded {
        w.u64_element(*id as u64);
    }
    w.end_array();
    w.end_object();

    w.begin_array_field("rules");
    for r in ordered {
        w.begin_object();
        w.u64_field("id", r.id as u64);
        w.str_field("name", &r.name);
        w.str_field("stage", r.layer.as_str());
        w.u64_field("priority", r.priority as u64);
        w.str_field("action", r.effective_action().as_str());
        w.str_field("direction", r.direction.as_str());
        w.str_field("protocol", &r.protocol.as_str());
        w.str_field("source", &render_address(&r.source));
        w.str_field("source_ports", &render_ports(&r.source_ports));
        w.str_field("dest", &render_address(&r.dest));
        w.str_field("dest_ports", &render_ports(&r.dest_ports));
        w.str_field(
            "hook",
            if offloaded.contains(&r.id) {
                "tc-ingress+netfilter"
            } else {
                netfilter_hook(r.direction)
            },
        );
        w.bool_field("needs_identity", r.app.is_some());
        w.bool_field("needs_dpi", r.dpi.is_some());
        w.bool_field("log", r.log);
        w.str_array_field("tags", r.tags.iter().map(|s| s.as_str()));
        w.end_object();
    }
    w.end_array();
    w.end_object();
    w.finish()
}

fn netfilter_hook(d: Direction) -> &'static str {
    match d {
        Direction::Inbound => "NF_INET_LOCAL_IN",
        Direction::Outbound => "NF_INET_LOCAL_OUT",
        Direction::Any => "NF_INET_LOCAL_IN,NF_INET_LOCAL_OUT",
    }
}

// ===========================================================================
// nftables parity ruleset
// ===========================================================================

/// Emit an nftables ruleset covering the header-only rules.
///
/// This is not the enforcement path — the kernel module is — but it is a
/// genuinely useful artifact: an operator can read it, diff it against the
/// host's existing firewall, and see what the policy will do without loading
/// anything. Rules that need identity or payload context are emitted as
/// comments, because nftables cannot express them and silently dropping them
/// would make the file lie.
fn emit_nftables(policy: &CompiledPolicy, ordered: &[CompiledRule]) -> String {
    let mut s = String::new();
    let _ = write!(
        s,
        "#!/usr/sbin/nft -f\n\
         # Generated by the Unified Policy Language compiler. Do not edit.\n\
         #\n\
         # policy   : {}\n\
         # revision : {}\n\
         #\n\
         # PARITY ARTIFACT, NOT THE ENFORCEMENT PATH. The kernel module enforces the\n\
         # full policy including identity and DPI predicates, which nftables cannot\n\
         # express; those rules appear below as comments so this file never implies\n\
         # coverage it does not have.\n\n\
         table inet ufw {{\n",
        policy.name, policy.revision
    );

    for (chain, hook, dir) in [
        ("input", "input", Direction::Inbound),
        ("output", "output", Direction::Outbound),
    ] {
        let _ = write!(
            s,
            "    chain {} {{\n        type filter hook {} priority 0; policy {};\n",
            chain,
            hook,
            match policy.default_action {
                Decision::Allow => "accept",
                Decision::Deny => "drop",
            }
        );
        for r in ordered {
            if !r.direction.matches(dir) {
                continue;
            }
            match nft_rule(r) {
                Some(line) => {
                    let _ = writeln!(s, "        {line}");
                }
                None => {
                    let _ = writeln!(
                        s,
                        "        # [{}] `{}` needs {} context; enforced by the kernel module only",
                        r.layer.as_str(),
                        r.name,
                        if r.dpi.is_some() { "payload" } else { "process" }
                    );
                }
            }
        }
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    s
}

fn nft_rule(r: &CompiledRule) -> Option<String> {
    if r.app.is_some() || r.dpi.is_some() || r.schedule.is_some() {
        return None;
    }
    let mut parts: Vec<String> = Vec::new();
    if let Some(n) = r.protocol.number() {
        parts.push(format!("meta l4proto {n}"));
    }
    if !r.source.cidrs.is_empty() {
        parts.push(format!(
            "ip saddr {{ {} }}",
            r.source
                .cidrs
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !r.dest.cidrs.is_empty() {
        parts.push(format!(
            "ip daddr {{ {} }}",
            r.dest
                .cidrs
                .iter()
                .map(|c| c.to_string())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    if !r.dest_ports.ranges.is_empty() && r.protocol.has_ports() {
        parts.push(format!(
            "{} dport {{ {} }}",
            r.protocol.as_str(),
            r.dest_ports
                .ranges
                .iter()
                .map(|p| if p.lo == p.hi {
                    p.lo.to_string()
                } else {
                    format!("{}-{}", p.lo, p.hi)
                })
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }
    let verdict = match r.effective_action() {
        Action::Allow | Action::AllowInspect => "accept",
        Action::Deny => "drop",
        Action::Alert => "log prefix \"ufw-alert \"",
        Action::Continue => "continue",
    };
    let comment = format!("comment \"{}\"", r.name.replace('"', "'"));
    Some(format!("{} {verdict} {comment}", parts.join(" ")).trim().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::json;
    use ufw_shared::policy_types::AppMatch;

    fn header_rule(id: u32, name: &str, priority: u16, dir: Direction) -> CompiledRule {
        let mut r = CompiledRule::new(id, name, Layer::Packet, Action::Deny);
        r.priority = priority;
        r.protocol = Protocol::Tcp;
        r.direction = dir;
        r.dest_ports = PortMatch { ranges: vec![PortRange::single(23)], negate: false };
        r
    }

    fn identity_rule(id: u32, name: &str, priority: u16) -> CompiledRule {
        let mut r = CompiledRule::new(id, name, Layer::Identity, Action::Deny);
        r.priority = priority;
        r.app = Some(AppMatch::any());
        r
    }

    /// A packet-stage rule that is *not* eBPF-expressible, because zone
    /// classification needs the daemon's network profile.
    fn zone_rule(id: u32, name: &str, priority: u16) -> CompiledRule {
        let mut r = CompiledRule::new(id, name, Layer::Packet, Action::Deny);
        r.priority = priority;
        r.dest = AddressMatch { cidrs: vec![], zones: vec![Zone::External], negate: false };
        r
    }

    fn build(rules: Vec<CompiledRule>) -> CompiledPolicy {
        let mut p = CompiledPolicy::new("lin", Decision::Deny);
        p.rules = rules;
        p.finalize();
        crate::optimizer::optimize(
            &mut p,
            &crate::optimizer::OptimizerOptions {
                eliminate_unreachable: false,
                eliminate_duplicates: false,
                ..Default::default()
            },
        );
        p
    }

    #[test]
    fn header_only_prefix_is_offloaded() {
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Any),
            header_rule(2, "b", 20, Direction::Any),
        ]);
        let a = LinuxBackend.generate(&p);
        let ebpf: Vec<u32> = a.model.rules_on(Engine::Ebpf).map(|r| r.id).collect();
        assert_eq!(ebpf, vec![1, 2]);
    }

    #[test]
    fn offload_stops_at_the_first_rule_that_needs_context() {
        // `b` is header-only but sits behind a zone rule, which the fast path
        // cannot evaluate. Offloading `b` would let tc ingress decide ahead of
        // the zone rule.
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Any),
            zone_rule(2, "zoned", 20),
            header_rule(3, "b", 30, Direction::Any),
        ]);
        let a = LinuxBackend.generate(&p);
        let ebpf: Vec<u32> = a.model.rules_on(Engine::Ebpf).map(|r| r.id).collect();
        assert_eq!(ebpf, vec![1]);
        assert!(a.notes.has_code(codes::EBPF_OFFLOAD));
    }

    #[test]
    fn a_later_stage_never_blocks_offload_of_an_earlier_one() {
        // Identity rules sort after every packet rule regardless of priority,
        // so they cannot interrupt the packet-stage prefix.
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Any),
            identity_rule(2, "ident", 1),
            header_rule(3, "b", 30, Direction::Any),
        ]);
        let a = LinuxBackend.generate(&p);
        let ebpf: Vec<u32> = a.model.rules_on(Engine::Ebpf).map(|r| r.id).collect();
        assert_eq!(ebpf, vec![1, 3]);
    }

    #[test]
    fn outbound_only_rules_neither_offload_nor_block_the_prefix() {
        // An outbound rule cannot match an inbound packet, so it is invisible
        // to the ingress fast path in both directions.
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Inbound),
            {
                let mut r = identity_rule(2, "out-ident", 20);
                r.direction = Direction::Outbound;
                r
            },
            header_rule(3, "b", 30, Direction::Inbound),
        ]);
        let a = LinuxBackend.generate(&p);
        let ebpf: Vec<u32> = a.model.rules_on(Engine::Ebpf).map(|r| r.id).collect();
        assert_eq!(ebpf, vec![1, 3]);
    }

    #[test]
    fn the_netfilter_table_always_holds_every_rule() {
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Any),
            zone_rule(2, "zoned", 20),
            header_rule(3, "b", 30, Direction::Any),
        ]);
        let a = LinuxBackend.generate(&p);
        assert_eq!(a.model.rules.len(), 3);
        let json_text = &a.file("linux/ufw_policy.json").unwrap().contents;
        let v = json::parse(json_text).unwrap();
        assert_eq!(v.get("rules").unwrap().as_array().unwrap().len(), 3);
    }

    #[test]
    fn an_empty_fast_path_still_emits_a_compilable_header() {
        let p = build(vec![identity_rule(1, "ident", 10)]);
        let a = LinuxBackend.generate(&p);
        let h = &a.file("linux/ufw_ebpf_rules.h").unwrap().contents;
        assert!(h.contains("#define UFW_EBPF_RULE_COUNT 0"));
        assert!(h.contains("ufw_ebpf_rules[1]"), "must not emit a zero-length array");
    }

    #[test]
    fn ebpf_header_holds_only_the_offloaded_rules() {
        let p = build(vec![
            header_rule(1, "fast", 10, Direction::Any),
            zone_rule(2, "zoned", 20),
            header_rule(3, "slow", 30, Direction::Any),
        ]);
        let a = LinuxBackend.generate(&p);
        let h = &a.file("linux/ufw_ebpf_rules.h").unwrap().contents;
        assert!(h.contains("\"fast\""));
        assert!(!h.contains("\"slow\""));
        assert!(h.contains("#define UFW_EBPF_RULE_COUNT 1"));
    }

    #[test]
    fn nftables_output_comments_rules_it_cannot_express() {
        let p = build(vec![
            header_rule(1, "telnet", 10, Direction::Inbound),
            identity_rule(2, "ident", 20),
        ]);
        let a = LinuxBackend.generate(&p);
        let nft = &a.file("linux/ufw.nft").unwrap().contents;
        assert!(nft.contains("tcp dport { 23 } drop comment \"telnet\""));
        assert!(nft.contains("# [identity] `ident` needs process context"));
        assert!(nft.contains("table inet ufw"));
    }

    #[test]
    fn generated_c_balances_its_braces() {
        let p = build(vec![
            header_rule(1, "a", 10, Direction::Any),
            identity_rule(2, "ident", 20),
        ]);
        let a = LinuxBackend.generate(&p);
        for f in &a.files {
            if f.path.ends_with(".h") {
                assert_eq!(
                    f.contents.matches('{').count(),
                    f.contents.matches('}').count(),
                    "unbalanced braces in {}",
                    f.path
                );
            }
        }
    }

    #[test]
    fn json_records_the_offload_plan() {
        let p = build(vec![header_rule(1, "a", 10, Direction::Any)]);
        let a = LinuxBackend.generate(&p);
        let v = json::parse(&a.file("linux/ufw_policy.json").unwrap().contents).unwrap();
        let fast = v.get("fast_path").unwrap();
        assert_eq!(fast.get("offloaded_rules").unwrap().as_u64(), Some(1));
        assert_eq!(fast.get("rule_ids").unwrap().as_array().unwrap().len(), 1);
    }
}
