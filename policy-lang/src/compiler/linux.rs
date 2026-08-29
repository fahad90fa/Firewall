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
            GeneratedFile::new(
                "linux/ufw_policy.json",
                emit_json(policy, &ordered, &offloaded),
            ),
            GeneratedFile::new("linux/ufw.nft", emit_nftables(policy, &ordered)),
        ];

        Artifact {
            platform: Platform::Linux,
            files,
            model,
            notes,
        }
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

fn emit_ebpf_header(
    policy: &CompiledPolicy,
    ordered: &[CompiledRule],
    offloaded: &[u32],
) -> String {
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
            v4_count(&r.source.cidrs),
            cidr_list(&r.dest.cidrs),
            v4_count(&r.dest.cidrs),
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
    // `struct ufw_ebpf_cidr` is IPv4-only by design; the optimizer refuses to
    // mark a rule with an IPv6 prefix as eBPF-eligible, so nothing reaching
    // here should carry one. Skipping rather than asserting keeps a future
    // caller from emitting an initialiser the struct cannot accept — which is
    // the failure this used to produce, and it surfaced as the eBPF programs
    // not compiling rather than as anything a policy test would see.
    cidrs
        .iter()
        .filter_map(|c| match c.addr() {
            std::net::IpAddr::V4(a) => Some(format!(
                "{{ .addr = 0x{:08x}, .prefix_len = {} }}",
                u32::from(a),
                c.prefix()
            )),
            std::net::IpAddr::V6(_) => None,
        })
        .collect::<Vec<_>>()
        .join(", ")
}

/// Count the IPv4 CIDRs in a set — exactly the ones [`cidr_list`] emits, so the
/// eBPF struct's `.src_n`/`.dst_n` can never claim more elements than the
/// initializer holds (an IPv6 prefix is skipped by `cidr_list` but was still
/// counted by a bare `.len()`). Guarded today by the optimizer refusing to make
/// an IPv6-bearing rule eBPF-eligible, but the count must match the array.
fn v4_count(cidrs: &[Cidr]) -> usize {
    cidrs
        .iter()
        .filter(|c| matches!(c.addr(), std::net::IpAddr::V4(_)))
        .count()
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
    let _ = writeln!(
        s,
        "#define UFW_ABI_REVISION_EXPECTED {}",
        constants::ABI_REVISION
    );
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
        let _ = writeln!(
            s,
            "    {{ .id = {}, .name = \"{}\", .stage = {}, .priority = {}, .action = {}, \
             .direction = {}, .protocol = {}, .flags = {} }},",
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

/// Escape a string for a C string literal. Beyond `\` and `"`, control
/// characters must be escaped too — a raw newline in a rule name would split
/// the generated `.name = "..."` across two lines and fail the build. Control
/// bytes use a three-digit octal escape (`\ooo`) rather than `\x`, because C's
/// `\x` is greedy and would swallow a following hex letter.
fn escape_c(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\{:03o}", c as u32 & 0xff);
            }
            c => out.push(c),
        }
    }
    out
}

/// Neutralise a string for an nftables quoted token (a `comment "…"` or an
/// interface name): drop control characters — a newline would break the rule
/// line the loader parses — and turn an embedded double quote into a single one
/// so it cannot close the token early.
fn nft_quoted(s: &str) -> String {
    s.chars()
        .filter(|c| !c.is_control())
        .map(|c| if c == '"' { '\'' } else { c })
        .collect()
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
    w.str_field(
        "ruleset_sha256",
        &ufw_shared::hash::hex(&policy.ruleset_hash),
    );
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
/// anything (and `ufw-nft apply` loads exactly this file). Rules that need
/// identity or payload context are emitted as comments, because nftables
/// cannot express them and silently dropping them would make the file lie.
///
/// The same honesty applies to matchers, not just whole rules. An `inet`
/// table matches IPv4 with `ip` expressions and IPv6 with `ip6` expressions,
/// so an address set that mixes families cannot be one nftables set: the rule
/// is split into an IPv4 line and an IPv6 line with the same verdict. Zone
/// predicates are lowered through the same `NetworkProfile::classify` order
/// the reference model uses (loopback, then internal, then perimeter, then
/// external); a predicate whose exact lowering does not exist — a negated
/// zone+address combination, say — becomes a comment rather than a rule that
/// matches more or less than the policy said.
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
            match nft_rule(policy, r, dir) {
                Lowering::Lines(lines) => {
                    for line in lines {
                        let _ = writeln!(s, "        {line}");
                    }
                }
                Lowering::Kernel(reason) => {
                    let _ = writeln!(
                        s,
                        "        # [{}] `{}` {reason}; enforced by the kernel module only",
                        r.layer.as_str(),
                        r.name,
                    );
                }
                Lowering::Unmatchable(reason) => {
                    let _ = writeln!(
                        s,
                        "        # [{}] `{}` {reason}; it can never match a packet and is omitted",
                        r.layer.as_str(),
                        r.name,
                    );
                }
            }
        }
        s.push_str("    }\n");
    }
    s.push_str("}\n");
    s
}

/// What became of one policy rule on the way into nftables.
enum Lowering {
    /// One line per address family that can match — two when an address set
    /// mixes IPv4 and IPv6, one otherwise.
    Lines(Vec<String>),
    /// nftables cannot express the rule; the string completes the sentence
    /// "`name` …; enforced by the kernel module only".
    Kernel(String),
    /// The rule contradicts itself (an IPv4-only source with an IPv6-only
    /// destination, a negated wildcard); no packet can ever satisfy it.
    Unmatchable(String),
}

/// The two address families an `inet` chain sees. nftables has no expression
/// that matches an address of either family, which is the entire reason rules
/// get split.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Fam {
    V4,
    V6,
}

impl Fam {
    fn keyword(self) -> &'static str {
        match self {
            Fam::V4 => "ip",
            Fam::V6 => "ip6",
        }
    }

    fn holds(self, c: &Cidr) -> bool {
        c.is_v4() == (self == Fam::V4)
    }
}

/// How one side (source or destination) of a rule lowers for one family.
enum SideMatch {
    /// Zero or more match statements; zero means unconstrained.
    Stmts(Vec<String>),
    /// This family cannot satisfy the predicate (e.g. an IPv4-only address
    /// set on the IPv6 line); the family's rule line is skipped.
    NoFamily,
}

fn nft_rule(policy: &CompiledPolicy, r: &CompiledRule, chain_dir: Direction) -> Lowering {
    if r.app.is_some() || r.dpi.is_some() {
        return Lowering::Kernel(format!(
            "needs {} context",
            if r.dpi.is_some() {
                "payload"
            } else {
                "process"
            }
        ));
    }
    if r.schedule.is_some() {
        return Lowering::Kernel("is active only on a schedule".into());
    }
    // `allow-inspect` is provisional in the reference model: it permits the flow
    // *so far* but keeps evaluating deeper stages, which may still deny. nftables
    // has only terminal verdicts, so lowering it to `accept` here would skip a
    // deeper header-only `deny` that the model would honour — a silent bypass on
    // the module-off path. It cannot be expressed as a non-terminal permit, so it
    // belongs to the kernel module (which does the inspection it names); emitting
    // it as a comment lets the flow fall through to the deeper rules and the
    // default policy, which is fail-closed rather than fail-open.
    if r.effective_action() == Action::AllowInspect {
        return Lowering::Kernel(
            "is `allow-inspect`, a provisional permit nftables cannot express \
             without skipping the deeper stages it asks to keep inspecting"
                .into(),
        );
    }
    for (side, m) in [("source", &r.source), ("destination", &r.dest)] {
        if m.negate && m.cidrs.is_empty() && m.zones.is_empty() {
            return Lowering::Unmatchable(format!("negates the wildcard {side} address"));
        }
    }
    for (side, p) in [("source", &r.source_ports), ("destination", &r.dest_ports)] {
        if p.negate && p.ranges.is_empty() {
            return Lowering::Unmatchable(format!("negates the wildcard {side} port"));
        }
    }

    let mut lines = Vec::new();
    for fam in [Fam::V4, Fam::V6] {
        // ICMP is an IPv4 protocol and ICMPv6 an IPv6 one; the other family's
        // line would be a rule no packet can hit.
        match (r.protocol, fam) {
            (Protocol::Icmp, Fam::V6) | (Protocol::IcmpV6, Fam::V4) => continue,
            _ => {}
        }
        let src = match side_match(&policy.network_profile, &r.source, "saddr", fam) {
            Ok(SideMatch::Stmts(v)) => v,
            Ok(SideMatch::NoFamily) => continue,
            Err(reason) => return Lowering::Kernel(reason),
        };
        let dst = match side_match(&policy.network_profile, &r.dest, "daddr", fam) {
            Ok(SideMatch::Stmts(v)) => v,
            Ok(SideMatch::NoFamily) => continue,
            Err(reason) => return Lowering::Kernel(reason),
        };

        let mut parts: Vec<String> = Vec::new();
        if !r.interfaces.is_empty() {
            // The packet's interface is the receiving one on the input hook
            // and the sending one on the output hook, so the same rule
            // constrains a different meta key per chain.
            let key = match chain_dir {
                Direction::Outbound => "oifname",
                _ => "iifname",
            };
            let names = r
                .interfaces
                .iter()
                .map(|i| format!("\"{}\"", nft_quoted(i)))
                .collect::<Vec<_>>()
                .join(", ");
            parts.push(format!("{key} {{ {names} }}"));
        }
        if let Some(n) = r.protocol.number() {
            parts.push(format!("meta l4proto {n}"));
        }
        parts.extend(src);
        parts.extend(dst);
        // Ports. nftables names the port field with a per-transport keyword.
        // A rule that carries ports but leaves the protocol as `any` still
        // means the port-bearing transports — the semantic analyzer allows
        // exactly `any` (never icmp) to pair with ports — so it lowers to the
        // generic transport header under an `l4proto` guard, which both
        // matches tcp/udp/sctp and cannot misread an ICMP packet's header
        // bytes as a port. Dropping the port entirely, as this once did, made
        // "deny any protocol to port 3389" silently mean "deny everything".
        let have_ports = !r.source_ports.ranges.is_empty() || !r.dest_ports.ranges.is_empty();
        if have_ports {
            let keyword = match r.protocol {
                Protocol::Tcp => Some("tcp"),
                Protocol::Udp => Some("udp"),
                Protocol::Other(132) => Some("sctp"),
                Protocol::Any => {
                    // Constrain to the same transports `Protocol::has_ports`
                    // recognises, so the nft rule matches exactly the set the
                    // decision model treats as port-bearing — no broader, no
                    // narrower.
                    parts.push("meta l4proto { 6, 17, 132 }".to_string());
                    Some("th")
                }
                // icmp/icmpv6/other non-port protocols with a port list are a
                // semantic error and never reach here; skip defensively.
                _ => None,
            };
            if let Some(kw) = keyword {
                if let Some(m) = port_match(&r.source_ports, kw, "sport") {
                    parts.push(m);
                }
                if let Some(m) = port_match(&r.dest_ports, kw, "dport") {
                    parts.push(m);
                }
            }
        }

        // Denies the policy asked to log carry a structured prefix naming the
        // rule, so a kernel log line can be traced back to the decision that
        // produced it. Logged *allows* are deliberately not lowered to a log
        // statement: nf_log on every accepted packet floods the ring buffer,
        // and the kernel module's own sink is where that firehose belongs.
        let log = match r.effective_action() {
            Action::Alert => Some(log_statement("alert", &r.name)),
            Action::Deny if r.log => Some(log_statement("deny", &r.name)),
            _ => None,
        };
        let verdict = match r.effective_action() {
            Action::Allow | Action::AllowInspect => Some("accept"),
            Action::Deny => Some("drop"),
            // An alert observes and lets evaluation continue; the log
            // statement above is the whole of it.
            Action::Alert => None,
            Action::Continue => Some("continue"),
        };
        if let Some(log) = log {
            parts.push(log);
        }
        // A rate limit lowers to nft's native `limit` statement: the rule
        // matches — and accepts — up to the rate, and excess *new* connections
        // fail the match and fall through to the default deny. That is exactly
        // SYN-flood and brute-force dampening, enforced in the kernel's own
        // conntrack path with no module involvement.
        if let Some(rl) = &r.rate_limit {
            if matches!(r.effective_action(), Action::Allow | Action::AllowInspect) {
                let mut limit = format!("ct state new limit rate {}/{}", rl.rate, rl.per.as_nft());
                if rl.burst > 0 {
                    let _ = write!(limit, " burst {} packets", rl.burst);
                }
                parts.push(limit);
            }
        }
        if let Some(v) = verdict {
            parts.push(v.to_string());
        }
        parts.push(format!("comment \"{}\"", nft_quoted(&r.name)));
        lines.push(parts.join(" ").trim().to_string());
    }

    // A rule with no family-specific matcher lowers identically for both
    // families; one line covers the whole inet chain.
    lines.dedup();
    if lines.is_empty() {
        return Lowering::Unmatchable(
            "combines predicates whose address families never intersect".into(),
        );
    }
    Lowering::Lines(lines)
}

/// The kernel-log prefix for a logged deny or alert:
/// `ufw#<deny|alert>#<rule-name> `. The dashboard and any log pipeline parse
/// this back into (action, rule); the trailing space separates it from the
/// packet fields netfilter appends. Kept well under NF_LOG's 127-character
/// prefix ceiling.
fn log_statement(kind: &str, rule_name: &str) -> String {
    let mut name: String = rule_name
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-') {
                c
            } else {
                '-'
            }
        })
        .collect();
    name.truncate(96);
    format!("log prefix \"ufw#{kind}#{name} \"")
}

/// One port expression, e.g. `tcp dport { 80, 443 }` or, for an any-protocol
/// rule, `th dport { 53 }`. `keyword` is the nftables transport keyword
/// (`tcp`/`udp`/`sctp`/`th`), already chosen by the caller.
fn port_match(ports: &PortMatch, keyword: &str, field: &str) -> Option<String> {
    if ports.ranges.is_empty() {
        return None;
    }
    let list = ports
        .ranges
        .iter()
        .map(|p| {
            if p.lo == p.hi {
                p.lo.to_string()
            } else {
                format!("{}-{}", p.lo, p.hi)
            }
        })
        .collect::<Vec<_>>()
        .join(", ");
    let op = if ports.negate { "!= " } else { "" };
    Some(format!("{keyword} {field} {op}{{ {list} }}"))
}

/// The address sets that define `Zone::Loopback`, per family. Internal and
/// perimeter come from the network profile; loopback is the address
/// architecture's.
fn loopback_cidrs() -> [Cidr; 2] {
    [
        Cidr::parse("127.0.0.0/8").expect("constant"),
        Cidr::parse("::1/128").expect("constant"),
    ]
}

/// Lower one side's address predicate for one family.
///
/// `Err` carries a reason the predicate has no exact nftables form; the rule
/// then falls back to a comment. Widening (dropping a constraint) or
/// narrowing (inventing one) are both lies this function refuses to tell.
fn side_match(
    profile: &NetworkProfile,
    m: &AddressMatch,
    field: &str,
    fam: Fam,
) -> Result<SideMatch, String> {
    if m.cidrs.is_empty() && m.zones.is_empty() {
        return Ok(SideMatch::Stmts(Vec::new()));
    }

    if m.negate {
        if !m.zones.is_empty() && !m.cidrs.is_empty() {
            // ¬(addr ∈ set ∧ zone ∈ Z) is a disjunction, and an nftables rule
            // is a conjunction.
            return Err(format!(
                "negates a combined address+zone {} predicate, which nftables \
                 cannot express as one rule",
                if field == "saddr" {
                    "source"
                } else {
                    "destination"
                }
            ));
        }
        if !m.cidrs.is_empty() {
            // ¬(addr ∈ set): membership in the other family is impossible, so
            // its negation holds vacuously — that family's line simply loses
            // the constraint.
            let members: Vec<&Cidr> = m.cidrs.iter().filter(|c| fam.holds(c)).collect();
            if members.is_empty() {
                return Ok(SideMatch::Stmts(Vec::new()));
            }
            if members.iter().any(|c| c.is_any()) {
                // ¬(everything in this family) matches nothing in it.
                return Ok(SideMatch::NoFamily);
            }
            return Ok(SideMatch::Stmts(vec![format!(
                "{} {field} != {{ {} }}",
                fam.keyword(),
                render_cidrs(&members)
            )]));
        }
        // ¬(zone ∈ Z) ≡ zone ∈ (complement of Z); reuse the positive lowering.
        let complement: Vec<Zone> = [
            Zone::Loopback,
            Zone::Internal,
            Zone::Perimeter,
            Zone::External,
        ]
        .into_iter()
        .filter(|z| !m.zones.contains(z))
        .collect();
        if complement.is_empty() {
            // The predicate negated every zone there is.
            return Ok(SideMatch::NoFamily);
        }
        return zone_stmts(profile, &complement, field, fam);
    }

    let mut stmts = Vec::new();
    if !m.cidrs.is_empty() {
        let members: Vec<&Cidr> = m.cidrs.iter().filter(|c| fam.holds(c)).collect();
        if members.is_empty() {
            // Every listed address is the other family; nothing of this
            // family can ever satisfy the predicate.
            return Ok(SideMatch::NoFamily);
        }
        stmts.push(format!(
            "{} {field} {{ {} }}",
            fam.keyword(),
            render_cidrs(&members)
        ));
    }
    if !m.zones.is_empty() {
        match zone_stmts(profile, &m.zones, field, fam)? {
            SideMatch::Stmts(z) => stmts.extend(z),
            SideMatch::NoFamily => return Ok(SideMatch::NoFamily),
        }
    }
    Ok(SideMatch::Stmts(stmts))
}

/// Lower `zone ∈ Z` (a union of zones, not negated) for one family, exactly.
///
/// `classify` tries loopback, internal, perimeter, external, in that order,
/// so a zone's addresses are its defining set *minus every earlier zone's*.
/// A union of zones without External is therefore membership in the union of
/// defining sets plus an exclusion for any earlier, unselected set that
/// overlaps — both expressible, since an nftables rule is a conjunction. A
/// union containing External is rewritten as ¬(the complement union), which
/// is only expressible when that complement needs no exclusions of its own.
fn zone_stmts(
    profile: &NetworkProfile,
    zones: &[Zone],
    field: &str,
    fam: Fam,
) -> Result<SideMatch, String> {
    let selected = |z: Zone| zones.contains(&z);
    if selected(Zone::External) {
        let complement: Vec<Zone> = [Zone::Loopback, Zone::Internal, Zone::Perimeter]
            .into_iter()
            .filter(|z| !selected(*z))
            .collect();
        if complement.is_empty() {
            // Every zone is selected: the wildcard.
            return Ok(SideMatch::Stmts(Vec::new()));
        }
        let (members, exclusions) = zone_union_sets(profile, &complement, field)?;
        if !exclusions.is_empty() {
            return Err(format!(
                "matches a set of zones whose complement nftables cannot express \
                 exactly (the profile's zone ranges overlap on {field})"
            ));
        }
        let members: Vec<&Cidr> = members.into_iter().filter(|c| fam.holds(c)).collect();
        if members.is_empty() {
            // Nothing of this family is in the complement, so everything in
            // this family matches.
            return Ok(SideMatch::Stmts(Vec::new()));
        }
        if members.iter().any(|c| c.is_any()) {
            // The complement covers the whole family.
            return Ok(SideMatch::NoFamily);
        }
        return Ok(SideMatch::Stmts(vec![format!(
            "{} {field} != {{ {} }}",
            fam.keyword(),
            render_cidrs(&members)
        )]));
    }

    let (members, exclusions) = zone_union_sets(profile, zones, field)?;
    let members: Vec<&Cidr> = members.into_iter().filter(|c| fam.holds(c)).collect();
    if members.is_empty() {
        return Ok(SideMatch::NoFamily);
    }
    let mut stmts = vec![format!(
        "{} {field} {{ {} }}",
        fam.keyword(),
        render_cidrs(&members)
    )];
    let exclusions: Vec<&Cidr> = exclusions.into_iter().filter(|c| fam.holds(c)).collect();
    if !exclusions.is_empty() {
        stmts.push(format!(
            "{} {field} != {{ {} }}",
            fam.keyword(),
            render_cidrs(&exclusions)
        ));
    }
    Ok(SideMatch::Stmts(stmts))
}

/// For a union of zones (External never among them): the defining sets whose
/// union the address must fall in, and the earlier-zone sets it must *not*
/// fall in for the classification to actually land on a selected zone.
/// Exclusions are only generated where sets overlap; on any sane profile
/// (internal ranges that do not contain 127.0.0.1) there are none.
///
/// `Err` marks the one shape a conjunction cannot carry: an excluded set that
/// also overlaps a *selected* zone classified before it, where subtracting
/// the set would wrongly remove addresses the earlier zone already claimed.
fn zone_union_sets<'a>(
    profile: &'a NetworkProfile,
    zones: &[Zone],
    field: &str,
) -> Result<(Vec<&'a Cidr>, Vec<&'a Cidr>), String> {
    let loopback: &'static [Cidr] = {
        // The loopback defining set never changes; one shared copy lets it sit
        // beside profile-owned CIDRs without cloning the profile's.
        static LOOPBACK: std::sync::OnceLock<[Cidr; 2]> = std::sync::OnceLock::new();
        LOOPBACK.get_or_init(loopback_cidrs)
    };
    let defining = |z: Zone| -> &[Cidr] {
        match z {
            Zone::Loopback => loopback,
            Zone::Internal => &profile.internal,
            Zone::Perimeter => &profile.perimeter,
            Zone::External => &[],
        }
    };
    let overlaps = |a: &Cidr, set: &[Cidr]| set.iter().any(|m| a.covers(m) || m.covers(a));
    let order = [Zone::Loopback, Zone::Internal, Zone::Perimeter];
    let mut members: Vec<&Cidr> = Vec::new();
    let mut exclusions: Vec<&Cidr> = Vec::new();
    for (i, z) in order.iter().enumerate() {
        if !zones.contains(z) {
            continue;
        }
        members.extend(defining(*z));
        // An address in a selected zone's set is only classified there if no
        // earlier zone's set claims it first.
        for (j, earlier) in order[..i].iter().enumerate() {
            if zones.contains(earlier) {
                continue;
            }
            for e in defining(*earlier) {
                if !overlaps(e, defining(*z)) {
                    continue;
                }
                // Subtracting `e` must not take back addresses a selected
                // zone ahead of `earlier` already classified.
                for prior in &order[..j] {
                    if zones.contains(prior) && overlaps(e, defining(*prior)) {
                        return Err(format!(
                            "matches a set of zones the profile's overlapping \
                             ranges keep nftables from expressing exactly (on {field})"
                        ));
                    }
                }
                if !exclusions.contains(&e) {
                    exclusions.push(e);
                }
            }
        }
    }
    Ok((members, exclusions))
}

fn render_cidrs(cidrs: &[&Cidr]) -> String {
    cidrs
        .iter()
        .map(|c| c.to_string())
        .collect::<Vec<_>>()
        .join(", ")
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
        r.dest_ports = PortMatch {
            ranges: vec![PortRange::single(23)],
            negate: false,
        };
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
        r.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::External],
            negate: false,
        };
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
        assert!(
            h.contains("ufw_ebpf_rules[1]"),
            "must not emit a zero-length array"
        );
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
        // `log` defaults to true, so the deny carries its attribution prefix.
        assert!(nft
            .contains("tcp dport { 23 } log prefix \"ufw#deny#telnet \" drop comment \"telnet\""));
        assert!(nft.contains("# [identity] `ident` needs process context"));
        assert!(nft.contains("table inet ufw"));
    }

    fn cidrs(list: &[&str]) -> Vec<Cidr> {
        list.iter().map(|s| Cidr::parse(s).unwrap()).collect()
    }

    fn nft_artifact(p: &CompiledPolicy) -> String {
        LinuxBackend
            .generate(p)
            .file("linux/ufw.nft")
            .unwrap()
            .contents
            .clone()
    }

    #[test]
    fn allow_inspect_is_not_lowered_to_a_terminal_accept() {
        // `allow-inspect` is provisional: a deeper deny may still win. Lowering it
        // to a terminal nft `accept` would skip that deny — a silent bypass. It
        // must become a kernel-only comment, never an `accept` line.
        let mut ai = header_rule(1, "inspect-web", 10, Direction::Outbound);
        ai.action = Action::AllowInspect;
        ai.dest_ports = PortMatch::default();
        let nft = nft_artifact(&build(vec![ai]));
        assert!(nft.contains("`inspect-web`"), "{nft}");
        assert!(nft.contains("allow-inspect"), "{nft}");
        // No terminal accept carrying this rule's verdict.
        assert!(
            !nft.contains("accept comment \"inspect-web\""),
            "allow-inspect must not emit a terminal accept:\n{nft}"
        );
        for line in nft.lines() {
            if line.contains("inspect-web") {
                assert!(
                    line.trim_start().starts_with('#'),
                    "the allow-inspect rule must be a comment, got: {line}"
                );
            }
        }
    }

    #[test]
    fn a_rate_limited_allow_emits_a_native_nft_limit_statement() {
        let mut r = header_rule(1, "ssh-in", 10, Direction::Inbound);
        r.action = Action::Allow;
        r.rate_limit = Some(RateLimit {
            rate: 20,
            per: RatePer::Minute,
            burst: 5,
        });
        let nft = nft_artifact(&build(vec![r]));
        assert!(
            nft.contains("ct state new limit rate 20/minute burst 5 packets accept"),
            "{nft}"
        );
    }

    #[test]
    fn a_rate_limit_with_no_burst_omits_the_burst_clause() {
        let mut r = header_rule(1, "web-in", 10, Direction::Inbound);
        r.action = Action::Allow;
        r.rate_limit = Some(RateLimit {
            rate: 200,
            per: RatePer::Second,
            burst: 0,
        });
        let nft = nft_artifact(&build(vec![r]));
        assert!(
            nft.contains("ct state new limit rate 200/second accept"),
            "{nft}"
        );
        assert!(!nft.contains("burst"), "{nft}");
    }

    #[test]
    fn a_mixed_family_address_set_is_split_into_ip_and_ip6_rules() {
        // The exact shape that used to be emitted as one `ip daddr` set with
        // `::1/128` inside it — which nft rejects outright.
        let mut r = header_rule(1, "allow-loopback", 10, Direction::Any);
        r.action = Action::Allow;
        r.protocol = Protocol::Any;
        r.dest_ports = PortMatch::default();
        r.dest = AddressMatch {
            cidrs: cidrs(&["127.0.0.0/8", "::1/128"]),
            zones: vec![],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("ip daddr { 127.0.0.0/8 } accept comment \"allow-loopback\""));
        assert!(nft.contains("ip6 daddr { ::1/128 } accept comment \"allow-loopback\""));
        // No set may mix the families.
        for line in nft.lines() {
            if line.trim_start().starts_with("ip daddr") {
                assert!(!line.contains("::"), "IPv6 address in an ip match: {line}");
            }
            if line.trim_start().starts_with("ip6 daddr") {
                assert!(
                    !line.contains("127."),
                    "IPv4 address in an ip6 match: {line}"
                );
            }
        }
    }

    #[test]
    fn a_single_family_address_set_emits_one_rule_for_that_family_only() {
        let mut r = header_rule(1, "v4-only", 10, Direction::Any);
        r.dest = AddressMatch {
            cidrs: cidrs(&["10.0.0.0/8"]),
            zones: vec![],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("ip daddr { 10.0.0.0/8 }"));
        assert!(!nft.contains("ip6 daddr"));
    }

    #[test]
    fn a_cross_family_contradiction_is_omitted_with_a_comment() {
        // IPv4-only source, IPv6-only destination: no packet has both.
        let mut r = header_rule(1, "impossible", 10, Direction::Any);
        r.source = AddressMatch {
            cidrs: cidrs(&["10.0.0.0/8"]),
            zones: vec![],
            negate: false,
        };
        r.dest = AddressMatch {
            cidrs: cidrs(&["2001:db8::/32"]),
            zones: vec![],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("`impossible`"));
        assert!(nft.contains("can never match a packet"));
        assert!(!nft.contains("drop comment \"impossible\""));
    }

    #[test]
    fn an_external_zone_lowers_to_exclusion_of_loopback_and_internal() {
        let mut r = header_rule(1, "no-smb-egress", 10, Direction::Outbound);
        r.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::External],
            negate: false,
        };
        let mut p = CompiledPolicy::new("lin", Decision::Allow);
        p.network_profile.internal = cidrs(&["10.0.0.0/8", "fd00::/8"]);
        p.rules = vec![r];
        p.finalize();
        crate::optimizer::optimize(&mut p, &crate::optimizer::OptimizerOptions::default());
        let nft = nft_artifact(&p);
        assert!(
            nft.contains("ip daddr != { 127.0.0.0/8, 10.0.0.0/8 }"),
            "external zone must exclude loopback and internal v4 ranges:\n{nft}"
        );
        assert!(
            nft.contains("ip6 daddr != { ::1/128, fd00::/8 }"),
            "external zone must exclude loopback and internal v6 ranges:\n{nft}"
        );
    }

    #[test]
    fn a_negated_address_set_lowers_to_set_exclusion() {
        let mut r = header_rule(1, "not-lan", 10, Direction::Outbound);
        r.dest = AddressMatch {
            cidrs: cidrs(&["192.168.0.0/16"]),
            zones: vec![],
            negate: true,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("ip daddr != { 192.168.0.0/16 }"));
        // For IPv6 the negated IPv4 set holds vacuously: the rule applies to
        // all v6 traffic, so a second line without the address matcher exists.
        assert!(nft.contains(
            "meta l4proto 6 tcp dport { 23 } log prefix \"ufw#deny#not-lan \" drop comment \"not-lan\""
        ));
    }

    #[test]
    fn source_ports_are_emitted_not_silently_dropped() {
        let mut r = header_rule(1, "sport", 10, Direction::Any);
        r.source_ports = PortMatch {
            ranges: vec![PortRange::single(20)],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("tcp sport { 20 }"));
    }

    #[test]
    fn an_any_protocol_rule_with_ports_keeps_the_port_constraint() {
        // The regression: `protocol: any` + `ports: [3389]` must NOT become a
        // rule that matches every port. It lowers to the port-bearing
        // transports with a generic transport-header match.
        let mut r = CompiledRule::new(1, "deny-any-rdp", Layer::Packet, Action::Deny);
        r.priority = 10;
        r.protocol = Protocol::Any;
        r.direction = Direction::Inbound;
        r.dest_ports = PortMatch {
            ranges: vec![PortRange::single(3389)],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(
            nft.contains("meta l4proto { 6, 17, 132 } th dport { 3389 }"),
            "any-protocol port rule must constrain to port-bearing transports:\n{nft}"
        );
        // It must NOT emit a bare `drop` that ignores the port.
        for line in nft.lines() {
            if line.contains("deny-any-rdp") {
                assert!(line.contains("dport"), "port constraint dropped: {line}");
            }
        }
    }

    #[test]
    fn an_sctp_rule_uses_the_sctp_keyword_not_a_raw_proto_number() {
        let mut r = CompiledRule::new(1, "sctp-rule", Layer::Packet, Action::Deny);
        r.priority = 10;
        r.protocol = Protocol::Other(132);
        r.direction = Direction::Inbound;
        r.dest_ports = PortMatch {
            ranges: vec![PortRange::single(9999)],
            negate: false,
        };
        let nft = nft_artifact(&build(vec![r]));
        assert!(nft.contains("sctp dport { 9999 }"), "{nft}");
        assert!(
            !nft.contains("proto-132 dport"),
            "invalid keyword emitted:\n{nft}"
        );
    }

    #[test]
    fn logged_denies_and_alerts_carry_a_rule_named_log_prefix() {
        let mut deny = header_rule(1, "deny-telnet", 10, Direction::Any);
        deny.log = true;
        let mut alert = header_rule(2, "watch-db", 20, Direction::Any);
        alert.action = Action::Alert;
        alert.dest_ports = PortMatch {
            ranges: vec![PortRange::single(5432)],
            negate: false,
        };
        let mut quiet = header_rule(3, "deny-quietly", 30, Direction::Any);
        quiet.log = false;
        let nft = nft_artifact(&build(vec![deny, alert, quiet]));
        assert!(nft.contains("log prefix \"ufw#deny#deny-telnet \" drop"));
        assert!(nft.contains("log prefix \"ufw#alert#watch-db \" comment"));
        assert!(!nft.contains("ufw#deny#deny-quietly"));
        // An alert is observation, not a verdict; evaluation continues.
        assert!(!nft.contains("ufw#alert#watch-db \" accept"));
        assert!(!nft.contains("ufw#alert#watch-db \" drop"));
    }

    #[test]
    fn icmp_and_icmpv6_rules_stay_in_their_own_family() {
        let mut v4 = header_rule(1, "ping4", 10, Direction::Any);
        v4.protocol = Protocol::Icmp;
        v4.action = Action::Allow;
        v4.dest_ports = PortMatch::default();
        let mut v6 = header_rule(2, "ping6", 20, Direction::Any);
        v6.protocol = Protocol::IcmpV6;
        v6.action = Action::Allow;
        v6.dest_ports = PortMatch::default();
        let nft = nft_artifact(&build(vec![v4, v6]));
        // One line each, not a duplicated pair.
        assert_eq!(nft.matches("meta l4proto 1 accept").count(), 2); // input + output chains
        assert_eq!(nft.matches("meta l4proto 58 accept").count(), 2);
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
