//! Rule consolidation, redundancy elimination and fast-path marking.
//!
//! Every transform here must be *provably* behaviour-preserving against
//! [`CompiledPolicy::evaluate`]. That is not a slogan: the equivalence test
//! suite runs a corpus of flows through a policy before and after
//! optimization and fails on any divergence. If a transform cannot be proven
//! safe for a given pair of rules, it declines — the predicates below all
//! answer "no" when they cannot answer "yes".
//!
//! # What runs by default, and what does not
//!
//! Normalization, unreachable-rule elimination and eBPF marking run always.
//! **Adjacent-rule merging does not.**
//!
//! The reason is observability, not correctness. Merging two rules into one
//! means the absorbed rule's id never appears in a log line again, and rule
//! ids are the primary key operators use to answer "why was this blocked?".
//! Eliminating an *unreachable* rule costs nothing by that measure — it could
//! never have appeared in a log line — but merging two live rules does.
//! Merging is therefore available behind [`OptimizerOptions::merge_adjacent`]
//! for deployments that need the smaller rule table more than they need the
//! attribution.

use std::collections::BTreeSet;

use ufw_shared::identity_types::TrustMask;
use ufw_shared::policy_types::*;

use crate::error::{codes, Diagnostic, Diagnostics, Span};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OptimizerOptions {
    /// Drop rules that can never be reached. On by default.
    pub eliminate_unreachable: bool,
    /// Drop later rules whose predicate and action are byte-identical to an
    /// earlier one. On by default.
    pub eliminate_duplicates: bool,
    /// Fuse adjacent rules that differ in exactly one address or port set.
    /// Off by default; see the module docs.
    pub merge_adjacent: bool,
    /// Mark header-only rules as candidates for the Linux eBPF fast path.
    pub mark_ebpf: bool,
}

impl Default for OptimizerOptions {
    fn default() -> Self {
        OptimizerOptions {
            eliminate_unreachable: true,
            eliminate_duplicates: true,
            merge_adjacent: false,
            mark_ebpf: true,
        }
    }
}

/// What the optimizer changed.
#[derive(Debug, Clone, Default)]
pub struct OptimizationReport {
    /// `(removed rule id, removed rule name, id of the rule that shadows it)`.
    pub removed_unreachable: Vec<(u32, String, u32)>,
    /// `(removed rule id, removed rule name, id of the identical rule)`.
    pub removed_duplicates: Vec<(u32, String, u32)>,
    /// `(surviving rule id, absorbed rule id)`.
    pub merged: Vec<(u32, u32)>,
    /// Rules marked eligible for the Linux eBPF fast path.
    pub ebpf_eligible: usize,
    /// CIDRs dropped because a wider CIDR in the same set already covered them.
    pub cidrs_pruned: usize,
    /// Port ranges removed by fusing overlapping or adjacent ranges.
    pub port_ranges_fused: usize,
    pub diagnostics: Diagnostics,
}

impl OptimizationReport {
    pub fn rules_removed(&self) -> usize {
        self.removed_unreachable.len() + self.removed_duplicates.len() + self.merged.len()
    }

    pub fn is_noop(&self) -> bool {
        self.rules_removed() == 0 && self.cidrs_pruned == 0 && self.port_ranges_fused == 0
    }
}

/// Optimize a compiled policy in place, returning what changed.
pub fn optimize(policy: &mut CompiledPolicy, opts: &OptimizerOptions) -> OptimizationReport {
    let mut report = OptimizationReport::default();

    // Ordering matters: normalization first so later passes compare canonical
    // predicates, then duplicate removal (cheap, exact), then shadow analysis
    // (expensive, needs a stable order), then merging, then marking.
    policy.finalize();
    normalize(policy, &mut report);

    if opts.eliminate_duplicates {
        eliminate_duplicates(policy, &mut report);
    }
    if opts.eliminate_unreachable {
        eliminate_unreachable(policy, &mut report);
    }
    if opts.merge_adjacent {
        merge_adjacent(policy, &mut report);
    }
    if opts.mark_ebpf {
        report.ebpf_eligible = mark_ebpf(policy);
    }

    policy.finalize();
    report
}

// ===========================================================================
// Pass 1: normalization
// ===========================================================================

fn normalize(policy: &mut CompiledPolicy, report: &mut OptimizationReport) {
    for rule in &mut policy.rules {
        report.port_ranges_fused += normalize_ports(&mut rule.source_ports);
        report.port_ranges_fused += normalize_ports(&mut rule.dest_ports);
        report.cidrs_pruned += normalize_addresses(&mut rule.source);
        report.cidrs_pruned += normalize_addresses(&mut rule.dest);

        if let Some(app) = &mut rule.app {
            normalize_app(app);
        }
        if let Some(dpi) = &mut rule.dpi {
            dpi.signatures.sort_unstable();
            dpi.signatures.dedup();
            dpi.l7.sort_by_key(|p| *p as u8);
            dpi.l7.dedup();
        }
        rule.interfaces.sort();
        rule.interfaces.dedup();
        rule.tags.sort();
        rule.tags.dedup();
    }
    normalize_cidr_list(&mut policy.network_profile.internal);
    normalize_cidr_list(&mut policy.network_profile.perimeter);
}

fn normalize_ports(m: &mut PortMatch) -> usize {
    let before = m.ranges.len();
    m.normalize();
    before.saturating_sub(m.ranges.len())
}

fn normalize_addresses(m: &mut AddressMatch) -> usize {
    let before = m.cidrs.len();
    normalize_cidr_list(&mut m.cidrs);
    m.zones.sort_by_key(|z| *z as u8);
    m.zones.dedup();
    before.saturating_sub(m.cidrs.len())
}

/// Sort, deduplicate, and drop any CIDR already covered by another in the same
/// list. `[10.0.0.0/8, 10.1.0.0/16]` becomes `[10.0.0.0/8]`.
fn normalize_cidr_list(cidrs: &mut Vec<Cidr>) {
    if cidrs.len() < 2 {
        return;
    }
    // Widest first, so the first CIDR that covers a candidate is found early.
    cidrs.sort_by(|a, b| {
        a.prefix()
            .cmp(&b.prefix())
            .then(a.to_string().cmp(&b.to_string()))
    });
    let mut kept: Vec<Cidr> = Vec::with_capacity(cidrs.len());
    for c in cidrs.drain(..) {
        if kept.iter().any(|k| k.covers(&c)) {
            continue;
        }
        kept.push(c);
    }
    *cidrs = kept;
}

fn normalize_app(app: &mut AppMatch) {
    for fp in &mut app.fingerprints {
        fp.paths.sort_by(|a, b| a.pattern.cmp(&b.pattern));
        fp.paths
            .dedup_by(|a, b| a.pattern == b.pattern && a.case_insensitive == b.case_insensitive);
        fp.sha256.sort_unstable();
        fp.sha256.dedup();
        fp.signers.sort();
        fp.signers.dedup();
        fp.team_ids.sort();
        fp.team_ids.dedup();
        fp.bundle_ids.sort();
        fp.bundle_ids.dedup();
    }
    // Two identical alternatives cost a second scan for nothing. An *empty*
    // alternative is different: it matches any identified process, so it
    // subsumes every other alternative and the rest can go.
    app.fingerprints.retain(|f| !f.is_empty());
    app.fingerprints.dedup();

    // A mask naming every level is the same as no constraint; storing it as
    // the canonical wildcard lets `is_unconstrained` see through it.
    if app.trust.is_any() {
        app.trust = TrustMask::ANY;
    }
}

// ===========================================================================
// Pass 2: exact duplicate removal
// ===========================================================================

fn eliminate_duplicates(policy: &mut CompiledPolicy, report: &mut OptimizationReport) {
    let mut keep: Vec<CompiledRule> = Vec::with_capacity(policy.rules.len());
    for rule in std::mem::take(&mut policy.rules) {
        if let Some(prev) = keep.iter().find(|k| same_predicate_and_action(k, &rule)) {
            let prev_id = prev.id;
            let prev_name = prev.name.clone();
            report
                .removed_duplicates
                .push((rule.id, rule.name.clone(), prev_id));
            report.diagnostics.push(
                Diagnostic::note(
                    codes::RULE_ELIMINATED,
                    Span::default(),
                    format!(
                        "rule `{}` is identical to `{}` and was removed",
                        rule.name, prev_name
                    ),
                )
                .with_help("delete one of them, or give them different scopes"),
            );
            continue;
        }
        keep.push(rule);
    }
    policy.rules = keep;
}

fn same_predicate_and_action(a: &CompiledRule, b: &CompiledRule) -> bool {
    a.layer == b.layer
        && a.action == b.action
        && a.direction == b.direction
        && a.protocol == b.protocol
        && a.source == b.source
        && a.source_ports == b.source_ports
        && a.dest == b.dest
        && a.dest_ports == b.dest_ports
        && a.app == b.app
        && a.dpi == b.dpi
        && a.interfaces == b.interfaces
        && a.schedule == b.schedule
}

// ===========================================================================
// Pass 3: unreachable rule elimination
// ===========================================================================

fn eliminate_unreachable(policy: &mut CompiledPolicy, report: &mut OptimizationReport) {
    let rules = std::mem::take(&mut policy.rules);
    let mut keep: Vec<CompiledRule> = Vec::with_capacity(rules.len());

    for rule in rules {
        // `keep` is in evaluation order and contains only surviving rules, so
        // any shadow found here is a real one.
        let shadow = keep.iter().find(|earlier| shadows(earlier, &rule));
        match shadow {
            Some(earlier) => {
                let by_id = earlier.id;
                let by_name = earlier.name.clone();
                report
                    .removed_unreachable
                    .push((rule.id, rule.name.clone(), by_id));
                report.diagnostics.push(
                    Diagnostic::warning(
                        codes::UNREACHABLE_RULE,
                        Span::default(),
                        format!(
                            "rule `{}` can never match: `{}` is evaluated first and covers \
                             everything `{}` would",
                            rule.name, by_name, rule.name
                        ),
                    )
                    .with_help(
                        "give the earlier rule a narrower scope, or the later rule a lower \
                         `priority:` so it is evaluated first",
                    ),
                );
            }
            None => keep.push(rule),
        }
    }
    policy.rules = keep;
}

/// Whether `earlier` prevents `later` from ever being evaluated.
///
/// Two conditions must both hold: `earlier` must stop evaluation before
/// `later` would run, and `earlier` must match every flow `later` would.
fn shadows(earlier: &CompiledRule, later: &CompiledRule) -> bool {
    match earlier.effective_action() {
        // A terminal verdict returns immediately, so it shadows everything
        // that comes after it anywhere in the policy.
        Action::Allow | Action::Deny => {}
        // A provisional allow breaks out of its own stage but lets deeper
        // stages run, so it only shadows rules in the same stage.
        Action::AllowInspect => {
            if earlier.layer != later.layer {
                return false;
            }
        }
        // `alert` and `continue` decide nothing and shadow nothing.
        Action::Alert | Action::Continue => return false,
    }
    covers(earlier, later)
}

/// Whether every flow matching `narrow` also matches `wide`.
///
/// Conservative throughout: any predicate whose coverage cannot be decided
/// statically makes the whole answer `false`.
pub fn covers(wide: &CompiledRule, narrow: &CompiledRule) -> bool {
    if wide.direction != Direction::Any && wide.direction != narrow.direction {
        return false;
    }
    if wide.protocol != Protocol::Any && wide.protocol != narrow.protocol {
        return false;
    }

    // A wider rule that constrains identity, payload, time or interface cannot
    // be shown to cover a rule that does not — the extra predicate could fail
    // on exactly the flows the narrow rule was written for.
    if wide.app.is_some() && wide.app != narrow.app {
        return false;
    }
    if wide.dpi.is_some() && wide.dpi != narrow.dpi {
        return false;
    }
    if wide.schedule.is_some() && wide.schedule != narrow.schedule {
        return false;
    }
    if !wide.interfaces.is_empty() && wide.interfaces != narrow.interfaces {
        return false;
    }

    if !wide.source.covers(&narrow.source) || !wide.dest.covers(&narrow.dest) {
        return false;
    }

    // Port coverage is only meaningful once the protocols agree, because
    // `CompiledRule::matches` skips port predicates entirely for portless
    // protocols. Requiring an unconstrained wide rule, or identical
    // protocols, sidesteps that interaction.
    let ports_unconstrained = wide.source_ports.is_any() && wide.dest_ports.is_any();
    if !ports_unconstrained {
        if wide.protocol != narrow.protocol {
            return false;
        }
        if !wide.source_ports.covers(&narrow.source_ports)
            || !wide.dest_ports.covers(&narrow.dest_ports)
        {
            return false;
        }
    }

    true
}

// ===========================================================================
// Pass 4: adjacent rule merging
// ===========================================================================

fn merge_adjacent(policy: &mut CompiledPolicy, report: &mut OptimizationReport) {
    let rules = std::mem::take(&mut policy.rules);
    let mut out: Vec<CompiledRule> = Vec::with_capacity(rules.len());

    for rule in rules {
        let merged = match out.last_mut() {
            Some(prev) => try_merge(prev, &rule),
            None => false,
        };
        if merged {
            let prev_id = out.last().map(|r| r.id).unwrap_or(0);
            report.merged.push((prev_id, rule.id));
            report.diagnostics.push(Diagnostic::note(
                codes::RULES_MERGED,
                Span::default(),
                format!(
                    "rule `{}` was folded into the rule before it; log events will attribute \
                     both scopes to the surviving rule",
                    rule.name
                ),
            ));
        } else {
            out.push(rule);
        }
    }
    policy.rules = out;
}

/// Fold `b` into `a` when they are adjacent in evaluation order and differ in
/// exactly one address or port set.
///
/// Adjacency is what makes this safe without a global analysis: no other rule
/// sits between them, so widening `a` cannot change the verdict for any flow
/// that a third rule would have decided first.
fn try_merge(a: &mut CompiledRule, b: &CompiledRule) -> bool {
    if a.layer != b.layer
        || a.priority != b.priority
        || a.action != b.action
        || a.direction != b.direction
        || a.protocol != b.protocol
        || a.app != b.app
        || a.dpi != b.dpi
        || a.interfaces != b.interfaces
        || a.schedule != b.schedule
        || a.log != b.log
        || a.stateful != b.stateful
    {
        return false;
    }

    let mut differences = 0;
    let mut differing = Difference::None;

    if a.source != b.source {
        differences += 1;
        differing = Difference::SourceAddr;
    }
    if a.dest != b.dest {
        differences += 1;
        differing = Difference::DestAddr;
    }
    if a.source_ports != b.source_ports {
        differences += 1;
        differing = Difference::SourcePorts;
    }
    if a.dest_ports != b.dest_ports {
        differences += 1;
        differing = Difference::DestPorts;
    }

    if differences != 1 {
        return false;
    }

    match differing {
        Difference::SourceAddr => union_addresses(&mut a.source, &b.source),
        Difference::DestAddr => union_addresses(&mut a.dest, &b.dest),
        Difference::SourcePorts => union_ports(&mut a.source_ports, &b.source_ports),
        Difference::DestPorts => union_ports(&mut a.dest_ports, &b.dest_ports),
        Difference::None => false,
    }
}

enum Difference {
    None,
    SourceAddr,
    DestAddr,
    SourcePorts,
    DestPorts,
}

fn union_addresses(a: &mut AddressMatch, b: &AddressMatch) -> bool {
    // Negation and zone predicates do not union cleanly; decline rather than
    // guess.
    if a.negate || b.negate || a.zones != b.zones {
        return false;
    }
    // An empty CIDR list already means "any", so unioning with it would be a
    // no-op that hides the second rule for nothing.
    if a.cidrs.is_empty() || b.cidrs.is_empty() {
        return false;
    }
    a.cidrs.extend(b.cidrs.iter().copied());
    normalize_cidr_list(&mut a.cidrs);
    true
}

fn union_ports(a: &mut PortMatch, b: &PortMatch) -> bool {
    if a.negate || b.negate || a.ranges.is_empty() || b.ranges.is_empty() {
        return false;
    }
    a.ranges.extend(b.ranges.iter().copied());
    a.normalize();
    true
}

// ===========================================================================
// Pass 5: eBPF fast-path marking
// ===========================================================================

/// Mark rules whose predicate is entirely expressible in eBPF.
///
/// Marking is necessary but not sufficient: the Linux backend applies a
/// further ordering constraint (only a *prefix* of eligible rules can actually
/// be offloaded) because the tc hook runs before netfilter and would otherwise
/// let a low-priority offloaded rule decide ahead of a high-priority one.
fn mark_ebpf(policy: &mut CompiledPolicy) -> usize {
    let mut count = 0;
    for rule in &mut policy.rules {
        rule.ebpf_eligible = is_ebpf_expressible(rule);
        if rule.ebpf_eligible {
            count += 1;
        }
    }
    count
}

/// Whether a rule's predicate and action fit inside an eBPF program.
pub fn is_ebpf_expressible(rule: &CompiledRule) -> bool {
    // No identity, payload, schedule or interface predicates: eBPF at the tc
    // hook has none of those facts.
    if !rule.is_header_only() {
        return false;
    }
    // Zone classification depends on the daemon's network profile, which the
    // fast path does not carry.
    if !rule.source.zones.is_empty() || !rule.dest.zones.is_empty() {
        return false;
    }
    // Negation is expressible but doubles the branch count for no measurable
    // benefit at the scale these rules run at; keep the fast path simple.
    if rule.source.negate || rule.dest.negate || rule.source_ports.negate || rule.dest_ports.negate
    {
        return false;
    }
    // Only a terminal verdict can be delivered as TC_ACT_OK/TC_ACT_SHOT. A
    // provisional allow has to reach the deeper layers, and attributing it to
    // a rule id requires the slow path.
    rule.action.is_terminal()
}

/// Rule ids currently marked eligible, for reporting.
pub fn ebpf_rule_ids(policy: &CompiledPolicy) -> BTreeSet<u32> {
    policy
        .rules
        .iter()
        .filter(|r| r.ebpf_eligible)
        .map(|r| r.id)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;
    use ufw_shared::identity_types::{AppIdentity, TrustLevel};

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn cidr(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    fn rule(id: u32, name: &str, priority: u16, action: Action) -> CompiledRule {
        let mut r = CompiledRule::new(id, name, Layer::Packet, action);
        r.priority = priority;
        r
    }

    fn policy_of(rules: Vec<CompiledRule>) -> CompiledPolicy {
        let mut p = CompiledPolicy::new("test", Decision::Deny);
        p.network_profile.internal = vec![cidr("10.0.0.0/8")];
        p.rules = rules;
        p.finalize();
        p
    }

    /// Flows used to prove that an optimization did not change behaviour.
    fn corpus(profile: &NetworkProfile) -> Vec<FlowContext<'static>> {
        let mut out = Vec::new();
        for (proto, sport, dport) in [
            (Protocol::Tcp, 40000u16, 443u16),
            (Protocol::Tcp, 40001, 80),
            (Protocol::Tcp, 40002, 22),
            (Protocol::Udp, 40003, 53),
            (Protocol::Udp, 40004, 123),
            (Protocol::Icmp, 0, 0),
        ] {
            for dst in [
                "10.0.0.9",
                "10.1.2.3",
                "192.168.1.5",
                "8.8.8.8",
                "203.0.113.7",
                "127.0.0.1",
            ] {
                for dir in [Direction::Outbound, Direction::Inbound] {
                    out.push(FlowContext::new(
                        profile,
                        dir,
                        proto,
                        (ip("10.0.0.1"), sport),
                        (ip(dst), dport),
                    ));
                }
            }
        }
        out
    }

    /// Assert that two policies agree on every flow in the corpus. Rule ids
    /// are allowed to differ only where the optimizer removed a rule that
    /// could never have decided anything.
    fn assert_same_decisions(before: &CompiledPolicy, after: &CompiledPolicy) {
        for ctx in corpus(&before.network_profile) {
            let a = before.evaluate(&ctx);
            let b = after.evaluate(&ctx);
            assert_eq!(
                a.decision, b.decision,
                "decision changed for {:?} -> {:?}:{} (was rule {}, now {})",
                ctx.src_ip, ctx.dst_ip, ctx.dst_port, a.rule_id, b.rule_id
            );
            assert_eq!(
                a.rule_id, b.rule_id,
                "attribution changed for {:?} -> {:?}:{}",
                ctx.src_ip, ctx.dst_ip, ctx.dst_port
            );
        }
    }

    // --- normalization ----------------------------------------------------

    #[test]
    fn covered_cidrs_are_pruned() {
        let mut r = rule(1, "a", 100, Action::Allow);
        r.dest = AddressMatch {
            cidrs: vec![cidr("10.1.0.0/16"), cidr("10.0.0.0/8"), cidr("10.1.2.0/24")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![r]);
        let before = p.clone();
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules[0].dest.cidrs, vec![cidr("10.0.0.0/8")]);
        assert_eq!(report.cidrs_pruned, 2);
        assert_same_decisions(&before, &p);
    }

    #[test]
    fn distinct_cidrs_are_kept() {
        let mut r = rule(1, "a", 100, Action::Allow);
        r.dest = AddressMatch {
            cidrs: vec![cidr("10.0.0.0/8"), cidr("192.168.0.0/16")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![r]);
        optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules[0].dest.cidrs.len(), 2);
    }

    #[test]
    fn overlapping_port_ranges_fuse() {
        let mut r = rule(1, "a", 100, Action::Allow);
        r.protocol = Protocol::Tcp;
        r.dest_ports = PortMatch {
            ranges: vec![
                PortRange::new(8000, 8100),
                PortRange::new(8050, 8200),
                PortRange::single(80),
            ],
            negate: false,
        };
        let mut p = policy_of(vec![r]);
        let before = p.clone();
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(
            p.rules[0].dest_ports.ranges,
            vec![PortRange::single(80), PortRange::new(8000, 8200)]
        );
        assert_eq!(report.port_ranges_fused, 1);
        assert_same_decisions(&before, &p);
    }

    // --- duplicate removal ------------------------------------------------

    #[test]
    fn identical_rules_are_deduplicated() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.protocol = Protocol::Tcp;
        let mut b = rule(2, "b", 200, Action::Allow);
        b.protocol = Protocol::Tcp;
        let mut p = policy_of(vec![a, b]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].id, 1);
        assert_eq!(report.removed_duplicates.len(), 1);
    }

    #[test]
    fn rules_differing_only_in_action_are_not_duplicates() {
        let a = rule(1, "a", 100, Action::Allow);
        let b = rule(2, "b", 200, Action::Deny);
        let mut p = policy_of(vec![a, b]);
        // Shadow analysis is disabled here so this exercises the duplicate
        // pass alone: `b` *is* unreachable behind a terminal wildcard allow,
        // and the next test covers that.
        let report = optimize(
            &mut p,
            &OptimizerOptions {
                eliminate_unreachable: false,
                ..Default::default()
            },
        );
        assert_eq!(p.rules.len(), 2);
        assert!(report.removed_duplicates.is_empty());
    }

    #[test]
    fn a_terminal_wildcard_allow_shadows_a_later_deny() {
        let a = rule(1, "allow-everything", 100, Action::Allow);
        let b = rule(2, "deny-everything", 200, Action::Deny);
        let before = policy_of(vec![a.clone(), b.clone()]);
        let mut p = policy_of(vec![a, b]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].id, 1);
        assert_eq!(report.removed_unreachable[0].0, 2);
        assert_same_decisions(&before, &p);
    }

    // --- unreachable elimination ------------------------------------------

    #[test]
    fn narrower_rule_after_a_terminal_wildcard_is_removed() {
        let wide = rule(1, "allow-all", 100, Action::Allow);
        let mut narrow = rule(2, "allow-lan", 200, Action::Allow);
        narrow.dest = AddressMatch {
            cidrs: vec![cidr("10.0.0.0/8")],
            zones: vec![],
            negate: false,
        };
        let before = policy_of(vec![wide.clone(), narrow.clone()]);
        let mut p = policy_of(vec![wide, narrow]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 1);
        assert_eq!(report.removed_unreachable[0].0, 2);
        assert!(report.diagnostics.has_code(codes::UNREACHABLE_RULE));
        assert_same_decisions(&before, &p);
    }

    #[test]
    fn a_deeper_layer_rule_is_shadowed_by_a_terminal_packet_rule() {
        let wide = rule(1, "allow-all", 100, Action::Allow);
        let mut ident = CompiledRule::new(2, "deny-untrusted", Layer::Identity, Action::Deny);
        ident.priority = 10;
        ident.app = Some(AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Untrusted]),
            ..AppMatch::any()
        });
        let before = policy_of(vec![wide.clone(), ident.clone()]);
        let mut p = policy_of(vec![wide, ident]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(
            p.rules.len(),
            1,
            "identity rule is unreachable behind a terminal allow"
        );
        assert_eq!(report.removed_unreachable[0].2, 1);

        // Prove it with an actual identity-bearing flow, which the header-only
        // corpus cannot express.
        let mut id = AppIdentity::unresolved(1, 0);
        id.path = "/tmp/x".into();
        id.trust = TrustLevel::Untrusted;
        let ctx = FlowContext::new(
            &before.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (ip("10.0.0.1"), 1),
            (ip("8.8.8.8"), 443),
        )
        .with_identity(&id);
        assert_eq!(before.evaluate(&ctx).verdict(), p.evaluate(&ctx).verdict());
    }

    #[test]
    fn allow_inspect_only_shadows_its_own_stage() {
        let mut inspect = rule(1, "inspect", 100, Action::AllowInspect);
        inspect.protocol = Protocol::Tcp;
        // Same stage, narrower: unreachable.
        let mut same_stage = rule(2, "same-stage", 200, Action::Deny);
        same_stage.protocol = Protocol::Tcp;
        same_stage.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        // Deeper stage: still reachable, which is the entire point of
        // `allow-inspect`.
        let mut deeper = CompiledRule::new(3, "deeper", Layer::Stream, Action::Deny);
        deeper.protocol = Protocol::Tcp;
        deeper.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };

        let mut p = policy_of(vec![inspect, same_stage, deeper]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        let kept: Vec<u32> = p.rules.iter().map(|r| r.id).collect();
        assert_eq!(kept, vec![1, 3]);
        assert_eq!(report.removed_unreachable.len(), 1);
    }

    #[test]
    fn alert_rules_never_shadow() {
        let alert = rule(1, "alert", 100, Action::Alert);
        let mut deny = rule(2, "deny", 200, Action::Deny);
        deny.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![alert, deny]);
        optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn a_rule_with_extra_predicates_does_not_shadow_a_plainer_one() {
        // The identity rule runs first only in its own stage; even so, its
        // extra predicate means it cannot be shown to cover everything.
        let mut ident = CompiledRule::new(1, "ident", Layer::Identity, Action::Deny);
        ident.priority = 10;
        ident.app = Some(AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Untrusted]),
            ..AppMatch::any()
        });
        let mut other = CompiledRule::new(2, "other", Layer::Identity, Action::Deny);
        other.priority = 20;
        let mut p = policy_of(vec![ident, other]);
        optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn protocol_specific_rule_does_not_shadow_other_protocols() {
        let mut tcp = rule(1, "tcp-all", 100, Action::Allow);
        tcp.protocol = Protocol::Tcp;
        let mut udp = rule(2, "udp-dns", 200, Action::Allow);
        udp.protocol = Protocol::Udp;
        udp.dest_ports = PortMatch {
            ranges: vec![PortRange::single(53)],
            negate: false,
        };
        let before = policy_of(vec![tcp.clone(), udp.clone()]);
        let mut p = policy_of(vec![tcp, udp]);
        optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 2);
        assert_same_decisions(&before, &p);
    }

    // --- merging ----------------------------------------------------------

    #[test]
    fn merging_is_off_by_default() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.protocol = Protocol::Tcp;
        a.dest = AddressMatch {
            cidrs: vec![cidr("1.1.1.1/32")],
            zones: vec![],
            negate: false,
        };
        let mut b = rule(2, "b", 100, Action::Allow);
        b.protocol = Protocol::Tcp;
        b.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![a, b]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(p.rules.len(), 2);
        assert!(report.merged.is_empty());
    }

    #[test]
    fn adjacent_rules_differing_in_one_address_set_merge_when_enabled() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.protocol = Protocol::Tcp;
        a.dest = AddressMatch {
            cidrs: vec![cidr("1.1.1.1/32")],
            zones: vec![],
            negate: false,
        };
        let mut b = rule(2, "b", 100, Action::Allow);
        b.protocol = Protocol::Tcp;
        b.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };

        let before = policy_of(vec![a.clone(), b.clone()]);
        let mut p = policy_of(vec![a, b]);
        let report = optimize(
            &mut p,
            &OptimizerOptions {
                merge_adjacent: true,
                ..Default::default()
            },
        );
        assert_eq!(p.rules.len(), 1);
        assert_eq!(p.rules[0].dest.cidrs.len(), 2);
        assert_eq!(report.merged, vec![(1, 2)]);

        // Merging changes attribution by design, so only the verdict is
        // required to be stable here.
        for ctx in corpus(&before.network_profile) {
            assert_eq!(before.evaluate(&ctx).decision, p.evaluate(&ctx).decision);
        }
    }

    #[test]
    fn rules_differing_in_two_fields_do_not_merge() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.protocol = Protocol::Tcp;
        a.dest = AddressMatch {
            cidrs: vec![cidr("1.1.1.1/32")],
            zones: vec![],
            negate: false,
        };
        a.dest_ports = PortMatch {
            ranges: vec![PortRange::single(80)],
            negate: false,
        };
        let mut b = rule(2, "b", 100, Action::Allow);
        b.protocol = Protocol::Tcp;
        b.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        b.dest_ports = PortMatch {
            ranges: vec![PortRange::single(443)],
            negate: false,
        };
        let mut p = policy_of(vec![a, b]);
        optimize(
            &mut p,
            &OptimizerOptions {
                merge_adjacent: true,
                ..Default::default()
            },
        );
        assert_eq!(p.rules.len(), 2);
    }

    #[test]
    fn rules_with_different_actions_do_not_merge() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.dest = AddressMatch {
            cidrs: vec![cidr("1.1.1.1/32")],
            zones: vec![],
            negate: false,
        };
        let mut b = rule(2, "b", 100, Action::Deny);
        b.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![a, b]);
        optimize(
            &mut p,
            &OptimizerOptions {
                merge_adjacent: true,
                ..Default::default()
            },
        );
        assert_eq!(p.rules.len(), 2);
    }

    // --- eBPF marking -----------------------------------------------------

    #[test]
    fn header_only_terminal_rules_are_ebpf_eligible() {
        let mut r = rule(1, "a", 100, Action::Deny);
        r.protocol = Protocol::Tcp;
        r.dest = AddressMatch {
            cidrs: vec![cidr("8.8.8.8/32")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![r]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert!(p.rules[0].ebpf_eligible);
        assert_eq!(report.ebpf_eligible, 1);
    }

    #[test]
    fn rules_needing_context_are_not_ebpf_eligible() {
        let mut with_app = CompiledRule::new(1, "app", Layer::Identity, Action::Deny);
        with_app.app = Some(AppMatch::any());

        let mut with_zone = rule(2, "zone", 100, Action::Deny);
        with_zone.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::External],
            negate: false,
        };

        let mut with_schedule = rule(3, "sched", 100, Action::Deny);
        with_schedule.schedule = Some(TimeWindow {
            days: TimeWindow::ALL_DAYS,
            start_minute: 0,
            end_minute: 60,
        });

        let inspect = rule(4, "inspect", 100, Action::AllowInspect);

        let mut negated = rule(5, "neg", 100, Action::Deny);
        negated.dest = AddressMatch {
            cidrs: vec![cidr("10.0.0.0/8")],
            zones: vec![],
            negate: true,
        };

        let mut p = policy_of(vec![with_app, with_zone, with_schedule, inspect, negated]);
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(report.ebpf_eligible, 0);
        assert!(ebpf_rule_ids(&p).is_empty());
    }

    // --- end-to-end -------------------------------------------------------

    #[test]
    fn optimizing_twice_is_a_fixed_point() {
        let mut a = rule(1, "a", 100, Action::Allow);
        a.protocol = Protocol::Tcp;
        a.dest = AddressMatch {
            cidrs: vec![cidr("10.0.0.0/8"), cidr("10.1.0.0/16")],
            zones: vec![],
            negate: false,
        };
        let b = rule(2, "b", 900, Action::Deny);
        let mut p = policy_of(vec![a, b]);
        optimize(&mut p, &OptimizerOptions::default());
        let once = p.clone();
        let report = optimize(&mut p, &OptimizerOptions::default());
        assert_eq!(once, p);
        assert!(report.is_noop());
    }

    #[test]
    fn hash_is_recomputed_after_optimization() {
        let mut r = rule(1, "a", 100, Action::Allow);
        r.dest = AddressMatch {
            cidrs: vec![cidr("10.0.0.0/8"), cidr("10.1.0.0/16")],
            zones: vec![],
            negate: false,
        };
        let mut p = policy_of(vec![r]);
        let before_hash = p.ruleset_hash;
        optimize(&mut p, &OptimizerOptions::default());
        assert_ne!(before_hash, p.ruleset_hash);
        assert!(p.verify_hash());
    }
}
