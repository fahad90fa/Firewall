//! Backend dispatch and the cross-platform equivalence verifier.
//!
//! Each backend turns a [`CompiledPolicy`] into two things:
//!
//! 1. **Artifacts** — the platform-native files a kernel component consumes.
//! 2. **A [`DecisionModel`]** — a flat, ordered list of the rules *as that
//!    backend will actually evaluate them*, built from the same intermediate
//!    structures the artifacts are generated from.
//!
//! The model is the interesting half. It is not a copy of the input policy: it
//! is the backend's own claim about evaluation order, which differs from the
//! reference order in ways that are easy to get wrong. Two real examples,
//! both caught by the verifier during development:
//!
//! * **Windows** installs filters into WFP layers, and within a layer, order
//!   comes from a 64-bit filter weight. Perimeter (L1) and packet (L2) rules
//!   both land in the IP packet layers, so a weight derived from priority
//!   alone would let a low-priority packet rule decide ahead of a
//!   high-priority perimeter rule. The weight has to encode the *stage* above
//!   the priority.
//!
//! * **Linux** runs tc ingress before netfilter on the inbound path but
//!   *after* it on the outbound path. An eBPF fast path that carried an
//!   arbitrary subset of rules would therefore reorder outbound decisions.
//!   See `linux.rs` for the prefix argument that makes the offload safe.
//!
//! [`verify_equivalence`] runs a corpus of flows through the reference
//! semantics and through all three models, and reports any scenario where they
//! disagree.

use std::net::{IpAddr, Ipv4Addr};

use ufw_shared::identity_types::{AppIdentity, SignatureType, TrustLevel};
use ufw_shared::policy_types::*;
use ufw_shared::Platform;

use crate::error::Diagnostics;

pub mod linux;
pub mod macos;
pub mod windows;

// ===========================================================================
// Artifacts
// ===========================================================================

/// One generated file. `path` is relative to the output directory.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GeneratedFile {
    pub path: String,
    pub contents: String,
}

impl GeneratedFile {
    pub fn new(path: impl Into<String>, contents: impl Into<String>) -> Self {
        GeneratedFile {
            path: path.into(),
            contents: contents.into(),
        }
    }
}

/// Everything one backend produced.
#[derive(Debug, Clone)]
pub struct Artifact {
    pub platform: Platform,
    pub files: Vec<GeneratedFile>,
    pub model: DecisionModel,
    pub notes: Diagnostics,
}

impl Artifact {
    pub fn file(&self, path: &str) -> Option<&GeneratedFile> {
        self.files.iter().find(|f| f.path == path)
    }

    pub fn total_bytes(&self) -> usize {
        self.files.iter().map(|f| f.contents.len()).sum()
    }
}

/// A backend: one platform's code generator.
pub trait Backend {
    fn platform(&self) -> Platform;
    fn generate(&self, policy: &CompiledPolicy) -> Artifact;
}

/// Compile for one platform.
pub fn compile_for(platform: Platform, policy: &CompiledPolicy) -> Artifact {
    match platform {
        Platform::Windows => windows::WindowsBackend.generate(policy),
        Platform::Linux => linux::LinuxBackend.generate(policy),
        Platform::MacOS => macos::MacOsBackend.generate(policy),
    }
}

/// Compile for all three platforms.
pub fn compile_all(policy: &CompiledPolicy) -> Vec<Artifact> {
    Platform::ALL
        .iter()
        .map(|p| compile_for(*p, policy))
        .collect()
}

// ===========================================================================
// Decision model
// ===========================================================================

/// The concrete enforcement engine a rule was assigned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Engine {
    /// Windows: `FWPM_LAYER_{IN,OUT}BOUND_IPPACKET_V4/V6`.
    WfpPacket,
    /// Windows: `FWPM_LAYER_ALE_AUTH_{CONNECT,RECV_ACCEPT}_V4/V6`.
    WfpAle,
    /// Windows: `FWPM_LAYER_STREAM_V4/V6`.
    WfpStream,
    /// Linux: tc ingress eBPF fast path.
    Ebpf,
    /// Linux: netfilter hook inside the kernel module.
    Netfilter,
    /// macOS: `handleNewFlow`.
    NeFlow,
    /// macOS: `handleNewPacket`.
    NePacket,
}

impl Engine {
    pub fn as_str(self) -> &'static str {
        match self {
            Engine::WfpPacket => "wfp-packet",
            Engine::WfpAle => "wfp-ale",
            Engine::WfpStream => "wfp-stream",
            Engine::Ebpf => "ebpf",
            Engine::Netfilter => "netfilter",
            Engine::NeFlow => "ne-flow",
            Engine::NePacket => "ne-packet",
        }
    }
}

/// Which transport protocols a backend's filter is installed for.
///
/// Needed because two of the three platforms decide connection-oriented
/// traffic at a flow-level hook (WFP ALE, `NEFilterDataProvider.handleNewFlow`)
/// that never fires for ICMP. Those backends install the same rule twice, once
/// at the flow hook restricted to TCP/UDP and once at the packet hook
/// *excluding* TCP/UDP, so the two copies are disjoint and exactly one can
/// decide any given flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolScope {
    Any,
    Only(Vec<Protocol>),
    Excluding(Vec<Protocol>),
}

impl ProtocolScope {
    pub fn admits(&self, p: Protocol) -> bool {
        match self {
            ProtocolScope::Any => true,
            ProtocolScope::Only(list) => list.contains(&p),
            ProtocolScope::Excluding(list) => !list.contains(&p),
        }
    }

    pub fn describe(&self) -> String {
        match self {
            ProtocolScope::Any => "any".into(),
            ProtocolScope::Only(l) => {
                format!(
                    "only {}",
                    l.iter().map(|p| p.as_str()).collect::<Vec<_>>().join("/")
                )
            }
            ProtocolScope::Excluding(l) => format!(
                "not {}",
                l.iter().map(|p| p.as_str()).collect::<Vec<_>>().join("/")
            ),
        }
    }
}

/// One rule as a backend will evaluate it.
#[derive(Debug, Clone)]
pub struct ModelRule {
    pub id: u32,
    pub name: String,
    pub layer: Layer,
    pub engine: Engine,
    /// Backend-specific ordering key, e.g. a WFP filter weight. Recorded so a
    /// divergence report can show *why* the order came out as it did.
    pub order_key: u64,
    /// Protocols this installed copy of the rule is scoped to.
    pub scope: ProtocolScope,
    /// The predicate the backend emitted. Cloned from the compiled rule; a
    /// backend that dropped or altered a predicate would show up here.
    pub predicate: CompiledRule,
}

impl ModelRule {
    pub fn new(rule: &CompiledRule, engine: Engine) -> Self {
        ModelRule {
            id: rule.id,
            name: rule.name.clone(),
            layer: rule.layer,
            engine,
            order_key: evaluation_order_key(rule),
            scope: ProtocolScope::Any,
            predicate: rule.clone(),
        }
    }

    pub fn with_scope(mut self, scope: ProtocolScope) -> Self {
        self.scope = scope;
        self
    }

    fn effective_action(&self) -> Action {
        self.predicate.effective_action()
    }
}

/// A backend's complete claim about how it will decide flows.
#[derive(Debug, Clone)]
pub struct DecisionModel {
    pub platform: Platform,
    pub default_action: Decision,
    pub profile: NetworkProfile,
    /// Rules in the order this backend evaluates them.
    pub rules: Vec<ModelRule>,
}

impl DecisionModel {
    /// Evaluate a flow against this model.
    ///
    /// Deliberately written as a flat walk over `rules` rather than by staging
    /// like [`CompiledPolicy::evaluate`]. If a backend's claimed order is
    /// wrong, this produces a different answer than the reference — which is
    /// the entire point.
    pub fn evaluate(&self, ctx: &FlowContext<'_>) -> (Decision, u32) {
        // Set once an `allow-inspect` fires: the rest of that layer is
        // skipped, but deeper layers still run.
        let mut skip_layer: Option<Layer> = None;
        let mut provisional: Option<(Decision, u32)> = None;

        for rule in &self.rules {
            if skip_layer == Some(rule.layer) {
                continue;
            }
            if !rule.scope.admits(ctx.protocol) {
                continue;
            }
            if !rule.predicate.matches(ctx) {
                continue;
            }
            match rule.effective_action() {
                Action::Allow => return (Decision::Allow, rule.id),
                Action::Deny => return (Decision::Deny, rule.id),
                Action::AllowInspect => {
                    provisional = Some((Decision::Allow, rule.id));
                    skip_layer = Some(rule.layer);
                }
                Action::Alert | Action::Continue => {}
            }
        }

        provisional.unwrap_or((self.default_action, ufw_shared::constants::RULE_ID_DEFAULT))
    }

    pub fn rules_on(&self, engine: Engine) -> impl Iterator<Item = &ModelRule> {
        self.rules.iter().filter(move |r| r.engine == engine)
    }
}

/// Sort key shared by every backend: stage first, then priority, then id.
///
/// The stage component is what keeps a low-priority packet rule from
/// overtaking a high-priority perimeter rule when both land in the same
/// platform layer.
pub fn evaluation_order_key(rule: &CompiledRule) -> u64 {
    ((rule.layer.stage_index() as u64) << 48) | ((rule.priority as u64) << 32) | (rule.id as u64)
}

/// Rules in reference evaluation order.
pub fn ordered_rules(policy: &CompiledPolicy) -> Vec<&CompiledRule> {
    let mut v: Vec<&CompiledRule> = policy.rules.iter().collect();
    v.sort_by_key(|r| evaluation_order_key(r));
    v
}

// ===========================================================================
// Equivalence verification
// ===========================================================================

/// One flow to check all backends against.
///
/// Owns its identity and DPI data so a corpus can be built once and evaluated
/// repeatedly; [`Scenario::context`] borrows from it to make a
/// [`FlowContext`].
#[derive(Debug, Clone)]
pub struct Scenario {
    pub name: String,
    pub direction: Direction,
    pub protocol: Protocol,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub identity: Option<AppIdentity>,
    pub dpi: Option<DpiScan>,
    pub interface: Option<String>,
    pub minute_of_week: Option<u16>,
}

impl Scenario {
    pub fn new(name: impl Into<String>, protocol: Protocol, dst: (IpAddr, u16)) -> Self {
        Scenario {
            name: name.into(),
            direction: Direction::Outbound,
            protocol,
            src: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 45678),
            dst,
            identity: None,
            dpi: None,
            interface: None,
            minute_of_week: None,
        }
    }

    pub fn context<'a>(&'a self, profile: &NetworkProfile) -> FlowContext<'a> {
        let mut ctx = FlowContext::new(profile, self.direction, self.protocol, self.src, self.dst);
        ctx.identity = self.identity.as_ref();
        ctx.dpi = self.dpi.clone();
        ctx.interface = self.interface.as_deref();
        ctx.minute_of_week = self.minute_of_week;
        ctx
    }
}

/// A scenario where the backends did not agree.
#[derive(Debug, Clone)]
pub struct Divergence {
    pub scenario: String,
    pub reference: (Decision, u32),
    pub results: Vec<(Platform, (Decision, u32))>,
}

impl Divergence {
    /// Platforms whose answer differs from the reference.
    pub fn offenders(&self) -> Vec<Platform> {
        self.results
            .iter()
            .filter(|(_, r)| *r != self.reference)
            .map(|(p, _)| *p)
            .collect()
    }
}

#[derive(Debug, Clone, Default)]
pub struct EquivalenceReport {
    pub scenarios_checked: usize,
    pub divergences: Vec<Divergence>,
}

impl EquivalenceReport {
    pub fn is_equivalent(&self) -> bool {
        self.divergences.is_empty()
    }

    /// Human-readable summary for CI and `ufwctl policy verify`.
    pub fn render(&self) -> String {
        if self.is_equivalent() {
            return format!(
                "cross-platform equivalence verified across {} scenarios\n",
                self.scenarios_checked
            );
        }
        let mut out = format!(
            "cross-platform equivalence FAILED: {} of {} scenarios diverged\n",
            self.divergences.len(),
            self.scenarios_checked
        );
        for d in &self.divergences {
            out.push_str(&format!("\n  scenario: {}\n", d.scenario));
            out.push_str(&format!(
                "    reference: {} (rule {})\n",
                d.reference.0.as_str(),
                d.reference.1
            ));
            for (platform, (decision, rule)) in &d.results {
                let flag = if (*decision, *rule) == d.reference {
                    "  "
                } else {
                    "<<"
                };
                out.push_str(&format!(
                    "    {:<8}: {} (rule {}) {}\n",
                    platform.as_str(),
                    decision.as_str(),
                    rule,
                    flag
                ));
            }
        }
        out
    }
}

/// Run every scenario through the reference semantics and all three backend
/// models, reporting disagreements.
pub fn verify_equivalence(policy: &CompiledPolicy, scenarios: &[Scenario]) -> EquivalenceReport {
    let models: Vec<DecisionModel> = compile_all(policy).into_iter().map(|a| a.model).collect();
    verify_models(policy, &models, scenarios)
}

/// Verify against already-generated models, so a caller that has the artifacts
/// does not regenerate them.
pub fn verify_models(
    policy: &CompiledPolicy,
    models: &[DecisionModel],
    scenarios: &[Scenario],
) -> EquivalenceReport {
    let mut report = EquivalenceReport {
        scenarios_checked: scenarios.len(),
        ..Default::default()
    };

    for scenario in scenarios {
        let ctx = scenario.context(&policy.network_profile);
        let reference = policy.evaluate(&ctx).verdict();
        let results: Vec<(Platform, (Decision, u32))> = models
            .iter()
            .map(|m| (m.platform, m.evaluate(&ctx)))
            .collect();
        if results.iter().any(|(_, r)| *r != reference) {
            report.divergences.push(Divergence {
                scenario: scenario.name.clone(),
                reference,
                results,
            });
        }
    }

    report
}

// ===========================================================================
// Scenario generation
// ===========================================================================

/// Upper bound on generated scenarios. A policy with hundreds of rules would
/// otherwise produce a combinatorial corpus that dominates compile time.
pub const MAX_GENERATED_SCENARIOS: usize = 2048;

/// Derive a corpus of flows from the policy itself.
///
/// A fixed corpus would only exercise whatever addresses the author of the
/// corpus happened to think of. Deriving the corpus from the policy means the
/// probes land on the actual boundaries the policy draws: one address inside
/// each CIDR and one just outside it, the endpoints of each port range and the
/// ports either side, an identity that satisfies each application predicate
/// and one that does not, and a DPI result for each referenced signature.
pub fn default_scenarios(policy: &CompiledPolicy) -> Vec<Scenario> {
    let mut protocols: Vec<Protocol> = vec![Protocol::Tcp, Protocol::Udp, Protocol::Icmp];
    let mut addresses: Vec<IpAddr> = vec![
        "127.0.0.1".parse().unwrap(),
        "10.0.0.9".parse().unwrap(),
        "192.168.1.5".parse().unwrap(),
        "8.8.8.8".parse().unwrap(),
        "203.0.113.7".parse().unwrap(),
        "2001:db8::1".parse().unwrap(),
    ];
    let mut ports: Vec<u16> = vec![0, 53, 80, 443, 22, 8080, 65535];
    let mut identities: Vec<Option<AppIdentity>> = vec![None, Some(unresolvable_identity())];
    let mut dpi_results: Vec<Option<DpiScan>> = vec![None];
    let mut interfaces: Vec<Option<String>> = vec![None];
    let mut minutes: Vec<Option<u16>> = vec![None];

    for rule in &policy.rules {
        if rule.protocol != Protocol::Any && !protocols.contains(&rule.protocol) {
            protocols.push(rule.protocol);
        }
        for m in [&rule.source, &rule.dest] {
            for c in &m.cidrs {
                push_unique(&mut addresses, inside(c));
                if let Some(out) = outside(c) {
                    push_unique(&mut addresses, out);
                }
            }
        }
        for m in [&rule.source_ports, &rule.dest_ports] {
            for r in &m.ranges {
                push_unique(&mut ports, r.lo);
                push_unique(&mut ports, r.hi);
                push_unique(&mut ports, r.lo.saturating_sub(1));
                push_unique(&mut ports, r.hi.saturating_add(1));
            }
        }
        if let Some(app) = &rule.app {
            if let Some(id) = satisfying_identity(app) {
                identities.push(Some(id));
            }
        }
        if let Some(dpi) = &rule.dpi {
            let l7 = dpi.l7.first().copied().unwrap_or(L7Protocol::Http);
            dpi_results.push(Some(DpiScan {
                l7,
                hits: dpi.signatures.clone(),
                first_hit_offset: 0,
                truncated: false,
            }));
            // A scan that completed and found nothing is a distinct case from
            // no scan at all.
            dpi_results.push(Some(DpiScan {
                l7,
                hits: vec![],
                first_hit_offset: 0,
                truncated: false,
            }));
        }
        for iface in &rule.interfaces {
            push_unique(&mut interfaces, Some(iface.clone()));
        }
        if let Some(w) = &rule.schedule {
            push_unique(&mut minutes, Some(w.start_minute));
            push_unique(&mut minutes, Some(w.end_minute.saturating_sub(1)));
            push_unique(&mut minutes, Some(w.end_minute));
        }
    }
    for c in policy
        .network_profile
        .internal
        .iter()
        .chain(policy.network_profile.perimeter.iter())
    {
        push_unique(&mut addresses, inside(c));
    }

    // Bound each axis so the cross product stays computable, keeping a spread
    // of each list rather than its head — truncating would drop every
    // boundary contributed by the rules at the bottom of a large policy.
    subsample(&mut protocols, 8);
    subsample(&mut addresses, 64);
    subsample(&mut ports, 64);
    subsample(&mut identities, 6);
    subsample(&mut dpi_results, 6);
    subsample(&mut interfaces, 4);
    subsample(&mut minutes, 4);

    let directions = [Direction::Outbound, Direction::Inbound];
    let radices = [
        protocols.len(),
        directions.len(),
        addresses.len(),
        ports.len(),
        identities.len(),
        dpi_results.len(),
        interfaces.len(),
        minutes.len(),
    ];
    let total: usize = radices.iter().product();

    // Walk the product space with a stride instead of taking a prefix of the
    // nested loops. A prefix is heavily biased: it exhausts the fastest-moving
    // axes for the first value of the slowest one and never reaches the rest,
    // which once left the UDP half of a policy completely unprobed and made
    // the verifier miss a genuinely dropped rule. An odd stride visits every
    // axis evenly.
    let mut stride = total.div_ceil(MAX_GENERATED_SCENARIOS).max(1);
    if stride % 2 == 0 {
        stride += 1;
    }

    let mut out = Vec::with_capacity(total.min(MAX_GENERATED_SCENARIOS));
    let mut i = 0usize;
    while i < total && out.len() < MAX_GENERATED_SCENARIOS {
        let idx = decode_mixed_radix(i, &radices);
        let protocol = protocols[idx[0]];
        let direction = directions[idx[1]];
        let dst = addresses[idx[2]];
        let port = ports[idx[3]];
        let identity = identities[idx[4]].clone();
        let dpi = dpi_results[idx[5]].clone();
        let iface = interfaces[idx[6]].clone();
        let minute = minutes[idx[7]];

        let src: IpAddr = if dst.is_ipv6() {
            "2001:db8::9".parse().unwrap()
        } else {
            "10.0.0.1".parse().unwrap()
        };
        out.push(Scenario {
            name: format!(
                "{} {} -> {}:{} app={} dpi={} if={} t={}",
                protocol.as_str(),
                direction.as_str(),
                dst,
                port,
                identity.as_ref().map(|i| i.path.as_str()).unwrap_or("-"),
                dpi.as_ref()
                    .map(|d| format!("{:?}", d.hits))
                    .unwrap_or_else(|| "-".into()),
                iface.as_deref().unwrap_or("-"),
                minute.map(|m| m.to_string()).unwrap_or_else(|| "-".into()),
            ),
            direction,
            protocol,
            src: (src, 45678),
            dst: (dst, port),
            identity,
            dpi,
            interface: iface,
            minute_of_week: minute,
        });
        i += stride;
    }
    out
}

/// Decode a flat index into per-axis indices, last axis varying fastest.
fn decode_mixed_radix(mut i: usize, radices: &[usize]) -> Vec<usize> {
    let mut out = vec![0usize; radices.len()];
    for k in (0..radices.len()).rev() {
        let r = radices[k].max(1);
        out[k] = i % r;
        i /= r;
    }
    out
}

/// Reduce `v` to at most `cap` entries, keeping an even spread including the
/// first and last.
fn subsample<T: Clone>(v: &mut Vec<T>, cap: usize) {
    if v.len() <= cap || cap == 0 {
        return;
    }
    let mut kept = Vec::with_capacity(cap);
    for k in 0..cap {
        // Map k across the full range so the last element is always included.
        let idx = k * (v.len() - 1) / (cap - 1).max(1);
        kept.push(v[idx].clone());
    }
    kept.dedup_by(|_, _| false);
    *v = kept;
}

fn push_unique<T: PartialEq>(v: &mut Vec<T>, item: T) {
    if !v.contains(&item) {
        v.push(item);
    }
}

/// An address inside `c`: the network address plus one where there is room.
fn inside(c: &Cidr) -> IpAddr {
    match c.addr() {
        IpAddr::V4(a) => {
            let bits = u32::from(a);
            let host = if c.prefix() < 32 { 1 } else { 0 };
            IpAddr::V4(Ipv4Addr::from(bits | host))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a);
            let host = if c.prefix() < 128 { 1 } else { 0 };
            IpAddr::V6(std::net::Ipv6Addr::from(bits | host))
        }
    }
}

/// An address just outside `c`, or `None` for the wildcard.
fn outside(c: &Cidr) -> Option<IpAddr> {
    if c.prefix() == 0 {
        return None;
    }
    match c.addr() {
        IpAddr::V4(a) => {
            // Flip the last bit of the network prefix.
            let bits = u32::from(a) ^ (1u32 << (32 - c.prefix()));
            Some(IpAddr::V4(Ipv4Addr::from(bits)))
        }
        IpAddr::V6(a) => {
            let bits = u128::from(a) ^ (1u128 << (128 - c.prefix()));
            Some(IpAddr::V6(std::net::Ipv6Addr::from(bits)))
        }
    }
}

fn unresolvable_identity() -> AppIdentity {
    AppIdentity::unresolved(9999, 0)
}

/// Build an identity that satisfies `m`, so the corpus exercises the match
/// path and not just the miss path.
fn satisfying_identity(m: &AppMatch) -> Option<AppIdentity> {
    if m.negate {
        // A negated predicate is satisfied by the unresolvable identity and by
        // anything else that fails the inner match; no construction needed.
        return None;
    }
    let mut id = AppIdentity::unresolved(4242, 0);
    id.signature_type = SignatureType::ElfContentHash;
    id.signature_valid = true;
    // The highest level the mask admits: a rule written `trust: [">= known"]`
    // should be probed with the strongest identity it accepts, not the weakest.
    id.trust = m.trust.levels().last().unwrap_or(TrustLevel::Trusted);
    // Satisfy the first alternative: fingerprints are a disjunction, so one is
    // enough, and probing each in turn would multiply the corpus for little
    // extra coverage.
    if let Some(fp) = m.fingerprints.first() {
        id.path = match fp.paths.first() {
            Some(p) => concretize_glob(&p.pattern),
            None => "/usr/bin/probe".into(),
        };
        if let Some(h) = fp.sha256.first() {
            id.sha256 = Some(*h);
        }
        if let Some(s) = fp.signers.first() {
            id.signer = Some(s.clone());
        }
        if let Some(t) = fp.team_ids.first() {
            id.team_id = Some(t.clone());
        }
        if let Some(b) = fp.bundle_ids.first() {
            id.bundle_id = Some(b.clone());
        }
    } else {
        id.path = "/usr/bin/probe".into();
    }
    Some(id)
}

/// Turn a glob into a concrete path that the glob matches.
fn concretize_glob(pattern: &str) -> String {
    pattern.replace('*', "probe").replace('?', "x")
}

#[cfg(test)]
mod tests {
    use super::*;
    use ufw_shared::identity_types::TrustMask;

    fn cidr(s: &str) -> Cidr {
        Cidr::parse(s).unwrap()
    }

    fn sample_policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("sample", Decision::Deny);
        p.network_profile.internal = vec![cidr("10.0.0.0/8")];
        p.network_profile.perimeter = vec![cidr("203.0.113.0/24")];

        let mut dns = CompiledRule::new(10, "allow-dns", Layer::Packet, Action::Allow);
        dns.priority = 100;
        dns.protocol = Protocol::Udp;
        dns.direction = Direction::Outbound;
        dns.dest_ports = PortMatch {
            ranges: vec![PortRange::single(53)],
            negate: false,
        };

        let mut web = CompiledRule::new(20, "allow-web", Layer::Packet, Action::AllowInspect);
        web.priority = 200;
        web.protocol = Protocol::Tcp;
        web.dest_ports = PortMatch {
            ranges: vec![PortRange::single(80), PortRange::single(443)],
            negate: false,
        };

        let mut ident = CompiledRule::new(30, "deny-untrusted", Layer::Identity, Action::Deny);
        ident.priority = 50;
        ident.app = Some(AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Untrusted, TrustLevel::Unknown]),
            ..AppMatch::any()
        });

        let mut dpi = CompiledRule::new(40, "block-exploit", Layer::Stream, Action::Allow);
        dpi.priority = 10;
        dpi.dpi = Some(DpiMatch {
            signatures: vec![1001],
            l7: vec![L7Protocol::Http],
            on_match: Action::Deny,
        });

        let mut lan = CompiledRule::new(50, "allow-lan", Layer::Perimeter, Action::Allow);
        lan.priority = 900;
        lan.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::Internal, Zone::Loopback],
            negate: false,
        };

        p.rules = vec![dns, web, ident, dpi, lan];
        p.finalize();
        p
    }

    #[test]
    fn all_three_backends_produce_files_and_a_model() {
        for artifact in compile_all(&sample_policy()) {
            assert!(
                !artifact.files.is_empty(),
                "{} produced no files",
                artifact.platform
            );
            assert_eq!(artifact.model.platform, artifact.platform);
            assert!(artifact.total_bytes() > 0);
            for f in &artifact.files {
                assert!(!f.contents.is_empty(), "{} is empty", f.path);
            }
        }
    }

    #[test]
    fn every_rule_survives_into_every_model() {
        let policy = sample_policy();
        for artifact in compile_all(&policy) {
            let ids: std::collections::BTreeSet<u32> =
                artifact.model.rules.iter().map(|r| r.id).collect();
            for rule in &policy.rules {
                assert!(
                    ids.contains(&rule.id),
                    "{} dropped rule {}",
                    artifact.platform,
                    rule.name
                );
            }
            // A backend may install one rule twice under disjoint protocol
            // scopes, but it must never invent an id.
            assert_eq!(ids.len(), policy.rules.len());
        }
    }

    #[test]
    fn duplicated_rule_copies_are_protocol_disjoint() {
        // Two installed copies of one rule must never both admit the same
        // protocol, or a single flow could be decided twice.
        let policy = sample_policy();
        for artifact in compile_all(&policy) {
            for rule in &policy.rules {
                let copies: Vec<&ModelRule> = artifact
                    .model
                    .rules
                    .iter()
                    .filter(|m| m.id == rule.id)
                    .collect();
                for proto in [
                    Protocol::Tcp,
                    Protocol::Udp,
                    Protocol::Icmp,
                    Protocol::IcmpV6,
                    Protocol::Other(132),
                ] {
                    let admitting = copies.iter().filter(|c| c.scope.admits(proto)).count();
                    assert!(
                        admitting <= 1,
                        "{}: rule {} has {} copies admitting {}",
                        artifact.platform,
                        rule.name,
                        admitting,
                        proto.as_str()
                    );
                }
            }
        }
    }

    #[test]
    fn backends_agree_with_the_reference_on_a_generated_corpus() {
        let policy = sample_policy();
        let scenarios = default_scenarios(&policy);
        assert!(scenarios.len() > 100, "corpus too small to be meaningful");
        let report = verify_equivalence(&policy, &scenarios);
        assert!(report.is_equivalent(), "{}", report.render());
    }

    #[test]
    fn the_verifier_actually_catches_a_reordered_model() {
        // Confidence check on the checker: reverse one model and confirm the
        // verifier notices. A verifier that always passes is worthless.
        let policy = sample_policy();
        let mut models: Vec<DecisionModel> =
            compile_all(&policy).into_iter().map(|a| a.model).collect();
        models[0].rules.reverse();
        let report = verify_models(&policy, &models, &default_scenarios(&policy));
        assert!(!report.is_equivalent());
        assert!(report
            .divergences
            .iter()
            .any(|d| d.offenders().contains(&Platform::Windows)));
        assert!(report.render().contains("FAILED"));
    }

    #[test]
    fn the_verifier_catches_a_dropped_rule() {
        let policy = sample_policy();
        let mut models: Vec<DecisionModel> =
            compile_all(&policy).into_iter().map(|a| a.model).collect();
        let linux = models
            .iter_mut()
            .find(|m| m.platform == Platform::Linux)
            .unwrap();
        linux.rules.retain(|r| r.id != 10);
        let report = verify_models(&policy, &models, &default_scenarios(&policy));
        assert!(!report.is_equivalent());
    }

    #[test]
    fn order_key_puts_stage_above_priority() {
        let mut perimeter = CompiledRule::new(1, "p", Layer::Perimeter, Action::Allow);
        perimeter.priority = 60000;
        let mut packet = CompiledRule::new(2, "k", Layer::Packet, Action::Allow);
        packet.priority = 1;
        assert!(
            evaluation_order_key(&perimeter) < evaluation_order_key(&packet),
            "a perimeter rule must sort before a packet rule regardless of priority"
        );
    }

    #[test]
    fn generated_corpus_probes_cidr_boundaries() {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        let mut r = CompiledRule::new(1, "a", Layer::Packet, Action::Allow);
        r.dest = AddressMatch {
            cidrs: vec![cidr("198.51.100.0/24")],
            zones: vec![],
            negate: false,
        };
        p.rules = vec![r];
        p.finalize();
        let scenarios = default_scenarios(&p);
        let dsts: Vec<IpAddr> = scenarios.iter().map(|s| s.dst.0).collect();
        assert!(dsts.contains(&"198.51.100.1".parse::<IpAddr>().unwrap()));
        assert!(dsts.contains(&"198.51.101.0".parse::<IpAddr>().unwrap()));
    }

    #[test]
    fn corpus_stays_within_its_budget() {
        let mut p = CompiledPolicy::new("big", Decision::Deny);
        for i in 0..200u32 {
            let mut r = CompiledRule::new(i + 1, format!("r{i}"), Layer::Packet, Action::Allow);
            r.dest = AddressMatch {
                cidrs: vec![Cidr::parse(&format!("10.{}.{}.0/24", i / 256, i % 256)).unwrap()],
                zones: vec![],
                negate: false,
            };
            r.dest_ports = PortMatch {
                ranges: vec![PortRange::single(1000 + i as u16)],
                negate: false,
            };
            p.rules.push(r);
        }
        p.finalize();
        assert!(default_scenarios(&p).len() <= MAX_GENERATED_SCENARIOS);
    }

    #[test]
    fn empty_policy_is_equivalent_everywhere() {
        let mut p = CompiledPolicy::new("empty", Decision::Deny);
        p.finalize();
        let report = verify_equivalence(&p, &default_scenarios(&p));
        assert!(report.is_equivalent(), "{}", report.render());
        for artifact in compile_all(&p) {
            assert!(artifact.model.rules.is_empty());
            assert!(
                !artifact.files.is_empty(),
                "backends must still emit a policy file"
            );
        }
    }
}
