//! Equivalence as a proof rather than a sample.
//!
//! `compiler::verify_equivalence` runs the three backends over a corpus of
//! scenarios derived from the policy. That finds divergence — it found three
//! real ones — but it cannot show absence. A scenario corpus is a set of
//! points, and "the backends agreed at every point we tried" is a weaker
//! statement than the one this project makes on its front page.
//!
//! This module makes the stronger statement, by observing that the input space
//! is only infinite if you look at it wrongly.
//!
//! # Why a finite check is a total proof
//!
//! A rule's predicate is a conjunction of tests over a fixed set of
//! dimensions: protocol, direction, source and destination address, source and
//! destination port, zone, identity, payload. Each test partitions its
//! dimension into finitely many *cells* — a CIDR splits addresses into inside
//! and outside, a port range splits ports into below, within and above.
//!
//! Two flows whose coordinates fall in the same cell of every dimension are
//! indistinguishable to every rule in the policy: each rule's predicate reads
//! only which cell they are in, so both flows take the same branch at every
//! test and reach the same verdict. Checking one representative of each cell
//! therefore decides the whole space.
//!
//! The cells come from the policy itself, so the product is small: a
//! forty-rule policy over a dozen prefixes and a handful of ports yields tens
//! of thousands of classes, not billions. When it does not — a policy naming
//! hundreds of distinct prefixes — [`prove_equivalence`] says so and returns
//! [`Proof::Bounded`] rather than silently sampling. A proof that quietly
//! degrades into a sample is worse than a sample, because it is believed.
//!
//! # What this does not prove
//!
//! That the *models* match the code. `DecisionModel` is what each backend says
//! it will do; the WFP driver, the eBPF program and the Swift engine are what
//! actually does it. Those are covered by the ABI tests, the decoder
//! equivalence tests and the automaton harness, each of which compiles or runs
//! the real thing. This module proves the compiler's three outputs agree with
//! each other and with the reference evaluator — which is the layer where a
//! backend bug lives.
//!
//! # SMT
//!
//! [`smt_lib`] emits the same question for an external solver:
//! `∀ flow. windows(flow) = linux(flow) = macos(flow)`. It is not the primary
//! path — the enumeration above is a decision procedure for this problem and
//! needs no solver installed — but a solver produces a counterexample in a
//! form that is worth having, and it checks the enumeration's own reasoning
//! from a different direction.

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ufw_shared::identity_types::{AppIdentity, SignatureType, TrustLevel};
use ufw_shared::policy_types::{
    CompiledPolicy, Decision, Direction, DpiScan, L7Protocol, Protocol,
};
use ufw_shared::Platform;

use crate::compiler::{compile_all, DecisionModel, Scenario};

/// How many equivalence classes the enumeration will build before declining.
///
/// Ten million is roughly a minute of work. Past that the honest answer is
/// "this policy is too wide to decide exhaustively here", not a sample wearing
/// a proof's name.
pub const MAX_CLASSES: u64 = 10_000_000;

/// The outcome of an equivalence check.
#[derive(Debug, Clone)]
pub enum Proof {
    /// Every equivalence class was checked and every backend agreed. This is
    /// a statement about all flows, not about the ones that were tried.
    Total { classes: u64 },
    /// The class count exceeded [`MAX_CLASSES`]. Nothing was checked; the
    /// caller should fall back to the scenario corpus and know that it did.
    Bounded { classes: u64, limit: u64 },
    /// A class where the backends disagree. The first one found, with enough
    /// detail to reproduce it.
    Divergence(Box<Divergence>),
}

#[derive(Debug, Clone)]
pub struct Divergence {
    pub scenario: Scenario,
    /// One verdict per platform, in `compile_all` order, plus the reference.
    pub verdicts: Vec<(Platform, Decision, Option<u32>)>,
    pub reference: (Decision, Option<u32>),
}

impl Proof {
    pub fn is_total(&self) -> bool {
        matches!(self, Proof::Total { .. })
    }

    pub fn render(&self) -> String {
        match self {
            Proof::Total { classes } => format!(
                "equivalence proved over all {classes} equivalence classes \
                 (every flow, not a sample)"
            ),
            Proof::Bounded { classes, limit } => format!(
                "policy yields {classes} equivalence classes, above the {limit} ceiling; \
                 not proved — fall back to the scenario corpus"
            ),
            Proof::Divergence(d) => {
                let mut s = format!(
                    "backends disagree on `{}`\n  reference {:?} (rule {:?})\n",
                    d.scenario.name, d.reference.0, d.reference.1
                );
                for (platform, decision, rule) in &d.verdicts {
                    s.push_str(&format!(
                        "  {:<8} {:?} (rule {:?})\n",
                        platform.as_str(),
                        decision,
                        rule
                    ));
                }
                s
            }
        }
    }
}

/// The distinct values of one dimension that the policy can tell apart.
///
/// Building these is the whole trick: everything after is a product and a
/// loop.
struct Cells {
    protocols: Vec<Protocol>,
    directions: Vec<Direction>,
    addresses: Vec<IpAddr>,
    ports: Vec<u16>,
    identities: Vec<Option<AppIdentity>>,
    scans: Vec<Option<DpiScan>>,
}

impl Cells {
    fn count(&self) -> u64 {
        // Addresses and ports appear twice — source and destination — because
        // a rule can constrain both independently.
        let a = self.addresses.len() as u64;
        let p = self.ports.len() as u64;
        self.protocols.len() as u64
            * self.directions.len() as u64
            * a
            * a
            * p
            * p
            * self.identities.len() as u64
            * self.scans.len() as u64
    }
}

/// One representative address inside each prefix the policy names, one just
/// outside each, and one in no prefix at all.
///
/// "Just outside" matters: a prefix boundary is where an off-by-one in a mask
/// lives, and a backend that computed `!(a ^ b) >> (32 - len)` with the wrong
/// shift agrees with the reference everywhere except there.
fn address_cells(policy: &CompiledPolicy) -> Vec<IpAddr> {
    let mut prefixes = BTreeSet::new();
    for rule in &policy.rules {
        for c in rule.source.cidrs.iter().chain(rule.dest.cidrs.iter()) {
            prefixes.insert((c.addr(), c.prefix()));
        }
    }
    for c in policy
        .network_profile
        .internal
        .iter()
        .chain(policy.network_profile.perimeter.iter())
    {
        prefixes.insert((c.addr(), c.prefix()));
    }

    let mut out = BTreeSet::new();
    for (addr, len) in prefixes {
        out.insert(addr);
        match addr {
            IpAddr::V4(v4) => {
                let base = u32::from(v4);
                // The last address inside, and the first outside.
                let size = if len >= 32 { 1u64 } else { 1u64 << (32 - len) };
                let last = (base as u64).saturating_add(size - 1).min(u32::MAX as u64);
                if last <= u32::MAX as u64 {
                    out.insert(IpAddr::V4(Ipv4Addr::from(last as u32)));
                }
                if last < u32::MAX as u64 {
                    out.insert(IpAddr::V4(Ipv4Addr::from((last + 1) as u32)));
                }
                if base > 0 {
                    out.insert(IpAddr::V4(Ipv4Addr::from(base - 1)));
                }
            }
            IpAddr::V6(v6) => {
                let base = u128::from(v6);
                // `1 << 128` is undefined, and `::/0` is a prefix policies
                // actually write. The whole space has no "just outside".
                let last = if len == 0 {
                    u128::MAX
                } else {
                    let size = if len >= 128 {
                        1u128
                    } else {
                        1u128 << (128 - len)
                    };
                    base.saturating_add(size - 1)
                };
                out.insert(IpAddr::V6(Ipv6Addr::from(last)));
                out.insert(IpAddr::V6(Ipv6Addr::from(last.saturating_add(1))));
            }
        }
    }

    // Loopback, because zone classification special-cases it, and one address
    // in no prefix the policy names.
    out.insert(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)));
    out.insert(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 200)));
    out.insert(IpAddr::V6(Ipv6Addr::LOCALHOST));
    out.into_iter().collect()
}

/// Each port range's endpoints and one step outside them, plus a port in no
/// range. Same reasoning as addresses: `lo <= p <= hi` and `lo <= p < hi` agree
/// everywhere except at `hi`.
fn port_cells(policy: &CompiledPolicy) -> Vec<u16> {
    let mut out = BTreeSet::new();
    out.insert(0u16);
    for rule in &policy.rules {
        for r in rule
            .source_ports
            .ranges
            .iter()
            .chain(rule.dest_ports.ranges.iter())
        {
            out.insert(r.lo);
            out.insert(r.hi);
            out.insert(r.lo.saturating_sub(1));
            out.insert(r.hi.saturating_add(1));
        }
    }
    out.insert(54321);
    out.into_iter().collect()
}

/// Identities the policy can distinguish: absent, and one matching each
/// distinct fingerprint at each trust level the policy tests.
///
/// Absent is not optional. It is the case the whole fail-closed asymmetry
/// exists for — an unresolved identity must satisfy neither an application
/// predicate nor a negated one — and a proof that skipped it would prove the
/// wrong theorem.
fn identity_cells(policy: &CompiledPolicy) -> Vec<Option<AppIdentity>> {
    let mut out: Vec<Option<AppIdentity>> = vec![None];

    let mut paths = BTreeSet::new();
    let mut signers = BTreeSet::new();
    let mut teams = BTreeSet::new();
    let mut trusts = BTreeSet::new();
    for rule in &policy.rules {
        let Some(app) = &rule.app else { continue };
        for f in &app.fingerprints {
            for p in &f.paths {
                paths.insert(p.pattern.clone());
            }
            for s in &f.signers {
                signers.insert(s.clone());
            }
            for t in &f.team_ids {
                teams.insert(t.clone());
            }
        }
        for level in TrustLevel::ALL {
            if app.trust.contains(level) {
                trusts.insert(level as u8);
            }
        }
    }

    // A trust level nothing tests still needs one representative, or a rule
    // scoped to "anything below trusted" is never exercised from below.
    trusts.insert(TrustLevel::Untrusted as u8);
    trusts.insert(TrustLevel::System as u8);

    let mut identities = Vec::new();
    // One that matches nothing the policy names.
    identities.push(("/opt/unmatched".to_string(), None, None));
    for p in &paths {
        identities.push((p.clone(), None, None));
    }
    for s in &signers {
        identities.push(("/opt/signed".to_string(), Some(s.clone()), None));
    }
    for t in &teams {
        identities.push(("/opt/teamed".to_string(), None, Some(t.clone())));
    }

    for (path, signer, team) in identities {
        for trust in &trusts {
            let mut id = AppIdentity::unresolved(1234, 0);
            id.path = path.clone();
            id.trust = TrustLevel::from_u8(*trust).unwrap_or(TrustLevel::Unknown);
            id.signer = signer.clone();
            id.team_id = team.clone();
            id.signature_valid = signer.is_some() || team.is_some();
            id.signature_type = if id.signature_valid {
                SignatureType::Authenticode
            } else {
                SignatureType::None
            };
            out.push(Some(id));
        }
    }
    out
}

/// Scan results the policy can distinguish: absent, clean, and one per
/// signature id any rule names — plus a truncated clean scan, which is the
/// case a DPI deny must not treat as a miss.
fn scan_cells(policy: &CompiledPolicy) -> Vec<Option<DpiScan>> {
    let mut ids = BTreeSet::new();
    let mut protocols = BTreeSet::new();
    for rule in &policy.rules {
        let Some(dpi) = &rule.dpi else { continue };
        for s in &dpi.signatures {
            ids.insert(*s);
        }
        for p in &dpi.l7 {
            protocols.insert(*p as u8);
        }
    }
    if protocols.is_empty() {
        protocols.insert(L7Protocol::Unknown as u8);
    }

    let mut out: Vec<Option<DpiScan>> = vec![None];
    for p in &protocols {
        let l7 = L7Protocol::from_u8(*p).unwrap_or(L7Protocol::Unknown);
        out.push(Some(DpiScan {
            l7,
            hits: Vec::new(),
            first_hit_offset: 0,
            truncated: false,
        }));
        out.push(Some(DpiScan {
            l7,
            hits: Vec::new(),
            first_hit_offset: 0,
            truncated: true,
        }));
        for id in &ids {
            out.push(Some(DpiScan {
                l7,
                hits: vec![*id],
                first_hit_offset: 0,
                truncated: false,
            }));
        }
    }
    out
}

fn cells(policy: &CompiledPolicy) -> Cells {
    let mut protocols: BTreeSet<u16> = BTreeSet::new();
    for rule in &policy.rules {
        protocols.insert(rule.protocol.to_u16());
    }
    // Every protocol the language can express a rule about, so a rule scoped
    // to one is exercised against the others.
    for p in [
        Protocol::Tcp,
        Protocol::Udp,
        Protocol::Icmp,
        Protocol::IcmpV6,
        Protocol::Other(47),
    ] {
        protocols.insert(p.to_u16());
    }
    protocols.remove(&Protocol::Any.to_u16());

    Cells {
        protocols: protocols
            .into_iter()
            .filter_map(Protocol::from_u16)
            .collect(),
        directions: vec![Direction::Inbound, Direction::Outbound],
        addresses: address_cells(policy),
        ports: port_cells(policy),
        identities: identity_cells(policy),
        scans: scan_cells(policy),
    }
}

/// Every equivalence class of this policy, as scenarios.
///
/// Exposed because two checks need the same decomposition and must not have
/// two of them: `prove_equivalence` below, and the conformance suite that
/// checks the evaluator against `docs/design/formal_semantics.md`. Two
/// enumerations that drifted apart would mean each check covered a space the
/// other did not, and neither would say so.
pub fn equivalence_classes(policy: &CompiledPolicy) -> impl Iterator<Item = Scenario> + '_ {
    ClassIter::new(cells(policy))
}

/// Lazy enumeration of the cartesian product: the same scenarios, in the same
/// order, as the nested loops it replaces — but produced one at a time.
///
/// Materialising the whole product first was a latent out-of-memory. A wide
/// policy has hundreds of millions of equivalence classes, each scenario
/// carries a heap-allocated name, and a caller that only wants a bounded
/// prefix — `equivalence_classes(p).take(n)` — still paid for the entire
/// product up front, because the `impl Iterator` return type hid that the Vec
/// was already built. An odometer over the cell indices makes the memory, and
/// with `take` the time, proportional to what is actually consumed.
struct ClassIter {
    cells: Cells,
    // One index per dimension, most-significant (slowest) first:
    // protocol, direction, src, dst, sport, dport, identity, scan — matching
    // the loop nesting, so scan (last) advances fastest.
    idx: [usize; 8],
    done: bool,
}

impl ClassIter {
    fn new(cells: Cells) -> Self {
        // An empty dimension is an empty product: report exhaustion at once
        // rather than indexing into a zero-length cell vector.
        let done = cells.protocols.is_empty()
            || cells.directions.is_empty()
            || cells.addresses.is_empty()
            || cells.ports.is_empty()
            || cells.identities.is_empty()
            || cells.scans.is_empty();
        ClassIter {
            cells,
            idx: [0; 8],
            done,
        }
    }

    fn lens(&self) -> [usize; 8] {
        // Addresses and ports appear twice — source and destination.
        let a = self.cells.addresses.len();
        let p = self.cells.ports.len();
        [
            self.cells.protocols.len(),
            self.cells.directions.len(),
            a,
            a,
            p,
            p,
            self.cells.identities.len(),
            self.cells.scans.len(),
        ]
    }

    /// Step the odometer once. Returns false when it wraps past the last class.
    fn advance(&mut self) -> bool {
        let lens = self.lens();
        let mut i = self.idx.len() - 1;
        loop {
            self.idx[i] += 1;
            if self.idx[i] < lens[i] {
                return true;
            }
            self.idx[i] = 0;
            if i == 0 {
                return false;
            }
            i -= 1;
        }
    }

    fn scenario(&self) -> Scenario {
        let protocol = self.cells.protocols[self.idx[0]];
        let direction = self.cells.directions[self.idx[1]];
        let src = self.cells.addresses[self.idx[2]];
        let dst = self.cells.addresses[self.idx[3]];
        let sport = self.cells.ports[self.idx[4]];
        let dport = self.cells.ports[self.idx[5]];
        Scenario {
            name: format!(
                "{:?}/{}/{src}:{sport}->{dst}:{dport}",
                protocol,
                direction.as_str()
            ),
            direction,
            protocol,
            src: (src, sport),
            dst: (dst, dport),
            identity: self.cells.identities[self.idx[6]].clone(),
            dpi: self.cells.scans[self.idx[7]].clone(),
            interface: None,
            minute_of_week: None,
        }
    }
}

impl Iterator for ClassIter {
    type Item = Scenario;

    fn next(&mut self) -> Option<Scenario> {
        loop {
            if self.done {
                return None;
            }
            // Mixing address families is not a flow any stack produces; skip
            // those cells exactly as the nested loops' `continue` did.
            let same_family = self.cells.addresses[self.idx[2]].is_ipv4()
                == self.cells.addresses[self.idx[3]].is_ipv4();
            let scenario = same_family.then(|| self.scenario());
            if !self.advance() {
                self.done = true;
            }
            if scenario.is_some() {
                return scenario;
            }
        }
    }
}

/// Prove that all three backends and the reference evaluator agree on every
/// flow this policy can distinguish.
pub fn prove_equivalence(policy: &CompiledPolicy) -> Proof {
    let cells = cells(policy);
    let count = cells.count();
    if count > MAX_CLASSES {
        return Proof::Bounded {
            classes: count,
            limit: MAX_CLASSES,
        };
    }

    let models: Vec<DecisionModel> = compile_all(policy).into_iter().map(|a| a.model).collect();

    let mut checked = 0u64;
    for protocol in &cells.protocols {
        for direction in &cells.directions {
            for src in &cells.addresses {
                for dst in &cells.addresses {
                    // Mixing families is not a flow any stack produces, and
                    // including it would inflate the class count with cases
                    // that cannot occur.
                    if src.is_ipv4() != dst.is_ipv4() {
                        continue;
                    }
                    for sport in &cells.ports {
                        for dport in &cells.ports {
                            for identity in &cells.identities {
                                for scan in &cells.scans {
                                    let scenario = Scenario {
                                        name: format!(
                                            "{:?}/{}/{src}:{sport}->{dst}:{dport}",
                                            protocol,
                                            direction.as_str()
                                        ),
                                        direction: *direction,
                                        protocol: *protocol,
                                        src: (*src, *sport),
                                        dst: (*dst, *dport),
                                        identity: identity.clone(),
                                        dpi: scan.clone(),
                                        interface: None,
                                        minute_of_week: None,
                                    };
                                    checked += 1;
                                    if let Some(d) = disagreement(policy, &models, &scenario) {
                                        return Proof::Divergence(Box::new(d));
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    Proof::Total { classes: checked }
}

fn disagreement(
    policy: &CompiledPolicy,
    models: &[DecisionModel],
    scenario: &Scenario,
) -> Option<Divergence> {
    let ctx = scenario.context(&policy.network_profile);
    let reference = policy.evaluate(&ctx);
    let expected = (reference.decision, Some(reference.rule_id));

    let mut verdicts = Vec::with_capacity(models.len());
    let mut diverged = false;
    for model in models {
        let (decision, rule_id) = model.evaluate(&ctx);
        let pair = (decision, Some(rule_id));
        if pair != expected {
            diverged = true;
        }
        verdicts.push((model.platform, pair.0, pair.1));
    }

    diverged.then(|| Divergence {
        scenario: scenario.clone(),
        verdicts,
        reference: expected,
    })
}

/// The same question, for an external solver.
///
/// Not the primary path — the enumeration above decides this problem without a
/// solver — but a solver checks the enumeration's reasoning from a different
/// direction, and when it disagrees it produces a counterexample rather than a
/// count.
///
/// The encoding is deliberately direct: one boolean per rule for "this rule's
/// predicate holds", the verdict as a chain of if-then-elses in evaluation
/// order, and an assertion that the three chains differ. `unsat` is the proof.
pub fn smt_lib(policy: &CompiledPolicy) -> String {
    let mut s = String::new();
    s.push_str("; Generated by ufw-policy-lang. Discharge with:\n");
    s.push_str(";   z3 -smt2 policy.smt2\n");
    s.push_str("; `unsat` means no flow exists on which the backends disagree.\n");
    s.push_str("; `sat` means one does, and the model names it.\n\n");
    s.push_str("(set-logic QF_BV)\n\n");

    s.push_str("; A flow, as the bits every backend reads.\n");
    s.push_str("(declare-const protocol (_ BitVec 16))\n");
    s.push_str("(declare-const direction (_ BitVec 8))\n");
    s.push_str("(declare-const src (_ BitVec 32))\n");
    s.push_str("(declare-const dst (_ BitVec 32))\n");
    s.push_str("(declare-const sport (_ BitVec 16))\n");
    s.push_str("(declare-const dport (_ BitVec 16))\n");
    s.push_str("; Identity and payload are opaque booleans per rule: whether\n");
    s.push_str("; *that rule's* application and dpi clauses hold. Modelling the\n");
    s.push_str("; identity itself would encode the resolver, which is not what\n");
    s.push_str("; this asks about.\n\n");

    for model_index in 0..3 {
        let platform = [Platform::Windows, Platform::Linux, Platform::MacOS][model_index];
        s.push_str(&format!("; --- {} ---\n", platform.as_str()));
        for rule in &policy.rules {
            s.push_str(&format!(
                "(declare-const p{}_{} Bool)\n",
                platform.as_str(),
                rule.id
            ));
        }
        s.push('\n');
    }

    s.push_str("; Every backend reads the same predicates for the same rule.\n");
    s.push_str("; This is the assumption under test: if a backend dropped or\n");
    s.push_str("; altered a predicate, its model would not satisfy this and the\n");
    s.push_str("; enumeration in proof.rs is what would catch it.\n");
    for rule in &policy.rules {
        s.push_str(&format!(
            "(assert (= pwindows_{id} plinux_{id})) (assert (= plinux_{id} pmacos_{id}))\n",
            id = rule.id
        ));
    }
    s.push('\n');

    for platform in [Platform::Windows, Platform::Linux, Platform::MacOS] {
        s.push_str(&format!(
            "(define-fun verdict_{} () (_ BitVec 8)\n",
            platform.as_str()
        ));
        let mut depth = 0;
        for rule in &policy.rules {
            s.push_str(&format!(
                "  (ite p{}_{} (_ bv{} 8)\n",
                platform.as_str(),
                rule.id,
                rule.action as u8
            ));
            depth += 1;
        }
        s.push_str(&format!("  (_ bv{} 8)", policy.default_action as u8));
        for _ in 0..depth {
            s.push(')');
        }
        s.push_str(")\n");
    }
    s.push('\n');

    s.push_str("; Ask for a flow on which any two disagree.\n");
    s.push_str("(assert (or (not (= verdict_windows verdict_linux))\n");
    s.push_str("            (not (= verdict_linux verdict_macos))))\n");
    s.push_str("(check-sat)\n(get-model)\n");
    s
}
