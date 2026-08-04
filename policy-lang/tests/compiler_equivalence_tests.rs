//! Cross-platform equivalence: the test category this project exists for.
//!
//! One policy source compiles to three kernel implementations. These tests
//! check the claim that follows from that: for the same flow, all three
//! produce the same verdict and attribute it to the same rule.
//!
//! Two things make these tests worth trusting rather than merely reassuring:
//!
//! * The corpus is **derived from the policy**, not hand-written, so it probes
//!   the boundaries each policy actually draws.
//! * There are **negative controls** — deliberately broken models that the
//!   verifier must reject. A checker that never fails proves nothing.

use ufw_policy_lang::compiler::{
    compile_all, default_scenarios, verify_equivalence, verify_models, DecisionModel, Engine,
    Scenario,
};
use ufw_policy_lang::{compile_str, CompileOptions};
use ufw_shared::identity_types::{AppIdentity, SignatureType, TrustLevel};
use ufw_shared::policy_types::*;
use ufw_shared::Platform;

fn compile(src: &str) -> CompiledPolicy {
    let r = compile_str("equiv", src, &CompileOptions::default());
    r.policy
        .clone()
        .unwrap_or_else(|| panic!("policy failed to compile:\n{}", r.render()))
}

fn fixture() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/realistic.yaml"
    ))
    .expect("fixture")
}

fn assert_equivalent(policy: &CompiledPolicy) {
    let scenarios = default_scenarios(policy);
    assert!(
        scenarios.len() >= 64,
        "corpus of {} scenarios is too small to mean much",
        scenarios.len()
    );
    let report = verify_equivalence(policy, &scenarios);
    assert!(report.is_equivalent(), "{}", report.render());
}

// ===========================================================================
// The headline property
// ===========================================================================

#[test]
fn the_realistic_policy_is_equivalent_on_all_three_platforms() {
    assert_equivalent(&compile(&fixture()));
}

#[test]
fn the_compiler_driver_verifies_equivalence_by_default() {
    let r = compile_str("equiv", &fixture(), &CompileOptions::default());
    let eq = r.equivalence.as_ref().expect("verification runs by default");
    assert!(eq.is_equivalent(), "{}", eq.render());
    assert!(eq.scenarios_checked > 100);
}

/// Each of these isolates one language feature that a backend could plausibly
/// mistranslate.
#[test]
fn every_language_feature_is_equivalent_in_isolation() {
    let cases: [(&str, &str); 12] = [
        ("empty policy", "version: 1\ndefaults:\n  action: deny\n"),
        (
            "default allow",
            "version: 1\ndefaults:\n  action: allow\nrules:\n  - id: a\n    action: deny\n    protocol: tcp\n    destination:\n      ports: [445]\n",
        ),
        (
            "ipv6",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n    destination: 2001:db8::/32\n",
        ),
        (
            "icmp",
            "version: 1\ndefaults:\n  action: allow\nrules:\n  - id: a\n    action: deny\n    protocol: icmp\n",
        ),
        (
            "port ranges",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n    protocol: tcp\n    destination:\n      ports: [80, 443, 8000-8100]\n",
        ),
        (
            "zones",
            "version: 1\ndefaults:\n  action: deny\nnetwork_profile:\n  internal: [10.0.0.0/8]\n  perimeter: [203.0.113.0/24]\nrules:\n  - id: a\n    action: allow\n    destination:\n      zone: internal\n  - id: b\n    priority: 200\n    action: deny\n    destination:\n      zone: external\n",
        ),
        (
            "negation",
            "version: 1\ndefaults:\n  action: allow\nrules:\n  - id: a\n    action: deny\n    protocol: tcp\n    destination:\n      addresses: [10.0.0.0/8]\n      negate: true\n",
        ),
        (
            "identity",
            "version: 1\ndefaults:\n  action: deny\napplications:\n  app:\n    trust: [trusted, system]\n    platforms:\n      linux:\n        path: /usr/bin/app\n      windows:\n        path: \"C:\\\\app.exe\"\n        signer: Example\nrules:\n  - id: a\n    action: allow\n    protocol: tcp\n    application: app\n",
        ),
        (
            "trust bounds",
            "version: 1\ndefaults:\n  action: allow\nrules:\n  - id: a\n    action: deny\n    protocol: tcp\n    application:\n      trust: [untrusted, unknown]\n",
        ),
        (
            "dpi over tcp and udp",
            "version: 1\ndefaults:\n  action: deny\nsignature_groups:\n  bad: [exploit-a, exploit-b]\nrules:\n  - id: web\n    priority: 100\n    action: allow\n    protocol: tcp\n  - id: dns\n    priority: 110\n    action: allow\n    protocol: udp\n  - id: sig\n    priority: 10\n    layer: stream\n    action: allow\n    dpi:\n      signatures: [bad]\n      on_match: deny\n",
        ),
        (
            "schedules",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n    protocol: tcp\n    schedule:\n      days: [weekdays]\n      start: \"09:00\"\n      end: \"17:00\"\n",
        ),
        (
            "interfaces",
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n    protocol: tcp\n    interfaces: [eth0, wg0]\n",
        ),
    ];

    for (label, src) in cases {
        let policy = compile(src);
        let scenarios = default_scenarios(&policy);
        let report = verify_equivalence(&policy, &scenarios);
        assert!(report.is_equivalent(), "{label}:\n{}", report.render());
    }
}

#[test]
fn allow_inspect_overriding_across_layers_is_equivalent() {
    // The interesting case: a packet-layer provisional allow that a stream
    // rule later overturns. Every backend has to keep the deeper layer
    // installed and evaluated after the shallower one permitted the flow.
    let policy = compile(
        "version: 1\ndefaults:\n  action: deny\n\
         network_profile:\n  internal: [10.0.0.0/8]\n  perimeter_crossing_requires_dpi: true\n\
         rules:\n\
         \x20 - id: allow-web\n    priority: 100\n    action: allow\n    protocol: tcp\n\
         \x20   destination:\n      ports: [80, 443]\n\
         \x20 - id: block-exploit\n    priority: 10\n    layer: stream\n    action: allow\n\
         \x20   protocol: tcp\n    dpi:\n      signatures: [http-exploit-post]\n      on_match: deny\n",
    );

    let allow_web = policy.rules.iter().find(|r| r.name == "allow-web").unwrap();
    assert_eq!(
        allow_web.action,
        Action::AllowInspect,
        "the perimeter upgrade should have lowered this to allow-inspect"
    );

    assert_equivalent(&policy);

    // And spot-check the actual override on every model.
    let sig = ufw_shared::hash::derive_signature_id("http-exploit-post");
    let scenario = Scenario {
        name: "exploit over https".into(),
        direction: Direction::Outbound,
        protocol: Protocol::Tcp,
        src: ("10.0.0.5".parse().unwrap(), 40000),
        dst: ("198.51.100.9".parse().unwrap(), 443),
        identity: None,
        dpi: Some(DpiScan {
            l7: L7Protocol::Http,
            hits: vec![sig],
            first_hit_offset: 0,
            truncated: false,
        }),
        interface: None,
        minute_of_week: None,
    };
    let ctx = scenario.context(&policy.network_profile);
    assert_eq!(policy.evaluate(&ctx).decision, Decision::Deny);
    for artifact in compile_all(&policy) {
        assert_eq!(
            artifact.model.evaluate(&ctx).0,
            Decision::Deny,
            "{} let an exploit through a provisionally-allowed flow",
            artifact.platform
        );
    }
}

#[test]
fn identity_rules_agree_across_platforms_for_each_platform_binary() {
    let policy = compile(
        "version: 1\ndefaults:\n  action: deny\n\
         applications:\n  browser:\n    trust: [\">= trusted\"]\n    platforms:\n\
         \x20     windows:\n        path: \"C:\\\\Browser\\\\b.exe\"\n        signer: Contoso Ltd\n\
         \x20     linux:\n        path: /usr/bin/b\n\
         \x20     macos:\n        bundle_id: com.contoso.b\n        team_id: ABCDE12345\n\
         rules:\n  - id: browser-web\n    action: allow\n    protocol: tcp\n    application: browser\n\
         \x20   destination:\n      ports: [443]\n",
    );

    let mk = |path: &str, signer: Option<&str>, bundle: Option<&str>, team: Option<&str>| {
        let mut id = AppIdentity::unresolved(1, 0);
        id.path = path.into();
        id.signer = signer.map(str::to_string);
        id.bundle_id = bundle.map(str::to_string);
        id.team_id = team.map(str::to_string);
        id.trust = TrustLevel::Trusted;
        id.signature_valid = true;
        id.signature_type = SignatureType::Authenticode;
        id
    };

    let identities = [
        mk(r"C:\Browser\b.exe", Some("Contoso Ltd"), None, None),
        mk("/usr/bin/b", None, None, None),
        mk("/Applications/B.app", None, Some("com.contoso.b"), Some("ABCDE12345")),
    ];

    let models: Vec<DecisionModel> = compile_all(&policy).into_iter().map(|a| a.model).collect();

    for id in &identities {
        let ctx = FlowContext::new(
            &policy.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            ("10.0.0.5".parse().unwrap(), 40000),
            ("198.51.100.9".parse().unwrap(), 443),
        )
        .with_identity(id);
        let reference = policy.evaluate(&ctx);
        assert_eq!(
            reference.decision,
            Decision::Allow,
            "the platform binary at {} should be allowed",
            id.path
        );
        for m in &models {
            assert_eq!(
                m.evaluate(&ctx),
                reference.verdict(),
                "{} disagreed for {}",
                m.platform,
                id.path
            );
        }
    }
}

// ===========================================================================
// Negative controls: the verifier must be able to fail
// ===========================================================================

#[test]
fn the_verifier_rejects_a_reordered_model() {
    let policy = compile(&fixture());
    let scenarios = default_scenarios(&policy);
    for i in 0..3 {
        let mut models: Vec<DecisionModel> =
            compile_all(&policy).into_iter().map(|a| a.model).collect();
        models[i].rules.reverse();
        let report = verify_models(&policy, &models, &scenarios);
        assert!(
            !report.is_equivalent(),
            "reversing {} went unnoticed",
            models[i].platform
        );
    }
}

#[test]
fn the_verifier_rejects_a_dropped_rule() {
    let policy = compile(&fixture());
    let scenarios = default_scenarios(&policy);
    let dropped = policy
        .rules
        .iter()
        .find(|r| r.name == "block-telnet")
        .unwrap()
        .id;

    for platform in Platform::ALL {
        let mut models: Vec<DecisionModel> =
            compile_all(&policy).into_iter().map(|a| a.model).collect();
        models
            .iter_mut()
            .find(|m| m.platform == platform)
            .unwrap()
            .rules
            .retain(|r| r.id != dropped);
        let report = verify_models(&policy, &models, &scenarios);
        assert!(
            !report.is_equivalent(),
            "dropping a rule from {platform} went unnoticed"
        );
        assert!(report
            .divergences
            .iter()
            .any(|d| d.offenders().contains(&platform)));
    }
}

#[test]
fn the_verifier_rejects_a_flipped_action() {
    let policy = compile(&fixture());
    let scenarios = default_scenarios(&policy);
    let mut models: Vec<DecisionModel> =
        compile_all(&policy).into_iter().map(|a| a.model).collect();
    for rule in &mut models[1].rules {
        if rule.predicate.action == Action::Deny {
            rule.predicate.action = Action::Allow;
            rule.predicate.dpi = None;
        }
    }
    let report = verify_models(&policy, &models, &scenarios);
    assert!(!report.is_equivalent());
}

#[test]
fn the_verifier_rejects_a_widened_predicate() {
    let policy = compile(&fixture());
    let scenarios = default_scenarios(&policy);
    let mut models: Vec<DecisionModel> =
        compile_all(&policy).into_iter().map(|a| a.model).collect();
    // Strip every destination constraint from one backend: a classic
    // "too permissive" translation bug.
    for rule in &mut models[2].rules {
        rule.predicate.dest = AddressMatch::any();
        rule.predicate.dest_ports = PortMatch::any();
    }
    let report = verify_models(&policy, &models, &scenarios);
    assert!(!report.is_equivalent());
    assert!(report.render().contains("FAILED"));
}

// ===========================================================================
// Backend-specific properties that equivalence depends on
// ===========================================================================

#[test]
fn the_linux_ebpf_offload_is_always_a_prefix_of_the_evaluation_order() {
    // The safety argument for the fast path is that offloaded rules form a
    // prefix of the inbound-relevant rules. If that ever stops holding, the
    // tc ingress hook can decide ahead of a higher-priority netfilter rule.
    for src in [fixture(), simple_policy(), identity_first_policy()] {
        let policy = compile(&src);
        let artifact = compile_all(&policy)
            .into_iter()
            .find(|a| a.platform == Platform::Linux)
            .unwrap();

        let inbound_relevant: Vec<u32> = artifact
            .model
            .rules
            .iter()
            .filter(|r| r.predicate.direction != Direction::Outbound)
            .map(|r| r.id)
            .collect();
        let offloaded: Vec<u32> = artifact.model.rules_on(Engine::Ebpf).map(|r| r.id).collect();

        assert_eq!(
            offloaded,
            inbound_relevant[..offloaded.len()].to_vec(),
            "offloaded rules are not a prefix of the inbound-relevant order"
        );
    }
}

#[test]
fn windows_filter_weights_reproduce_the_evaluation_order() {
    let policy = compile(&fixture());
    let artifact = compile_all(&policy)
        .into_iter()
        .find(|a| a.platform == Platform::Windows)
        .unwrap();

    // Inside the ALE/packet layer group, higher weight must mean earlier.
    let group: Vec<_> = artifact
        .model
        .rules
        .iter()
        .filter(|r| matches!(r.engine, Engine::WfpAle | Engine::WfpPacket))
        .collect();
    for pair in group.windows(2) {
        assert!(
            pair[0].order_key >= pair[1].order_key,
            "filter weights are not monotone: {} then {}",
            pair[0].name,
            pair[1].name
        );
    }

    // And the stream layer always comes after that group.
    let first_stream = artifact
        .model
        .rules
        .iter()
        .position(|r| r.engine == Engine::WfpStream);
    let last_group = artifact
        .model
        .rules
        .iter()
        .rposition(|r| matches!(r.engine, Engine::WfpAle | Engine::WfpPacket));
    if let (Some(s), Some(g)) = (first_stream, last_group) {
        assert!(s > g, "stream-layer filters must sort after ALE/packet ones");
    }
}

#[test]
fn optimization_does_not_change_behaviour() {
    use ufw_policy_lang::optimizer::OptimizerOptions;

    let src = fixture();
    let unoptimized = compile_str(
        "equiv",
        &src,
        &CompileOptions {
            optimizer: OptimizerOptions {
                eliminate_unreachable: false,
                eliminate_duplicates: false,
                merge_adjacent: false,
                mark_ebpf: true,
            },
            ..Default::default()
        },
    )
    .policy
    .expect("compiles");

    let optimized = compile(&src);

    // Verdicts must agree on the union of both corpora.
    let mut scenarios = default_scenarios(&unoptimized);
    scenarios.extend(default_scenarios(&optimized));
    for s in &scenarios {
        let a = unoptimized.evaluate(&s.context(&unoptimized.network_profile));
        let b = optimized.evaluate(&s.context(&optimized.network_profile));
        assert_eq!(a.decision, b.decision, "optimization changed `{}`", s.name);
        assert_eq!(a.rule_id, b.rule_id, "attribution changed for `{}`", s.name);
    }
}

fn simple_policy() -> String {
    "version: 1\ndefaults:\n  action: deny\n\
     rules:\n\
     \x20 - id: a\n    priority: 10\n    action: deny\n    protocol: tcp\n    destination:\n      ports: [23]\n\
     \x20 - id: b\n    priority: 20\n    action: allow\n    protocol: tcp\n    destination:\n      ports: [443]\n"
        .to_string()
}

fn identity_first_policy() -> String {
    "version: 1\ndefaults:\n  action: deny\n\
     rules:\n\
     \x20 - id: zoned\n    priority: 5\n    action: deny\n    destination:\n      zone: external\n\
     \x20 - id: b\n    priority: 20\n    action: allow\n    protocol: tcp\n    destination:\n      ports: [443]\n"
        .to_string()
}
