//! Integration tests for semantic analysis, exercised through the full
//! compiler driver so defaults, inference and lowering are all in play.

use ufw_policy_lang::error::codes;
use ufw_policy_lang::{compile_str, CompileOptions, Compilation};
use ufw_shared::identity_types::{AppIdentity, SignatureType, TrustLevel};
use ufw_shared::policy_types::*;

fn fixture() -> String {
    std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/realistic.yaml"
    ))
    .expect("fixture")
}

fn compile(src: &str) -> Compilation {
    compile_str("test", src, &CompileOptions::default())
}

fn compiled(src: &str) -> CompiledPolicy {
    let r = compile(src);
    r.policy
        .clone()
        .unwrap_or_else(|| panic!("expected success:\n{}", r.render()))
}

const BASE: &str = "version: 1\ndefaults:\n  action: deny\n";

#[test]
fn the_realistic_fixture_compiles_cleanly() {
    let r = compile(&fixture());
    assert!(r.is_ok(), "{}", r.render());
    assert_eq!(r.diagnostics.error_count(), 0);

    let policy = r.policy.as_ref().unwrap();
    assert_eq!(policy.name, "workstation-baseline");
    assert_eq!(policy.default_action, Decision::Deny);
    assert!(policy.verify_hash());

    // Every rule kept a name and got a distinct id.
    let mut ids: Vec<u32> = policy.rules.iter().map(|r| r.id).collect();
    let count = ids.len();
    ids.sort_unstable();
    ids.dedup();
    assert_eq!(ids.len(), count, "rule ids must be unique");
    assert!(policy.rules.iter().all(|r| !r.name.is_empty()));
}

#[test]
fn group_references_resolve_transitively_through_the_fixture() {
    let policy = compiled(&fixture());
    let dns = policy.rules.iter().find(|r| r.name == "allow-dns").unwrap();
    // corp_dns (2) + public_dns (3), reached through `all_dns`.
    assert_eq!(dns.dest.cidrs.len(), 5);
    assert_eq!(dns.dest_ports.ranges, vec![PortRange::single(53)]);

    // The network profile expanded `rfc1918`.
    assert_eq!(policy.network_profile.internal.len(), 3);
    assert_eq!(policy.network_profile.dns_servers.len(), 2);
}

#[test]
fn layers_are_inferred_from_the_predicates_a_rule_carries() {
    let policy = compiled(&fixture());
    let layer = |name: &str| {
        policy
            .rules
            .iter()
            .find(|r| r.name == name)
            .unwrap_or_else(|| panic!("no rule {name}"))
            .layer
    };
    assert_eq!(layer("allow-loopback"), Layer::Packet);
    assert_eq!(layer("browser-web"), Layer::Identity);
    assert_eq!(layer("deny-unsigned-egress"), Layer::Identity);
    assert_eq!(layer("dns-exfiltration"), Layer::Stream);
    assert_eq!(layer("audit-external-tls"), Layer::AppDpi);
}

#[test]
fn perimeter_upgrade_applies_only_where_the_destination_can_leave() {
    let policy = compiled(&fixture());
    let action = |name: &str| policy.rules.iter().find(|r| r.name == name).unwrap().action;
    // Loopback is provably internal, so it keeps a terminal allow.
    assert_eq!(action("allow-loopback"), Action::Allow);
    // `browser-web` has no address constraint at all, so it may cross.
    assert_eq!(action("browser-web"), Action::AllowInspect);
    // DNS goes to a mix of corporate and public resolvers, so it may cross.
    assert_eq!(action("allow-dns"), Action::AllowInspect);
}

#[test]
fn application_definitions_lower_to_platform_aware_predicates() {
    let policy = compiled(&fixture());
    let browser = policy.rules.iter().find(|r| r.name == "browser-web").unwrap();
    let app = browser.app.as_ref().expect("identity predicate");

    // One fingerprint per platform block, so the Windows signer requirement
    // never applies to the Linux binary.
    assert_eq!(app.fingerprints.len(), 3);

    // Windows and macOS paths compare case-insensitively; Linux paths do not.
    let paths: Vec<_> = app.fingerprints.iter().flat_map(|f| f.paths.iter()).collect();
    let win = paths.iter().find(|p| p.pattern.contains('\\')).unwrap();
    assert!(win.case_insensitive);
    let lin = paths
        .iter()
        .find(|p| p.pattern.starts_with("/usr/lib"))
        .unwrap();
    assert!(!lin.case_insensitive);

    let has = |f: fn(&ufw_shared::policy_types::AppFingerprint) -> bool| {
        app.fingerprints.iter().any(f)
    };
    assert!(has(|f| f.signers.iter().any(|s| s == "Contoso Ltd")));
    assert!(has(|f| f.team_ids.iter().any(|t| t == "ABCDE12345")));
    assert!(has(|f| f.bundle_ids.iter().any(|b| b == "com.contoso.browser")));
    assert!(app.require_valid_signature);
    // `>= trusted` admits trusted and system, nothing weaker.
    assert!(!app.trust.contains(TrustLevel::Known));
    assert!(app.trust.contains(TrustLevel::Trusted));
    assert!(app.trust.contains(TrustLevel::System));
}

#[test]
fn the_compiled_fixture_enforces_what_it_says() {
    // Behavioural spot checks against the reference evaluator, so this test
    // fails if lowering silently changes meaning.
    let policy = compiled(&fixture());
    let profile = &policy.network_profile;

    let signed_browser = {
        let mut id = AppIdentity::unresolved(100, 0);
        id.path = "/usr/lib/contoso-browser/browser".into();
        id.trust = TrustLevel::Trusted;
        id.signature_type = SignatureType::ElfContentHash;
        id.signature_valid = true;
        id
    };
    let dropper = {
        let mut id = AppIdentity::unresolved(200, 0);
        id.path = "/tmp/dropper".into();
        id.trust = TrustLevel::Unknown;
        id.signature_valid = false;
        id
    };

    // Telnet is blocked outright at the packet layer.
    let telnet = FlowContext::new(
        profile,
        Direction::Outbound,
        Protocol::Tcp,
        ("10.0.0.5".parse().unwrap(), 40000),
        ("198.51.100.7".parse().unwrap(), 23),
    )
    .with_identity(&signed_browser);
    assert_eq!(policy.evaluate(&telnet).decision, Decision::Deny);

    // The browser reaches the web.
    let web = FlowContext::new(
        profile,
        Direction::Outbound,
        Protocol::Tcp,
        ("10.0.0.5".parse().unwrap(), 40001),
        ("198.51.100.7".parse().unwrap(), 443),
    )
    .with_identity(&signed_browser);
    assert_eq!(policy.evaluate(&web).decision, Decision::Allow);

    // An unsigned binary does not, even to the same destination.
    let sneaky = FlowContext::new(
        profile,
        Direction::Outbound,
        Protocol::Tcp,
        ("10.0.0.5".parse().unwrap(), 40002),
        ("198.51.100.7".parse().unwrap(), 443),
    )
    .with_identity(&dropper);
    assert_eq!(policy.evaluate(&sneaky).decision, Decision::Deny);

    // DNS is allowed, but only provisionally: a tunnelling signature on the
    // same flow still terminates it, which is the whole point of the
    // allow-inspect action.
    let dns = FlowContext::new(
        profile,
        Direction::Outbound,
        Protocol::Udp,
        ("10.0.0.5".parse().unwrap(), 40003),
        ("1.1.1.1".parse().unwrap(), 53),
    )
    .with_identity(&signed_browser);
    assert_eq!(policy.evaluate(&dns).decision, Decision::Allow);

    let tunnel = dns.clone().with_dpi(DpiScan {
        l7: L7Protocol::Dns,
        hits: vec![ufw_shared::hash::derive_signature_id("dns-tunnel-high-entropy")],
        first_hit_offset: 12,
        truncated: false,
    });
    let verdict = policy.evaluate(&tunnel);
    assert_eq!(verdict.decision, Decision::Deny);
    assert_eq!(
        policy.find(verdict.rule_id).map(|r| r.name.as_str()),
        Some("dns-exfiltration")
    );
}

#[test]
fn every_documented_error_code_is_reachable() {
    // A diagnostic code nobody can trigger is dead documentation.
    let cases: [(&str, &str); 12] = [
        (codes::MISSING_FIELD, "version: 1\nrules:\n  - action: allow\n"),
        (codes::UNSUPPORTED_VERSION, "version: 42\n"),
        (
            codes::UNKNOWN_ENUM,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    protocol: banana\n",
        ),
        (
            codes::BAD_LITERAL,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    priority: soon\n",
        ),
        (
            codes::UNRESOLVED_REFERENCE,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    destination:\n      addresses: [nope]\n",
        ),
        (
            codes::CYCLIC_REFERENCE,
            "version: 1\naddress_groups:\n  a: [b]\n  b: [a]\nrules:\n  - id: r\n    action: allow\n    destination:\n      addresses: [a]\n",
        ),
        (
            codes::EMPTY_SELECTOR,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    dpi:\n      on_match: deny\n",
        ),
        (
            codes::LAYER_MISMATCH,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    layer: packet\n    dpi:\n      protocols: [http]\n",
        ),
        (
            codes::PORTS_ON_PORTLESS_PROTOCOL,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    protocol: icmp\n    destination:\n      ports: [80]\n",
        ),
        (
            codes::BAD_TIME_RANGE,
            "version: 1\nrules:\n  - id: a\n    action: allow\n    schedule:\n      start: \"99:99\"\n      end: \"10:00\"\n",
        ),
        (
            codes::BROAD_ALLOW,
            "version: 1\ndefaults:\n  action: deny\nrules:\n  - id: a\n    action: allow\n",
        ),
        (
            codes::UNUSED_DEFINITION,
            "version: 1\nport_groups:\n  unused: [1]\nrules:\n  - id: a\n    action: deny\n    destination: 1.2.3.4/32\n",
        ),
    ];

    for (code, src) in cases {
        let r = compile(src);
        assert!(
            r.diagnostics.has_code(code),
            "{code} was not produced by:\n{src}\ngot: {:?}",
            r.diagnostics.codes()
        );
    }
}

#[test]
fn rule_ids_are_stable_when_a_policy_grows() {
    let before = compiled(&format!(
        "{BASE}rules:\n  - id: keep\n    action: deny\n    destination: 1.2.3.4/32\n"
    ));
    let after = compiled(&format!(
        "{BASE}rules:\n\
         \x20 - id: inserted\n    priority: 1\n    action: deny\n    destination: 5.6.7.8/32\n\
         \x20 - id: keep\n    action: deny\n    destination: 1.2.3.4/32\n"
    ));
    let id_of = |p: &CompiledPolicy, n: &str| p.rules.iter().find(|r| r.name == n).unwrap().id;
    assert_eq!(id_of(&before, "keep"), id_of(&after, "keep"));
}

#[test]
fn diagnostics_render_with_a_caret_under_the_offending_text() {
    let src = "version: 1\nrules:\n  - id: a\n    action: allowe\n";
    let r = compile(src);
    let text = r.render();
    assert!(text.contains("error[E0202]"));
    assert!(text.contains("did you mean `allow`?"));
    assert!(text.contains("action: allowe"));
    assert!(text.lines().any(|l| l.trim_start().starts_with('^')
        || l.contains("^^^")));
}

#[test]
fn a_default_allow_policy_is_expressible() {
    let policy = compiled(
        "version: 1\ndefaults:\n  action: allow\n\
         rules:\n  - id: block-smb\n    action: deny\n    protocol: tcp\n    destination:\n      ports: [445]\n",
    );
    assert_eq!(policy.default_action, Decision::Allow);
    let ctx = FlowContext::new(
        &policy.network_profile,
        Direction::Outbound,
        Protocol::Tcp,
        ("10.0.0.1".parse().unwrap(), 1),
        ("10.0.0.2".parse().unwrap(), 445),
    );
    assert_eq!(policy.evaluate(&ctx).decision, Decision::Deny);
}

#[test]
fn a_header_only_rule_can_be_pinned_to_the_perimeter_stage() {
    // The perimeter stage is Layer 1 and the evaluation order starts there,
    // but a rule only lands in it if it says so: header-only rules default to
    // `packet`, because a default that put every address rule ahead of every
    // zone rule would leave the perimeter stage with nothing in it.
    //
    // Writing `layer: perimeter` is how a zone-scoped deny is made to run
    // before every address rule, and for a while the compiler rejected it —
    // with a message about `application:` selectors, on a rule that had none.
    let result = compile_str(
        "perimeter",
        "version: 1\ndefaults:\n  action: deny\nrules:\n  \
         - id: no-external-egress\n    layer: perimeter\n    priority: 10\n    \
         action: deny\n    protocol: tcp\n    destination:\n      zone: external\n",
        &CompileOptions::default(),
    );
    assert!(result.is_ok(), "{}", result.render());
    let policy = result.policy.as_ref().expect("compiled");
    assert_eq!(policy.rules[0].layer, ufw_shared::policy_types::Layer::Perimeter);
}

#[test]
fn an_identity_rule_still_cannot_be_pinned_below_the_identity_stage() {
    // The other half of the same check. Identity is not resolved at the
    // perimeter stage, so such a rule could only ever fail to match — which
    // is worse than an error, because it installs and silently never fires.
    for layer in ["perimeter", "packet"] {
        let source = format!(
            "version: 1\napplications:\n  agent:\n    platforms:\n      linux:\n        \
             paths: [/usr/bin/agent]\nrules:\n  - id: a\n    action: allow\n    \
             layer: {layer}\n    application: agent\n"
        );
        let result = compile_str("identity", &source, &CompileOptions::default());
        assert!(
            result.diagnostics.iter().any(|d| d.code == codes::LAYER_MISMATCH),
            "`layer: {layer}` on an identity rule should be refused:\n{}",
            result.render()
        );
    }
}
