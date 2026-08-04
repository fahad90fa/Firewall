//! Scenario: filtering by who sent the traffic, not by which port it used.
//!
//! This is the property the system exists for, and the one most easily broken
//! by a change that looks like an improvement. Two invariants matter more than
//! the rest:
//!
//!   1. **An absent identity matches nothing**, including a negated predicate.
//!      "Deny anything that is not our signed binary" must not be satisfied by
//!      a process the resolver could not inspect — that is precisely the set an
//!      attacker can arrange to be in.
//!   2. **Fingerprints are a disjunction across platforms, a conjunction
//!      within one.** One logical application is a Windows signer, a Linux path
//!      and a macOS Team ID at once; a Linux binary must not be required to
//!      carry an Authenticode signature to match.
//!
//! Both were real bugs during development. Both are invisible in review.

use ufw_e2e::connection_tracker::{assert_decided_by, assert_default, assert_denied};
use ufw_e2e::packet_generator::{identities, Flow};
use ufw_e2e::policy;
use ufw_shared::identity_types::TrustLevel;

const IDENTITY_POLICY: &str = "\
version: 1
defaults:
  action: deny
port_groups:
  web: [80, 443]
applications:
  browser:
    trust: [\">= trusted\"]
    require_valid_signature: true
    platforms:
      windows:
        path: \"C:\\\\Program Files\\\\Contoso Browser\\\\browser.exe\"
        signer: \"Contoso Ltd\"
      linux:
        paths: [/usr/lib/contoso-browser/browser, /opt/contoso/browser]
      macos:
        bundle_id: com.contoso.browser
        team_id: ABCDE12345
rules:
  - id: browser-web
    priority: 100
    direction: outbound
    action: allow
    protocol: tcp
    application: browser
    destination:
      ports: web
  - id: deny-unsigned-web
    priority: 900
    direction: outbound
    action: deny
    protocol: tcp
    application:
      trust: [untrusted, unknown]
    destination:
      ports: web
";

#[test]
fn a_signed_binary_matching_its_fingerprint_is_permitted() {
    let p = policy(IDENTITY_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "/usr/lib/contoso-browser/browser",
        "Contoso Ltd",
        TrustLevel::Trusted,
    ));
    assert_decided_by(&p, &flow, "browser-web", "the deployed browser reaching the web");
}

#[test]
fn one_application_can_be_described_for_three_platforms_at_once() {
    // The disjunction. A Linux binary satisfies the Linux fingerprint without
    // carrying the Windows signer, and a macOS bundle satisfies the macOS
    // fingerprint without a path match. Flattening the three into one
    // conjunctive fingerprint made the application unmatchable everywhere but
    // Windows, and every rule still looked correct.
    let p = policy(IDENTITY_POLICY);

    let linux = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "/opt/contoso/browser", "irrelevant-on-linux", TrustLevel::Trusted));
    assert_decided_by(&p, &linux, "browser-web", "the Linux build, identified by path");

    let macos = Flow::tcp("93.184.216.34", 443).with_identity(identities::team(
        "/Applications/Contoso Browser.app/Contents/MacOS/browser",
        "ABCDE12345", "com.contoso.browser", TrustLevel::Trusted));
    assert_decided_by(&p, &macos, "browser-web", "the macOS build, identified by Team ID");

    let windows = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "C:\\Program Files\\Contoso Browser\\browser.exe", "Contoso Ltd",
        TrustLevel::Trusted));
    assert_decided_by(&p, &windows, "browser-web", "the Windows build, identified by signer");
}

#[test]
fn the_same_path_from_a_different_signer_does_not_match() {
    // Within a platform the fingerprint is conjunctive. A binary written to
    // the browser's path but signed by someone else is not the browser — which
    // is the entire reason the rule names a signer as well as a path.
    let p = policy(IDENTITY_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "C:\\Program Files\\Contoso Browser\\browser.exe", "Someone Else",
        TrustLevel::Trusted));
    // Falls through the allow to the unsigned-deny? No: it is `trusted`, so it
    // matches neither. It reaches the policy default, which is deny.
    assert_default(&p, &flow, "a trusted binary at the browser's path, signed by someone else");
}

#[test]
fn an_unresolved_identity_matches_nothing() {
    // The fail-closed asymmetry, stated as a test.
    let p = policy(IDENTITY_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443).unidentified();

    // It does not match `browser-web`, which is the obvious half.
    let outcome = ufw_e2e::connection_tracker::evaluate(
        &p, &flow, "an unresolved process reaching the web");
    assert_ne!(outcome.rule_name.as_deref(), Some("browser-web"),
               "an unresolved process must not satisfy an application rule");

    // And it does not match `deny-unsigned-web` either, which is the half that
    // matters: that rule's predicate is `trust: [untrusted, unknown]`, and an
    // absent identity has no trust level at all. It is not "unknown trust" —
    // it is "no answer", and a rule written about trust levels must not fire on
    // the absence of one.
    assert_ne!(outcome.rule_name.as_deref(), Some("deny-unsigned-web"),
               "an absent identity is not the same as a known-untrusted one");

    // The flow is still denied — by the policy default, which is where an
    // undecidable flow belongs.
    assert_default(&p, &flow, "an unresolved process falls through to the default");
}

#[test]
fn an_unsigned_binary_is_denied_by_the_rule_written_for_it() {
    // The distinction the previous test draws only matters if the rule *does*
    // fire when identity is present and says "unsigned". This is that check.
    let p = policy(IDENTITY_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443)
        .with_identity(identities::unsigned("/tmp/downloaded-thing"));
    assert_decided_by(&p, &flow, "deny-unsigned-web",
                      "an unsigned binary reaching the web");
}

#[test]
fn a_tampered_signature_is_worse_than_no_signature() {
    // `Untrusted` is not a synonym for `Unknown`. A binary that carries a
    // signature which does not verify was signed and then modified; a binary
    // with no signature was simply never signed. Collapsing the two loses the
    // only evidence that something was altered.
    let p = policy(IDENTITY_POLICY);
    let flow = Flow::tcp("93.184.216.34", 443)
        .with_identity(identities::tampered("/usr/lib/contoso-browser/browser", "Contoso Ltd"));

    // It is at the browser's exact path with the right signer string, and it
    // still does not match `browser-web`, because the rule requires the
    // signature to *validate*.
    assert_decided_by(&p, &flow, "deny-unsigned-web",
                      "a modified copy of the browser at the browser's path");
}

#[test]
fn a_trust_bound_admits_everything_at_or_above_it() {
    let p = policy("\
version: 1
defaults:
  action: deny
rules:
  - id: allow-known-or-better
    priority: 100
    direction: outbound
    action: allow
    protocol: tcp
    application:
      trust: [\">= known\"]
    destination:
      ports: [443]
");
    for (trust, label) in [
        (TrustLevel::Known, "known"),
        (TrustLevel::Trusted, "trusted"),
        (TrustLevel::System, "system"),
    ] {
        let flow = Flow::tcp("93.184.216.34", 443)
            .with_identity(identities::signed("/usr/bin/thing", "Someone", trust));
        assert_decided_by(&p, &flow, "allow-known-or-better",
                          &format!("a `{label}` binary against `>= known`"));
    }

    for (identity, label) in [
        (identities::unsigned("/tmp/thing"), "unsigned"),
        (identities::tampered("/tmp/thing", "Someone"), "tampered"),
    ] {
        let flow = Flow::tcp("93.184.216.34", 443).with_identity(identity);
        assert_denied(&p, &flow, &format!("a `{label}` binary against `>= known`"));
    }
}

#[test]
fn identity_rules_do_not_apply_to_protocols_that_carry_no_process() {
    // ICMP has no socket, so no platform can attribute it to a process. A
    // policy that tried would be expressing something two of the three
    // platforms cannot enforce — so the compiler rejects it outright, and the
    // reference evaluator gates on the protocol as a second line of defence.
    //
    // This is asserted through the compiler rather than through a verdict,
    // because the error is the behaviour worth having.
    let result = ufw_policy_lang::compile_str(
        "icmp-identity",
        "\
version: 1
defaults:
  action: deny
rules:
  - id: icmp-from-browser
    priority: 100
    action: allow
    protocol: icmp
    application:
      trust: [trusted]
",
        &ufw_policy_lang::CompileOptions::default(),
    );
    assert!(!result.is_ok(),
            "an identity predicate on ICMP should not compile:\n{}", result.render());
    assert!(result.render().contains("icmp"),
            "the diagnostic should name the protocol:\n{}", result.render());
}
