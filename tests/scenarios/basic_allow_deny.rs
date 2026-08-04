//! Scenario: the decisions a policy most obviously promises.
//!
//! Every other scenario builds on this one being true. If a plain
//! "allow UDP/53 to these resolvers" rule does not permit UDP/53 to those
//! resolvers, nothing further up is worth investigating.
//!
//! The cases here are chosen to be hand-verifiable against the fixture in
//! `harness/mod.rs`. A failure should send the reader to the rule, not to a
//! debugger.

use ufw_e2e::connection_tracker::{
    assert_allowed, assert_decided_by, assert_default, assert_denied,
};
use ufw_e2e::packet_generator::Flow;
use ufw_e2e::{policy, BASELINE};

#[test]
fn a_named_destination_and_port_is_permitted() {
    let p = policy(BASELINE);
    assert_decided_by(
        &p,
        &Flow::udp("1.1.1.1", 53),
        "allow-dns",
        "DNS to a resolver the policy names",
    );
    assert_decided_by(
        &p,
        &Flow::tcp("10.1.2.3", 443),
        "allow-internal-web",
        "HTTPS to the internal range",
    );
}

#[test]
fn anything_the_policy_did_not_name_is_denied() {
    let p = policy(BASELINE);
    // The default-deny promise, which is the whole reason to write a
    // default-deny policy.
    assert_default(
        &p,
        &Flow::udp("9.9.9.9", 53),
        "DNS to a resolver outside the group",
    );
    assert_default(
        &p,
        &Flow::tcp("93.184.216.34", 443),
        "HTTPS to an external address",
    );
    assert_default(
        &p,
        &Flow::tcp("10.1.2.3", 8080),
        "an internal address on a port no rule names",
    );
}

#[test]
fn an_explicit_deny_beats_a_later_allow() {
    let p = policy(BASELINE);
    // `block-telnet` is priority 20, `allow-internal-web` is 200, and both are
    // at the packet stage — so the deny is evaluated first and wins even for a
    // destination the allow would have covered.
    assert_decided_by(
        &p,
        &Flow::tcp("10.1.2.3", 23),
        "block-telnet",
        "telnet to an internal address the web rule also covers",
    );
}

#[test]
fn direction_is_part_of_the_match() {
    let p = policy(BASELINE);
    // `allow-dns` and `allow-internal-web` are both `direction: outbound`. An
    // inbound flow with the same five-tuple must not match them — a rule that
    // permitted a service in both directions because the author only thought
    // about one is how a workstation ends up with a listener.
    assert_allowed(&p, &Flow::udp("1.1.1.1", 53), "outbound DNS");
    assert_default(
        &p,
        &Flow::udp("1.1.1.1", 53).inbound(),
        "the same tuple arriving inbound",
    );

    assert_allowed(&p, &Flow::tcp("10.1.2.3", 443), "outbound HTTPS");
    assert_default(
        &p,
        &Flow::tcp("10.1.2.3", 443).inbound(),
        "an inbound connection to the same address and port",
    );
}

#[test]
fn a_portless_protocol_is_matched_without_ports() {
    let p = policy(BASELINE);
    // `allow-icmp` names a protocol and nothing else. ICMP has no ports, so a
    // port-constrained rule must not match it — which is what keeps
    // `block-telnet` (tcp/23) from applying here.
    assert_decided_by(
        &p,
        &Flow::icmp("8.8.8.8"),
        "allow-icmp",
        "an ICMP echo to an external address",
    );
    assert_decided_by(
        &p,
        &Flow::icmp("10.1.2.3"),
        "allow-icmp",
        "an ICMP echo to an internal address",
    );
}

#[test]
fn the_verdict_does_not_depend_on_facts_the_rules_never_mention() {
    let p = policy(BASELINE);
    // None of the baseline rules carries an identity predicate, so supplying
    // one — or not — must not change any verdict. This is worth asserting
    // because the fail-closed asymmetry lives on the same code path: a change
    // that made a missing identity fail *every* rule rather than only
    // identity rules would break exactly this, and would look like a hardening
    // improvement in review.
    use ufw_e2e::packet_generator::identities;
    use ufw_shared::identity_types::TrustLevel;

    let with = Flow::udp("1.1.1.1", 53).with_identity(identities::unsigned("/usr/bin/curl"));
    let without = Flow::udp("1.1.1.1", 53).unidentified();

    assert_decided_by(&p, &with, "allow-dns", "DNS from an unsigned binary");
    assert_decided_by(&p, &without, "allow-dns", "DNS from an unresolved process");

    let trusted = Flow::tcp("10.1.2.3", 23).with_identity(identities::signed(
        "/usr/bin/telnet",
        "Contoso Ltd",
        TrustLevel::Trusted,
    ));
    assert_denied(
        &p,
        &trusted,
        "telnet is denied regardless of how well-signed the client is",
    );
}

#[test]
fn source_constraints_narrow_a_rule_rather_than_widening_it() {
    let p = policy(
        "\
version: 1
defaults:
  action: deny
rules:
  - id: allow-from-management
    priority: 100
    layer: packet
    direction: inbound
    action: allow
    protocol: tcp
    source:
      addresses: [10.99.0.0/24]
    destination:
      ports: [22]
",
    );
    assert_decided_by(
        &p,
        &Flow::tcp("10.0.0.5", 22).inbound().from("10.99.0.7", 40000),
        "allow-from-management",
        "SSH from the management range",
    );
    assert_default(
        &p,
        &Flow::tcp("10.0.0.5", 22).inbound().from("10.50.0.7", 40000),
        "SSH from anywhere else",
    );
}
