//! Scenario: IPv6 is a first-class enforcement target, at parity with IPv4.
//!
//! A firewall that filters IPv4 well and treats IPv6 as an afterthought is a
//! firewall an attacker reaches over IPv6. Parity has to be shown, not assumed,
//! and it has three parts, each checked here:
//!
//!   1. **The reference model decides IPv6 flows the way it decides IPv4 flows.**
//!      A rule that names a v6 destination permits the v6 flow; an unnamed v6
//!      port is denied; and — the part that is easy to get wrong — a v4 rule
//!      does not match a v6 flow that happens to share a port, nor the reverse.
//!      Families do not leak into each other's decisions.
//!
//!   2. **The emitted nftables keeps the families separate.** Each family's
//!      addresses appear only under that family's match (`ip daddr` /
//!      `ip6 daddr`), never one rule carrying both — the exact defect an earlier
//!      fix closed, pinned here so it cannot regress.
//!
//!   3. **The kernel accepts the IPv6 ruleset.** `nft --check` runs the running
//!      kernel's own parser over the emitted v6 rules, so a v6 expression the
//!      kernel does not support fails here, not in production. (Real v6 packet
//!      enforcement is environment-gated: many CI/container kernels ship without
//!      IPv6, so this level is loadability, and the model check above carries
//!      the verdict parity.)

use ufw_e2e::connection_tracker::{assert_decided_by, assert_default};
use ufw_e2e::enforcement::{emit_linux_nft, nft_check, resolve};
use ufw_e2e::packet_generator::Flow;
use ufw_e2e::policy;

/// Parallel v4 and v6 allow rules of identical shape, so any asymmetry in how
/// the two families are handled shows up as a decision that differs between
/// otherwise-identical flows.
const PARITY: &str = "\
version: 1
metadata:
  name: ipv6-parity
defaults:
  action: deny
address_groups:
  v4web: [203.0.113.0/24]
  v6web: [2001:db8:1::/48]
port_groups:
  web: [443]
rules:
  - id: allow-v4-web
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [v4web]
      ports: web
  - id: allow-v6-web
    priority: 101
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [v6web]
      ports: web
";

#[test]
fn the_model_permits_and_denies_ipv6_the_same_way_it_does_ipv4() {
    let p = policy(PARITY);
    // The named destination is permitted in each family, by its own rule.
    assert_decided_by(
        &p,
        &Flow::tcp("203.0.113.5", 443),
        "allow-v4-web",
        "the v4 web destination",
    );
    assert_decided_by(
        &p,
        &Flow::tcp("2001:db8:1::5", 443),
        "allow-v6-web",
        "the v6 web destination — parity with v4",
    );
    // An unnamed port is denied in each family.
    assert_default(
        &p,
        &Flow::tcp("2001:db8:1::5", 8080),
        "a v6 destination on a port no rule names",
    );
}

#[test]
fn a_v4_rule_does_not_match_a_v6_flow_or_the_reverse() {
    let p = policy(PARITY);
    // The v6 flow must not be admitted by the v4 rule (its address is not in the
    // v4 group), and vice versa. If the model compared addresses without
    // checking the family, one of these would be wrongly decided by the other
    // family's rule.
    assert_default(
        &p,
        &Flow::tcp("2001:db8:9::9", 443),
        "a v6 address outside the v6 group is not caught by the v4 rule",
    );
    assert_default(
        &p,
        &Flow::tcp("198.51.100.9", 443),
        "a v4 address outside the v4 group is not caught by the v6 rule",
    );
}

#[test]
fn the_emitted_ruleset_keeps_the_two_families_apart() {
    let nft = emit_linux_nft(PARITY);
    assert!(
        nft.contains("ip daddr { 203.0.113.0/24 }"),
        "the v4 rule must lower to an `ip daddr` match:\n{nft}"
    );
    assert!(
        nft.contains("ip6 daddr { 2001:db8:1::/48 }"),
        "the v6 rule must lower to an `ip6 daddr` match:\n{nft}"
    );
    // No single emitted rule may carry both families — that was the family-
    // mixing bug, and an `ip daddr ... ip6 daddr ...` line is nonsense nft would
    // reject anyway.
    for line in nft.lines() {
        assert!(
            !(line.contains("ip daddr") && line.contains("ip6 daddr")),
            "a rule mixes v4 and v6 address matches: {line}"
        );
    }
    // And the kernel's own parser accepts it.
    resolve(nft_check(&nft), "UFW_NFT_REQUIRE");
}

/// A group whose members span both families must emit one line per family, each
/// carrying only its own addresses — the fix for the original mixing bug.
#[test]
fn a_mixed_family_group_splits_into_one_line_per_family() {
    const MIXED: &str = "\
version: 1
metadata:
  name: ipv6-mixed-group
defaults:
  action: deny
address_groups:
  both: [10.0.0.0/8, 2001:db8::/32]
rules:
  - id: allow-both
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [both]
      ports: [443]
";
    let nft = emit_linux_nft(MIXED);
    let v4 = nft
        .lines()
        .filter(|l| l.contains("ip daddr") && !l.contains("ip6 daddr"))
        .count();
    let v6 = nft.lines().filter(|l| l.contains("ip6 daddr")).count();
    assert!(v4 >= 1, "the mixed group must emit a v4 line:\n{nft}");
    assert!(v6 >= 1, "the mixed group must emit a v6 line:\n{nft}");
    // The v4 line carries the v4 member and not the v6 one, and vice versa.
    for line in nft.lines() {
        if line.contains("ip daddr") && !line.contains("ip6 daddr") {
            assert!(line.contains("10.0.0.0/8") && !line.contains("2001:db8::/32"));
        }
        if line.contains("ip6 daddr") {
            assert!(line.contains("2001:db8::/32") && !line.contains("10.0.0.0/8"));
        }
    }
    resolve(nft_check(&nft), "UFW_NFT_REQUIRE");
}
