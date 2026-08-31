//! Scenario: the emitted Linux artifact enforces the policy against real
//! packets — not just against the reference model.
//!
//! See `harness/enforcement.rs` for the two levels (loadability and real-packet
//! enforcement) and why a model test could not stand in for this one. The cases
//! below are chosen so that each asserts a property a *packet* reveals:
//!
//!   1. A named allow lets a connection through; an unnamed port is dropped by
//!      the default-deny. The floor every policy stands on.
//!   2. `allow-inspect` does not, by itself, permit the flow on the nft path.
//!      This is the regression test for the bypass that a model check missed:
//!      the emitter must lower a provisional permit to a comment (fail-closed),
//!      never to a terminal `accept`. If someone reintroduces the terminal
//!      accept, the probe connects and this test goes red.
//!   3. The emitted ruleset for a broad, mixed-family policy loads clean into
//!      the kernel's own parser.

use ufw_e2e::enforcement::{emit_linux_nft, netns_enforces, nft_check, resolve, Outcome, Probe};

/// Default-deny, with a bidirectional packet-layer allow for one port. Both
/// directions are named because a loopback handshake traverses the input and
/// output hooks for both the forward and the return packets, so a stateless
/// ruleset must accept `dport P` and `sport P` to let the connection complete.
const ALLOW_DENY: &str = "\
version: 1
metadata:
  name: conformance-allow-deny
defaults:
  action: deny
rules:
  - id: allow-probe-forward
    priority: 100
    layer: packet
    action: allow
    protocol: tcp
    destination:
      ports: [19443]
  - id: allow-probe-return
    priority: 101
    layer: packet
    action: allow
    protocol: tcp
    source:
      ports: [19443]
";

/// The `allow-inspect` regression fixture.
///
/// `probe-return` unconditionally permits the return path (source port 19500),
/// so the *only* thing standing between the forward SYN and a completed
/// handshake is how `inspect-allow` lowers. With the fix it lowers to a comment
/// — the forward SYN hits the default-deny and the connection fails. With the
/// old bug it lowered to `tcp dport 19500 accept` — the SYN is admitted, the
/// return path is already open, and the handshake completes. So a connection
/// that *fails* is the proof the bypass is closed.
const ALLOW_INSPECT_REGRESSION: &str = "\
version: 1
metadata:
  name: conformance-allow-inspect
defaults:
  action: deny
rules:
  - id: probe-return
    priority: 50
    layer: packet
    action: allow
    protocol: tcp
    source:
      ports: [19500]
  - id: inspect-allow
    priority: 100
    layer: packet
    action: allow-inspect
    protocol: tcp
    destination:
      ports: [19500]
";

/// A broad policy mixing IPv4 and IPv6 address groups, ICMP/ICMPv6, port
/// groups and both directions — the shape most likely to emit an expression the
/// running kernel does not support. Level 1 only; it is about loadability.
const WIDE: &str = "\
version: 1
metadata:
  name: conformance-wide
defaults:
  action: deny
  log: true
address_groups:
  v4: [10.0.0.0/8, 192.168.0.0/16]
  v6: [2001:db8::/32, fd00::/8]
  mixed: [10.0.0.0/8, 2001:db8::/32]
port_groups:
  web: [80, 443]
rules:
  - id: icmp
    priority: 10
    layer: packet
    action: allow
    protocol: icmp
  - id: icmp6
    priority: 11
    layer: packet
    action: allow
    protocol: icmpv6
  - id: web-v4
    priority: 100
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [v4]
      ports: web
  - id: web-v6
    priority: 101
    layer: packet
    direction: outbound
    action: allow
    protocol: tcp
    destination:
      addresses: [v6]
      ports: web
  - id: dns-mixed
    priority: 120
    layer: packet
    direction: outbound
    action: allow
    protocol: udp
    destination:
      addresses: [mixed]
      ports: [53]
";

#[test]
fn a_named_allow_passes_and_an_unnamed_port_is_dropped() {
    let nft = emit_linux_nft(ALLOW_DENY);
    // Level 1: it must load at all.
    resolve(nft_check(&nft), "UFW_NFT_REQUIRE");
    // Level 2: 19443 is allowed both ways; 19444 is named by no rule.
    resolve(
        netns_enforces(&nft, &[Probe::allow(19443), Probe::deny(19444)]),
        "UFW_NETNS_REQUIRE",
    );
}

#[test]
fn allow_inspect_does_not_permit_on_the_nft_path() {
    let nft = emit_linux_nft(ALLOW_INSPECT_REGRESSION);
    // The emitted text must not contain a terminal accept for the inspected
    // destination port — that is the bug, catchable without a kernel. The
    // emitter writes port sets in braces (`dport { 19500 }`); `sport { 19500 }
    // accept` (the expected return path) must not trip this.
    assert!(
        !nft.contains("dport { 19500 } accept"),
        "allow-inspect lowered to a terminal accept — the bypass is back:\n{nft}"
    );
    resolve(nft_check(&nft), "UFW_NFT_REQUIRE");
    // And the packet proof: with the return path open, the connection still
    // fails, because the forward SYN is not admitted by the nft path.
    resolve(
        netns_enforces(&nft, &[Probe::deny(19500)]),
        "UFW_NETNS_REQUIRE",
    );
}

#[test]
fn a_wide_mixed_family_policy_loads_into_the_kernel_parser() {
    let nft = emit_linux_nft(WIDE);
    match nft_check(&nft) {
        Outcome::Ran => {}
        other => resolve(other, "UFW_NFT_REQUIRE"),
    }
}

#[test]
fn the_emergency_fail_closed_barrier_loads_into_the_kernel() {
    // The barrier the daemon installs when enforcement is unavailable and
    // fail_mode = closed. It uses conntrack state and a negative hook priority,
    // both of which the running kernel must actually support — a string test
    // cannot confirm that, `nft --check` against the live kernel can.
    let barrier = ufw_daemon::failsafe::fail_closed_ruleset(&[9443]);
    resolve(nft_check(&barrier), "UFW_NFT_REQUIRE");
}

#[test]
fn the_edge_flood_hardening_layer_loads_into_the_kernel() {
    // The opt-in flood layer the daemon installs when edge.flood_protection is
    // set. It leans on kernel features a string test cannot confirm: a negative
    // hook priority (-150), `ct state` matching, per-source `ct count` meters,
    // TCP-flag masks and ICMP/ICMPv6 echo matching. `nft --check` against the
    // live kernel is what proves the ruleset the daemon would feed to `nft -f -`
    // is actually loadable, not merely well-formed text.
    let ruleset =
        ufw_daemon::edge_hardening::flood_hardening_ruleset(&ufw_daemon::edge_hardening::FloodOpts::default());
    resolve(nft_check(&ruleset), "UFW_NFT_REQUIRE");
}

/// Not an assertion — a diagnostic. Run with `--ignored --nocapture` to see the
/// exact ruleset the compiler emits for the probe fixtures, which is the first
/// thing to look at when a conformance case fails.
#[test]
#[ignore]
fn dump_emitted_rulesets() {
    eprintln!("=== ALLOW_DENY ===\n{}", emit_linux_nft(ALLOW_DENY));
    eprintln!(
        "=== ALLOW_INSPECT_REGRESSION ===\n{}",
        emit_linux_nft(ALLOW_INSPECT_REGRESSION)
    );
    eprintln!("=== WIDE ===\n{}", emit_linux_nft(WIDE));
}
