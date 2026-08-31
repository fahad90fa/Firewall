//! Scenario: every advertised layer actually runs.
//!
//! The website names nine capabilities; the danger with a layered product is
//! not that one layer is subtly wrong — the per-layer scenario tests cover that
//! — but that a whole layer quietly becomes a no-op (a detector unwired from the
//! pipeline, an engine that constructs but never matches) and every *other* test
//! still passes because it never asked that layer to do anything. This file is
//! the one place that asks each layer to produce a concrete effect, so ripping
//! one out turns a single, clearly-named test red.
//!
//! It exercises the layers reachable from a library test: policy enforcement
//! (the reference model), identity, the DPI/IPS signature engine, the inbound
//! WAF, all five egress detectors, and signed fleet rollout with auto-rollback.
//! Three advertised layers live in the `ufw-nft` binary rather than a library —
//! the honeypot decoys, the RBAC/mTLS console, and one-click contain — and are
//! exercised by that crate's own tests (`dashboard::router_tests`, `rbac`,
//! `honeypot`), including the new HTTP-head fuzzing; they are named here so the
//! map from "advertised" to "tested" is complete, not to be re-tested from a
//! crate that cannot import a binary.

use std::sync::Arc;

use ufw_e2e::connection_tracker::{assert_decided_by, assert_default};
use ufw_e2e::packet_generator::{identities, Flow};
use ufw_e2e::{policy, BASELINE};

use ufw_shared::log_types::{FiveTuple, IdentitySummary, LogEvent};
use ufw_shared::policy_types::{Decision, Direction, Protocol, Zone};
use ufw_shared::Platform;

use ufw_daemon::fleet::{
    in_canary, Bundle, BundleError, Health, HealthWindow, RolloutMonitor, Verifier,
};
use ufw_daemon::logging::anomaly::EgressBaseline;
use ufw_daemon::logging::beacon::BeaconDetector;
use ufw_daemon::logging::bruteforce::BruteForceDetector;
use ufw_daemon::logging::dns_exfil::DnsExfilDetector;
use ufw_daemon::logging::portscan::PortScanDetector;
use ufw_daemon::signatures;
use ufw_daemon::waf::WafEngine;

const SEC: u64 = 1_000_000;

// ---------------------------------------------------------------------------
// KERNEL / EQUIVALENCE — one policy compiles to three enforcers, proven equal.
// ---------------------------------------------------------------------------

#[test]
fn layer_equivalence_one_policy_three_verified_kernels() {
    let c = ufw_policy_lang::compile_str("layers", BASELINE, &Default::default());
    assert!(
        c.is_ok(),
        "the baseline policy must compile:\n{}",
        c.render()
    );
    assert_eq!(
        c.artifacts.len(),
        Platform::ALL.len(),
        "one policy must emit an artifact per platform"
    );
    for p in Platform::ALL {
        let a = c
            .artifact(p)
            .unwrap_or_else(|| panic!("no artifact for {p:?}"));
        assert!(!a.model.rules.is_empty(), "{p:?} emitted no decision model");
    }
    // The equivalence verifier ran and did not find a divergence.
    let eq = c.equivalence.as_ref().expect("an equivalence report");
    assert!(
        eq.is_equivalent(),
        "the three backends disagreed for the baseline policy"
    );
    assert!(
        eq.scenarios_checked > 0,
        "the equivalence check ran zero scenarios — it did not actually verify"
    );
}

// ---------------------------------------------------------------------------
// PACKET — the reference model makes the decisions the policy promises.
// ---------------------------------------------------------------------------

#[test]
fn layer_packet_enforcement_decides() {
    let p = policy(BASELINE);
    assert_decided_by(
        &p,
        &Flow::udp("1.1.1.1", 53),
        "allow-dns",
        "a named resolver is permitted",
    );
    assert_default(
        &p,
        &Flow::tcp("93.184.216.34", 25),
        "a port no rule names falls to the default deny",
    );
}

// ---------------------------------------------------------------------------
// IDENTITY — the decision depends on *who*, not just where.
// ---------------------------------------------------------------------------

const IDENTITY_POLICY: &str = "\
version: 1
metadata:
  name: layers-identity
defaults:
  action: deny
rules:
  - id: allow-signed-updater
    priority: 100
    layer: identity
    action: allow
    protocol: tcp
    destination:
      ports: [443]
    application:
      signer: ACME Corp
";

#[test]
fn layer_identity_filters_by_who_not_where() {
    let p = policy(IDENTITY_POLICY);
    let signed = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "/usr/bin/updater",
        "ACME Corp",
        ufw_shared::identity_types::TrustLevel::Trusted,
    ));
    assert_decided_by(
        &p,
        &signed,
        "allow-signed-updater",
        "the correctly-signed binary is permitted",
    );
    // The same destination and port, a different signer: the identity rule must
    // not fire, and default-deny takes it. If identity were a no-op, both would
    // be allowed and this would fail.
    let impostor = Flow::tcp("93.184.216.34", 443).with_identity(identities::signed(
        "/usr/bin/updater",
        "Someone Else",
        ufw_shared::identity_types::TrustLevel::Trusted,
    ));
    assert_default(
        &p,
        &impostor,
        "a binary signed by a different party is not the named application",
    );
}

// ---------------------------------------------------------------------------
// IPS — the shipped signature set compiles, and the inbound WAF matches on it.
// ---------------------------------------------------------------------------

fn shipped_signatures() -> signatures::SignatureSet {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .join("sig-rules");
    let (set, errors) = signatures::load_dir(&root);
    assert!(
        errors.is_empty(),
        "the shipped signatures must load: {errors:#?}"
    );
    set
}

#[test]
fn layer_ips_signatures_compile_to_an_automaton() {
    let set = shipped_signatures();
    assert!(!set.is_empty(), "the shipped signature set is empty");
    assert!(
        set.automaton().is_some(),
        "the signature set produced no content automaton — the DPI fast path is a no-op"
    );
}

#[test]
fn layer_ips_waf_blocks_a_known_exploit_shape() {
    let engine = WafEngine::new(Arc::new(shipped_signatures()));
    let clean = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8\r\n\r\n";
    assert!(
        engine.inspect(clean).is_none(),
        "a benign GET must not be flagged (the WAF would be crying wolf, not running)"
    );
    let sqli = b"GET /items?id=1' or 1=1-- HTTP/1.1\r\nHost: shop.example\r\n\r\n";
    assert!(
        engine.inspect(sqli).is_some(),
        "a SQLi tautology must trip the inbound WAF"
    );
}

// ---------------------------------------------------------------------------
// EGRESS — every advertised detector fires on its own attack shape.
//
// Each helper mirrors the detector's own unit test, so a detector that stops
// firing fails here for the same reason it would there — but all in one place,
// so "one detector was unwired" is a single obvious red.
// ---------------------------------------------------------------------------

fn flow_event(app: Option<&str>, src: &str, dst: &str, port: u16, at_secs: u64) -> LogEvent {
    let mut e = LogEvent::new(
        at_secs * SEC,
        "host",
        Decision::Allow,
        42,
        FiveTuple {
            protocol: Protocol::Tcp,
            src_ip: src.parse().unwrap(),
            src_port: 40000,
            dst_ip: dst.parse().unwrap(),
            dst_port: port,
        },
    );
    e.direction = Direction::Outbound;
    e.remote_zone = Zone::External;
    e.perimeter_crossing = true;
    if let Some(path) = app {
        e.identity = Some(IdentitySummary {
            pid: 1,
            path: path.into(),
            sha256_hex: None,
            signer: None,
            trust: None,
        });
    }
    e
}

#[test]
fn layer_egress_portscan_fires() {
    // A detector fires once as its threshold is crossed and then throttles, so
    // the alert can land on any iteration — track whether *any* did, not the
    // last one's return.
    let mut d = PortScanDetector::new(Default::default());
    let mut fired = false;
    for port in 1..=40u16 {
        fired |= d
            .observe(&flow_event(None, "203.0.113.9", "10.0.0.1", port, 10))
            .is_some();
    }
    assert!(fired, "a 40-port sweep must raise a scan alert");
}

#[test]
fn layer_egress_bruteforce_fires() {
    let mut d = BruteForceDetector::new(Default::default());
    let mut fired = false;
    for i in 0..25u64 {
        // Milliseconds in the source recipe; scaled to microseconds here.
        fired |= d
            .observe(&flow_event(None, "198.51.100.7", "10.0.0.1", 22, i))
            .is_some();
    }
    assert!(
        fired,
        "25 SSH connections in the window must raise a brute-force alert"
    );
}

#[test]
fn layer_egress_beacon_fires() {
    let mut d = BeaconDetector::new(Default::default());
    let mut fired = false;
    for i in 0..12u64 {
        // A dead-steady 60s cadence — the signature of C2.
        fired |= d
            .observe(&flow_event(
                Some("/opt/implant"),
                "10.0.0.1",
                "203.0.113.5",
                443,
                i * 60,
            ))
            .is_some();
    }
    assert!(fired, "a metronomic callback must be flagged as a beacon");
}

#[test]
fn layer_egress_dns_exfil_fires() {
    let mut d = DnsExfilDetector::new(Default::default());
    // A single long high-entropy label is an encoded blob — fires immediately.
    let blob = "k7fj39dk2mfhqp48zmv0aql3xr9bd7tn2wcs6hg1ye5u.example.com";
    let fired = d.observe_query("10.0.0.5".parse().unwrap(), blob, 10 * SEC);
    assert!(
        fired.is_some(),
        "a high-entropy encoded label must raise a DNS-exfil alert"
    );
}

#[test]
fn layer_egress_anomaly_fires() {
    use ufw_daemon::logging::anomaly::AnomalyConfig;
    // A short learning window and small baseline so the test reaches
    // "established" without simulating an hour of traffic — the same shape the
    // detector's own unit test uses.
    let mut e = EgressBaseline::new(AnomalyConfig {
        learning_secs: 100,
        min_baseline: 3,
        realert_interval_secs: 0,
        ..Default::default()
    });
    // Establish a baseline of distinct known destinations during warm-up. The
    // third octet varies so each is a distinct destination key (addresses in one
    // /24 collapse together, by design — a CDN is not five destinations).
    for i in 0..5u32 {
        let dst = format!("198.51.{i}.10");
        let _ = e.observe(&flow_event(
            Some("/opt/app"),
            "10.0.0.1",
            &dst,
            443,
            10 + i as u64,
        ));
    }
    // ...then a never-before-seen destination for the same app, after warm-up.
    let novel = e.observe(&flow_event(
        Some("/opt/app"),
        "10.0.0.1",
        "203.0.113.9",
        443,
        200,
    ));
    assert!(
        novel.is_some(),
        "a signed app reaching a brand-new destination after its baseline must alert"
    );
}

// ---------------------------------------------------------------------------
// FLEET — a bundle arrives signed or not at all, and a regression rolls back.
// ---------------------------------------------------------------------------

fn bundle(revision: u64, source: &str) -> Bundle {
    Bundle {
        revision,
        source: source.into(),
        canary_percent: 10,
        canary_seconds: 300,
        mac: [0u8; 32],
        sig_ed25519: Vec::new(),
    }
}

#[test]
fn layer_fleet_signing_authenticates_the_bundle() {
    let v = Verifier::new(b"fleet-secret".to_vec());
    let mut b = bundle(2, "version: 1\nrules: []\n");
    v.sign(&mut b);
    assert_eq!(
        v.accept(&b, 1),
        Ok(()),
        "a correctly-signed bundle is accepted"
    );

    // One byte of tampering must be caught.
    let mut tampered = b.clone();
    tampered.source.push(' ');
    assert_eq!(
        v.accept(&tampered, 1),
        Err(BundleError::NotAuthentic),
        "a modified bundle must be rejected"
    );

    // A bundle signed with a different key is not ours.
    let mut theirs = bundle(3, "policy");
    Verifier::new(b"theirs".to_vec()).sign(&mut theirs);
    assert_eq!(
        v.accept(&theirs, 1),
        Err(BundleError::NotAuthentic),
        "a bundle signed with another key must be rejected"
    );
}

#[test]
fn layer_fleet_canary_is_a_stable_gated_subset() {
    // 0% includes nobody, 100% includes everybody, and membership is stable for
    // a given revision — the property that makes a staged rollout staged.
    assert!(!in_canary("host-a", 7, 0), "0% canary includes nobody");
    assert!(
        in_canary("host-a", 7, 100),
        "100% canary includes everybody"
    );
    assert_eq!(
        in_canary("host-a", 7, 25),
        in_canary("host-a", 7, 25),
        "canary membership must be deterministic for a host and revision"
    );
}

#[test]
fn layer_fleet_regression_triggers_rollback() {
    // Baseline 10 denials per mille; the new policy quadruples that. The monitor
    // must report Degraded — the signal that rolls the fleet back automatically.
    let baseline = HealthWindow {
        denials: 10,
        allows: 990,
    };
    let mut m = RolloutMonitor::new(baseline, std::time::Duration::from_secs(0));
    for i in 0..1000 {
        m.record(i % 10 == 0); // 100 per mille
    }
    assert!(
        matches!(
            m.assess(std::time::Duration::from_secs(600)),
            Health::Degraded { .. }
        ),
        "a policy that quadruples the denial rate must be judged Degraded"
    );
}
