//! Detection-efficacy harness (lever #4).
//!
//! Runs a **labeled corpus** through the two callable detectors — the
//! egress-anomaly baseline and the signature engine — and prints a confusion
//! matrix (catch-rate + false-positive rate). This is what turns "we have
//! detection" into a measured number.
//!
//! HONEST SCOPE. This measures detection *correctness* and *false-positive rate*
//! on a known corpus: does the detector fire on the shapes it is meant to catch,
//! and stay quiet on benign traffic? It is NOT a measure of catching novel or
//! unknown attacks — the signature corpus is built from the engine's own shipped
//! patterns, and the anomaly corpus is built to the detector's documented model.
//! A real efficacy number against fresh, independent adversary captures is a
//! larger effort; this guards the detectors against regression and reports a
//! floor, not a marketing ceiling.
//!
//! Run with output:  cargo test -p ufw-daemon --test detection_efficacy -- --nocapture

use std::path::Path;

use ufw_daemon::logging::anomaly::{AnomalyConfig, EgressBaseline};
use ufw_daemon::signatures;
use ufw_shared::log_types::{FiveTuple, IdentitySummary, LogEvent};
use ufw_shared::policy_types::{Decision, Direction, Protocol, Zone};

const SECOND: u64 = 1_000_000;

#[derive(Default)]
struct Confusion {
    tp: u32,
    fp: u32,
    tn: u32,
    fn_: u32,
}

impl Confusion {
    fn record(&mut self, malicious: bool, detected: bool) {
        match (malicious, detected) {
            (true, true) => self.tp += 1,
            (true, false) => self.fn_ += 1,
            (false, true) => self.fp += 1,
            (false, false) => self.tn += 1,
        }
    }
    fn catch_rate(&self) -> f64 {
        let d = self.tp + self.fn_;
        if d == 0 {
            1.0
        } else {
            self.tp as f64 / d as f64
        }
    }
    fn fp_rate(&self) -> f64 {
        let d = self.fp + self.tn;
        if d == 0 {
            0.0
        } else {
            self.fp as f64 / d as f64
        }
    }
    fn report(&self, name: &str) {
        println!(
            "  {name}: TP={} FN={} FP={} TN={}  catch-rate={:.1}%  false-positive-rate={:.1}%",
            self.tp,
            self.fn_,
            self.fp,
            self.tn,
            self.catch_rate() * 100.0,
            self.fp_rate() * 100.0,
        );
    }
}

/// An allowed, perimeter-crossing egress flow (time injected, never a clock).
fn egress(app: &str, dst: &str, at_secs: u64) -> LogEvent {
    let mut e = LogEvent::new(
        at_secs * SECOND,
        "host",
        Decision::Allow,
        42,
        FiveTuple {
            protocol: Protocol::Tcp,
            src_ip: "10.0.0.1".parse().unwrap(),
            src_port: 40000,
            dst_ip: dst.parse().unwrap(),
            dst_port: 443,
        },
    );
    e.direction = Direction::Outbound;
    e.remote_zone = Zone::External;
    e.perimeter_crossing = true;
    e.identity = Some(IdentitySummary {
        pid: 1,
        path: app.into(),
        sha256_hex: None,
        signer: None,
        trust: None,
    });
    e
}

fn new_engine() -> EgressBaseline {
    EgressBaseline::new(AnomalyConfig {
        learning_secs: 100,
        min_baseline: 3,
        realert_interval_secs: 0,
        ..Default::default()
    })
}

/// Learn five distinct destinations inside the learning window.
fn establish(e: &mut EgressBaseline, app: &str) {
    for i in 0..5u32 {
        e.observe(&egress(app, &format!("198.51.{i}.10"), 10 + i as u64));
    }
}

#[test]
fn egress_anomaly_efficacy() {
    let mut c = Confusion::default();
    let mut e = new_engine();

    // MALICIOUS: an app that established a baseline then, after the learning
    // window, beacons out to a brand-new external destination (C2-shaped).
    for k in 0..25u32 {
        let app = format!("/opt/beacon-{k}");
        establish(&mut e, &app);
        let hit = e
            .observe(&egress(&app, &format!("203.0.113.{k}"), 200))
            .is_some();
        c.record(true, hit);
    }

    // BENIGN 1: an app that only ever revisits destinations from its baseline.
    for k in 0..15u32 {
        let app = format!("/opt/steady-{k}");
        establish(&mut e, &app);
        let hit = e.observe(&egress(&app, "198.51.2.10", 200)).is_some();
        c.record(false, hit);
    }
    // BENIGN 2: still inside the learning window — new destinations are normal.
    for k in 0..15u32 {
        let app = format!("/opt/warmup-{k}");
        let hit = e
            .observe(&egress(&app, &format!("203.0.200.{k}"), 20))
            .is_some();
        c.record(false, hit);
    }

    println!("egress-anomaly detector:");
    c.report("egress");
    // Deterministic model: it must catch every post-baseline novel destination
    // and never fire during warm-up or on a known destination.
    assert!(
        c.catch_rate() >= 0.95,
        "egress catch-rate too low: {}",
        c.catch_rate()
    );
    assert!(
        c.fp_rate() <= 0.02,
        "egress false-positive rate too high: {}",
        c.fp_rate()
    );
}

/// The signature engine has two stages: a fast content **pre-filter**
/// (`scan_content`, an Aho-Corasick automaton over every pattern) and, on a
/// candidate, the full evaluation of a signature's condition tree against the
/// matched patterns AND its field constraints (protocol, http.uri, ja3, …).
///
/// This test measures the pre-filter's **recall** — the property that actually
/// matters for it: it must never drop a payload that carries a real signature
/// pattern, or the precise second stage never gets to look. It deliberately does
/// NOT treat a pre-filter hit as a detection: the pre-filter over-matches by
/// design (benign HTTP shares byte-substrings with attack patterns), and
/// precision is the condition-evaluator's job, which needs full flow field
/// context and is out of this harness's scope. So the benign column is reported,
/// not asserted, and is expected to be noisy — that is the pre-filter working.
#[test]
fn signature_prefilter_recall() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../sig-rules");
    let (set, errs) = signatures::load_dir(&dir);
    assert!(errs.is_empty(), "sig-rules failed to load: {errs:?}");
    let patterns = set.patterns();
    assert!(
        !patterns.is_empty(),
        "no content patterns loaded from {dir:?}"
    );

    // RECALL: a payload carrying a real shipped pattern must survive the
    // pre-filter. Skip <4-byte patterns that benign text could carry by chance.
    let (mut hit, mut total) = (0u32, 0u32);
    for p in patterns.iter().filter(|p| p.bytes.len() >= 4).take(80) {
        let mut payload = b"POST /submit HTTP/1.1\r\nHost: t\r\n\r\n".to_vec();
        payload.extend_from_slice(&p.bytes);
        payload.extend_from_slice(b"\r\n--tail--");
        if set.scan_content(&payload).is_some_and(|t| !t.is_empty()) {
            hit += 1;
        }
        total += 1;
    }
    assert!(total > 0, "no usable (>=4 byte) patterns to test");
    let recall = hit as f64 / total as f64;

    // Benign traffic — REPORTED for context, not asserted. Pre-filter hits here
    // are candidates the second stage would then accept or reject.
    let benign: &[&[u8]] = &[
        b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: curl/8.0\r\n\r\n",
        b"the quick brown fox jumps over the lazy dog while the sun sets slowly",
        b"{\"event\":\"login\",\"user\":\"alice\",\"ok\":true,\"ts\":1700000000}",
        b"GET /static/app.css HTTP/1.1\r\nHost: cdn.example.net\r\nAccept: text/css\r\n\r\n",
        b"Subject: lunch?\r\n\r\nAre we still on for noon at the usual place. Cheers.",
        b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}",
    ];
    let benign_hits = benign
        .iter()
        .filter(|b| set.scan_content(b).is_some_and(|t| !t.is_empty()))
        .count();

    println!(
        "signature pre-filter ({} signatures, {} content patterns):",
        set.len(),
        patterns.len()
    );
    println!(
        "  recall={:.1}% ({hit}/{total} pattern-bearing payloads survive the pre-filter)",
        recall * 100.0
    );
    println!(
        "  benign pre-filter candidates: {benign_hits}/{} (expected non-zero; the condition \
         evaluator is the precise stage, not measured here)",
        benign.len()
    );
    assert!(recall >= 0.95, "pre-filter recall too low: {recall}");
}
