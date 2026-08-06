//! Soak harness: the runtime measurement that static verification cannot do.
//!
//! Every other test in this workspace asks whether the code is *correct*. This
//! one asks whether it stays *healthy over time* — the question that is the
//! dominant open risk in the deployment story (`docs/design/production_readiness.md`,
//! gap 1) precisely because no proof can answer it. A leak of a few bytes per
//! operation is invisible to correctness checking and OOMs the box on day nine.
//!
//! The harness drives the real data-path code — an actual [`KernelChannel`]
//! talking to the loopback mock kernel, installing policies and signatures and
//! pumping events, exactly as the daemon does — while sampling the process's
//! resident memory. It then fits a line through the samples with the
//! leak detector in [`ufw_daemon::metrics`], whose maths is unit-tested there,
//! and fails if memory is trending up beyond a threshold.
//!
//! Two entry points:
//!
//!   * [`soak_smoke_churns_and_collects_samples`] always runs: a short, fixed
//!     churn that proves the harness drives real code without panicking and the
//!     sampler collects points. Cheap enough for every `cargo test`.
//!   * [`soak_data_path_churn_does_not_leak`] is `#[ignore]`d — the real soak.
//!     Run it for as long as you like:
//!
//!     ```sh
//!     UFW_SOAK_SECS=1800 cargo test --release -p ufw-daemon --test soak -- --ignored
//!     ```
//!
//!     A 30-minute run is a smoke; the production soak points a Prometheus
//!     monitor at the daemon's `/metrics` for 30 days and watches the same
//!     `ufw_process_resident_memory_bytes` series this test fits a line through.

use std::sync::mpsc::{channel, Receiver};
use std::time::{Duration, Instant};

use ufw_daemon::ipc::loopback::{self, MockKernelModule};
use ufw_daemon::ipc::{KernelChannel, KernelEvent};
use ufw_daemon::metrics::{LeakVerdict, ResourceSampler};
use ufw_daemon::signatures::SignatureSet;
use ufw_shared::now_us;
use ufw_shared::policy_types::{Action, CompiledPolicy, CompiledRule, Decision, Layer};

const TIMEOUT: Duration = Duration::from_secs(2);

/// A channel wired to a fresh mock kernel, the same setup the ipc tests use.
fn connect() -> (KernelChannel, Receiver<KernelEvent>, MockKernelModule) {
    let (daemon_side, module_side) = loopback::pair();
    let module = MockKernelModule::spawn(module_side);
    let (tx, rx) = channel();
    let (chan, _handshake) =
        KernelChannel::open(daemon_side, tx, "soak", TIMEOUT).expect("handshake");
    (chan, rx, module)
}

/// A policy with `n` rules, rebuilt each call so the churn actually allocates —
/// a leak that only shows under real allocation would hide behind a cached one.
fn make_policy(n: usize) -> CompiledPolicy {
    let mut p = CompiledPolicy::new("soak", Decision::Deny);
    for i in 0..n {
        p.rules.push(CompiledRule::new(
            i as u32 + 1,
            &format!("rule-{i}"),
            Layer::Packet,
            Action::Allow,
        ));
    }
    p.finalize();
    p
}

/// One unit of data-path work: install a (varying) policy and signature set,
/// push an asynchronous event, and drain whatever came back — the allocation
/// profile of a busy daemon in miniature.
fn churn_once(chan: &KernelChannel, module: &MockKernelModule, rx: &Receiver<KernelEvent>, i: u64) {
    let policy = make_policy((i % 32) as usize + 1);
    let _ = chan.install_policy(&policy, TIMEOUT);

    let sigs = SignatureSet::default().encode();
    let _ = chan.install_signatures(&sigs, TIMEOUT);

    module.push_log_event("soak event carrying a little payload text to allocate");
    while rx.try_recv().is_ok() {}
}

#[test]
fn soak_smoke_churns_and_collects_samples() {
    let (chan, rx, module) = connect();
    let mut sampler = ResourceSampler::new(256);

    for i in 0..100u64 {
        churn_once(&chan, &module, &rx, i);
        if i % 10 == 0 {
            sampler.sample_now(now_us());
        }
    }

    drop(chan);
    module.stop();

    // Plumbing check only — the leak *maths* is unit-tested in metrics.rs. This
    // proves the harness drives real code end to end without panicking, and that
    // on a platform reporting RSS the sampler actually captured points.
    let has_rss = ufw_daemon::metrics::process_rss_bytes().is_some();
    assert!(
        !has_rss || sampler.len() >= 2,
        "expected RSS samples on a platform that reports them"
    );
}

#[test]
#[ignore = "long-running soak; run with `UFW_SOAK_SECS=1800 cargo test --release -p ufw-daemon --test soak -- --ignored`"]
fn soak_data_path_churn_does_not_leak() {
    let secs: u64 = std::env::var("UFW_SOAK_SECS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20);

    let (chan, rx, module) = connect();

    // A wall-clock warmup with no sampling. RSS climbs while the allocator
    // acquires arenas it will reuse but not return — a one-time step, not a
    // leak. Measuring across it would extrapolate that step to a huge hourly
    // rate. So we let RSS reach steady state first, and only then start weighing
    // it; a longer run gets a longer warmup.
    let warmup = Duration::from_secs((secs / 4).clamp(2, 120));
    let warm_deadline = Instant::now() + warmup;
    let mut i = 0u64;
    while Instant::now() < warm_deadline {
        churn_once(&chan, &module, &rx, i);
        i += 1;
    }

    // Steady-state measurement over the remainder.
    let mut sampler = ResourceSampler::new(16_384);
    let measure_secs = secs.saturating_sub(warmup.as_secs()).max(1);
    let deadline = Instant::now() + Duration::from_secs(measure_secs);
    while Instant::now() < deadline {
        churn_once(&chan, &module, &rx, i);
        i += 1;
        if i % 200 == 0 {
            sampler.sample_now(now_us());
        }
    }

    drop(chan);
    module.stop();

    // 8 MB/hour is the gate. It sits deliberately in the gap between two
    // measured quantities: residual allocator-arena growth after warmup reads a
    // few MB/hour over a short span and vanishes over a long one, while the
    // smallest *real* leak — one byte per operation at these data-path rates —
    // extrapolates to tens of MB/hour. A slower leak than that hides under any
    // fixed threshold on a short run and only shows as absolute RSS creep over a
    // long one, which is why the production instrument is the /metrics RSS series
    // watched for days, not this coarse gate.
    let report = sampler.report(8, 8.0 * 1024.0 * 1024.0);
    eprintln!(
        "soak: {i} iterations, {} samples over {:.1}s steady state; slope {:.0} B/s = {:.2} MB/hour; \
         RSS {} -> {} (peak {}) bytes; verdict {}",
        report.samples,
        report.span_secs,
        report.slope_bytes_per_sec,
        report.projected_bytes_per_hour / 1024.0 / 1024.0,
        report.first_rss,
        report.last_rss,
        report.peak_rss,
        report.verdict.as_str(),
    );

    // Extrapolating a short window to an hourly rate is unreliable: a single
    // page-sized step reads as a large slope over a few seconds and as nothing
    // over an hour. Below a real steady-state span we report and decline to
    // conclude, rather than fail on noise. A production soak runs for hours; set
    // UFW_SOAK_SECS accordingly to get a verdict.
    const MIN_ASSERT_SPAN_SECS: f64 = 30.0;
    if report.span_secs < MIN_ASSERT_SPAN_SECS {
        eprintln!(
            "soak: steady-state span {:.1}s is under {MIN_ASSERT_SPAN_SECS:.0}s; \
             run longer (e.g. UFW_SOAK_SECS=300) to reach a leak verdict",
            report.span_secs
        );
        return;
    }

    match report.verdict {
        LeakVerdict::Growing => panic!("soak detected a memory leak: {report:?}"),
        // No RSS on this platform (macOS/Windows here). Not a failure — the
        // harness could not weigh the process; the production soak runs on Linux
        // and reads /metrics.
        LeakVerdict::Insufficient => {
            eprintln!("soak: could not measure RSS here; leak assertion skipped");
        }
        LeakVerdict::Stable => {}
    }
}
