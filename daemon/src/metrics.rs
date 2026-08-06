//! Runtime telemetry: the instrument a soak and a production monitor read.
//!
//! Everything else in this project answers "is the verdict correct?". This
//! module answers the question static verification cannot: "is the process
//! *healthy over time* — not leaking, not thrashing, still fast?" That question
//! only has an answer at runtime, which is exactly why it is the dominant open
//! risk in [`crate`]'s deployment story (see `docs/design/production_readiness.md`).
//! You cannot close that risk without first being able to *measure* it, and that
//! is what this file is: the measurement.
//!
//! Two pieces:
//!
//!   * [`prometheus`] renders the daemon's counters and the process's resident
//!     memory as a Prometheus text exposition, served at `GET /metrics`. This is
//!     what a monitor scrapes every few seconds for the life of a deployment.
//!   * [`ResourceSampler`] records `(time, RSS)` samples and fits a line through
//!     them, turning "memory crept up over the run" — the leak that only OOMs
//!     the box on day nine, and that no correctness proof can see — into a
//!     number with a verdict. The soak harness drives it; the leak-detection
//!     maths is unit-tested here so the instrument itself is trustworthy before
//!     anyone points it at a 30-day run.

use crate::state::DaemonState;

/// Resident set size of this process, in bytes, if the platform can report it
/// cheaply and without a dependency.
///
/// Linux exposes it in `/proc/self/status` as `VmRSS`, in kB. macOS and Windows
/// would each need a platform call (`task_info` / `GetProcessMemoryInfo`); until
/// those are wired the gauge is simply absent there rather than wrong, and the
/// soak on those platforms reads RSS from the OS's own tooling instead.
pub fn process_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let status = std::fs::read_to_string("/proc/self/status").ok()?;
        for line in status.lines() {
            if let Some(rest) = line.strip_prefix("VmRSS:") {
                let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
                return Some(kb.saturating_mul(1024));
            }
        }
        None
    }
    #[cfg(not(target_os = "linux"))]
    {
        None
    }
}

/// The verdict a [`LeakReport`] carries.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LeakVerdict {
    /// Not enough samples, or too short a span, to say anything. Reporting
    /// "stable" here would be a false all-clear, which is the one answer a leak
    /// detector must never give when it does not know.
    Insufficient,
    /// Memory is flat within the threshold: no leak detected over this run.
    Stable,
    /// Memory is trending up faster than the threshold. Projected growth per
    /// hour is in the report; this is the signal a soak exists to catch.
    Growing,
}

impl LeakVerdict {
    pub fn as_str(self) -> &'static str {
        match self {
            LeakVerdict::Insufficient => "insufficient",
            LeakVerdict::Stable => "stable",
            LeakVerdict::Growing => "growing",
        }
    }
}

/// The outcome of fitting a line through the RSS samples.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct LeakReport {
    pub samples: usize,
    pub span_secs: f64,
    pub first_rss: u64,
    pub last_rss: u64,
    pub peak_rss: u64,
    /// Least-squares slope of RSS against time.
    pub slope_bytes_per_sec: f64,
    /// The slope projected to an hour — the human-legible form of the trend, and
    /// what the verdict's threshold is expressed in.
    pub projected_bytes_per_hour: f64,
    pub verdict: LeakVerdict,
}

/// Records `(time, RSS)` over a run and fits a trend line.
///
/// Bounded: a sampler left running for a month must not itself be the leak. Once
/// full it keeps the most recent `capacity` samples, which is all a slope needs
/// — the trend of the recent past is what predicts the near future.
#[derive(Debug, Clone)]
pub struct ResourceSampler {
    samples: Vec<(u64, u64)>, // (t_micros, rss_bytes)
    capacity: usize,
    peak: u64,
}

impl ResourceSampler {
    pub fn new(capacity: usize) -> Self {
        let capacity = capacity.max(2);
        ResourceSampler {
            samples: Vec::with_capacity(capacity),
            capacity,
            peak: 0,
        }
    }

    /// Record one sample. `t_us` is microseconds since the epoch; `rss` is bytes.
    pub fn record(&mut self, t_us: u64, rss: u64) {
        if self.samples.len() >= self.capacity {
            self.samples.remove(0);
        }
        self.samples.push((t_us, rss));
        self.peak = self.peak.max(rss);
    }

    /// Convenience: sample the live process RSS now. Returns the value recorded,
    /// or `None` if the platform does not expose RSS.
    pub fn sample_now(&mut self, t_us: u64) -> Option<u64> {
        let rss = process_rss_bytes()?;
        self.record(t_us, rss);
        Some(rss)
    }

    pub fn len(&self) -> usize {
        self.samples.len()
    }

    pub fn is_empty(&self) -> bool {
        self.samples.is_empty()
    }

    pub fn peak_bytes(&self) -> u64 {
        self.peak
    }

    /// Fit a line through the samples and judge it.
    ///
    /// `min_samples` guards against a slope drawn through too few points;
    /// `threshold_bytes_per_hour` is the growth rate above which the run is
    /// called a leak. A run whose observed span is zero (every sample at the
    /// same instant) is `Insufficient`, not stable: you cannot measure a rate
    /// over no time.
    pub fn report(&self, min_samples: usize, threshold_bytes_per_hour: f64) -> LeakReport {
        let n = self.samples.len();
        let first_rss = self.samples.first().map(|&(_, r)| r).unwrap_or(0);
        let last_rss = self.samples.last().map(|&(_, r)| r).unwrap_or(0);
        let t0 = self.samples.first().map(|&(t, _)| t).unwrap_or(0);
        let span_secs = self
            .samples
            .last()
            .map(|&(t, _)| (t.saturating_sub(t0)) as f64 / 1_000_000.0)
            .unwrap_or(0.0);

        if n < min_samples.max(2) || span_secs <= 0.0 {
            return LeakReport {
                samples: n,
                span_secs,
                first_rss,
                last_rss,
                peak_rss: self.peak,
                slope_bytes_per_sec: 0.0,
                projected_bytes_per_hour: 0.0,
                verdict: LeakVerdict::Insufficient,
            };
        }

        // Least squares over (seconds-since-start, bytes). Seconds relative to
        // the first sample keeps the magnitudes small and the fit numerically
        // steady over a long run.
        let xs: Vec<f64> = self
            .samples
            .iter()
            .map(|&(t, _)| (t.saturating_sub(t0)) as f64 / 1_000_000.0)
            .collect();
        let ys: Vec<f64> = self.samples.iter().map(|&(_, r)| r as f64).collect();
        let nf = n as f64;
        let mean_x = xs.iter().sum::<f64>() / nf;
        let mean_y = ys.iter().sum::<f64>() / nf;
        let mut num = 0.0;
        let mut den = 0.0;
        for i in 0..n {
            let dx = xs[i] - mean_x;
            num += dx * (ys[i] - mean_y);
            den += dx * dx;
        }
        let slope = if den > 0.0 { num / den } else { 0.0 };
        let per_hour = slope * 3600.0;

        let verdict = if per_hour > threshold_bytes_per_hour {
            LeakVerdict::Growing
        } else {
            LeakVerdict::Stable
        };

        LeakReport {
            samples: n,
            span_secs,
            first_rss,
            last_rss,
            peak_rss: self.peak,
            slope_bytes_per_sec: slope,
            projected_bytes_per_hour: per_hour,
            verdict,
        }
    }
}

/// Render the daemon's state as a Prometheus text exposition.
///
/// Deliberately hand-written, like the rest of this workspace's wire formats:
/// the exposition grammar is a dozen lines of `# HELP`/`# TYPE`/`name value`,
/// and a scrape endpoint on a firewall's management plane is not worth a
/// dependency tree. The metric names follow Prometheus convention — `_total`
/// for counters, `_bytes`/`_seconds` unit suffixes, a single-series `_info`-style
/// gauge for enumerated state.
pub fn prometheus(state: &DaemonState) -> String {
    let kernel = state.kernel();
    let stats = state.kernel_stats();
    let counters = state.counters();
    let logs = state.logs.stats();
    let cache = state.identity.cache_stats();
    let wd = state.watchdog_report();

    let mut m = Exposition::with_capacity(4096);

    m.gauge("ufw_up", "1 when the daemon process is running", 1.0);
    m.gauge(
        "ufw_uptime_seconds",
        "Seconds since the daemon started",
        state.uptime_secs() as f64,
    );

    // Enumerated states as a one-hot gauge: the active label is 1, and a query
    // like `ufw_health{state="degraded"}` alerts cleanly.
    m.help("ufw_health", "Daemon health, one-hot by state", "gauge");
    for s in ["enforcing", "degraded", "safe-mode", "starting", "stopping"] {
        m.labeled_value("ufw_health", "state", s, bool_f64(state.health().as_str() == s));
    }
    m.help("ufw_enforcement_mode", "Enforcement mode, one-hot", "gauge");
    for s in ["enforce", "monitor", "emergency-allow"] {
        m.labeled_value(
            "ufw_enforcement_mode",
            "mode",
            s,
            bool_f64(state.mode().as_str() == s),
        );
    }

    m.gauge(
        "ufw_kernel_connected",
        "1 when the kernel module is reachable",
        bool_f64(kernel.connected),
    );
    m.gauge(
        "ufw_kernel_reconnect_attempts",
        "Consecutive failed reconnect attempts",
        kernel.reconnect_attempts as f64,
    );

    // Watchdog: the signal a headless server watches to tell "up" from
    // "up, but crash-looping".
    m.help("ufw_watchdog_state", "Data-path watchdog state, one-hot", "gauge");
    for s in ["nominal", "recovering", "safe-mode"] {
        m.labeled_value("ufw_watchdog_state", "state", s, bool_f64(wd.state == s));
    }
    m.gauge(
        "ufw_watchdog_faults_in_window",
        "Data-path faults currently inside the fault window",
        wd.faults_in_window as f64,
    );
    m.counter(
        "ufw_watchdog_faults_total",
        "Data-path faults since start",
        wd.total_faults as f64,
    );
    m.counter(
        "ufw_watchdog_safe_mode_entries_total",
        "Times the watchdog has entered safe mode",
        wd.safe_mode_entries as f64,
    );

    m.gauge(
        "ufw_policy_revision",
        "Active policy revision",
        state.active_revision() as f64,
    );
    m.gauge(
        "ufw_policy_rules",
        "Rules in the active policy",
        state.rule_count() as f64,
    );
    m.counter(
        "ufw_policy_reloads_total",
        "Successful policy reloads",
        counters.policy_reloads as f64,
    );
    m.counter(
        "ufw_policy_failed_reloads_total",
        "Failed policy reloads",
        counters.failed_reloads as f64,
    );

    m.counter(
        "ufw_identity_queries_total",
        "Identity resolutions answered",
        counters.identity_queries as f64,
    );
    m.counter("ufw_identity_cache_hits_total", "Identity cache hits", cache.hits as f64);
    m.counter(
        "ufw_identity_cache_misses_total",
        "Identity cache misses",
        cache.misses as f64,
    );
    m.gauge(
        "ufw_identity_cache_entries",
        "Entries in the identity cache",
        cache.entries as f64,
    );

    // Traffic, straight from the kernel module's counters.
    m.counter("ufw_flows_seen_total", "Flows observed", stats.flows_seen as f64);
    m.counter("ufw_flows_allowed_total", "Flows allowed", stats.flows_allowed as f64);
    m.counter("ufw_flows_denied_total", "Flows denied", stats.flows_denied as f64);
    m.counter("ufw_packets_seen_total", "Packets observed", stats.packets_seen as f64);
    m.counter("ufw_dpi_scans_total", "DPI scans performed", stats.dpi_scans as f64);
    m.counter("ufw_dpi_hits_total", "DPI signature hits", stats.dpi_hits as f64);
    m.gauge(
        "ufw_conntrack_entries",
        "Connection-tracking entries",
        stats.conntrack_entries as f64,
    );
    m.counter(
        "ufw_ebpf_fastpath_decisions_total",
        "Decisions taken on the eBPF fast path",
        stats.ebpf_fastpath_decisions as f64,
    );

    // Logging pipeline health: dropped events are a back-pressure signal.
    m.counter("ufw_log_events_received_total", "Log events received", logs.received as f64);
    m.counter("ufw_log_events_written_total", "Log events written", logs.written as f64);
    m.counter(
        "ufw_log_events_dropped_total",
        "Log events dropped by a full queue",
        logs.dropped_queue_full as f64,
    );
    m.counter("ufw_log_sink_errors_total", "Log sink errors", logs.sink_errors as f64);

    // The leak signal itself, when the platform can report it.
    if let Some(rss) = process_rss_bytes() {
        m.gauge(
            "ufw_process_resident_memory_bytes",
            "Resident set size of the daemon process",
            rss as f64,
        );
    }

    m.finish()
}

fn bool_f64(b: bool) -> f64 {
    if b {
        1.0
    } else {
        0.0
    }
}

/// A tiny Prometheus text-exposition builder. Emits `# HELP`/`# TYPE` once per
/// metric name, then the sample lines.
struct Exposition {
    out: String,
}

impl Exposition {
    fn with_capacity(cap: usize) -> Self {
        Exposition {
            out: String::with_capacity(cap),
        }
    }

    fn help(&mut self, name: &str, help: &str, kind: &str) {
        self.out.push_str("# HELP ");
        self.out.push_str(name);
        self.out.push(' ');
        self.out.push_str(help);
        self.out.push('\n');
        self.out.push_str("# TYPE ");
        self.out.push_str(name);
        self.out.push(' ');
        self.out.push_str(kind);
        self.out.push('\n');
    }

    fn gauge(&mut self, name: &str, help: &str, value: f64) {
        self.help(name, help, "gauge");
        self.value(name, value);
    }

    fn counter(&mut self, name: &str, help: &str, value: f64) {
        self.help(name, help, "counter");
        self.value(name, value);
    }

    fn value(&mut self, name: &str, value: f64) {
        self.out.push_str(name);
        self.out.push(' ');
        self.push_number(value);
        self.out.push('\n');
    }

    fn labeled_value(&mut self, name: &str, label: &str, label_value: &str, value: f64) {
        self.out.push_str(name);
        self.out.push('{');
        self.out.push_str(label);
        self.out.push_str("=\"");
        self.out.push_str(label_value);
        self.out.push_str("\"} ");
        self.push_number(value);
        self.out.push('\n');
    }

    /// Render a number the way Prometheus expects: integers without a decimal
    /// point, everything else with enough precision to be faithful.
    fn push_number(&mut self, value: f64) {
        if value.is_finite() && value.fract() == 0.0 && value.abs() < 1e15 {
            self.out.push_str(&(value as i64).to_string());
        } else {
            self.out.push_str(&format!("{value}"));
        }
    }

    fn finish(self) -> String {
        self.out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: u64 = 1_000_000;

    #[test]
    fn a_flat_run_is_stable() {
        let mut s = ResourceSampler::new(64);
        for i in 0..20 {
            // Constant RSS with a little jitter that averages out.
            let jitter = if i % 2 == 0 { 4096 } else { 0 };
            s.record(i * 10 * S, 100 * 1024 * 1024 + jitter);
        }
        let r = s.report(5, 1024.0 * 1024.0); // 1 MB/hour threshold
        assert_eq!(r.verdict, LeakVerdict::Stable, "{r:?}");
        assert!(r.projected_bytes_per_hour.abs() < 1024.0 * 1024.0);
    }

    #[test]
    fn a_rising_run_is_flagged_as_growing() {
        let mut s = ResourceSampler::new(64);
        // +10 MB every 10 seconds = 3.6 GB/hour. Unmissable.
        for i in 0..20 {
            s.record(i * 10 * S, 100 * 1024 * 1024 + i * 10 * 1024 * 1024);
        }
        let r = s.report(5, 1024.0 * 1024.0);
        assert_eq!(r.verdict, LeakVerdict::Growing, "{r:?}");
        assert!(r.projected_bytes_per_hour > 1024.0 * 1024.0 * 1024.0); // > 1 GB/h
        assert!(r.last_rss > r.first_rss);
    }

    #[test]
    fn a_slow_creep_below_threshold_stays_stable() {
        let mut s = ResourceSampler::new(256);
        // +1 KB every 10 s = 360 KB/hour, under a 1 MB/hour threshold.
        for i in 0..100 {
            s.record(i * 10 * S, 100 * 1024 * 1024 + i * 1024);
        }
        let r = s.report(5, 1024.0 * 1024.0);
        assert_eq!(r.verdict, LeakVerdict::Stable, "{r:?}");
        // ...but the same run against a tighter 100 KB/hour budget is a leak.
        let strict = s.report(5, 100.0 * 1024.0);
        assert_eq!(strict.verdict, LeakVerdict::Growing, "{strict:?}");
    }

    #[test]
    fn too_few_samples_are_insufficient_not_stable() {
        let mut s = ResourceSampler::new(64);
        s.record(0, 100 * 1024 * 1024);
        let r = s.report(5, 1024.0 * 1024.0);
        assert_eq!(r.verdict, LeakVerdict::Insufficient);
    }

    #[test]
    fn a_zero_span_run_is_insufficient() {
        let mut s = ResourceSampler::new(64);
        // Ten samples, all at the same instant: a rate is undefined.
        for _ in 0..10 {
            s.record(42 * S, 100 * 1024 * 1024);
        }
        let r = s.report(5, 1024.0 * 1024.0);
        assert_eq!(r.verdict, LeakVerdict::Insufficient);
    }

    #[test]
    fn the_sampler_is_bounded_and_tracks_peak() {
        let mut s = ResourceSampler::new(10);
        for i in 0..1000u64 {
            s.record(i * S, 1024 * 1024 + i);
        }
        assert!(s.len() <= 10);
        // Peak survives eviction: it saw the largest value even after it fell
        // out of the window.
        assert_eq!(s.peak_bytes(), 1024 * 1024 + 999);
    }

    #[test]
    fn the_exposition_is_well_formed() {
        // A hand-check that HELP/TYPE precede samples and the numbers render as
        // integers. Uses a minimal state.
        let out = sample_exposition();
        assert!(out.contains("# HELP ufw_up 1 when the daemon process is running\n"));
        assert!(out.contains("# TYPE ufw_up gauge\n"));
        assert!(out.contains("\nufw_up 1\n"));
        // One-hot health: exactly one state line is 1.
        let ones = out
            .lines()
            .filter(|l| l.starts_with("ufw_health{") && l.ends_with(" 1"))
            .count();
        assert_eq!(ones, 1, "exactly one health state should be active");
        // Counters carry the _total suffix and a TYPE line.
        assert!(out.contains("# TYPE ufw_policy_reloads_total counter\n"));
    }

    // Build a minimal DaemonState and render it, mirroring state.rs's own test
    // setup so this file needs no bespoke fixtures.
    fn sample_exposition() -> String {
        use crate::config::LoggingConfig;
        use crate::identity::{IdentityService, NullResolver, ResolverOptions, TrustDatabase};
        use crate::logging::{Enrichment, Logger};
        use ufw_shared::log_types::Severity;
        use ufw_shared::protocol::EnforcementMode;

        let logging = LoggingConfig {
            level: Severity::Debug,
            log_allowed: true,
            file: None,
            syslog: None,
            siem: None,
            stdout: false,
            correlation: false,
            correlation_window_secs: 300,
            correlation_threshold: 3,
        };
        let logger = Logger::with_sinks(&logging, Enrichment::default(), Vec::new());
        let identity = std::sync::Arc::new(IdentityService::new(
            Box::new(NullResolver::new(ResolverOptions::default())),
            TrustDatabase::new(),
            ResolverOptions::default(),
            16,
        ));
        let state = DaemonState::new("host-a", EnforcementMode::Enforce, identity, logger.handle());
        prometheus(&state)
    }
}
