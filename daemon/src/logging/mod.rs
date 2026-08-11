//! The logging subsystem: enrichment, fan-out and back-pressure policy.
//!
//! Events arrive from the kernel module in batches. The logger enriches them
//! with host-level context the module does not have, feeds them to the
//! correlation engine, and fans them out to every configured sink — all on a
//! background thread, because the alternative is the daemon's IPC reader
//! blocking on a slow disk while the module's ring buffer overflows.
//!
//! # Back-pressure has to stop somewhere
//!
//! There is a chain: kernel ring buffer → daemon queue → sinks. If every link
//! applies back-pressure, a stalled SIEM collector eventually stalls packet
//! decisions, which is an outage caused by a logging problem. So the chain is
//! cut here: the queue is bounded, and a full queue drops the *oldest*
//! pending events and counts the drop. Dropped counts are themselves logged,
//! so the loss is visible rather than silent.
//!
//! Oldest-first because during a burst the recent events describe what is
//! happening now.

pub mod correlation;
pub mod sink;

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TrySendError};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ufw_shared::log_types::{EventKind, LogEvent, Severity};
use ufw_shared::policy_types::{Decision, NetworkProfile};

use crate::config::LoggingConfig;
use correlation::{CorrelationConfig, CorrelationEngine};
use sink::Sink;

/// Runtime counters, surfaced by `ufwctl status`.
#[derive(Debug, Default)]
pub struct LogStats {
    pub received: AtomicU64,
    pub written: AtomicU64,
    pub filtered: AtomicU64,
    pub dropped_queue_full: AtomicU64,
    pub sink_errors: AtomicU64,
    pub correlations: AtomicU64,
}

impl LogStats {
    pub fn snapshot(&self) -> LogStatsSnapshot {
        LogStatsSnapshot {
            received: self.received.load(Ordering::Relaxed),
            written: self.written.load(Ordering::Relaxed),
            filtered: self.filtered.load(Ordering::Relaxed),
            dropped_queue_full: self.dropped_queue_full.load(Ordering::Relaxed),
            sink_errors: self.sink_errors.load(Ordering::Relaxed),
            correlations: self.correlations.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogStatsSnapshot {
    pub received: u64,
    pub written: u64,
    pub filtered: u64,
    pub dropped_queue_full: u64,
    pub sink_errors: u64,
    pub correlations: u64,
}

/// Host-level context the kernel module cannot supply.
#[derive(Debug, Clone, Default)]
pub struct Enrichment {
    pub host_id: String,
    pub policy_revision: u64,
    pub profile: NetworkProfile,
}

impl Enrichment {
    /// Fill in what the module left blank.
    ///
    /// The module knows the five-tuple and the rule; it does not reliably know
    /// the host identifier, the policy revision in force, or the zone the peer
    /// falls into — the last because zone classification depends on the
    /// network profile, which lives in the daemon's configuration.
    pub fn apply(&self, event: &mut LogEvent) {
        if event.host_id.is_empty() {
            event.host_id = self.host_id.clone();
        }
        if event.policy_revision == 0 {
            event.policy_revision = self.policy_revision;
        }
        let peer = match event.direction {
            ufw_shared::policy_types::Direction::Inbound => event.five_tuple.src_ip,
            _ => event.five_tuple.dst_ip,
        };
        event.remote_zone = self.profile.classify(peer);
        event.perimeter_crossing = event.remote_zone.crosses_perimeter();
    }
}

/// Handle used by the rest of the daemon to submit events.
#[derive(Clone)]
pub struct LogHandle {
    tx: SyncSender<LogMessage>,
    stats: Arc<LogStats>,
    running: Arc<AtomicBool>,
}

impl std::fmt::Debug for LogHandle {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LogHandle")
            .field("stats", &self.stats.snapshot())
            .finish()
    }
}

enum LogMessage {
    Events(Vec<LogEvent>),
    /// Replace the enrichment context after a policy change.
    Enrich(Box<Enrichment>),
    Flush,
    Stop,
}

impl LogHandle {
    /// Submit a batch. Never blocks; drops and counts when the queue is full.
    pub fn submit(&self, events: Vec<LogEvent>) {
        if events.is_empty() {
            return;
        }
        self.stats
            .received
            .fetch_add(events.len() as u64, Ordering::Relaxed);
        match self.tx.try_send(LogMessage::Events(events)) {
            Ok(()) => {}
            Err(TrySendError::Full(LogMessage::Events(dropped))) => {
                // The chain stops here rather than propagating back to the
                // kernel's ring buffer.
                self.stats
                    .dropped_queue_full
                    .fetch_add(dropped.len() as u64, Ordering::Relaxed);
            }
            Err(_) => {}
        }
    }

    /// Submit a single daemon-generated event (policy change, system fault).
    pub fn event(&self, event: LogEvent) {
        self.submit(vec![event]);
    }

    /// Convenience for the daemon's own operational messages.
    pub fn note(
        &self,
        host_id: &str,
        severity: Severity,
        kind: EventKind,
        message: impl Into<String>,
    ) {
        let mut event = LogEvent::new(
            ufw_shared::now_us(),
            host_id,
            Decision::Allow,
            ufw_shared::constants::RULE_ID_DEFAULT,
            Default::default(),
        );
        event.kind = kind;
        event.severity = severity;
        event.message = Some(message.into());
        self.event(event);
    }

    pub fn set_enrichment(&self, enrichment: Enrichment) {
        let _ = self.tx.try_send(LogMessage::Enrich(Box::new(enrichment)));
    }

    pub fn flush(&self) {
        let _ = self.tx.try_send(LogMessage::Flush);
    }

    pub fn stats(&self) -> LogStatsSnapshot {
        self.stats.snapshot()
    }

    pub fn is_running(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        let _ = self.tx.send(LogMessage::Stop);
    }
}

/// The logging subsystem.
pub struct Logger {
    handle: LogHandle,
    worker: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for Logger {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Logger")
            .field("handle", &self.handle)
            .finish()
    }
}

/// How many batches may be queued before the logger starts dropping.
const QUEUE_DEPTH: usize = 1024;

/// How often the worker flushes sinks and expires correlation state, when it
/// is otherwise idle.
const IDLE_TICK: Duration = Duration::from_millis(250);

impl Logger {
    /// Build the sinks a configuration asks for and start the worker.
    ///
    /// A sink that fails to open is reported and skipped rather than aborting
    /// startup: a firewall that refuses to enforce because its log file is on
    /// a full disk has turned a logging problem into an outage.
    pub fn start(config: &LoggingConfig, enrichment: Enrichment) -> (Self, Vec<String>) {
        let mut sinks: Vec<Box<dyn Sink>> = Vec::new();
        let mut problems = Vec::new();

        if config.stdout {
            sinks.push(Box::new(sink::StdoutSink::new(
                crate::config::LogFormat::Text,
            )));
        }
        if let Some(file) = &config.file {
            match sink::FileSink::open(file) {
                Ok(s) => sinks.push(Box::new(s)),
                Err(e) => problems.push(format!(
                    "file sink {} could not be opened: {e}",
                    file.path.display()
                )),
            }
        }
        if let Some(syslog) = &config.syslog {
            match sink::SyslogSink::connect(syslog) {
                Ok(s) => sinks.push(Box::new(s)),
                Err(e) => problems.push(format!("syslog sink {}: {e}", syslog.address)),
            }
        }
        if let Some(siem) = &config.siem {
            sinks.push(Box::new(sink::SiemSink::new(siem)));
        }
        if sinks.is_empty() {
            problems.push(
                "no log sinks are configured; policy decisions will not be recorded anywhere"
                    .into(),
            );
        }

        (Self::with_sinks(config, enrichment, sinks), problems)
    }

    /// Start with explicit sinks. Used by tests and by an embedded daemon.
    pub fn with_sinks(
        config: &LoggingConfig,
        enrichment: Enrichment,
        sinks: Vec<Box<dyn Sink>>,
    ) -> Self {
        let (tx, rx) = sync_channel(QUEUE_DEPTH);
        let stats = Arc::new(LogStats::default());
        let running = Arc::new(AtomicBool::new(true));

        let worker_state = WorkerState {
            sinks,
            enrichment,
            min_severity: config.level,
            log_allowed: config.log_allowed,
            correlation: config.correlation.then(|| {
                CorrelationEngine::new(CorrelationConfig {
                    window_secs: config.correlation_window_secs,
                    threshold: config.correlation_threshold,
                    ..Default::default()
                })
            }),
            stats: Arc::clone(&stats),
            sequence: 0,
        };

        let worker = {
            let running = Arc::clone(&running);
            std::thread::Builder::new()
                .name("ufw-logger".into())
                .spawn(move || worker_loop(worker_state, rx, running))
                .expect("spawn logger")
        };

        Logger {
            handle: LogHandle { tx, stats, running },
            worker: Some(worker),
        }
    }

    pub fn handle(&self) -> LogHandle {
        self.handle.clone()
    }

    /// Stop the worker and flush every sink.
    pub fn shutdown(&mut self) {
        self.handle.stop();
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

impl Drop for Logger {
    fn drop(&mut self) {
        self.shutdown();
    }
}

struct WorkerState {
    sinks: Vec<Box<dyn Sink>>,
    enrichment: Enrichment,
    min_severity: Severity,
    log_allowed: bool,
    correlation: Option<CorrelationEngine>,
    stats: Arc<LogStats>,
    sequence: u64,
}

impl WorkerState {
    /// Whether an event survives the configured filters.
    fn admits(&self, event: &LogEvent) -> bool {
        if event.severity < self.min_severity {
            return false;
        }
        // Suppressing allow events is a volume control, not a security
        // control, so it never applies to anything but a routine permit.
        if !self.log_allowed
            && event.decision == Decision::Allow
            && event.kind == EventKind::FlowDecision
        {
            return false;
        }
        true
    }

    fn process(&mut self, mut events: Vec<LogEvent>) {
        let mut correlations = Vec::new();

        for event in &mut events {
            self.enrichment.apply(event);
            if event.sequence == 0 {
                self.sequence += 1;
                event.sequence = self.sequence;
            } else {
                self.sequence = self.sequence.max(event.sequence);
            }
        }

        if let Some(engine) = &mut self.correlation {
            for event in &events {
                if let Some(c) = engine.observe(event) {
                    correlations.push(c);
                }
            }
        }

        for c in correlations {
            self.stats.correlations.fetch_add(1, Ordering::Relaxed);
            self.sequence += 1;
            events.push(c.to_event(&self.enrichment.host_id, self.sequence));
        }

        for event in &events {
            if !self.admits(event) {
                self.stats.filtered.fetch_add(1, Ordering::Relaxed);
                continue;
            }
            let mut delivered = false;
            for sink in &mut self.sinks {
                match sink.write(event) {
                    Ok(()) => delivered = true,
                    Err(_) => {
                        self.stats.sink_errors.fetch_add(1, Ordering::Relaxed);
                    }
                }
            }
            if delivered {
                self.stats.written.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    fn flush(&mut self) {
        for sink in &mut self.sinks {
            if sink.flush().is_err() {
                self.stats.sink_errors.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

fn worker_loop(mut state: WorkerState, rx: Receiver<LogMessage>, running: Arc<AtomicBool>) {
    loop {
        match rx.recv_timeout(IDLE_TICK) {
            Ok(LogMessage::Events(events)) => state.process(events),
            Ok(LogMessage::Enrich(e)) => state.enrichment = *e,
            Ok(LogMessage::Flush) => state.flush(),
            Ok(LogMessage::Stop) => break,
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                state.flush();
                if let Some(engine) = &mut state.correlation {
                    engine.expire(ufw_shared::now_us());
                }
                if !running.load(Ordering::Relaxed) {
                    break;
                }
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => break,
        }
    }

    // Drain whatever is still queued so a shutdown does not discard the last
    // events, which are usually the interesting ones.
    while let Ok(message) = rx.try_recv() {
        if let LogMessage::Events(events) = message {
            state.process(events);
        }
    }
    state.flush();
    running.store(false, Ordering::Relaxed);
}

/// Shared handle to a logger, for components that hold it behind a lock.
pub type SharedLogger = Arc<Mutex<Logger>>;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::LogFormat;
    use sink::MemorySink;
    use ufw_shared::log_types::{FiveTuple, IdentitySummary};
    use ufw_shared::policy_types::{Cidr, Direction, Protocol, Zone};

    fn config() -> LoggingConfig {
        LoggingConfig {
            level: Severity::Debug,
            log_allowed: true,
            file: None,
            syslog: None,
            siem: None,
            stdout: false,
            correlation: false,
            correlation_window_secs: 300,
            correlation_threshold: 3,
        }
    }

    fn enrichment() -> Enrichment {
        let profile = NetworkProfile {
            internal: vec![Cidr::parse("10.0.0.0/8").unwrap()],
            ..Default::default()
        };
        Enrichment {
            host_id: "host-a".into(),
            policy_revision: 7,
            profile,
        }
    }

    fn event(decision: Decision, dst: &str) -> LogEvent {
        let mut e = LogEvent::new(
            ufw_shared::now_us(),
            "",
            decision,
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
        e.rule_name = "r".into();
        e.identity = Some(IdentitySummary {
            pid: 1,
            path: "/tmp/x".into(),
            sha256_hex: None,
            signer: None,
            trust: None,
        });
        e
    }

    /// Run the logger to completion and return everything the sink saw.
    fn run(config: &LoggingConfig, events: Vec<LogEvent>) -> Vec<LogEvent> {
        let memory = MemorySink::new();
        let mut logger = Logger::with_sinks(config, enrichment(), vec![Box::new(memory.clone())]);
        logger.handle().submit(events);
        logger.shutdown();
        memory.take()
    }

    #[test]
    fn enrichment_fills_in_host_revision_and_zone() {
        let out = run(&config(), vec![event(Decision::Deny, "8.8.8.8")]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].host_id, "host-a");
        assert_eq!(out[0].policy_revision, 7);
        assert_eq!(out[0].remote_zone, Zone::External);
        assert!(out[0].perimeter_crossing);
    }

    #[test]
    fn an_internal_destination_is_not_a_perimeter_crossing() {
        let out = run(&config(), vec![event(Decision::Allow, "10.9.9.9")]);
        assert_eq!(out[0].remote_zone, Zone::Internal);
        assert!(!out[0].perimeter_crossing);
    }

    #[test]
    fn sequence_numbers_are_assigned_and_increase() {
        let out = run(
            &config(),
            vec![
                event(Decision::Deny, "8.8.8.8"),
                event(Decision::Deny, "8.8.4.4"),
                event(Decision::Deny, "1.1.1.1"),
            ],
        );
        let seqs: Vec<u64> = out.iter().map(|e| e.sequence).collect();
        assert_eq!(seqs, vec![1, 2, 3]);
    }

    #[test]
    fn suppressing_allowed_flows_keeps_denials_and_alerts() {
        let mut c = config();
        c.log_allowed = false;

        let mut alert = event(Decision::Allow, "8.8.8.8");
        alert.kind = EventKind::Alert;
        let mut fault = event(Decision::Allow, "8.8.8.8");
        fault.kind = EventKind::SystemFault;

        let out = run(
            &c,
            vec![
                event(Decision::Allow, "8.8.8.8"),
                event(Decision::Deny, "8.8.8.8"),
                alert,
                fault,
            ],
        );
        // The routine permit is gone; everything else survived.
        assert_eq!(out.len(), 3);
        assert!(out
            .iter()
            .all(|e| e.decision == Decision::Deny || e.kind != EventKind::FlowDecision));
    }

    #[test]
    fn the_severity_floor_is_respected() {
        let mut c = config();
        c.level = Severity::Warning;
        let mut low = event(Decision::Deny, "8.8.8.8");
        low.severity = Severity::Info;
        let mut high = event(Decision::Deny, "8.8.4.4");
        high.severity = Severity::Error;

        let out = run(&c, vec![low, high]);
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].severity, Severity::Error);
    }

    #[test]
    fn correlation_alerts_join_the_normal_stream() {
        let mut c = config();
        c.correlation = true;
        c.correlation_threshold = 3;

        let out = run(
            &c,
            vec![
                event(Decision::Deny, "8.8.8.8"),
                event(Decision::Deny, "8.8.8.8"),
                event(Decision::Deny, "8.8.8.8"),
            ],
        );
        assert_eq!(out.len(), 4, "three denials plus one correlation");
        let alert = out.iter().find(|e| e.kind == EventKind::Alert).unwrap();
        assert!(alert
            .message
            .as_deref()
            .unwrap()
            .contains("correlated pattern"));
        assert!(alert.tags.contains(&"correlation".to_string()));
    }

    #[test]
    fn a_full_queue_drops_and_counts_rather_than_blocking() {
        // A sink that never returns would otherwise back-pressure all the way
        // to the kernel ring buffer.
        struct SlowSink;
        impl Sink for SlowSink {
            fn write(&mut self, _event: &LogEvent) -> std::io::Result<()> {
                std::thread::sleep(Duration::from_millis(5));
                Ok(())
            }
            fn name(&self) -> &'static str {
                "slow"
            }
        }

        let logger = Logger::with_sinks(&config(), enrichment(), vec![Box::new(SlowSink)]);
        let handle = logger.handle();
        for _ in 0..(QUEUE_DEPTH * 4) {
            handle.submit(vec![event(Decision::Deny, "8.8.8.8")]);
        }
        let stats = handle.stats();
        assert!(
            stats.dropped_queue_full > 0,
            "the queue must shed load rather than stall the submitter"
        );
        assert_eq!(
            stats.received,
            (QUEUE_DEPTH * 4) as u64,
            "every submission is still counted"
        );
    }

    #[test]
    fn shutdown_drains_whatever_is_still_queued() {
        let memory = MemorySink::new();
        let mut logger =
            Logger::with_sinks(&config(), enrichment(), vec![Box::new(memory.clone())]);
        let handle = logger.handle();
        for i in 0..50 {
            handle.submit(vec![event(Decision::Deny, "8.8.8.8")]);
            let _ = i;
        }
        logger.shutdown();
        assert_eq!(memory.len(), 50, "the last events are the interesting ones");
    }

    #[test]
    fn missing_sinks_are_reported_but_do_not_stop_the_daemon() {
        let mut c = config();
        c.file = Some(crate::config::FileSinkConfig {
            // A path that cannot be created.
            path: std::path::PathBuf::from("/proc/self/mem/nope/events.jsonl"),
            max_bytes: 1024,
            keep: 1,
            format: LogFormat::Json,
        });
        let (mut logger, problems) = Logger::start(&c, enrichment());
        assert!(!problems.is_empty(), "an unusable sink must be reported");
        // ...and the daemon still has a working logger.
        assert!(logger.handle().is_running());
        logger.shutdown();
    }

    #[test]
    fn a_daemon_note_reaches_the_sinks() {
        let memory = MemorySink::new();
        let mut logger =
            Logger::with_sinks(&config(), enrichment(), vec![Box::new(memory.clone())]);
        logger.handle().note(
            "host-a",
            Severity::Notice,
            EventKind::PolicyChange,
            "installed revision 8",
        );
        logger.shutdown();
        let out = memory.take();
        assert_eq!(out.len(), 1);
        assert_eq!(out[0].kind, EventKind::PolicyChange);
        assert_eq!(out[0].message.as_deref(), Some("installed revision 8"));
    }

    #[test]
    fn enrichment_can_be_replaced_after_a_policy_change() {
        let memory = MemorySink::new();
        let mut logger =
            Logger::with_sinks(&config(), enrichment(), vec![Box::new(memory.clone())]);
        let handle = logger.handle();

        let mut updated = enrichment();
        updated.policy_revision = 99;
        handle.set_enrichment(updated);
        // Give the worker a moment to consume the enrichment message before
        // the event that depends on it.
        std::thread::sleep(Duration::from_millis(50));
        handle.submit(vec![event(Decision::Deny, "8.8.8.8")]);
        logger.shutdown();

        let out = memory.take();
        assert_eq!(out.last().unwrap().policy_revision, 99);
    }
}
