//! Assert on what the system said about a decision.
//!
//! # Why the log is worth testing separately from the verdict
//!
//! A firewall that makes the right decision and reports it wrongly is a
//! firewall whose incident response is wrong. Every downstream question — which
//! rule, which application, was it inspected, was it perimeter-crossing — is
//! answered from the log, not from the verdict. And unlike the verdict, the log
//! has no user who notices when it degrades: a field that silently stops being
//! populated produces dashboards that quietly stop being true.
//!
//! The correlation fields matter most. `rule_id` is derived from the rule's
//! *name*, so the same policy produces the same id on Windows, Linux and
//! macOS. That is the entire mechanism behind cross-platform correlation, and
//! it breaks silently: nothing fails, the aggregator simply stops grouping
//! events that belong together.

use ufw_daemon::logging::sink::MemorySink;
use ufw_shared::log_types::{EventKind, LogEvent, Severity};

/// A captured log stream.
pub struct Captured {
    pub events: Vec<LogEvent>,
}

impl Captured {
    pub fn from(sink: &MemorySink) -> Self {
        Captured { events: sink.events.lock().unwrap().clone() }
    }

    pub fn len(&self) -> usize {
        self.events.len()
    }

    pub fn is_empty(&self) -> bool {
        self.events.is_empty()
    }

    /// Events matching a predicate.
    pub fn matching(&self, f: impl Fn(&LogEvent) -> bool) -> Vec<&LogEvent> {
        self.events.iter().filter(|e| f(e)).collect()
    }

    pub fn by_rule(&self, rule_name: &str) -> Vec<&LogEvent> {
        self.matching(|e| e.rule_name == rule_name)
    }

    pub fn by_kind(&self, kind: EventKind) -> Vec<&LogEvent> {
        self.matching(|e| e.kind == kind)
    }

    pub fn at_least(&self, severity: Severity) -> Vec<&LogEvent> {
        self.matching(|e| e.severity >= severity)
    }

    /// Assert that exactly one event names this rule, and return it.
    ///
    /// "Exactly one" rather than "at least one" on purpose: a decision logged
    /// twice is a decision an aggregator will count twice, and duplicate log
    /// events are the most common way a rule appears far busier than it is.
    pub fn exactly_one_for(&self, rule_name: &str) -> &LogEvent {
        let found = self.by_rule(rule_name);
        assert_eq!(
            found.len(),
            1,
            "expected exactly one event for `{rule_name}`, found {}:\n{}",
            found.len(),
            self.render()
        );
        found[0]
    }

    pub fn assert_none_for(&self, rule_name: &str) {
        let found = self.by_rule(rule_name);
        assert!(
            found.is_empty(),
            "expected no events for `{rule_name}`, found {}:\n{}",
            found.len(),
            self.render()
        );
    }

    /// Assert every event carries the fields cross-platform correlation needs.
    ///
    /// This is the check that catches a field quietly falling out of the
    /// pipeline. Nothing else would: the events still arrive, the dashboards
    /// still render, and the grouping is simply wrong.
    pub fn assert_correlatable(&self) {
        for event in &self.events {
            assert!(
                event.timestamp_us > 0,
                "an event has no timestamp, so it cannot be ordered against \
                 events from another host:\n{event:?}"
            );
            assert!(
                !event.host_id.is_empty(),
                "an event has no host id, so a correlated finding cannot say \
                 which machine it came from:\n{event:?}"
            );
            // The join key. Derived from the rule's name, so the same policy
            // yields the same id on all three platforms.
            assert!(
                event.rule_id != 0 || event.rule_name.is_empty(),
                "an event names a rule but carries no rule id, which is the \
                 field correlation actually joins on:\n{event:?}"
            );
        }
    }

    pub fn render(&self) -> String {
        if self.events.is_empty() {
            return "  (no events)".to_string();
        }
        self.events
            .iter()
            .map(|e| format!("  {}", e.to_text()))
            .collect::<Vec<_>>()
            .join("\n")
    }
}
