//! Daemon ↔ kernel IPC, driven end to end against the mock module.
//!
//! These run the real [`KernelChannel`] over the loopback transport, so the
//! framing, the multiplexer, the handshake checks and the hash verification
//! are all under test — everything except the platform's own file descriptor.

use std::sync::mpsc::channel;
use std::time::Duration;

use ufw_daemon::ipc::loopback::{self, MockKernelModule};
use ufw_daemon::ipc::{KernelChannel, KernelEvent};
use ufw_daemon::policy_store;
use ufw_shared::identity_types::AppIdentity;
use ufw_shared::policy_types::{Action, CompiledPolicy, CompiledRule, Decision, Layer, Protocol};
use ufw_shared::protocol::{Capabilities, EnforcementMode};

const TIMEOUT: Duration = Duration::from_secs(5);

fn policy(rules: usize) -> CompiledPolicy {
    let mut p = CompiledPolicy::new("integration", Decision::Deny);
    for i in 0..rules {
        let mut r = CompiledRule::new(
            (i + 1) as u32,
            format!("rule-{i}"),
            Layer::Packet,
            Action::Allow,
        );
        r.protocol = Protocol::Tcp;
        r.priority = (100 + i) as u16;
        p.rules.push(r);
    }
    p.finalize();
    p
}

struct Connected {
    channel: KernelChannel,
    events: std::sync::mpsc::Receiver<KernelEvent>,
    module: MockKernelModule,
}

fn connect() -> Connected {
    let (daemon_side, module_side) = loopback::pair();
    let module = MockKernelModule::spawn(module_side);
    let (tx, events) = channel();
    let (channel, handshake) =
        KernelChannel::open(daemon_side, tx, "integration-host", TIMEOUT).expect("handshake");
    assert_eq!(handshake.platform, "mock");
    Connected { channel, events, module }
}

#[test]
fn a_full_install_then_incremental_updates() {
    let c = connect();

    // Install five rules.
    let first = policy(5);
    let ack = c.channel.install_policy(&first, TIMEOUT).unwrap();
    assert_eq!(ack.filters_installed, 5);
    assert_eq!(c.module.installed_rule_count(), 5);
    assert_eq!(c.module.installed_revision(), first.revision);

    // Add one, remove one, modify one.
    let mut second = first.clone();
    second.revision = first.revision + 1;
    second.rules.remove(0);
    second.rules[0].priority = 999;
    second.rules.push(CompiledRule::new(
        99,
        "added",
        Layer::Packet,
        Action::Deny,
    ));
    second.finalize();

    let delta = policy_store::diff(&first, &second);
    assert_eq!(delta.added.len(), 1);
    assert_eq!(delta.modified.len(), 1);
    assert_eq!(delta.removed.len(), 1);

    let ack = c.channel.update_policy(&delta, TIMEOUT).unwrap();
    assert_eq!(ack.filters_installed, 1);
    assert_eq!(ack.filters_removed, 1);
    assert_eq!(c.module.installed_rule_count(), 5);
    assert_eq!(c.module.installed_revision(), second.revision);

    c.module.stop();
}

#[test]
fn the_module_rejects_a_delta_built_against_the_wrong_revision() {
    let c = connect();
    let first = policy(3);
    c.channel.install_policy(&first, TIMEOUT).unwrap();

    // A delta that assumes a revision the module never had.
    let mut stale_base = first.clone();
    stale_base.revision = 42;
    let mut next = first.clone();
    next.revision = 43;
    next.finalize();
    let delta = policy_store::diff(&stale_base, &next);

    let err = c.channel.update_policy(&delta, TIMEOUT).unwrap_err();
    assert!(err.to_string().contains("revision"), "{err}");
    // The module kept what it had rather than applying half a change.
    assert_eq!(c.module.installed_rule_count(), 3);

    c.module.stop();
}

#[test]
fn identity_queries_are_answered_with_the_sequence_they_arrived_on() {
    let c = connect();

    for pid in [100u32, 200, 300] {
        c.module.push_identity_query(pid);
    }

    let mut answered = 0;
    let deadline = std::time::Instant::now() + TIMEOUT;
    while answered < 3 && std::time::Instant::now() < deadline {
        match c.events.recv_timeout(Duration::from_millis(200)) {
            Ok(KernelEvent::IdentityQuery { seq, query }) => {
                let mut identity = AppIdentity::unresolved(query.pid, 0);
                identity.path = format!("/proc/{}/exe", query.pid);
                c.channel.answer_identity(seq, &identity).unwrap();
                answered += 1;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    assert_eq!(answered, 3);
    assert!(c
        .module
        .last_identity_answer_path(TIMEOUT)
        .is_some_and(|p| p.starts_with("/proc/")));

    c.module.stop();
}

#[test]
fn log_batches_arrive_asynchronously_during_a_policy_install() {
    let c = connect();

    // Push events while an install is in flight; the multiplexer has to route
    // the ack to the waiter and the events to the channel.
    for i in 0..10 {
        c.module.push_log_event(&format!("event-{i}"));
    }
    c.channel.install_policy(&policy(4), TIMEOUT).unwrap();

    let mut seen = 0;
    let deadline = std::time::Instant::now() + TIMEOUT;
    while seen < 10 && std::time::Instant::now() < deadline {
        if let Ok(KernelEvent::Logs(batch)) = c.events.recv_timeout(Duration::from_millis(200)) {
            seen += batch.len();
        }
    }
    assert_eq!(seen, 10, "no log event may be lost to a concurrent request");

    c.module.stop();
}

#[test]
fn a_hash_mismatch_is_surfaced_rather_than_accepted() {
    let (daemon_side, module_side) = loopback::pair();
    let module = MockKernelModule::spawn_with(module_side, |m| m.corrupt_hash = true);
    let (tx, _events) = channel();
    let (channel, _) = KernelChannel::open(daemon_side, tx, "h", TIMEOUT).unwrap();

    let err = channel.install_policy(&policy(2), TIMEOUT).unwrap_err();
    assert!(err.to_string().contains("hash mismatch"), "{err}");
    module.stop();
}

#[test]
fn an_abi_mismatch_prevents_the_connection_entirely() {
    let (daemon_side, module_side) = loopback::pair();
    let module = MockKernelModule::spawn_with(module_side, |m| {
        m.abi_revision = ufw_shared::constants::ABI_REVISION + 7;
    });
    let (tx, _events) = channel();
    let err = KernelChannel::open(daemon_side, tx, "h", TIMEOUT).unwrap_err();
    assert!(err.to_string().contains("ABI mismatch"), "{err}");
    module.stop();
}

#[test]
fn capabilities_are_reported_and_readable() {
    let c = connect();
    let caps = c.channel.capabilities();
    assert!(caps.has(Capabilities::APP_IDENTITY));
    assert!(caps.has(Capabilities::DPI));
    assert!(caps.names().contains(&"incremental-update"));
    c.module.stop();
}

#[test]
fn enforcement_mode_changes_reach_the_module() {
    let c = connect();
    for mode in [
        EnforcementMode::Monitor,
        EnforcementMode::EmergencyAllow,
        EnforcementMode::Enforce,
    ] {
        assert_eq!(c.channel.set_mode(mode, TIMEOUT).unwrap(), mode);
        assert_eq!(c.module.mode(), mode);
    }
    c.module.stop();
}

#[test]
fn stats_come_back_with_per_rule_counters() {
    let c = connect();
    c.channel.install_policy(&policy(3), TIMEOUT).unwrap();
    let stats = c.channel.stats(TIMEOUT).unwrap();
    assert_eq!(stats.flows_seen, 100);
    assert_eq!(stats.rule_hits.len(), 3);
    c.module.stop();
}

#[test]
fn a_flush_removes_every_rule() {
    let c = connect();
    c.channel.install_policy(&policy(6), TIMEOUT).unwrap();
    assert_eq!(c.module.installed_rule_count(), 6);
    c.channel.flush(TIMEOUT).unwrap();
    assert_eq!(c.module.installed_rule_count(), 0);
    c.module.stop();
}

#[test]
fn losing_the_module_reports_a_disconnect_and_fails_later_requests() {
    let c = connect();
    c.channel.install_policy(&policy(1), TIMEOUT).unwrap();
    c.module.stop();

    let mut disconnected = false;
    let deadline = std::time::Instant::now() + TIMEOUT;
    while std::time::Instant::now() < deadline {
        match c.events.recv_timeout(Duration::from_millis(200)) {
            Ok(KernelEvent::Disconnected(_)) => {
                disconnected = true;
                break;
            }
            Ok(_) => continue,
            Err(_) => break,
        }
    }
    assert!(disconnected, "the supervisor must learn the module went away");
    assert!(!c.channel.is_connected());
    assert!(c.channel.stats(Duration::from_millis(200)).is_err());
}

#[test]
fn a_large_policy_survives_the_round_trip_intact() {
    let c = connect();
    // Large enough to exercise multi-kilobyte framing.
    let big = policy(2000);
    let ack = c.channel.install_policy(&big, TIMEOUT).unwrap();
    assert_eq!(ack.filters_installed, 2000);
    assert_eq!(ack.ruleset_hash, big.ruleset_hash);
    assert_eq!(c.module.installed_rule_count(), 2000);
    c.module.stop();
}

#[test]
fn concurrent_requests_do_not_cross_their_replies() {
    use std::sync::Arc;

    let c = connect();
    let channel = Arc::new(c.channel);
    channel.install_policy(&policy(5), TIMEOUT).unwrap();

    // Several threads issuing requests at once: each must get its own answer,
    // which is what the sequence-number routing exists to guarantee.
    let mut handles = Vec::new();
    for _ in 0..8 {
        let channel = Arc::clone(&channel);
        handles.push(std::thread::spawn(move || {
            for _ in 0..10 {
                let stats = channel.stats(TIMEOUT).expect("stats");
                assert_eq!(stats.rule_hits.len(), 5);
            }
        }));
    }
    for h in handles {
        h.join().expect("worker");
    }
    c.module.stop();
}
