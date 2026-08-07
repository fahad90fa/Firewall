//! A userspace kernel-module simulator.
//!
//! # What this is, and what it is not
//!
//! This serves the **module half** of the daemon ↔ kernel control protocol
//! (`ufw_shared::protocol`) over a Unix-domain socket. A daemon pointed at that
//! socket — `ipc.endpoint = "…"` — completes the handshake, installs its
//! policy and signatures, reads statistics and changes enforcement mode exactly
//! as it would against a loaded kernel module. `ufwctl status` and the
//! dashboard report a live, connected control channel.
//!
//! It **does not filter a single packet.** There is no kernel component here:
//! nothing is attached to a netfilter hook, no traffic is inspected, and no
//! verdict is enforced. Its purpose is to make the *control plane* fully
//! operable — for development, for demonstrating the management surface, and
//! for running the daemon on a host where loading an out-of-tree kernel module
//! is not an option. So that no operator can mistake it for enforcement, it
//! identifies itself as platform [`PLATFORM`] and reports its version with a
//! `-sim` suffix; both are visible in every status view and startup log line.
//!
//! Real enforcement is the kernel module (`kernel/linux/`), loaded on a host —
//! or a throwaway VM — where that is safe to do.
//!
//! # Fidelity
//!
//! The wire format is shared with the real module through
//! `ufw_shared::protocol`, so the framing and every message body are encoded
//! and decoded by the same code both ends of a real deployment use. The
//! simulator keeps just enough state — the installed rules, the current
//! revision and mode, the last signature payload — to answer faithfully: a
//! policy install echoes back the ruleset hash the daemon computed (a corrupt
//! echo would trip the daemon's post-install check), a delta against a stale
//! base revision is rejected the way the module rejects it, and a signature
//! install is acknowledged with a real SHA-256 of the bytes received.

#![cfg(unix)]

use std::io::{self, Write};
use std::os::unix::net::{UnixListener, UnixStream};

use ufw_shared::constants;
use ufw_shared::policy_types::CompiledRule;
use ufw_shared::protocol::{
    error_codes, Capabilities, ErrorMessage, HelloAck, InstallAck, KernelStats, Message,
    SignatureInstallAck,
};

use super::read_frame;

/// Platform string reported in the handshake. Deliberately unmistakable: it
/// appears in `ufwctl status`, on the dashboard, and in the daemon's startup
/// log, so no one reads "connected" as "enforcing".
pub const PLATFORM: &str = "linux-userspace-sim";

/// Capabilities the simulator advertises.
///
/// The full set the daemon knows how to drive, so the whole control path is
/// exercised: DPI pulls a signature install, and `INCREMENTAL_UPDATE` lets the
/// daemon send deltas on later reloads rather than only full installs.
fn capabilities() -> Capabilities {
    Capabilities(
        Capabilities::IPV6
            | Capabilities::APP_IDENTITY
            | Capabilities::STREAM_REASSEMBLY
            | Capabilities::DPI
            | Capabilities::CONNTRACK
            | Capabilities::INCREMENTAL_UPDATE
            | Capabilities::SCHEDULED_RULES
            | Capabilities::INTERFACE_MATCH,
    )
}

/// Per-connection module state.
///
/// Fresh for every connection, which mirrors the real contract: a module that
/// has just (re)loaded holds nothing, and the daemon repopulates it. That is
/// what makes a reconnect against the simulator take the same
/// full-reinstall path the supervisor runs against a real reloaded module.
///
/// Only what the replies actually depend on is kept: the installed rules and
/// revision (a delta applies against them, and stats reports per-rule hits) and
/// a poll counter. The enforcement mode and default action are echoed straight
/// back in their acks rather than stored, so there is nothing else to track.
#[derive(Default)]
struct SimState {
    rules: Vec<CompiledRule>,
    revision: u64,
    /// Bumped on every stats request so the reported counters advance between
    /// polls instead of sitting frozen — enough for a dashboard to look alive.
    stats_polls: u64,
}

/// Handle one decoded request, returning the reply to send (or `None` for
/// messages that are fire-and-forget, like an identity answer).
fn handle(state: &mut SimState, message: Message) -> Option<Message> {
    match message {
        Message::Hello(_) => Some(Message::HelloAck(HelloAck {
            module_version: format!("{}-sim", constants::VERSION),
            abi_revision: constants::ABI_REVISION,
            capabilities: capabilities(),
            installed_revision: state.revision,
            platform: PLATFORM.to_string(),
        })),

        Message::PolicyInstall(policy) => {
            state.rules = policy.rules.clone();
            state.revision = policy.revision;
            // Echo the daemon's own hash. Returning anything else is exactly
            // what the daemon's post-install check is there to catch, so a
            // faithful simulator returns the value that lets the install stand.
            Some(Message::PolicyInstallAck(InstallAck {
                revision: policy.revision,
                filters_installed: policy.rules.len() as u32,
                filters_removed: 0,
                ruleset_hash: policy.ruleset_hash,
                warnings: Vec::new(),
            }))
        }

        Message::PolicyUpdate(delta) => {
            if delta.base_revision != state.revision {
                // The module rejects a delta whose base is not what it holds,
                // and the daemon falls back to a full install. Simulate that
                // rather than silently applying it to the wrong base.
                return Some(Message::Error(ErrorMessage {
                    code: error_codes::STALE_BASE_REVISION,
                    detail: format!(
                        "delta expects base revision {} but {} is installed",
                        delta.base_revision, state.revision
                    ),
                }));
            }
            state.rules.retain(|r| !delta.removed.contains(&r.id));
            for m in &delta.modified {
                if let Some(existing) = state.rules.iter_mut().find(|r| r.id == m.id) {
                    *existing = m.clone();
                }
            }
            let added = delta.added.len() as u32;
            for a in &delta.added {
                if !state.rules.iter().any(|r| r.id == a.id) {
                    state.rules.push(a.clone());
                }
            }
            state.revision = delta.new_revision;
            Some(Message::PolicyUpdateAck(InstallAck {
                revision: delta.new_revision,
                filters_installed: added,
                filters_removed: delta.removed.len() as u32,
                ruleset_hash: delta.result_hash,
                warnings: Vec::new(),
            }))
        }

        Message::PolicyFlush => {
            let removed = state.rules.len() as u32;
            state.rules.clear();
            Some(Message::PolicyInstallAck(InstallAck {
                revision: state.revision,
                filters_installed: 0,
                filters_removed: removed,
                ruleset_hash: [0u8; 32],
                warnings: Vec::new(),
            }))
        }

        Message::SignatureInstall(install) => {
            // A real module counts signatures by decoding the leading u32 the
            // daemon's encoder wrote; do the same so a payload the daemon built
            // wrongly shows here rather than being masked. The hash is a genuine
            // SHA-256 of the received bytes — the daemon compares it against its
            // own and rejects a mismatch.
            let count = install
                .payload
                .get(..4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            Some(Message::SignatureInstallAck(SignatureInstallAck {
                signatures_installed: count,
                patterns_installed: 0,
                payload_hash: ufw_shared::hash::sha256(&install.payload),
            }))
        }

        Message::StatsRequest => {
            state.stats_polls += 1;
            let flows = state.stats_polls.saturating_mul(100);
            let denied = state.stats_polls;
            let allowed = flows.saturating_sub(denied);
            let mut stats = KernelStats {
                flows_seen: flows,
                flows_allowed: allowed,
                flows_denied: denied,
                packets_seen: flows.saturating_mul(8),
                packets_allowed: allowed.saturating_mul(8),
                packets_denied: denied.saturating_mul(8),
                ..Default::default()
            };
            // One hit per installed rule, so the per-rule view is populated.
            stats.rule_hits = state
                .rules
                .iter()
                .map(|r| (r.id, state.stats_polls))
                .collect();
            Some(Message::StatsResponse(Box::new(stats)))
        }

        // The daemon holds the authoritative mode; the module just confirms it.
        Message::SetMode(mode) => Some(Message::ModeAck(mode)),

        // An identity answer is the daemon replying to a query the module would
        // have sent; the simulator sends none, so it has nothing to do with one.
        Message::IdentityResponse(_) => None,

        // Everything else is a module→daemon message the simulator never
        // receives, or one it has no reason to answer.
        _ => None,
    }
}

/// Serve one connection until the peer disconnects.
///
/// Strictly request/response: read a frame, answer it, repeat. A frame the
/// simulator cannot decode is skipped rather than fatal — the same tolerance
/// the daemon shows a bad frame — because dropping the connection over one
/// undecodable message would be a worse failure than ignoring it.
pub fn serve_connection(mut stream: UnixStream) -> io::Result<()> {
    let mut state = SimState::default();
    loop {
        let frame = match read_frame(&mut stream)? {
            Some(f) => f,
            None => return Ok(()),
        };
        let (message, seq) = match Message::decode(&frame) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(reply) = handle(&mut state, message) {
            stream.write_all(&reply.encode(seq))?;
            stream.flush()?;
        }
    }
}

/// Accept connections forever, serving each on its own thread.
///
/// One daemon holds a single long-lived connection; a reconnect opens a new one
/// and the old thread ends when its stream closes. An accept error is returned
/// rather than swallowed so the caller can report it and exit.
pub fn serve(listener: &UnixListener) -> io::Result<()> {
    for stream in listener.incoming() {
        let stream = stream?;
        std::thread::Builder::new()
            .name("ufw-kmod-sim-conn".into())
            .spawn(move || {
                let _ = serve_connection(stream);
            })?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::{KernelChannel, StreamTransport, Transport};
    use std::sync::atomic::{AtomicU32, Ordering};
    use std::sync::mpsc::channel;
    use std::time::Duration;
    use ufw_shared::policy_types::{Action, CompiledPolicy, Decision, Layer};
    use ufw_shared::protocol::EnforcementMode;

    fn unique_socket_path() -> std::path::PathBuf {
        static N: AtomicU32 = AtomicU32::new(0);
        std::env::temp_dir().join(format!(
            "ufw-kmod-sim-{}-{}.sock",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn sample_policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        p.rules
            .push(CompiledRule::new(1, "allow-loopback", Layer::Packet, Action::Allow));
        p.finalize();
        p
    }

    /// Bind, accept exactly one connection on a background thread, and return a
    /// connected daemon-side [`KernelChannel`] that has already shaken hands.
    fn connect_to_simulator() -> (KernelChannel, std::path::PathBuf) {
        let path = unique_socket_path();
        let _ = std::fs::remove_file(&path);
        let listener = UnixListener::bind(&path).expect("bind");

        std::thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                let _ = serve_connection(stream);
            }
        });

        let stream = UnixStream::connect(&path).expect("connect");
        let transport: Box<dyn Transport> = Box::new(StreamTransport::new(stream, path.to_string_lossy()));
        let (tx, _rx) = channel();
        let (channel, handshake) =
            KernelChannel::open(transport, tx, "test-host", Duration::from_secs(2))
                .expect("handshake");

        // The simulator identifies itself unambiguously.
        assert_eq!(handshake.platform, PLATFORM);
        assert!(handshake.module_version.ends_with("-sim"));
        (channel, path)
    }

    #[test]
    fn a_daemon_handshakes_and_sees_the_capabilities() {
        let (channel, path) = connect_to_simulator();
        assert!(channel.capabilities().has(Capabilities::DPI));
        assert!(channel.capabilities().has(Capabilities::INCREMENTAL_UPDATE));
        assert!(channel.is_connected());
        drop(channel);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn a_policy_install_round_trips_and_its_hash_verifies() {
        let (channel, path) = connect_to_simulator();
        let policy = sample_policy();
        let ack = channel
            .install_policy(&policy, Duration::from_secs(2))
            .expect("install");
        assert_eq!(ack.revision, policy.revision);
        assert_eq!(ack.filters_installed, 1);
        assert_eq!(ack.ruleset_hash, policy.ruleset_hash);
        drop(channel);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn signatures_install_with_a_matching_hash() {
        use crate::signatures::SignatureSet;
        let (channel, path) = connect_to_simulator();
        let payload = SignatureSet::default().encode();
        // `install_signatures` fails unless the ack hash matches the payload.
        channel
            .install_signatures(&payload, Duration::from_secs(2))
            .expect("signature install");
        drop(channel);
        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn stats_and_mode_changes_are_answered() {
        let (channel, path) = connect_to_simulator();
        let stats = channel.stats(Duration::from_secs(2)).expect("stats");
        assert!(stats.flows_seen > 0);
        let mode = channel
            .set_mode(EnforcementMode::Monitor, Duration::from_secs(2))
            .expect("set mode");
        assert_eq!(mode, EnforcementMode::Monitor);
        drop(channel);
        let _ = std::fs::remove_file(&path);
    }
}
