//! In-process transport and a mock kernel module.
//!
//! Everything above [`Transport`] — framing, multiplexing, handshake checks,
//! hash verification, reconnection — is platform-independent, and none of it
//! should need a loaded kernel driver to test. The loopback pair provides two
//! ends of a frame carrier backed by channels, and [`MockKernelModule`]
//! implements the module half of the protocol on top of it.
//!
//! The mock is deliberately capable of *misbehaving*: it can corrupt a hash,
//! ignore a request, report a mismatched ABI, or emit an undecodable frame.
//! Those are the cases the daemon has to survive, and they are unreachable
//! with a well-behaved stub.

use std::io;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender, TryRecvError};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use ufw_shared::constants;
use ufw_shared::log_types::{FiveTuple, LogEvent};
use ufw_shared::policy_types::{CompiledPolicy, CompiledRule, Decision};
use ufw_shared::protocol::{
    Capabilities, EnforcementMode, ErrorMessage, HelloAck, IdentityQuery, InstallAck, Message,
};

use super::Transport;

/// One end of an in-process frame carrier.
#[derive(Debug)]
pub struct LoopbackTransport {
    tx: Sender<Vec<u8>>,
    rx: Arc<Mutex<Receiver<Vec<u8>>>>,
    closed: Arc<AtomicBool>,
    label: String,
}

/// Build a connected pair: `(daemon side, module side)`.
pub fn pair() -> (Box<dyn Transport>, Box<dyn Transport>) {
    let (a_tx, a_rx) = channel();
    let (b_tx, b_rx) = channel();
    let closed = Arc::new(AtomicBool::new(false));
    let a = LoopbackTransport {
        tx: a_tx,
        rx: Arc::new(Mutex::new(b_rx)),
        closed: Arc::clone(&closed),
        label: "loopback:daemon".into(),
    };
    let b = LoopbackTransport {
        tx: b_tx,
        rx: Arc::new(Mutex::new(a_rx)),
        closed,
        label: "loopback:module".into(),
    };
    (Box::new(a), Box::new(b))
}

impl Transport for LoopbackTransport {
    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        if self.closed.load(Ordering::Relaxed) {
            return Err(io::Error::new(io::ErrorKind::BrokenPipe, "loopback closed"));
        }
        self.tx
            .send(frame.to_vec())
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "peer gone"))
    }

    fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        // Poll rather than block indefinitely so `close()` can unblock a
        // reader thread without a second signalling mechanism.
        loop {
            match self.recv_frame_timeout(Duration::from_millis(20)) {
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                other => return other,
            }
        }
    }

    fn recv_frame_timeout(&mut self, timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        if self.closed.load(Ordering::Relaxed) {
            return Ok(None);
        }
        let guard = self.rx.lock().unwrap();
        match guard.recv_timeout(timeout) {
            Ok(frame) => Ok(Some(frame)),
            Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                Err(io::Error::new(io::ErrorKind::WouldBlock, "no frame"))
            }
            Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => Ok(None),
        }
    }

    fn close_unblocks_reader(&self) -> bool {
        true
    }

    fn endpoint(&self) -> String {
        self.label.clone()
    }

    fn close(&mut self) {
        self.closed.store(true, Ordering::Relaxed);
    }

    fn try_clone(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(LoopbackTransport {
            tx: self.tx.clone(),
            rx: Arc::clone(&self.rx),
            closed: Arc::clone(&self.closed),
            label: self.label.clone(),
        }))
    }
}

/// Behaviour switches for the mock module.
#[derive(Debug, Clone)]
pub struct MockBehaviour {
    pub abi_revision: u32,
    pub capabilities: Capabilities,
    /// Report a ruleset hash that does not match what was installed.
    pub corrupt_hash: bool,
    /// Never answer a stats request, so the daemon's timeout path runs.
    pub ignore_stats: bool,
    /// Acknowledge a signature install with a hash of something else, the way
    /// a module that decoded only part of the payload would. The daemon must
    /// treat that as a failure rather than as "installed".
    pub corrupt_signature_hash: bool,
}

impl Default for MockBehaviour {
    fn default() -> Self {
        MockBehaviour {
            abi_revision: constants::ABI_REVISION,
            capabilities: Capabilities(
                Capabilities::IPV6
                    | Capabilities::APP_IDENTITY
                    | Capabilities::STREAM_REASSEMBLY
                    | Capabilities::DPI
                    | Capabilities::CONNTRACK
                    | Capabilities::INCREMENTAL_UPDATE
                    | Capabilities::SCHEDULED_RULES
                    | Capabilities::INTERFACE_MATCH,
            ),
            corrupt_hash: false,
            ignore_stats: false,
            corrupt_signature_hash: false,
        }
    }
}

/// State the mock exposes to tests.
#[derive(Debug)]
struct MockState {
    rules: Vec<CompiledRule>,
    revision: u64,
    default_action: Option<Decision>,
    mode: EnforcementMode,
    identity_answers: Vec<String>,
    /// The last signature payload received, so a test can assert the module
    /// got the bytes the daemon meant to send rather than only that it
    /// answered.
    signatures: Vec<u8>,
}

impl Default for MockState {
    fn default() -> Self {
        MockState {
            rules: Vec::new(),
            revision: 0,
            default_action: None,
            mode: EnforcementMode::Enforce,
            identity_answers: Vec::new(),
            signatures: Vec::new(),
        }
    }
}

/// A kernel module that lives in this process.
pub struct MockKernelModule {
    running: Arc<AtomicBool>,
    state: Arc<Mutex<MockState>>,
    outbound: Sender<(Message, u32)>,
    seq: Arc<AtomicU32>,
    thread: Mutex<Option<std::thread::JoinHandle<()>>>,
}

impl MockKernelModule {
    pub fn spawn(transport: Box<dyn Transport>) -> Self {
        Self::spawn_with(transport, |_| {})
    }

    pub fn spawn_with(
        transport: Box<dyn Transport>,
        configure: impl FnOnce(&mut MockBehaviour),
    ) -> Self {
        let mut behaviour = MockBehaviour::default();
        configure(&mut behaviour);

        let running = Arc::new(AtomicBool::new(true));
        let state = Arc::new(Mutex::new(MockState::default()));
        let (out_tx, out_rx) = channel::<(Message, u32)>();
        let seq = Arc::new(AtomicU32::new(1));

        let thread = {
            let running = Arc::clone(&running);
            let state = Arc::clone(&state);
            std::thread::Builder::new()
                .name("mock-kernel-module".into())
                .spawn(move || module_loop(transport, behaviour, running, state, out_rx))
                .expect("spawn mock module")
        };

        MockKernelModule {
            running,
            state,
            outbound: out_tx,
            seq,
            thread: Mutex::new(Some(thread)),
        }
    }

    pub fn installed_rule_count(&self) -> usize {
        self.state.lock().unwrap().rules.len()
    }

    pub fn installed_revision(&self) -> u64 {
        self.state.lock().unwrap().revision
    }

    pub fn mode(&self) -> EnforcementMode {
        self.state.lock().unwrap().mode
    }

    /// The signature payload the module last received, byte for byte.
    pub fn installed_signatures(&self) -> Vec<u8> {
        self.state.lock().unwrap().signatures.clone()
    }

    /// Push an unsolicited log event, as the module's ring buffer drain does.
    pub fn push_log_event(&self, message: &str) {
        let mut event = LogEvent::new(
            ufw_shared::now_us(),
            "mock-host",
            Decision::Deny,
            constants::RULE_ID_DEFAULT,
            FiveTuple::default(),
        );
        event.message = Some(message.to_string());
        let _ = self.outbound.send((Message::LogEvents(vec![event]), 0));
    }

    /// Push an identity query, as an identity-cache miss does.
    pub fn push_identity_query(&self, pid: u32) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed);
        let _ = self.outbound.send((
            Message::IdentityQuery(IdentityQuery {
                pid,
                start_time_us: 0,
                hint_path: None,
                platform_token: Vec::new(),
            }),
            seq,
        ));
    }

    /// Emit a frame the daemon cannot decode.
    pub fn push_garbage(&self) {
        let _ = self.outbound.send((
            Message::Error(ErrorMessage {
                code: u32::MAX,
                detail: "__garbage__".into(),
            }),
            0,
        ));
    }

    /// Block until an identity answer arrives, returning its path.
    pub fn last_identity_answer_path(&self, timeout: Duration) -> Option<String> {
        let deadline = Instant::now() + timeout;
        loop {
            if let Some(p) = self.state.lock().unwrap().identity_answers.last().cloned() {
                return Some(p);
            }
            if Instant::now() >= deadline {
                return None;
            }
            std::thread::sleep(Duration::from_millis(5));
        }
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
        if let Some(handle) = self.thread.lock().unwrap().take() {
            let _ = handle.join();
        }
    }
}

impl Drop for MockKernelModule {
    fn drop(&mut self) {
        self.stop();
    }
}

fn module_loop(
    mut transport: Box<dyn Transport>,
    behaviour: MockBehaviour,
    running: Arc<AtomicBool>,
    state: Arc<Mutex<MockState>>,
    outbound: Receiver<(Message, u32)>,
) {
    let mut reader = match transport.try_clone() {
        Ok(t) => t,
        Err(_) => return,
    };

    while running.load(Ordering::Relaxed) {
        // Drain anything the test asked us to push.
        loop {
            match outbound.try_recv() {
                Ok((message, seq)) => {
                    let frame = if matches!(&message, Message::Error(e) if e.detail == "__garbage__")
                    {
                        // A frame with the right magic and a payload length
                        // that does not match its contents.
                        let mut f = Message::StatsRequest.encode(0);
                        f[12] = 0xFF;
                        f
                    } else {
                        message.encode(seq)
                    };
                    let _ = transport.send_frame(&frame);
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => break,
            }
        }

        let frame = match reader.recv_frame_timeout(Duration::from_millis(20)) {
            Ok(Some(f)) => f,
            Ok(None) => break,
            // Nothing to read yet: loop so `running` is rechecked and the
            // outbound queue gets another chance to drain.
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(_) => break,
        };
        let Ok((message, seq)) = Message::decode(&frame) else {
            continue;
        };

        let reply = handle(&behaviour, &state, message);
        if let Some(reply) = reply {
            if transport.send_frame(&reply.encode(seq)).is_err() {
                break;
            }
        }
    }

    running.store(false, Ordering::Relaxed);
    transport.close();
    reader.close();
}

fn handle(
    behaviour: &MockBehaviour,
    state: &Arc<Mutex<MockState>>,
    message: Message,
) -> Option<Message> {
    match message {
        Message::Hello(_) => {
            let s = state.lock().unwrap();
            Some(Message::HelloAck(HelloAck {
                module_version: constants::VERSION.to_string(),
                abi_revision: behaviour.abi_revision,
                capabilities: behaviour.capabilities,
                installed_revision: s.revision,
                platform: "mock".into(),
            }))
        }
        Message::PolicyInstall(policy) => {
            let mut s = state.lock().unwrap();
            s.rules = policy.rules.clone();
            s.revision = policy.revision;
            s.default_action = Some(policy.default_action);
            Some(Message::PolicyInstallAck(InstallAck {
                revision: policy.revision,
                filters_installed: policy.rules.len() as u32,
                filters_removed: 0,
                ruleset_hash: hash_of(&policy, behaviour.corrupt_hash),
                warnings: Vec::new(),
            }))
        }
        Message::PolicyUpdate(delta) => {
            let mut s = state.lock().unwrap();
            if delta.base_revision != s.revision {
                return Some(Message::Error(ErrorMessage {
                    code: ufw_shared::protocol::error_codes::STALE_BASE_REVISION,
                    detail: format!(
                        "delta expects base revision {} but {} is installed",
                        delta.base_revision, s.revision
                    ),
                }));
            }
            s.rules.retain(|r| !delta.removed.contains(&r.id));
            for m in &delta.modified {
                if let Some(existing) = s.rules.iter_mut().find(|r| r.id == m.id) {
                    *existing = m.clone();
                }
            }
            let added = delta.added.len() as u32;
            for a in &delta.added {
                if !s.rules.iter().any(|r| r.id == a.id) {
                    s.rules.push(a.clone());
                }
            }
            if let Some(action) = delta.default_action {
                s.default_action = Some(action);
            }
            s.revision = delta.new_revision;
            Some(Message::PolicyUpdateAck(InstallAck {
                revision: delta.new_revision,
                filters_installed: added,
                filters_removed: delta.removed.len() as u32,
                ruleset_hash: if behaviour.corrupt_hash {
                    [0xEE; 32]
                } else {
                    delta.result_hash
                },
                warnings: Vec::new(),
            }))
        }
        Message::PolicyFlush => {
            let mut s = state.lock().unwrap();
            let removed = s.rules.len() as u32;
            s.rules.clear();
            Some(Message::PolicyUpdateAck(InstallAck {
                revision: s.revision,
                filters_installed: 0,
                filters_removed: removed,
                ruleset_hash: [0u8; 32],
                warnings: Vec::new(),
            }))
        }
        Message::IdentityResponse(identity) => {
            state
                .lock()
                .unwrap()
                .identity_answers
                .push(identity.path.clone());
            None
        }
        Message::StatsRequest => {
            if behaviour.ignore_stats {
                return None;
            }
            let s = state.lock().unwrap();
            let mut stats = ufw_shared::protocol::KernelStats {
                flows_seen: 100,
                flows_allowed: 90,
                flows_denied: 10,
                ..Default::default()
            };
            stats.rule_hits = s.rules.iter().map(|r| (r.id, 1)).collect();
            Some(Message::StatsResponse(Box::new(stats)))
        }
        Message::SetMode(mode) => {
            state.lock().unwrap().mode = mode;
            Some(Message::ModeAck(mode))
        }
        Message::SignatureInstall(install) => {
            // Counting the signatures means decoding the leading u32 the way a
            // real module does, so a payload the daemon built wrongly shows up
            // here rather than at a kernel boundary.
            let count = install
                .payload
                .get(..4)
                .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
                .unwrap_or(0);
            let hash = if behaviour.corrupt_signature_hash {
                [0xEE; 32]
            } else {
                ufw_shared::hash::sha256(&install.payload)
            };
            state.lock().unwrap().signatures = install.payload.clone();
            Some(Message::SignatureInstallAck(
                ufw_shared::protocol::SignatureInstallAck {
                    signatures_installed: count,
                    patterns_installed: 0,
                    payload_hash: hash,
                },
            ))
        }
        _ => None,
    }
}

fn hash_of(policy: &CompiledPolicy, corrupt: bool) -> [u8; 32] {
    if corrupt {
        [0xEE; 32]
    } else {
        policy.ruleset_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::read_frame;

    #[test]
    fn a_loopback_pair_carries_frames_both_ways() {
        let (mut a, mut b) = pair();
        a.send_frame(b"hello").unwrap();
        assert_eq!(b.recv_frame().unwrap().as_deref(), Some(&b"hello"[..]));
        b.send_frame(b"world").unwrap();
        assert_eq!(a.recv_frame().unwrap().as_deref(), Some(&b"world"[..]));
    }

    #[test]
    fn closing_one_end_ends_the_other() {
        let (mut a, mut b) = pair();
        a.close();
        assert!(b.recv_frame().unwrap().is_none());
        assert!(a.send_frame(b"x").is_err());
    }

    #[test]
    fn stream_framing_reads_exactly_one_message() {
        let one = Message::StatsRequest.encode(7);
        let two = Message::PolicyFlush.encode(8);
        let mut joined = one.clone();
        joined.extend_from_slice(&two);

        let mut cursor = std::io::Cursor::new(joined);
        let first = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(first, one);
        let second = read_frame(&mut cursor).unwrap().unwrap();
        assert_eq!(second, two);
        assert!(read_frame(&mut cursor).unwrap().is_none());
    }

    #[test]
    fn a_truncated_stream_is_an_error_not_a_clean_end() {
        let frame = Message::StatsRequest.encode(1);
        let mut cursor = std::io::Cursor::new(frame[..constants::HEADER_LEN - 2].to_vec());
        assert!(read_frame(&mut cursor).is_err());
    }

    #[test]
    fn framing_rejects_a_bad_header_before_allocating() {
        let mut frame = Message::StatsRequest.encode(1);
        frame[0] ^= 0xFF;
        let mut cursor = std::io::Cursor::new(frame);
        let err = read_frame(&mut cursor).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidData);
    }
}
