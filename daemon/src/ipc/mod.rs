//! Daemon ↔ kernel module communication.
//!
//! # One framing, three endpoints
//!
//! The three kernel components expose different endpoints — a device object on
//! Windows, a character device on Linux, a socket in the shared app-group
//! container on macOS — but all three carry the *same* framed byte stream
//! defined in [`ufw_shared::protocol`]. That is deliberate: the framing, the
//! bounds checking and the request/response multiplexing are written once,
//! here, and the platform modules are reduced to "where is the endpoint and
//! how do I open it".
//!
//! A byte-stream endpoint is also the reason this layer is testable. The same
//! [`KernelChannel`] that drives a real driver drives [`loopback`], an
//! in-process pair backed by channels, which is what the daemon's tests and
//! the mock module run against.
//!
//! # Multiplexing
//!
//! The channel is not request/response. The module pushes log events and
//! identity queries at any time, including in the middle of a policy install.
//! So a reader thread owns the receive side and routes frames by sequence
//! number: a frame whose sequence matches an outstanding request goes to that
//! request's waiter, and everything else goes to the asynchronous handler.

use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use ufw_shared::constants;
use ufw_shared::identity_types::AppIdentity;
use ufw_shared::log_types::LogEvent;
use ufw_shared::protocol::{
    Capabilities, EnforcementMode, Hello, IdentityQuery, InstallAck, Message, MessageHeader,
    PolicyDelta,
};
use ufw_shared::policy_types::CompiledPolicy;

pub mod linux;
pub mod loopback;
pub mod macos;
pub mod windows;

// ===========================================================================
// Transport
// ===========================================================================

/// A bidirectional frame carrier.
///
/// Implementations are responsible for delivering byte strings intact and in
/// order. Everything above this trait assumes nothing else about them.
pub trait Transport: Send + std::fmt::Debug {
    /// Write one complete frame.
    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()>;
    /// Read one complete frame. Blocks; returns `Ok(None)` at end of stream.
    fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>>;
    /// Read one frame, giving up after `timeout` with
    /// [`io::ErrorKind::WouldBlock`].
    ///
    /// Transports that cannot bound a read fall back to the blocking form;
    /// the default is correct but means such a transport can only be
    /// interrupted by closing it. The loopback overrides this so a test can
    /// stop a mock module without racing.
    fn recv_frame_timeout(&mut self, _timeout: Duration) -> io::Result<Option<Vec<u8>>> {
        self.recv_frame()
    }
    /// Human-readable endpoint, for diagnostics.
    fn endpoint(&self) -> String;
    /// Best-effort shutdown, used to unblock a reader thread.
    fn close(&mut self) {}
    /// Whether [`Transport::close`] actually unblocks a reader parked in
    /// [`Transport::recv_frame`].
    ///
    /// Socket-backed transports can shut a half down; a character device
    /// cannot, and `close()` there only stops *future* reads. The channel uses
    /// this to decide whether joining the reader thread at shutdown is safe or
    /// whether it must detach it instead of hanging.
    fn close_unblocks_reader(&self) -> bool {
        false
    }
    /// A clone that can be moved to the reader thread. Implementations backed
    /// by a file descriptor duplicate it; the loopback splits its channels.
    fn try_clone(&self) -> io::Result<Box<dyn Transport>>;
}

/// Frame a byte stream: read the fixed header, then exactly `payload_len`
/// more bytes.
pub fn read_frame<R: Read>(r: &mut R) -> io::Result<Option<Vec<u8>>> {
    let mut header = [0u8; constants::HEADER_LEN];
    match read_exact_or_eof(r, &mut header)? {
        false => return Ok(None),
        true => {}
    }
    let parsed = MessageHeader::parse(&header)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    let mut frame = Vec::with_capacity(constants::HEADER_LEN + parsed.payload_len as usize);
    frame.extend_from_slice(&header);
    frame.resize(constants::HEADER_LEN + parsed.payload_len as usize, 0);
    r.read_exact(&mut frame[constants::HEADER_LEN..])?;
    Ok(Some(frame))
}

/// `Ok(false)` on a clean end of stream, `Err` on a truncated one. The
/// distinction matters: a module that exited cleanly is a reconnect, a module
/// that died mid-frame is a fault worth logging.
fn read_exact_or_eof<R: Read>(r: &mut R, buf: &mut [u8]) -> io::Result<bool> {
    let mut filled = 0;
    while filled < buf.len() {
        match r.read(&mut buf[filled..]) {
            Ok(0) if filled == 0 => return Ok(false),
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "stream ended mid-frame",
                ))
            }
            Ok(n) => filled += n,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(true)
}

/// A [`Transport`] over any read/write pair, used by every real platform.
#[derive(Debug)]
pub struct StreamTransport<S> {
    stream: S,
    endpoint: String,
}

impl<S> StreamTransport<S> {
    pub fn new(stream: S, endpoint: impl Into<String>) -> Self {
        StreamTransport { stream, endpoint: endpoint.into() }
    }
}

impl<S: Read + Write + Send + StreamClone + std::fmt::Debug + 'static> Transport
    for StreamTransport<S>
{
    fn send_frame(&mut self, frame: &[u8]) -> io::Result<()> {
        self.stream.write_all(frame)?;
        self.stream.flush()
    }

    fn recv_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        read_frame(&mut self.stream)
    }

    fn endpoint(&self) -> String {
        self.endpoint.clone()
    }

    fn try_clone(&self) -> io::Result<Box<dyn Transport>> {
        Ok(Box::new(StreamTransport {
            stream: self.stream.stream_clone()?,
            endpoint: self.endpoint.clone(),
        }))
    }

    fn close(&mut self) {
        self.stream.stream_shutdown();
    }

    fn close_unblocks_reader(&self) -> bool {
        S::SHUTDOWN_UNBLOCKS_READER
    }
}

/// Streams that can be duplicated for the reader thread.
pub trait StreamClone: Sized {
    /// Whether `stream_shutdown` wakes a reader blocked on this stream.
    const SHUTDOWN_UNBLOCKS_READER: bool;

    fn stream_clone(&self) -> io::Result<Self>;

    /// Best-effort "stop using this stream". Sockets can shut a half down; a
    /// character device has no equivalent in `std`, so the implementation is
    /// empty and `SHUTDOWN_UNBLOCKS_READER` says so.
    fn stream_shutdown(&self) {}
}

impl StreamClone for std::fs::File {
    const SHUTDOWN_UNBLOCKS_READER: bool = false;

    fn stream_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }
}

impl StreamClone for std::net::TcpStream {
    const SHUTDOWN_UNBLOCKS_READER: bool = true;

    fn stream_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn stream_shutdown(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

#[cfg(unix)]
impl StreamClone for std::os::unix::net::UnixStream {
    const SHUTDOWN_UNBLOCKS_READER: bool = true;

    fn stream_clone(&self) -> io::Result<Self> {
        self.try_clone()
    }

    fn stream_shutdown(&self) {
        let _ = self.shutdown(std::net::Shutdown::Both);
    }
}

// ===========================================================================
// Platform selection
// ===========================================================================

/// Open the platform's kernel endpoint.
///
/// `endpoint` overrides the platform default when non-empty, which is what
/// makes it possible to point a daemon at a test harness.
pub fn connect(endpoint: &str) -> io::Result<Box<dyn Transport>> {
    #[cfg(target_os = "windows")]
    {
        return windows::connect(endpoint);
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return linux::connect(endpoint);
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::connect(endpoint);
    }
    #[allow(unreachable_code)]
    {
        let _ = endpoint;
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "this build has no kernel backend for the host platform",
        ))
    }
}

/// The platform default endpoint, for diagnostics and `ufwctl status`.
pub fn default_endpoint() -> &'static str {
    #[cfg(target_os = "windows")]
    {
        return windows::DEFAULT_ENDPOINT;
    }
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        return linux::DEFAULT_ENDPOINT;
    }
    #[cfg(any(target_os = "macos", target_os = "ios"))]
    {
        return macos::DEFAULT_ENDPOINT;
    }
    #[allow(unreachable_code)]
    {
        "<unsupported platform>"
    }
}

// ===========================================================================
// Channel
// ===========================================================================

/// Asynchronous messages the module can push at any time.
pub enum KernelEvent {
    Logs(Vec<LogEvent>),
    IdentityQuery { seq: u32, query: IdentityQuery },
    /// The module reported a problem out of band.
    Error { code: u32, detail: String },
    /// The transport ended. The supervisor reconnects if configured to.
    Disconnected(Option<String>),
}

/// A live connection to a kernel module.
pub struct KernelChannel {
    writer: Mutex<Box<dyn Transport>>,
    seq: AtomicU32,
    pending: Arc<Mutex<HashMap<u32, Sender<Message>>>>,
    running: Arc<AtomicBool>,
    endpoint: String,
    capabilities: Capabilities,
    module_version: String,
    installed_revision: u64,
    reader: Option<std::thread::JoinHandle<()>>,
}

impl std::fmt::Debug for KernelChannel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("KernelChannel")
            .field("endpoint", &self.endpoint)
            .field("capabilities", &self.capabilities.names())
            .field("module_version", &self.module_version)
            .finish()
    }
}

/// Result of connecting and shaking hands.
#[derive(Debug, Clone)]
pub struct Handshake {
    pub module_version: String,
    pub capabilities: Capabilities,
    pub installed_revision: u64,
    pub platform: String,
}

impl KernelChannel {
    /// Take ownership of a transport, start the reader thread, and shake
    /// hands.
    ///
    /// `events` receives everything the module pushes asynchronously.
    pub fn open(
        transport: Box<dyn Transport>,
        events: Sender<KernelEvent>,
        host_id: &str,
        timeout: Duration,
    ) -> io::Result<(Self, Handshake)> {
        let endpoint = transport.endpoint();
        let reader_transport = transport.try_clone()?;

        let pending: Arc<Mutex<HashMap<u32, Sender<Message>>>> =
            Arc::new(Mutex::new(HashMap::new()));
        let running = Arc::new(AtomicBool::new(true));

        let reader = {
            let pending = Arc::clone(&pending);
            let running = Arc::clone(&running);
            std::thread::Builder::new()
                .name("ufw-ipc-reader".into())
                .spawn(move || reader_loop(reader_transport, pending, events, running))?
        };

        let mut channel = KernelChannel {
            writer: Mutex::new(transport),
            seq: AtomicU32::new(1),
            pending,
            running,
            endpoint,
            capabilities: Capabilities::default(),
            module_version: String::new(),
            installed_revision: 0,
            reader: Some(reader),
        };

        let hello = Message::Hello(Hello {
            daemon_version: constants::VERSION.to_string(),
            abi_revision: constants::ABI_REVISION,
            host_id: host_id.to_string(),
            pid: std::process::id(),
        });

        let ack = match channel.request(hello, timeout)? {
            Message::HelloAck(a) => a,
            Message::Error(e) => {
                return Err(io::Error::other(format!(
                    "kernel module rejected the handshake: {} ({})",
                    e.detail, e.code
                )))
            }
            other => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("expected a hello-ack, got {}", other.msg_type().as_str()),
                ))
            }
        };

        // An ABI mismatch means the two sides disagree about the layout of
        // every structure that follows. Refusing here is the only safe
        // outcome; continuing would install rules the module reads as
        // something else.
        if ack.abi_revision != constants::ABI_REVISION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ABI mismatch: daemon speaks revision {}, kernel module speaks {}. \
                     Reinstall the matching kernel component.",
                    constants::ABI_REVISION,
                    ack.abi_revision
                ),
            ));
        }

        channel.capabilities = ack.capabilities;
        channel.module_version = ack.module_version.clone();
        channel.installed_revision = ack.installed_revision;

        let handshake = Handshake {
            module_version: ack.module_version,
            capabilities: ack.capabilities,
            installed_revision: ack.installed_revision,
            platform: ack.platform,
        };
        Ok((channel, handshake))
    }

    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    pub fn capabilities(&self) -> Capabilities {
        self.capabilities
    }

    pub fn module_version(&self) -> &str {
        &self.module_version
    }

    pub fn installed_revision(&self) -> u64 {
        self.installed_revision
    }

    pub fn is_connected(&self) -> bool {
        self.running.load(Ordering::Relaxed)
    }

    fn next_seq(&self) -> u32 {
        // Sequence 0 is reserved for unsolicited module messages, so wrapping
        // must skip it.
        let mut s = self.seq.fetch_add(1, Ordering::Relaxed);
        if s == 0 {
            s = self.seq.fetch_add(1, Ordering::Relaxed);
        }
        s
    }

    /// Send a message and wait for the reply carrying the same sequence.
    pub fn request(&self, message: Message, timeout: Duration) -> io::Result<Message> {
        let seq = self.next_seq();
        let (tx, rx) = channel();
        self.pending.lock().unwrap().insert(seq, tx);

        let result = self.send_with_seq(&message, seq).and_then(|()| {
            rx.recv_timeout(timeout).map_err(|e| match e {
                RecvTimeoutError::Timeout => io::Error::new(
                    io::ErrorKind::TimedOut,
                    format!(
                        "kernel module did not answer {} within {}ms",
                        message.msg_type().as_str(),
                        timeout.as_millis()
                    ),
                ),
                RecvTimeoutError::Disconnected => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "kernel channel closed")
                }
            })
        });

        self.pending.lock().unwrap().remove(&seq);
        result
    }

    /// Send without waiting. Used for identity responses, which are replies to
    /// the *module's* request and carry its sequence number.
    pub fn send_with_seq(&self, message: &Message, seq: u32) -> io::Result<()> {
        let frame = message.encode(seq);
        self.writer.lock().unwrap().send_frame(&frame)
    }

    // --- high-level operations ------------------------------------------

    pub fn install_policy(&self, policy: &CompiledPolicy, timeout: Duration) -> io::Result<InstallAck> {
        match self.request(Message::PolicyInstall(Box::new(policy.clone())), timeout)? {
            Message::PolicyInstallAck(ack) => self.check_hash(ack, policy.ruleset_hash),
            Message::Error(e) => Err(io::Error::other(format!("policy install failed: {}", e.detail))),
            other => Err(unexpected(other)),
        }
    }

    pub fn update_policy(&self, delta: &PolicyDelta, timeout: Duration) -> io::Result<InstallAck> {
        match self.request(Message::PolicyUpdate(Box::new(delta.clone())), timeout)? {
            Message::PolicyUpdateAck(ack) => self.check_hash(ack, delta.result_hash),
            Message::Error(e) => Err(io::Error::other(format!("policy update failed: {}", e.detail))),
            other => Err(unexpected(other)),
        }
    }

    /// Ship the DPI signature set.
    ///
    /// Separate from the policy install because the two change on different
    /// schedules: a policy is revised when the deployment changes, a signature
    /// set when the threat intelligence does. Coupling them would make every
    /// signature drop a policy revision.
    ///
    /// The ack carries a hash of what the module decoded. A module that read
    /// half the set and stopped would otherwise report success, and the
    /// operator would believe traffic was being inspected against signatures
    /// it never loaded.
    pub fn install_signatures(
        &self,
        payload: &[u8],
        timeout: Duration,
    ) -> io::Result<ufw_shared::protocol::SignatureInstallAck> {
        let expected = ufw_shared::hash::sha256(payload);
        let message = Message::SignatureInstall(Box::new(
            ufw_shared::protocol::SignatureInstall { payload: payload.to_vec() },
        ));
        match self.request(message, timeout)? {
            Message::SignatureInstallAck(ack) => {
                if ack.payload_hash != expected {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        format!(
                            "signature payload hash mismatch: daemon sent {}, module \
                             reports {}",
                            ufw_shared::hash::hex(&expected),
                            ufw_shared::hash::hex(&ack.payload_hash)
                        ),
                    ));
                }
                Ok(ack)
            }
            Message::Error(e) => Err(io::Error::other(format!(
                "signature install failed: {}",
                e.detail
            ))),
            other => Err(unexpected(other)),
        }
    }

    /// A module whose recomputed hash differs from ours has ended up with a
    /// different rule set than we think it has. That is unrecoverable at this
    /// level, so it is surfaced as an error and the supervisor falls back to a
    /// full install.
    fn check_hash(&self, ack: InstallAck, expected: [u8; 32]) -> io::Result<InstallAck> {
        if ack.ruleset_hash != expected {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "ruleset hash mismatch after install: daemon has {}, module reports {}",
                    ufw_shared::hash::hex(&expected),
                    ufw_shared::hash::hex(&ack.ruleset_hash)
                ),
            ));
        }
        Ok(ack)
    }

    pub fn answer_identity(&self, seq: u32, identity: &AppIdentity) -> io::Result<()> {
        self.send_with_seq(&Message::IdentityResponse(Box::new(identity.clone())), seq)
    }

    pub fn stats(&self, timeout: Duration) -> io::Result<ufw_shared::protocol::KernelStats> {
        match self.request(Message::StatsRequest, timeout)? {
            Message::StatsResponse(s) => Ok(*s),
            other => Err(unexpected(other)),
        }
    }

    pub fn set_mode(&self, mode: EnforcementMode, timeout: Duration) -> io::Result<EnforcementMode> {
        match self.request(Message::SetMode(mode), timeout)? {
            Message::ModeAck(m) => Ok(m),
            other => Err(unexpected(other)),
        }
    }

    pub fn flush(&self, timeout: Duration) -> io::Result<()> {
        match self.request(Message::PolicyFlush, timeout)? {
            Message::PolicyUpdateAck(_) | Message::PolicyInstallAck(_) => Ok(()),
            Message::Error(e) => Err(io::Error::other(e.detail)),
            other => Err(unexpected(other)),
        }
    }

    /// Stop the reader thread and close the transport.
    ///
    /// The reader is only joined when the transport can actually be
    /// interrupted. On a character-device transport a blocked `read(2)` cannot
    /// be woken from `std`, so joining would hang the daemon's own shutdown;
    /// the thread is detached instead and dies when its descriptor closes or
    /// the process exits.
    pub fn shutdown(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        let joinable = {
            let mut w = self.writer.lock().unwrap();
            w.close();
            w.close_unblocks_reader()
        };
        // Waiters would otherwise block until their timeout.
        self.pending.lock().unwrap().clear();
        match self.reader.take() {
            Some(handle) if joinable => {
                let _ = handle.join();
            }
            _ => {}
        }
    }
}

impl Drop for KernelChannel {
    fn drop(&mut self) {
        self.running.store(false, Ordering::Relaxed);
        if let Ok(mut w) = self.writer.lock() {
            w.close();
        }
    }
}

fn unexpected(m: Message) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidData,
        format!("unexpected message from kernel module: {}", m.msg_type().as_str()),
    )
}

fn reader_loop(
    mut transport: Box<dyn Transport>,
    pending: Arc<Mutex<HashMap<u32, Sender<Message>>>>,
    events: Sender<KernelEvent>,
    running: Arc<AtomicBool>,
) {
    let reason = loop {
        if !running.load(Ordering::Relaxed) {
            break None;
        }
        let frame = match transport.recv_frame() {
            Ok(Some(f)) => f,
            Ok(None) => break None,
            Err(e) if e.kind() == io::ErrorKind::Interrupted => continue,
            Err(e) => break Some(e.to_string()),
        };

        let (message, seq) = match Message::decode(&frame) {
            Ok(v) => v,
            Err(e) => {
                // A malformed frame is a protocol fault, not a reason to drop
                // the connection: the next frame may well be fine, and tearing
                // down enforcement over one bad message would be worse.
                let _ = events.send(KernelEvent::Error {
                    code: ufw_shared::protocol::error_codes::INTERNAL,
                    detail: format!("undecodable frame from kernel module: {e}"),
                });
                continue;
            }
        };

        // A frame whose sequence matches an outstanding request is its reply.
        if seq != 0 {
            let waiter = pending.lock().unwrap().remove(&seq);
            if let Some(tx) = waiter {
                let _ = tx.send(message);
                continue;
            }
        }

        let event = match message {
            Message::LogEvents(v) => KernelEvent::Logs(v),
            Message::IdentityQuery(q) => KernelEvent::IdentityQuery { seq, query: q },
            Message::Error(e) => KernelEvent::Error { code: e.code, detail: e.detail },
            other => KernelEvent::Error {
                code: ufw_shared::protocol::error_codes::INTERNAL,
                detail: format!(
                    "unsolicited {} from kernel module",
                    other.msg_type().as_str()
                ),
            },
        };
        if events.send(event).is_err() {
            break None;
        }
    };

    running.store(false, Ordering::Relaxed);
    let _ = events.send(KernelEvent::Disconnected(reason));
}

/// Convenience wrapper: an event receiver paired with its channel.
pub struct Connection {
    pub channel: KernelChannel,
    pub events: Receiver<KernelEvent>,
    pub handshake: Handshake,
}

/// Connect to the platform endpoint and shake hands.
pub fn establish(endpoint: &str, host_id: &str, timeout: Duration) -> io::Result<Connection> {
    let transport = connect(endpoint)?;
    let (tx, rx) = channel();
    let (channel, handshake) = KernelChannel::open(transport, tx, host_id, timeout)?;
    Ok(Connection { channel, events: rx, handshake })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ipc::loopback::MockKernelModule;
    use ufw_shared::policy_types::{Action, CompiledRule, Decision, Layer};

    fn sample_policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("t", Decision::Deny);
        p.rules
            .push(CompiledRule::new(1, "a", Layer::Packet, Action::Allow));
        p.finalize();
        p
    }

    fn connect_mock() -> (KernelChannel, Receiver<KernelEvent>, MockKernelModule) {
        let (daemon_side, module_side) = loopback::pair();
        let module = MockKernelModule::spawn(module_side);
        let (tx, rx) = channel();
        let (channel, handshake) =
            KernelChannel::open(daemon_side, tx, "test-host", Duration::from_secs(2))
                .expect("handshake");
        assert_eq!(handshake.platform, "mock");
        (channel, rx, module)
    }

    #[test]
    fn handshake_reports_module_capabilities() {
        let (channel, _rx, module) = connect_mock();
        assert!(channel.capabilities().has(Capabilities::APP_IDENTITY));
        assert_eq!(channel.installed_revision(), 0);
        assert!(channel.is_connected());
        drop(channel);
        module.stop();
    }

    #[test]
    fn abi_mismatch_refuses_to_proceed() {
        let (daemon_side, module_side) = loopback::pair();
        let module = MockKernelModule::spawn_with(module_side, |m| {
            m.abi_revision = constants::ABI_REVISION + 1;
        });
        let (tx, _rx) = channel();
        let err = KernelChannel::open(daemon_side, tx, "h", Duration::from_secs(2))
            .expect_err("mismatched ABI must be refused");
        assert!(err.to_string().contains("ABI mismatch"), "{err}");
        module.stop();
    }

    #[test]
    fn policy_install_round_trips_and_verifies_the_hash() {
        let (channel, _rx, module) = connect_mock();
        let policy = sample_policy();
        let ack = channel
            .install_policy(&policy, Duration::from_secs(2))
            .expect("install");
        assert_eq!(ack.revision, policy.revision);
        assert_eq!(ack.filters_installed, 1);
        assert_eq!(ack.ruleset_hash, policy.ruleset_hash);
        assert_eq!(module.installed_rule_count(), 1);
        module.stop();
    }

    #[test]
    fn a_hash_mismatch_is_reported_rather_than_ignored() {
        let (daemon_side, module_side) = loopback::pair();
        let module = MockKernelModule::spawn_with(module_side, |m| m.corrupt_hash = true);
        let (tx, _rx) = channel();
        let (channel, _) =
            KernelChannel::open(daemon_side, tx, "h", Duration::from_secs(2)).unwrap();
        let err = channel
            .install_policy(&sample_policy(), Duration::from_secs(2))
            .expect_err("mismatched hash must surface");
        assert!(err.to_string().contains("hash mismatch"), "{err}");
        module.stop();
    }

    #[test]
    fn asynchronous_log_events_reach_the_event_channel() {
        let (channel, rx, module) = connect_mock();
        module.push_log_event("blocked something");
        let event = rx.recv_timeout(Duration::from_secs(2)).expect("event");
        match event {
            KernelEvent::Logs(v) => {
                assert_eq!(v.len(), 1);
                assert_eq!(v[0].message.as_deref(), Some("blocked something"));
            }
            _ => panic!("expected log events"),
        }
        drop(channel);
        module.stop();
    }

    #[test]
    fn identity_queries_carry_their_sequence_for_the_reply() {
        let (channel, rx, module) = connect_mock();
        module.push_identity_query(4242);
        let event = rx.recv_timeout(Duration::from_secs(2)).expect("event");
        let (seq, query) = match event {
            KernelEvent::IdentityQuery { seq, query } => (seq, query),
            _ => panic!("expected an identity query"),
        };
        assert_eq!(query.pid, 4242);
        assert_ne!(seq, 0, "the module must number its own requests");

        let mut identity = AppIdentity::unresolved(4242, 0);
        identity.path = "/usr/bin/probe".into();
        channel.answer_identity(seq, &identity).expect("answer");

        assert_eq!(
            module.last_identity_answer_path(Duration::from_secs(2)),
            Some("/usr/bin/probe".to_string())
        );
        module.stop();
    }

    #[test]
    fn a_request_times_out_rather_than_blocking_forever() {
        let (daemon_side, module_side) = loopback::pair();
        let module = MockKernelModule::spawn_with(module_side, |m| m.ignore_stats = true);
        let (tx, _rx) = channel();
        let (channel, _) =
            KernelChannel::open(daemon_side, tx, "h", Duration::from_secs(2)).unwrap();
        let err = channel
            .stats(Duration::from_millis(100))
            .expect_err("must time out");
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        module.stop();
    }

    #[test]
    fn a_disconnect_is_reported_to_the_supervisor() {
        let (channel, rx, module) = connect_mock();
        module.stop();
        let mut saw_disconnect = false;
        while let Ok(event) = rx.recv_timeout(Duration::from_secs(2)) {
            if matches!(event, KernelEvent::Disconnected(_)) {
                saw_disconnect = true;
                break;
            }
        }
        assert!(saw_disconnect);
        assert!(!channel.is_connected());
    }

    #[test]
    fn incremental_updates_are_applied_by_the_module() {
        let (channel, _rx, module) = connect_mock();
        let policy = sample_policy();
        channel
            .install_policy(&policy, Duration::from_secs(2))
            .unwrap();

        let mut next = policy.clone();
        next.revision = 2;
        next.rules
            .push(CompiledRule::new(2, "b", Layer::Packet, Action::Deny));
        next.finalize();

        let delta = crate::policy_store::diff(&policy, &next);
        let ack = channel.update_policy(&delta, Duration::from_secs(2)).unwrap();
        assert_eq!(ack.filters_installed, 1);
        assert_eq!(module.installed_rule_count(), 2);
        module.stop();
    }

    #[test]
    fn a_stale_base_revision_is_rejected_by_the_module() {
        let (channel, _rx, module) = connect_mock();
        channel
            .install_policy(&sample_policy(), Duration::from_secs(2))
            .unwrap();

        let bogus = PolicyDelta {
            base_revision: 99,
            new_revision: 100,
            added: Vec::new(),
            modified: Vec::new(),
            removed: Vec::new(),
            default_action: None,
            result_hash: [0u8; 32],
        };
        let err = channel
            .update_policy(&bogus, Duration::from_secs(2))
            .expect_err("stale base revision must be rejected");
        assert!(err.to_string().contains("revision"), "{err}");
        module.stop();
    }

    #[test]
    fn enforcement_mode_can_be_changed() {
        let (channel, _rx, module) = connect_mock();
        let mode = channel
            .set_mode(EnforcementMode::Monitor, Duration::from_secs(2))
            .unwrap();
        assert_eq!(mode, EnforcementMode::Monitor);
        assert_eq!(module.mode(), EnforcementMode::Monitor);
        module.stop();
    }

    #[test]
    fn a_malformed_frame_does_not_kill_the_connection() {
        let (channel, rx, module) = connect_mock();
        module.push_garbage();
        // The daemon reports the fault...
        let mut saw_error = false;
        for _ in 0..3 {
            match rx.recv_timeout(Duration::from_secs(2)) {
                Ok(KernelEvent::Error { detail, .. }) if detail.contains("undecodable") => {
                    saw_error = true;
                    break;
                }
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        assert!(saw_error);
        // ...and the channel still works.
        assert!(channel.stats(Duration::from_secs(2)).is_ok());
        module.stop();
    }
}
