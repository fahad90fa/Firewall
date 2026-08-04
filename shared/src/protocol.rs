//! Daemon ↔ kernel IPC message definitions and their binary encoding.
//!
//! The same message set travels over three very different transports — IOCTLs
//! on Windows, generic netlink on Linux, XPC on macOS — so the framing is kept
//! transport-independent: a fixed 16-byte header followed by a length-delimited
//! payload. Each transport is responsible only for delivering that byte string
//! intact.
//!
//! # Encoding rules
//!
//! * Everything is little-endian. Every supported platform is little-endian,
//!   and byte-swapping in a kernel hot path for a portability case that does
//!   not exist would be waste.
//! * Strings are `u16` byte length followed by UTF-8. Not NUL-terminated: the
//!   C side reads them as counted buffers, which removes a whole class of
//!   parsing bug from the kernel module.
//! * Optionals are a `u8` presence tag followed by the value when present.
//! * Every length is bounds-checked against a constant from
//!   [`crate::constants`] *before* allocation, so a malformed message from a
//!   compromised peer cannot drive an unbounded allocation.
//!
//! # Header layout
//!
//! ```text
//!  0      3 4    5 6      7 8         11 12        15
//! +--------+------+--------+------------+------------+
//! | magic  | ver  | type   |    seq     | payload_len|
//! +--------+------+--------+------------+------------+
//! ```

use crate::constants;
use crate::identity_types::AppIdentity;
pub use crate::identity_types::IdentityQuery;
use crate::log_types::LogEvent;
use crate::policy_types::{CompiledPolicy, CompiledRule, Decision};

use std::fmt;

// ===========================================================================
// Errors
// ===========================================================================

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtoError {
    /// Ran out of bytes mid-field.
    UnexpectedEof,
    /// Framing magic did not match, i.e. this is not one of our messages.
    BadMagic(u32),
    /// Peer speaks a protocol or policy version we do not.
    UnsupportedVersion(u16),
    UnknownMessageType(u16),
    InvalidUtf8,
    /// A length field exceeded the corresponding constant limit.
    TooLarge(usize),
    /// Structurally valid but semantically impossible.
    Malformed(&'static str),
}

impl fmt::Display for ProtoError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ProtoError::UnexpectedEof => f.write_str("truncated message"),
            ProtoError::BadMagic(m) => write!(f, "bad framing magic 0x{m:08x}"),
            ProtoError::UnsupportedVersion(v) => write!(f, "unsupported version {v}"),
            ProtoError::UnknownMessageType(t) => write!(f, "unknown message type {t}"),
            ProtoError::InvalidUtf8 => f.write_str("string field is not valid UTF-8"),
            ProtoError::TooLarge(n) => write!(f, "length {n} exceeds protocol limit"),
            ProtoError::Malformed(m) => write!(f, "malformed message: {m}"),
        }
    }
}

impl std::error::Error for ProtoError {}

// ===========================================================================
// Primitive codec
// ===========================================================================

/// Little-endian byte writer.
#[derive(Debug, Default)]
pub struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    pub fn new() -> Self {
        Writer {
            buf: Vec::with_capacity(256),
        }
    }

    pub fn with_capacity(n: usize) -> Self {
        Writer {
            buf: Vec::with_capacity(n),
        }
    }

    pub fn finish(self) -> Vec<u8> {
        self.buf
    }

    pub fn len(&self) -> usize {
        self.buf.len()
    }

    pub fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.buf
    }

    pub fn u8(&mut self, v: u8) {
        self.buf.push(v);
    }

    pub fn bool(&mut self, v: bool) {
        self.buf.push(v as u8);
    }

    pub fn u16(&mut self, v: u16) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u32(&mut self, v: u32) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn u64(&mut self, v: u64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    pub fn i64(&mut self, v: i64) {
        self.buf.extend_from_slice(&v.to_le_bytes());
    }

    /// Fixed-width bytes, no length prefix.
    pub fn raw(&mut self, v: &[u8]) {
        self.buf.extend_from_slice(v);
    }

    /// `u32` length prefix followed by bytes.
    pub fn bytes(&mut self, v: &[u8]) {
        self.u32(v.len() as u32);
        self.buf.extend_from_slice(v);
    }

    /// `u16` length prefix followed by UTF-8.
    ///
    /// Strings longer than [`constants::MAX_STRING_LEN`] are truncated on a
    /// character boundary rather than rejected: every string on this channel is
    /// a diagnostic label (a rule name, a path), and losing the tail of a
    /// pathological path is preferable to failing an entire policy install.
    pub fn string(&mut self, v: &str) {
        let mut s = v;
        if s.len() > constants::MAX_STRING_LEN {
            let mut end = constants::MAX_STRING_LEN;
            while end > 0 && !s.is_char_boundary(end) {
                end -= 1;
            }
            s = &s[..end];
        }
        self.u16(s.len() as u16);
        self.buf.extend_from_slice(s.as_bytes());
    }

    pub fn opt_string(&mut self, v: Option<&str>) {
        match v {
            Some(s) => {
                self.u8(1);
                self.string(s);
            }
            None => self.u8(0),
        }
    }

    pub fn string_list<S: AsRef<str>>(&mut self, v: &[S]) {
        self.u16(v.len() as u16);
        for s in v {
            self.string(s.as_ref());
        }
    }

    /// Reserve space for a `u32` that will be back-patched with
    /// [`Writer::patch_u32`]; returns the offset of the placeholder.
    pub fn reserve_u32(&mut self) -> usize {
        let at = self.buf.len();
        self.u32(0);
        at
    }

    pub fn patch_u32(&mut self, at: usize, v: u32) {
        self.buf[at..at + 4].copy_from_slice(&v.to_le_bytes());
    }
}

/// Little-endian byte reader with bounds checking on every access.
#[derive(Debug)]
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Reader { buf, pos: 0 }
    }

    pub fn position(&self) -> usize {
        self.pos
    }

    pub fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        if self.remaining() < n {
            return Err(ProtoError::UnexpectedEof);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    pub fn u8(&mut self) -> Result<u8, ProtoError> {
        Ok(self.take(1)?[0])
    }

    pub fn bool(&mut self) -> Result<bool, ProtoError> {
        Ok(self.u8()? != 0)
    }

    pub fn u16(&mut self) -> Result<u16, ProtoError> {
        let b = self.take(2)?;
        Ok(u16::from_le_bytes([b[0], b[1]]))
    }

    pub fn u32(&mut self) -> Result<u32, ProtoError> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
    }

    pub fn u64(&mut self) -> Result<u64, ProtoError> {
        let b = self.take(8)?;
        Ok(u64::from_le_bytes([
            b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7],
        ]))
    }

    pub fn i64(&mut self) -> Result<i64, ProtoError> {
        Ok(self.u64()? as i64)
    }

    pub fn raw(&mut self, n: usize) -> Result<&'a [u8], ProtoError> {
        self.take(n)
    }

    pub fn bytes(&mut self) -> Result<&'a [u8], ProtoError> {
        let n = self.u32()? as usize;
        if n > constants::MAX_MESSAGE_PAYLOAD {
            return Err(ProtoError::TooLarge(n));
        }
        self.take(n)
    }

    pub fn string(&mut self) -> Result<String, ProtoError> {
        let n = self.u16()? as usize;
        if n > constants::MAX_STRING_LEN {
            return Err(ProtoError::TooLarge(n));
        }
        let b = self.take(n)?;
        std::str::from_utf8(b)
            .map(|s| s.to_string())
            .map_err(|_| ProtoError::InvalidUtf8)
    }

    pub fn opt_string(&mut self) -> Result<Option<String>, ProtoError> {
        if self.u8()? != 0 {
            Ok(Some(self.string()?))
        } else {
            Ok(None)
        }
    }

    pub fn string_list(&mut self) -> Result<Vec<String>, ProtoError> {
        let n = self.u16()? as usize;
        // Bound the pre-allocation by what is actually left in the buffer: a
        // hostile `n` of 65535 must not reserve 65535 Strings up front.
        let mut v = Vec::with_capacity(n.min(self.remaining() / 2 + 1));
        for _ in 0..n {
            v.push(self.string()?);
        }
        Ok(v)
    }
}

// ===========================================================================
// Header
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MessageHeader {
    pub magic: u32,
    pub version: u16,
    pub msg_type: u16,
    pub seq: u32,
    pub payload_len: u32,
}

impl MessageHeader {
    pub fn parse(buf: &[u8]) -> Result<Self, ProtoError> {
        if buf.len() < constants::HEADER_LEN {
            return Err(ProtoError::UnexpectedEof);
        }
        let mut r = Reader::new(buf);
        let magic = r.u32()?;
        if magic != constants::PROTOCOL_MAGIC {
            return Err(ProtoError::BadMagic(magic));
        }
        let version = r.u16()?;
        if version != constants::PROTOCOL_VERSION {
            return Err(ProtoError::UnsupportedVersion(version));
        }
        let msg_type = r.u16()?;
        let seq = r.u32()?;
        let payload_len = r.u32()?;
        if payload_len as usize > constants::MAX_MESSAGE_PAYLOAD {
            return Err(ProtoError::TooLarge(payload_len as usize));
        }
        Ok(MessageHeader {
            magic,
            version,
            msg_type,
            seq,
            payload_len,
        })
    }

    pub fn write(&self, w: &mut Writer) {
        w.u32(self.magic);
        w.u16(self.version);
        w.u16(self.msg_type);
        w.u32(self.seq);
        w.u32(self.payload_len);
    }
}

// ===========================================================================
// Message types
// ===========================================================================

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum MessageType {
    Hello = 1,
    HelloAck = 2,
    PolicyInstall = 10,
    PolicyInstallAck = 11,
    PolicyUpdate = 12,
    PolicyUpdateAck = 13,
    PolicyFlush = 14,
    IdentityQuery = 20,
    IdentityResponse = 21,
    LogEvents = 30,
    StatsRequest = 40,
    StatsResponse = 41,
    SetMode = 50,
    ModeAck = 51,
    SignatureInstall = 60,
    SignatureInstallAck = 61,
    Error = 99,
}

impl MessageType {
    pub fn from_u16(v: u16) -> Option<Self> {
        Some(match v {
            1 => MessageType::Hello,
            2 => MessageType::HelloAck,
            10 => MessageType::PolicyInstall,
            11 => MessageType::PolicyInstallAck,
            12 => MessageType::PolicyUpdate,
            13 => MessageType::PolicyUpdateAck,
            14 => MessageType::PolicyFlush,
            20 => MessageType::IdentityQuery,
            21 => MessageType::IdentityResponse,
            30 => MessageType::LogEvents,
            40 => MessageType::StatsRequest,
            41 => MessageType::StatsResponse,
            50 => MessageType::SetMode,
            51 => MessageType::ModeAck,
            60 => MessageType::SignatureInstall,
            61 => MessageType::SignatureInstallAck,
            99 => MessageType::Error,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            MessageType::Hello => "hello",
            MessageType::HelloAck => "hello-ack",
            MessageType::PolicyInstall => "policy-install",
            MessageType::PolicyInstallAck => "policy-install-ack",
            MessageType::PolicyUpdate => "policy-update",
            MessageType::PolicyUpdateAck => "policy-update-ack",
            MessageType::PolicyFlush => "policy-flush",
            MessageType::IdentityQuery => "identity-query",
            MessageType::IdentityResponse => "identity-response",
            MessageType::LogEvents => "log-events",
            MessageType::StatsRequest => "stats-request",
            MessageType::StatsResponse => "stats-response",
            MessageType::SetMode => "set-mode",
            MessageType::ModeAck => "mode-ack",
            MessageType::SignatureInstall => "signature-install",
            MessageType::SignatureInstallAck => "signature-install-ack",
            MessageType::Error => "error",
        }
    }
}

/// How aggressively the enforcement point acts on its decisions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EnforcementMode {
    /// Decisions are applied.
    Enforce = 0,
    /// Decisions are computed and logged but every flow is permitted. Used to
    /// shake down a new policy against production traffic.
    Monitor = 1,
    /// Break-glass: all filters bypassed, every flow permitted, and every
    /// decision logged as [`constants::RULE_ID_EMERGENCY_ALLOW`].
    EmergencyAllow = 2,
}

impl EnforcementMode {
    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => EnforcementMode::Enforce,
            1 => EnforcementMode::Monitor,
            2 => EnforcementMode::EmergencyAllow,
            _ => return None,
        })
    }

    pub fn as_str(self) -> &'static str {
        match self {
            EnforcementMode::Enforce => "enforce",
            EnforcementMode::Monitor => "monitor",
            EnforcementMode::EmergencyAllow => "emergency-allow",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "enforce" => EnforcementMode::Enforce,
            "monitor" | "audit" => EnforcementMode::Monitor,
            "emergency-allow" | "allow-all" => EnforcementMode::EmergencyAllow,
            _ => return None,
        })
    }
}

/// Capability bits reported by a kernel module in its `HelloAck`.
///
/// The daemon uses these to refuse to install a policy the module cannot
/// actually enforce — installing a DPI rule into a module without a stream
/// engine would silently produce an allow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct Capabilities(pub u32);

impl Capabilities {
    pub const IPV6: u32 = 1 << 0;
    pub const APP_IDENTITY: u32 = 1 << 1;
    pub const STREAM_REASSEMBLY: u32 = 1 << 2;
    pub const DPI: u32 = 1 << 3;
    pub const EBPF_FASTPATH: u32 = 1 << 4;
    pub const CONNTRACK: u32 = 1 << 5;
    pub const INCREMENTAL_UPDATE: u32 = 1 << 6;
    pub const SCHEDULED_RULES: u32 = 1 << 7;
    pub const INTERFACE_MATCH: u32 = 1 << 8;

    pub fn has(self, bit: u32) -> bool {
        self.0 & bit != 0
    }

    pub fn names(self) -> Vec<&'static str> {
        let mut v = Vec::new();
        for (bit, name) in [
            (Self::IPV6, "ipv6"),
            (Self::APP_IDENTITY, "app-identity"),
            (Self::STREAM_REASSEMBLY, "stream-reassembly"),
            (Self::DPI, "dpi"),
            (Self::EBPF_FASTPATH, "ebpf-fastpath"),
            (Self::CONNTRACK, "conntrack"),
            (Self::INCREMENTAL_UPDATE, "incremental-update"),
            (Self::SCHEDULED_RULES, "scheduled-rules"),
            (Self::INTERFACE_MATCH, "interface-match"),
        ] {
            if self.has(bit) {
                v.push(name);
            }
        }
        v
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    pub daemon_version: String,
    pub abi_revision: u32,
    pub host_id: String,
    pub pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HelloAck {
    pub module_version: String,
    pub abi_revision: u32,
    pub capabilities: Capabilities,
    /// Revision currently installed, or 0 when the module has no policy.
    pub installed_revision: u64,
    pub platform: String,
}

/// Result of installing a full policy or applying a delta.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallAck {
    pub revision: u64,
    pub filters_installed: u32,
    pub filters_removed: u32,
    /// Module-side recomputation of the ruleset hash. A mismatch against the
    /// daemon's value means the two sides disagree about what is installed and
    /// the daemon re-sends a full policy.
    pub ruleset_hash: [u8; 32],
    /// Non-fatal notes, e.g. "3 rules downgraded: no DPI support".
    pub warnings: Vec<String>,
}

/// An incremental policy change.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyDelta {
    /// Revision the module must currently have installed. If it does not, it
    /// rejects the delta and the daemon falls back to a full install.
    pub base_revision: u64,
    pub new_revision: u64,
    pub added: Vec<CompiledRule>,
    pub modified: Vec<CompiledRule>,
    pub removed: Vec<u32>,
    /// Present when the default action changed.
    pub default_action: Option<Decision>,
    /// Hash of the resulting policy, for the module to verify against.
    pub result_hash: [u8; 32],
}

impl PolicyDelta {
    pub fn is_empty(&self) -> bool {
        self.added.is_empty()
            && self.modified.is_empty()
            && self.removed.is_empty()
            && self.default_action.is_none()
    }

    pub fn change_count(&self) -> usize {
        self.added.len() + self.modified.len() + self.removed.len()
    }
}

/// Counters reported by a kernel module.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct KernelStats {
    pub packets_seen: u64,
    pub packets_allowed: u64,
    pub packets_denied: u64,
    pub flows_seen: u64,
    pub flows_allowed: u64,
    pub flows_denied: u64,
    pub identity_cache_hits: u64,
    pub identity_cache_misses: u64,
    pub identity_queries_timed_out: u64,
    pub dpi_scans: u64,
    pub dpi_hits: u64,
    pub reassembly_contexts: u64,
    pub reassembly_truncated: u64,
    pub conntrack_entries: u64,
    pub log_events_dropped: u64,
    pub ebpf_fastpath_decisions: u64,
    /// Per-rule hit counters, `(rule_id, hits)`. Sparse: only rules that have
    /// matched at least once appear.
    pub rule_hits: Vec<(u32, u64)>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ErrorMessage {
    pub code: u32,
    pub detail: String,
}

/// A complete IPC message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    Hello(Hello),
    HelloAck(HelloAck),
    PolicyInstall(Box<CompiledPolicy>),
    PolicyInstallAck(InstallAck),
    PolicyUpdate(Box<PolicyDelta>),
    PolicyUpdateAck(InstallAck),
    PolicyFlush,
    IdentityQuery(IdentityQuery),
    IdentityResponse(Box<AppIdentity>),
    LogEvents(Vec<LogEvent>),
    StatsRequest,
    StatsResponse(Box<KernelStats>),
    SetMode(EnforcementMode),
    ModeAck(EnforcementMode),
    /// The DPI signature set, in the flat encoding
    /// `ufw_daemon::signatures::SignatureSet::encode` produces and all three
    /// kernel engines decode. Opaque here on purpose: the wire protocol
    /// carries it, it does not interpret it.
    SignatureInstall(Box<SignatureInstall>),
    SignatureInstallAck(SignatureInstallAck),
    Error(ErrorMessage),
}

/// A signature set on its way to a kernel module.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SignatureInstall {
    pub payload: Vec<u8>,
}

/// What the module made of it.
///
/// `payload_hash` is what turns "the module acknowledged" into "the module has
/// what we sent". Without it a module that decoded half the set and stopped
/// would report success, and the operator would believe traffic was being
/// inspected against signatures the module never loaded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct SignatureInstallAck {
    pub signatures_installed: u32,
    /// Distinct content patterns in the shipped automaton, or zero when the
    /// set had none or exceeded the module's table limits and every content
    /// condition fell back to the per-signature search.
    pub patterns_installed: u32,
    pub payload_hash: [u8; 32],
}

impl Message {
    pub fn msg_type(&self) -> MessageType {
        match self {
            Message::Hello(_) => MessageType::Hello,
            Message::HelloAck(_) => MessageType::HelloAck,
            Message::PolicyInstall(_) => MessageType::PolicyInstall,
            Message::PolicyInstallAck(_) => MessageType::PolicyInstallAck,
            Message::PolicyUpdate(_) => MessageType::PolicyUpdate,
            Message::PolicyUpdateAck(_) => MessageType::PolicyUpdateAck,
            Message::PolicyFlush => MessageType::PolicyFlush,
            Message::IdentityQuery(_) => MessageType::IdentityQuery,
            Message::IdentityResponse(_) => MessageType::IdentityResponse,
            Message::LogEvents(_) => MessageType::LogEvents,
            Message::StatsRequest => MessageType::StatsRequest,
            Message::StatsResponse(_) => MessageType::StatsResponse,
            Message::SetMode(_) => MessageType::SetMode,
            Message::ModeAck(_) => MessageType::ModeAck,
            Message::SignatureInstall(_) => MessageType::SignatureInstall,
            Message::SignatureInstallAck(_) => MessageType::SignatureInstallAck,
            Message::Error(_) => MessageType::Error,
        }
    }

    /// Serialize header + payload into a single frame.
    pub fn encode(&self, seq: u32) -> Vec<u8> {
        let mut payload = Writer::new();
        self.encode_payload(&mut payload);
        let payload = payload.finish();

        let mut w = Writer::with_capacity(constants::HEADER_LEN + payload.len());
        MessageHeader {
            magic: constants::PROTOCOL_MAGIC,
            version: constants::PROTOCOL_VERSION,
            msg_type: self.msg_type() as u16,
            seq,
            payload_len: payload.len() as u32,
        }
        .write(&mut w);
        w.raw(&payload);
        w.finish()
    }

    fn encode_payload(&self, w: &mut Writer) {
        match self {
            Message::Hello(h) => {
                w.string(&h.daemon_version);
                w.u32(h.abi_revision);
                w.string(&h.host_id);
                w.u32(h.pid);
            }
            Message::HelloAck(h) => {
                w.string(&h.module_version);
                w.u32(h.abi_revision);
                w.u32(h.capabilities.0);
                w.u64(h.installed_revision);
                w.string(&h.platform);
            }
            Message::PolicyInstall(p) => p.encode_into(w),
            Message::PolicyInstallAck(a) | Message::PolicyUpdateAck(a) => {
                w.u64(a.revision);
                w.u32(a.filters_installed);
                w.u32(a.filters_removed);
                w.raw(&a.ruleset_hash);
                w.string_list(&a.warnings);
            }
            Message::PolicyUpdate(d) => {
                w.u64(d.base_revision);
                w.u64(d.new_revision);
                w.u32(d.added.len() as u32);
                for r in &d.added {
                    r.encode(w);
                }
                w.u32(d.modified.len() as u32);
                for r in &d.modified {
                    r.encode(w);
                }
                w.u32(d.removed.len() as u32);
                for id in &d.removed {
                    w.u32(*id);
                }
                match d.default_action {
                    Some(a) => {
                        w.u8(1);
                        w.u8(a as u8);
                    }
                    None => w.u8(0),
                }
                w.raw(&d.result_hash);
            }
            Message::PolicyFlush | Message::StatsRequest => {}
            Message::IdentityQuery(q) => q.encode(w),
            Message::IdentityResponse(id) => id.encode(w),
            Message::LogEvents(events) => {
                w.u32(events.len() as u32);
                for e in events {
                    e.encode(w);
                }
            }
            Message::StatsResponse(s) => {
                for v in [
                    s.packets_seen,
                    s.packets_allowed,
                    s.packets_denied,
                    s.flows_seen,
                    s.flows_allowed,
                    s.flows_denied,
                    s.identity_cache_hits,
                    s.identity_cache_misses,
                    s.identity_queries_timed_out,
                    s.dpi_scans,
                    s.dpi_hits,
                    s.reassembly_contexts,
                    s.reassembly_truncated,
                    s.conntrack_entries,
                    s.log_events_dropped,
                    s.ebpf_fastpath_decisions,
                ] {
                    w.u64(v);
                }
                w.u32(s.rule_hits.len() as u32);
                for (id, hits) in &s.rule_hits {
                    w.u32(*id);
                    w.u64(*hits);
                }
            }
            Message::SetMode(m) | Message::ModeAck(m) => w.u8(*m as u8),
            Message::SignatureInstall(s) => w.bytes(&s.payload),
            Message::SignatureInstallAck(a) => {
                w.u32(a.signatures_installed);
                w.u32(a.patterns_installed);
                w.raw(&a.payload_hash);
            }
            Message::Error(e) => {
                w.u32(e.code);
                w.string(&e.detail);
            }
        }
    }

    /// Parse one complete frame. Returns the message and its sequence number.
    pub fn decode(frame: &[u8]) -> Result<(Message, u32), ProtoError> {
        let header = MessageHeader::parse(frame)?;
        let body_end = constants::HEADER_LEN + header.payload_len as usize;
        if frame.len() < body_end {
            return Err(ProtoError::UnexpectedEof);
        }
        let mut r = Reader::new(&frame[constants::HEADER_LEN..body_end]);
        let ty = MessageType::from_u16(header.msg_type)
            .ok_or(ProtoError::UnknownMessageType(header.msg_type))?;
        let msg = Self::decode_payload(ty, &mut r)?;
        Ok((msg, header.seq))
    }

    fn decode_payload(ty: MessageType, r: &mut Reader<'_>) -> Result<Message, ProtoError> {
        Ok(match ty {
            MessageType::Hello => Message::Hello(Hello {
                daemon_version: r.string()?,
                abi_revision: r.u32()?,
                host_id: r.string()?,
                pid: r.u32()?,
            }),
            MessageType::HelloAck => Message::HelloAck(HelloAck {
                module_version: r.string()?,
                abi_revision: r.u32()?,
                capabilities: Capabilities(r.u32()?),
                installed_revision: r.u64()?,
                platform: r.string()?,
            }),
            MessageType::PolicyInstall => {
                Message::PolicyInstall(Box::new(CompiledPolicy::decode_from(r)?))
            }
            MessageType::PolicyInstallAck | MessageType::PolicyUpdateAck => {
                let revision = r.u64()?;
                let filters_installed = r.u32()?;
                let filters_removed = r.u32()?;
                let mut ruleset_hash = [0u8; 32];
                ruleset_hash.copy_from_slice(r.raw(32)?);
                let warnings = r.string_list()?;
                let ack = InstallAck {
                    revision,
                    filters_installed,
                    filters_removed,
                    ruleset_hash,
                    warnings,
                };
                if ty == MessageType::PolicyInstallAck {
                    Message::PolicyInstallAck(ack)
                } else {
                    Message::PolicyUpdateAck(ack)
                }
            }
            MessageType::PolicyUpdate => {
                let base_revision = r.u64()?;
                let new_revision = r.u64()?;
                let read_rules = |r: &mut Reader<'_>| -> Result<Vec<CompiledRule>, ProtoError> {
                    let n = r.u32()? as usize;
                    if n > constants::MAX_RULES {
                        return Err(ProtoError::TooLarge(n));
                    }
                    let mut v = Vec::with_capacity(n.min(4096));
                    for _ in 0..n {
                        v.push(CompiledRule::decode(r)?);
                    }
                    Ok(v)
                };
                let added = read_rules(r)?;
                let modified = read_rules(r)?;
                let rn = r.u32()? as usize;
                if rn > constants::MAX_RULES {
                    return Err(ProtoError::TooLarge(rn));
                }
                let mut removed = Vec::with_capacity(rn.min(4096));
                for _ in 0..rn {
                    removed.push(r.u32()?);
                }
                let default_action = if r.u8()? != 0 {
                    Some(Decision::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad decision"))?)
                } else {
                    None
                };
                let mut result_hash = [0u8; 32];
                result_hash.copy_from_slice(r.raw(32)?);
                Message::PolicyUpdate(Box::new(PolicyDelta {
                    base_revision,
                    new_revision,
                    added,
                    modified,
                    removed,
                    default_action,
                    result_hash,
                }))
            }
            MessageType::PolicyFlush => Message::PolicyFlush,
            MessageType::IdentityQuery => Message::IdentityQuery(IdentityQuery::decode(r)?),
            MessageType::IdentityResponse => {
                Message::IdentityResponse(Box::new(AppIdentity::decode(r)?))
            }
            MessageType::LogEvents => {
                let n = r.u32()? as usize;
                if n > constants::LOG_RING_CAPACITY {
                    return Err(ProtoError::TooLarge(n));
                }
                let mut v = Vec::with_capacity(n.min(constants::LOG_BATCH_MAX_EVENTS));
                for _ in 0..n {
                    v.push(LogEvent::decode(r)?);
                }
                Message::LogEvents(v)
            }
            MessageType::StatsRequest => Message::StatsRequest,
            MessageType::StatsResponse => {
                let mut s = KernelStats::default();
                let fields: [&mut u64; 16] = [
                    &mut s.packets_seen,
                    &mut s.packets_allowed,
                    &mut s.packets_denied,
                    &mut s.flows_seen,
                    &mut s.flows_allowed,
                    &mut s.flows_denied,
                    &mut s.identity_cache_hits,
                    &mut s.identity_cache_misses,
                    &mut s.identity_queries_timed_out,
                    &mut s.dpi_scans,
                    &mut s.dpi_hits,
                    &mut s.reassembly_contexts,
                    &mut s.reassembly_truncated,
                    &mut s.conntrack_entries,
                    &mut s.log_events_dropped,
                    &mut s.ebpf_fastpath_decisions,
                ];
                for f in fields {
                    *f = r.u64()?;
                }
                let n = r.u32()? as usize;
                if n > constants::MAX_RULES {
                    return Err(ProtoError::TooLarge(n));
                }
                let mut rule_hits = Vec::with_capacity(n.min(4096));
                for _ in 0..n {
                    let id = r.u32()?;
                    let hits = r.u64()?;
                    rule_hits.push((id, hits));
                }
                s.rule_hits = rule_hits;
                Message::StatsResponse(Box::new(s))
            }
            MessageType::SetMode => Message::SetMode(
                EnforcementMode::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad mode"))?,
            ),
            MessageType::ModeAck => Message::ModeAck(
                EnforcementMode::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad mode"))?,
            ),
            MessageType::SignatureInstall => {
                let payload = r.bytes()?;
                if payload.len() > constants::MAX_SIGNATURE_PAYLOAD_BYTES {
                    return Err(ProtoError::TooLarge(payload.len()));
                }
                Message::SignatureInstall(Box::new(SignatureInstall {
                    payload: payload.to_vec(),
                }))
            }
            MessageType::SignatureInstallAck => {
                let signatures_installed = r.u32()?;
                let patterns_installed = r.u32()?;
                let mut payload_hash = [0u8; 32];
                payload_hash.copy_from_slice(r.raw(32)?);
                Message::SignatureInstallAck(SignatureInstallAck {
                    signatures_installed,
                    patterns_installed,
                    payload_hash,
                })
            }
            MessageType::Error => Message::Error(ErrorMessage {
                code: r.u32()?,
                detail: r.string()?,
            }),
        })
    }
}

/// Well-known error codes carried in [`ErrorMessage`].
pub mod error_codes {
    pub const ABI_MISMATCH: u32 = 1;
    pub const POLICY_TOO_LARGE: u32 = 2;
    pub const HASH_MISMATCH: u32 = 3;
    pub const STALE_BASE_REVISION: u32 = 4;
    pub const UNSUPPORTED_CAPABILITY: u32 = 5;
    pub const IDENTITY_UNRESOLVABLE: u32 = 6;
    pub const INTERNAL: u32 = 99;
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hash;
    use crate::log_types::{FiveTuple, LogEvent};
    use crate::policy_types::{Action, CompiledRule, Decision, Layer};

    fn sample_policy() -> CompiledPolicy {
        let mut p = CompiledPolicy::new("sample", Decision::Deny);
        p.rules.push(CompiledRule::new(
            7,
            "allow-loopback",
            Layer::Packet,
            Action::Allow,
        ));
        p.finalize();
        p
    }

    fn roundtrip(m: Message) {
        let frame = m.encode(42);
        let (back, seq) = Message::decode(&frame).unwrap();
        assert_eq!(seq, 42);
        assert_eq!(m, back, "roundtrip failed for {:?}", m.msg_type().as_str());
    }

    #[test]
    fn primitive_codec_roundtrip() {
        let mut w = Writer::new();
        w.u8(1);
        w.bool(true);
        w.u16(0xBEEF);
        w.u32(0xDEAD_BEEF);
        w.u64(u64::MAX);
        w.i64(-5);
        w.string("héllo");
        w.opt_string(None);
        w.opt_string(Some("x"));
        w.bytes(&[1, 2, 3]);
        w.string_list(&["a", "b"]);
        let buf = w.finish();

        let mut r = Reader::new(&buf);
        assert_eq!(r.u8().unwrap(), 1);
        assert!(r.bool().unwrap());
        assert_eq!(r.u16().unwrap(), 0xBEEF);
        assert_eq!(r.u32().unwrap(), 0xDEAD_BEEF);
        assert_eq!(r.u64().unwrap(), u64::MAX);
        assert_eq!(r.i64().unwrap(), -5);
        assert_eq!(r.string().unwrap(), "héllo");
        assert_eq!(r.opt_string().unwrap(), None);
        assert_eq!(r.opt_string().unwrap(), Some("x".into()));
        assert_eq!(r.bytes().unwrap(), &[1, 2, 3]);
        assert_eq!(r.string_list().unwrap(), vec!["a", "b"]);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn reader_reports_eof_not_panic() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.u32(), Err(ProtoError::UnexpectedEof));
        let mut r = Reader::new(&[]);
        assert_eq!(r.u8(), Err(ProtoError::UnexpectedEof));
    }

    #[test]
    fn writer_truncates_on_char_boundary() {
        let long = "é".repeat(constants::MAX_STRING_LEN);
        let mut w = Writer::new();
        w.string(&long);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        let back = r.string().unwrap();
        assert!(back.len() <= constants::MAX_STRING_LEN);
        assert!(long.starts_with(&back));
    }

    #[test]
    fn header_rejects_bad_magic_and_version() {
        let m = Message::PolicyFlush;
        let mut frame = m.encode(1);
        frame[0] ^= 0xFF;
        assert!(matches!(
            Message::decode(&frame),
            Err(ProtoError::BadMagic(_))
        ));

        let mut frame = m.encode(1);
        frame[4] = 0x7F;
        frame[5] = 0x7F;
        assert!(matches!(
            Message::decode(&frame),
            Err(ProtoError::UnsupportedVersion(_))
        ));
    }

    #[test]
    fn truncated_frame_is_rejected() {
        let frame = Message::StatsRequest.encode(1);
        assert!(Message::decode(&frame[..constants::HEADER_LEN - 1]).is_err());
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let mut frame = Message::PolicyFlush.encode(1);
        frame[6] = 0xAB;
        frame[7] = 0x00;
        assert!(matches!(
            Message::decode(&frame),
            Err(ProtoError::UnknownMessageType(0xAB))
        ));
    }

    #[test]
    fn all_messages_roundtrip() {
        roundtrip(Message::Hello(Hello {
            daemon_version: "0.1.0".into(),
            abi_revision: constants::ABI_REVISION,
            host_id: "host-a".into(),
            pid: 99,
        }));
        roundtrip(Message::HelloAck(HelloAck {
            module_version: "0.1.0".into(),
            abi_revision: constants::ABI_REVISION,
            capabilities: Capabilities(Capabilities::DPI | Capabilities::IPV6),
            installed_revision: 3,
            platform: "linux".into(),
        }));
        roundtrip(Message::PolicyInstall(Box::new(sample_policy())));
        roundtrip(Message::PolicyInstallAck(InstallAck {
            revision: 3,
            filters_installed: 12,
            filters_removed: 1,
            ruleset_hash: hash::sha256(b"x"),
            warnings: vec!["downgraded".into()],
        }));
        roundtrip(Message::PolicyUpdate(Box::new(PolicyDelta {
            base_revision: 2,
            new_revision: 3,
            added: vec![CompiledRule::new(1, "a", Layer::Packet, Action::Allow)],
            modified: vec![CompiledRule::new(2, "b", Layer::Stream, Action::Deny)],
            removed: vec![9, 10],
            default_action: Some(Decision::Deny),
            result_hash: hash::sha256(b"y"),
        })));
        roundtrip(Message::PolicyFlush);
        roundtrip(Message::IdentityQuery(IdentityQuery {
            pid: 12,
            start_time_us: 34,
            hint_path: Some("/usr/bin/x".into()),
            platform_token: vec![9, 9],
        }));
        roundtrip(Message::IdentityResponse(Box::new(
            AppIdentity::unresolved(5, 6),
        )));
        roundtrip(Message::LogEvents(vec![LogEvent::new(
            1_000,
            "host-a",
            Decision::Deny,
            7,
            FiveTuple::default(),
        )]));
        roundtrip(Message::StatsRequest);
        roundtrip(Message::StatsResponse(Box::new(KernelStats {
            packets_seen: 5,
            rule_hits: vec![(1, 2), (3, 4)],
            ..Default::default()
        })));
        roundtrip(Message::SetMode(EnforcementMode::Monitor));
        roundtrip(Message::ModeAck(EnforcementMode::Enforce));
        roundtrip(Message::Error(ErrorMessage {
            code: error_codes::HASH_MISMATCH,
            detail: "mismatch".into(),
        }));
    }

    #[test]
    fn capability_names() {
        let c = Capabilities(Capabilities::DPI | Capabilities::CONNTRACK);
        assert_eq!(c.names(), vec!["dpi", "conntrack"]);
        assert!(c.has(Capabilities::DPI));
        assert!(!c.has(Capabilities::EBPF_FASTPATH));
    }

    #[test]
    fn delta_emptiness() {
        let d = PolicyDelta {
            base_revision: 1,
            new_revision: 1,
            added: vec![],
            modified: vec![],
            removed: vec![],
            default_action: None,
            result_hash: [0u8; 32],
        };
        assert!(d.is_empty());
        assert_eq!(d.change_count(), 0);
    }

    #[test]
    fn oversized_length_fields_are_rejected_before_allocation() {
        // Hand-craft a LogEvents frame claiming an absurd event count.
        let mut payload = Writer::new();
        payload.u32(u32::MAX);
        let payload = payload.finish();
        let mut w = Writer::new();
        MessageHeader {
            magic: constants::PROTOCOL_MAGIC,
            version: constants::PROTOCOL_VERSION,
            msg_type: MessageType::LogEvents as u16,
            seq: 0,
            payload_len: payload.len() as u32,
        }
        .write(&mut w);
        w.raw(&payload);
        assert!(matches!(
            Message::decode(&w.finish()),
            Err(ProtoError::TooLarge(_))
        ));
    }
}
