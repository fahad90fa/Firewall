//! The compiled policy representation and its reference semantics.
//!
//! This module is the contract between the policy compiler and everything that
//! consumes a policy: the daemon, the three kernel backends, and the
//! cross-platform equivalence verifier.
//!
//! Two things live here and they are deliberately in the same file:
//!
//! * The **data model** — [`CompiledRule`], [`CompiledPolicy`] and their binary
//!   wire encoding, which is what the daemon ships to a kernel module.
//! * The **reference semantics** — [`CompiledPolicy::evaluate`], the single
//!   authoritative definition of what a policy *means*.
//!
//! Every backend is required to reproduce the reference semantics exactly. The
//! equivalence verifier in `policy-lang` works by running the same scenario
//! through this evaluator and through each backend's emitted model and
//! comparing the results, so if these two ever drift apart the drift is a test
//! failure rather than a silent behavioural difference between platforms.
//!
//! # Evaluation model
//!
//! A flow is evaluated in **stages**, one per defense layer, in the order the
//! facts become available to the enforcement point:
//!
//! ```text
//!   Perimeter (L1) -> Packet (L2) -> Identity (L4) -> AppDpi (L3) -> Stream (L5)
//! ```
//!
//! (The layer *numbers* come from the architecture's five-layer model; the
//! *order* is the order of the packet decision flow, where application identity
//! is known before payload inspection can begin.)
//!
//! Within a stage, rules are tried in ascending priority then ascending rule
//! id, and the first match decides what happens next:
//!
//! * `Allow` — terminal. The flow is permitted and no deeper stage runs.
//! * `Deny` — terminal. The flow is blocked.
//! * `AllowInspect` — the flow is permitted *so far*, but evaluation continues
//!   into deeper stages, which may still deny it. This is how "allow this, but
//!   inspect the payload" is expressed, and it is what lets a Layer 5 DPI rule
//!   terminate a connection that a Layer 2 rule already allowed.
//! * `Alert` — records the rule id and continues within the same stage.
//! * `Continue` — records nothing and continues within the same stage.
//!
//! If no stage reaches a terminal action, the policy's `default_action`
//! applies, reported against [`crate::constants::RULE_ID_DEFAULT`].
//!
//! A rule whose predicate needs a fact the context does not have (an identity
//! rule with no resolved identity, a DPI rule with no completed scan) does
//! **not** match. Absent facts are never wildcards; that asymmetry is what
//! makes the model fail closed.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::constants;
use crate::hash;
use crate::identity_types::{AppIdentity, TrustMask};
use crate::json::JsonWriter;
use crate::protocol::{ProtoError, Reader, Writer};

// ===========================================================================
// Scalar enums
// ===========================================================================

/// The defense layer a rule is evaluated at.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(u8)]
pub enum Layer {
    /// L1 — network perimeter awareness: zone classification and rules that
    /// only depend on where the peer sits relative to the perimeter.
    Perimeter = 1,
    /// L2 — host packet filtering on the L3/L4 header.
    Packet = 2,
    /// L3 — application-layer deep inspection of reassembled payload.
    AppDpi = 3,
    /// L4 — per-application identity enforcement.
    Identity = 4,
    /// L5 — combined evaluation over identity, network context and payload.
    Stream = 5,
}

/// Stages in the order they run. Note this is *not* numeric layer order:
/// identity (L4) is known before payload inspection (L3) can start.
pub const EVALUATION_ORDER: [Layer; 5] = [
    Layer::Perimeter,
    Layer::Packet,
    Layer::Identity,
    Layer::AppDpi,
    Layer::Stream,
];

impl Layer {
    pub fn as_str(self) -> &'static str {
        match self {
            Layer::Perimeter => "perimeter",
            Layer::Packet => "packet",
            Layer::AppDpi => "app-dpi",
            Layer::Identity => "identity",
            Layer::Stream => "stream",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            1 => Layer::Perimeter,
            2 => Layer::Packet,
            3 => Layer::AppDpi,
            4 => Layer::Identity,
            5 => Layer::Stream,
            _ => return None,
        })
    }

    /// Accepts both the symbolic name and the bare layer number, because
    /// policies in the wild are written both ways.
    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "perimeter" | "1" => Some(Layer::Perimeter),
            "packet" | "2" => Some(Layer::Packet),
            "app-dpi" | "dpi" | "3" => Some(Layer::AppDpi),
            "identity" | "4" => Some(Layer::Identity),
            "stream" | "5" => Some(Layer::Stream),
            _ => None,
        }
    }

    /// Position of this layer in [`EVALUATION_ORDER`].
    pub fn stage_index(self) -> usize {
        EVALUATION_ORDER
            .iter()
            .position(|l| *l == self)
            .unwrap_or(0)
    }
}

impl fmt::Display for Layer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// What a matching rule does.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Action {
    /// Terminal permit. Deeper layers are not consulted.
    Allow = 0,
    /// Terminal block.
    Deny = 1,
    /// Record the match and keep evaluating the current stage.
    Alert = 2,
    /// Record nothing and keep evaluating the current stage. Used by the
    /// optimizer to punch holes in broader rules without changing the verdict.
    Continue = 3,
    /// Permit *provisionally*: continue into deeper stages, which may deny.
    AllowInspect = 4,
}

impl Default for Action {
    /// A DPI clause with no explicit `on_match` denies. Signature matches are
    /// written to describe things that should not happen, so the safe default
    /// for "the signature fired and the policy did not say what to do" is to
    /// block.
    fn default() -> Self {
        Action::Deny
    }
}

impl Action {
    pub fn as_str(self) -> &'static str {
        match self {
            Action::Allow => "allow",
            Action::Deny => "deny",
            Action::Alert => "alert",
            Action::Continue => "continue",
            Action::AllowInspect => "allow-inspect",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Action::Allow,
            1 => Action::Deny,
            2 => Action::Alert,
            3 => Action::Continue,
            4 => Action::AllowInspect,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "allow" | "permit" => Action::Allow,
            "deny" | "block" | "drop" => Action::Deny,
            "alert" | "log" => Action::Alert,
            "continue" | "none" | "pass" => Action::Continue,
            "allow-inspect" | "inspect" => Action::AllowInspect,
            _ => return None,
        })
    }

    /// Whether this action ends evaluation.
    pub fn is_terminal(self) -> bool {
        matches!(self, Action::Allow | Action::Deny)
    }
}

impl fmt::Display for Action {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// The final verdict handed back to the OS filtering framework.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Decision {
    Allow = 0,
    Deny = 1,
}

impl Decision {
    pub fn as_str(self) -> &'static str {
        match self {
            Decision::Allow => "allow",
            Decision::Deny => "deny",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            0 => Some(Decision::Allow),
            1 => Some(Decision::Deny),
            _ => None,
        }
    }
}

impl fmt::Display for Decision {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Direction {
    Inbound = 0,
    Outbound = 1,
    Any = 2,
}

impl Direction {
    pub fn as_str(self) -> &'static str {
        match self {
            Direction::Inbound => "inbound",
            Direction::Outbound => "outbound",
            Direction::Any => "any",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Direction::Inbound,
            1 => Direction::Outbound,
            2 => Direction::Any,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "inbound" | "in" | "ingress" => Direction::Inbound,
            "outbound" | "out" | "egress" => Direction::Outbound,
            "any" | "both" => Direction::Any,
            _ => return None,
        })
    }

    pub fn matches(self, other: Direction) -> bool {
        self == Direction::Any || other == Direction::Any || self == other
    }
}

/// Transport protocol. `Any` is a wildcard; `Other` carries an IANA number for
/// protocols the language does not name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Protocol {
    Any,
    Icmp,
    IcmpV6,
    Tcp,
    Udp,
    Other(u8),
}

impl Protocol {
    pub fn as_str(self) -> String {
        match self {
            Protocol::Any => "any".into(),
            Protocol::Icmp => "icmp".into(),
            Protocol::IcmpV6 => "icmpv6".into(),
            Protocol::Tcp => "tcp".into(),
            Protocol::Udp => "udp".into(),
            Protocol::Other(n) => format!("proto-{n}"),
        }
    }

    /// IANA protocol number, or `None` for the wildcard.
    pub fn number(self) -> Option<u8> {
        Some(match self {
            Protocol::Any => return None,
            Protocol::Icmp => 1,
            Protocol::IcmpV6 => 58,
            Protocol::Tcp => 6,
            Protocol::Udp => 17,
            Protocol::Other(n) => n,
        })
    }

    pub fn from_number(n: u8) -> Self {
        match n {
            1 => Protocol::Icmp,
            6 => Protocol::Tcp,
            17 => Protocol::Udp,
            58 => Protocol::IcmpV6,
            n => Protocol::Other(n),
        }
    }

    pub fn to_u16(self) -> u16 {
        match self.number() {
            Some(n) => n as u16,
            None => 0xFFFF,
        }
    }

    pub fn from_u16(v: u16) -> Option<Self> {
        if v == 0xFFFF {
            Some(Protocol::Any)
        } else if v <= 0xFF {
            Some(Protocol::from_number(v as u8))
        } else {
            None
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "any" => Protocol::Any,
            "tcp" => Protocol::Tcp,
            "udp" => Protocol::Udp,
            "icmp" => Protocol::Icmp,
            "icmpv6" | "icmp6" => Protocol::IcmpV6,
            "sctp" => Protocol::Other(132),
            "gre" => Protocol::Other(47),
            "esp" => Protocol::Other(50),
            "ah" => Protocol::Other(51),
            other => {
                let n = other.strip_prefix("proto-")?;
                Protocol::Other(n.parse::<u8>().ok()?)
            }
        })
    }

    /// Whether port numbers are meaningful for this protocol. Used by the
    /// semantic analyzer to reject `protocol: icmp` alongside `ports:`.
    pub fn has_ports(self) -> bool {
        matches!(self, Protocol::Tcp | Protocol::Udp | Protocol::Other(132))
    }

    pub fn matches(self, observed: Protocol) -> bool {
        self == Protocol::Any || observed == Protocol::Any || self == observed
    }
}

/// Application-layer protocol, as identified by the DPI engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
#[derive(Default)]
pub enum L7Protocol {
    #[default]
    Unknown = 0,
    Http = 1,
    Tls = 2,
    Dns = 3,
    Ssh = 4,
    Smtp = 5,
    Quic = 6,
}

impl L7Protocol {
    pub fn as_str(self) -> &'static str {
        match self {
            L7Protocol::Unknown => "unknown",
            L7Protocol::Http => "http",
            L7Protocol::Tls => "tls",
            L7Protocol::Dns => "dns",
            L7Protocol::Ssh => "ssh",
            L7Protocol::Smtp => "smtp",
            L7Protocol::Quic => "quic",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => L7Protocol::Unknown,
            1 => L7Protocol::Http,
            2 => L7Protocol::Tls,
            3 => L7Protocol::Dns,
            4 => L7Protocol::Ssh,
            5 => L7Protocol::Smtp,
            6 => L7Protocol::Quic,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "http" => L7Protocol::Http,
            "tls" | "ssl" | "https" => L7Protocol::Tls,
            "dns" => L7Protocol::Dns,
            "ssh" => L7Protocol::Ssh,
            "smtp" => L7Protocol::Smtp,
            "quic" => L7Protocol::Quic,
            "unknown" | "any" => L7Protocol::Unknown,
            _ => return None,
        })
    }
}

/// Where a peer address sits relative to the host's network perimeter.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Zone {
    /// The host itself.
    Loopback = 0,
    /// Inside the local trusted network, per the daemon's network profile.
    Internal = 1,
    /// A range explicitly declared as a perimeter/DMZ boundary.
    Perimeter = 2,
    /// Anything else.
    External = 3,
}

impl Zone {
    pub fn as_str(self) -> &'static str {
        match self {
            Zone::Loopback => "loopback",
            Zone::Internal => "internal",
            Zone::Perimeter => "perimeter",
            Zone::External => "external",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Zone::Loopback,
            1 => Zone::Internal,
            2 => Zone::Perimeter,
            3 => Zone::External,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "loopback" | "local" => Zone::Loopback,
            "internal" | "lan" => Zone::Internal,
            "perimeter" | "dmz" => Zone::Perimeter,
            "external" | "wan" | "internet" => Zone::External,
            _ => return None,
        })
    }

    /// Whether reaching this zone crosses the network perimeter. Drives the
    /// `perimeter_crossing_requires_dpi` policy switch and enriches log events.
    pub fn crosses_perimeter(self) -> bool {
        matches!(self, Zone::Perimeter | Zone::External)
    }
}

// ===========================================================================
// Address and port matching
// ===========================================================================

/// An IPv4 or IPv6 network in CIDR form, always stored canonicalized (host
/// bits cleared) so that equality and coverage tests are exact.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Cidr {
    addr: IpAddr,
    prefix: u8,
}

impl Cidr {
    /// Build a CIDR, clearing host bits. Returns `None` if the prefix is
    /// longer than the address family allows.
    pub fn new(addr: IpAddr, prefix: u8) -> Option<Self> {
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return None;
        }
        Some(Cidr {
            addr: mask_addr(addr, prefix),
            prefix,
        })
    }

    pub fn addr(&self) -> IpAddr {
        self.addr
    }

    pub fn prefix(&self) -> u8 {
        self.prefix
    }

    pub fn is_v4(&self) -> bool {
        self.addr.is_ipv4()
    }

    /// Parse `a.b.c.d`, `a.b.c.d/n`, `::1` or `2001:db8::/32`. A bare address
    /// is treated as a host route (/32 or /128).
    pub fn parse(s: &str) -> Option<Self> {
        let (addr_part, prefix_part) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_part.trim().parse().ok()?;
        let default = if addr.is_ipv4() { 32 } else { 128 };
        let prefix = match prefix_part {
            Some(p) => p.trim().parse::<u8>().ok()?,
            None => default,
        };
        Cidr::new(addr, prefix)
    }

    /// The `0.0.0.0/0` and `::/0` wildcards.
    pub fn any_v4() -> Self {
        Cidr {
            addr: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            prefix: 0,
        }
    }

    pub fn any_v6() -> Self {
        Cidr {
            addr: IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            prefix: 0,
        }
    }

    pub fn is_any(&self) -> bool {
        self.prefix == 0
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                prefix_eq(&net.octets(), &ip.octets(), self.prefix)
            }
            // An IPv4-mapped IPv6 address is compared against IPv4 networks by
            // its embedded IPv4 form; without this, dual-stack sockets would
            // silently escape IPv4 rules.
            (IpAddr::V4(_), IpAddr::V6(v6)) => match v6.to_ipv4_mapped() {
                Some(v4) => self.contains(IpAddr::V4(v4)),
                None => false,
            },
            (IpAddr::V6(_), IpAddr::V4(v4)) => self.contains(IpAddr::V6(v4.to_ipv6_mapped())),
        }
    }

    /// Whether `self` is a superset of `other`. Drives the optimizer's
    /// redundancy elimination.
    pub fn covers(&self, other: &Cidr) -> bool {
        if self.addr.is_ipv4() != other.addr.is_ipv4() {
            return false;
        }
        self.prefix <= other.prefix && self.contains(other.addr)
    }

    pub fn encode(&self, w: &mut Writer) {
        match self.addr {
            IpAddr::V4(a) => {
                w.u8(4);
                w.raw(&a.octets());
            }
            IpAddr::V6(a) => {
                w.u8(6);
                w.raw(&a.octets());
            }
        }
        w.u8(self.prefix);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let family = r.u8()?;
        let addr = match family {
            4 => {
                let mut o = [0u8; 4];
                o.copy_from_slice(r.raw(4)?);
                IpAddr::V4(Ipv4Addr::from(o))
            }
            6 => {
                let mut o = [0u8; 16];
                o.copy_from_slice(r.raw(16)?);
                IpAddr::V6(Ipv6Addr::from(o))
            }
            _ => return Err(ProtoError::Malformed("bad address family")),
        };
        let prefix = r.u8()?;
        Cidr::new(addr, prefix).ok_or(ProtoError::Malformed("prefix out of range"))
    }
}

impl fmt::Display for Cidr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}/{}", self.addr, self.prefix)
    }
}

fn mask_addr(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(a) => {
            let mut o = a.octets();
            mask_bytes(&mut o, prefix);
            IpAddr::V4(Ipv4Addr::from(o))
        }
        IpAddr::V6(a) => {
            let mut o = a.octets();
            mask_bytes(&mut o, prefix);
            IpAddr::V6(Ipv6Addr::from(o))
        }
    }
}

fn mask_bytes(bytes: &mut [u8], prefix: u8) {
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    for (i, b) in bytes.iter_mut().enumerate() {
        if i < full {
            continue;
        } else if i == full && rem != 0 {
            *b &= 0xFFu8 << (8 - rem);
        } else {
            *b = 0;
        }
    }
}

fn prefix_eq(a: &[u8], b: &[u8], prefix: u8) -> bool {
    let full = (prefix / 8) as usize;
    let rem = prefix % 8;
    if a[..full] != b[..full] {
        return false;
    }
    if rem == 0 {
        return true;
    }
    let mask = 0xFFu8 << (8 - rem);
    (a[full] & mask) == (b[full] & mask)
}

/// Inclusive port range.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct PortRange {
    pub lo: u16,
    pub hi: u16,
}

impl PortRange {
    pub fn new(lo: u16, hi: u16) -> Self {
        if lo <= hi {
            PortRange { lo, hi }
        } else {
            PortRange { lo: hi, hi: lo }
        }
    }

    pub fn single(p: u16) -> Self {
        PortRange { lo: p, hi: p }
    }

    pub const ANY: PortRange = PortRange {
        lo: 0,
        hi: u16::MAX,
    };

    /// Parse `443` or `8000-8100`.
    pub fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        match s.split_once('-') {
            Some((a, b)) => Some(PortRange::new(
                a.trim().parse().ok()?,
                b.trim().parse().ok()?,
            )),
            None => Some(PortRange::single(s.parse().ok()?)),
        }
    }

    pub fn contains(&self, p: u16) -> bool {
        p >= self.lo && p <= self.hi
    }

    pub fn covers(&self, other: &PortRange) -> bool {
        self.lo <= other.lo && self.hi >= other.hi
    }

    pub fn is_any(&self) -> bool {
        self.lo == 0 && self.hi == u16::MAX
    }

    /// Whether two ranges touch or overlap, and can therefore be fused.
    pub fn adjacent_or_overlapping(&self, other: &PortRange) -> bool {
        self.lo <= other.hi.saturating_add(1) && other.lo <= self.hi.saturating_add(1)
    }
}

impl fmt::Display for PortRange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.lo == self.hi {
            write!(f, "{}", self.lo)
        } else if self.is_any() {
            f.write_str("any")
        } else {
            write!(f, "{}-{}", self.lo, self.hi)
        }
    }
}

/// Address-side predicate.
///
/// Semantics: **union within a kind, intersection across kinds**. If `cidrs`
/// is non-empty the address must fall in one of them; if `zones` is non-empty
/// the address's zone must be one of them; both constraints apply. An entirely
/// empty match is the wildcard. `negate` inverts the whole predicate.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AddressMatch {
    pub cidrs: Vec<Cidr>,
    pub zones: Vec<Zone>,
    pub negate: bool,
}

impl AddressMatch {
    pub fn any() -> Self {
        AddressMatch::default()
    }

    pub fn is_any(&self) -> bool {
        !self.negate
            && self.zones.is_empty()
            && (self.cidrs.is_empty() || self.cidrs.iter().any(|c| c.is_any()))
    }

    pub fn matches(&self, ip: IpAddr, zone: Zone) -> bool {
        let mut hit = true;
        if !self.cidrs.is_empty() {
            hit &= self.cidrs.iter().any(|c| c.contains(ip));
        }
        if !self.zones.is_empty() {
            hit &= self.zones.contains(&zone);
        }
        hit != self.negate
    }

    /// Conservative superset test used by the optimizer. Returns `true` only
    /// when it can *prove* every address matched by `other` is matched by
    /// `self`; negated or zone-constrained matches always answer `false`.
    pub fn covers(&self, other: &AddressMatch) -> bool {
        if self.negate || other.negate {
            return false;
        }
        if !self.zones.is_empty() {
            // Zone membership depends on the runtime network profile, so no
            // static coverage claim is safe.
            return false;
        }
        if self.cidrs.is_empty() {
            return true;
        }
        if other.cidrs.is_empty() {
            return false;
        }
        other
            .cidrs
            .iter()
            .all(|o| self.cidrs.iter().any(|s| s.covers(o)))
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.cidrs.len() as u16);
        for c in &self.cidrs {
            c.encode(w);
        }
        w.u8(self.zones.len() as u8);
        for z in &self.zones {
            w.u8(*z as u8);
        }
        w.bool(self.negate);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let n = r.u16()? as usize;
        if n > constants::MAX_CIDRS_PER_RULE {
            return Err(ProtoError::TooLarge(n));
        }
        let mut cidrs = Vec::with_capacity(n);
        for _ in 0..n {
            cidrs.push(Cidr::decode(r)?);
        }
        let zn = r.u8()? as usize;
        let mut zones = Vec::with_capacity(zn);
        for _ in 0..zn {
            zones.push(Zone::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad zone"))?);
        }
        Ok(AddressMatch {
            cidrs,
            zones,
            negate: r.bool()?,
        })
    }
}

/// Port-side predicate. Empty means "any port".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct PortMatch {
    pub ranges: Vec<PortRange>,
    pub negate: bool,
}

impl PortMatch {
    pub fn any() -> Self {
        PortMatch::default()
    }

    pub fn is_any(&self) -> bool {
        !self.negate && (self.ranges.is_empty() || self.ranges.iter().any(|r| r.is_any()))
    }

    pub fn matches(&self, port: u16) -> bool {
        if self.ranges.is_empty() {
            return !self.negate;
        }
        self.ranges.iter().any(|r| r.contains(port)) != self.negate
    }

    pub fn covers(&self, other: &PortMatch) -> bool {
        if self.negate || other.negate {
            return false;
        }
        if self.ranges.is_empty() {
            return true;
        }
        if other.ranges.is_empty() {
            return false;
        }
        other
            .ranges
            .iter()
            .all(|o| self.ranges.iter().any(|s| s.covers(o)))
    }

    /// Sort and fuse overlapping/adjacent ranges. Called by the optimizer;
    /// also makes two policies that spell the same port set differently
    /// compare equal.
    pub fn normalize(&mut self) {
        if self.ranges.len() < 2 {
            return;
        }
        self.ranges.sort();
        let mut merged: Vec<PortRange> = Vec::with_capacity(self.ranges.len());
        for r in self.ranges.drain(..) {
            match merged.last_mut() {
                Some(last) if last.adjacent_or_overlapping(&r) => {
                    last.hi = last.hi.max(r.hi);
                }
                _ => merged.push(r),
            }
        }
        self.ranges = merged;
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.ranges.len() as u16);
        for r in &self.ranges {
            w.u16(r.lo);
            w.u16(r.hi);
        }
        w.bool(self.negate);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let n = r.u16()? as usize;
        if n > constants::MAX_PORT_RANGES_PER_RULE {
            return Err(ProtoError::TooLarge(n));
        }
        let mut ranges = Vec::with_capacity(n);
        for _ in 0..n {
            let lo = r.u16()?;
            let hi = r.u16()?;
            ranges.push(PortRange { lo, hi });
        }
        Ok(PortMatch {
            ranges,
            negate: r.bool()?,
        })
    }
}

// ===========================================================================
// Application matching
// ===========================================================================

/// A glob over an executable path.
///
/// Case sensitivity is a property of the platform the pattern was written for,
/// decided by the compiler when it lowers a per-platform `applications:` block:
/// Windows and macOS paths compare case-insensitively, Linux paths do not.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PathPattern {
    pub pattern: String,
    pub case_insensitive: bool,
}

impl PathPattern {
    pub fn new(pattern: impl Into<String>, case_insensitive: bool) -> Self {
        PathPattern {
            pattern: pattern.into(),
            case_insensitive,
        }
    }

    pub fn matches(&self, path: &str) -> bool {
        if self.case_insensitive {
            glob_match(
                &self.pattern.to_ascii_lowercase(),
                &path.to_ascii_lowercase(),
            )
        } else {
            glob_match(&self.pattern, path)
        }
    }
}

/// Glob matcher supporting `*` (any run of characters, including separators)
/// and `?` (exactly one character).
///
/// Iterative with backtracking rather than recursive: a pattern like
/// `*a*a*a*...` against a long path is quadratic here but exponential in the
/// naive recursive formulation, and policy patterns are attacker-influenced on
/// the *path* side.
pub fn glob_match(pattern: &str, text: &str) -> bool {
    let p: Vec<char> = pattern.chars().collect();
    let t: Vec<char> = text.chars().collect();

    let (mut pi, mut ti) = (0usize, 0usize);
    let mut star: Option<usize> = None;
    let mut star_ti = 0usize;

    while ti < t.len() {
        if pi < p.len() && (p[pi] == '?' || p[pi] == t[ti]) {
            pi += 1;
            ti += 1;
        } else if pi < p.len() && p[pi] == '*' {
            star = Some(pi);
            star_ti = ti;
            pi += 1;
        } else if let Some(s) = star {
            pi = s + 1;
            star_ti += 1;
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pi < p.len() && p[pi] == '*' {
        pi += 1;
    }
    pi == p.len()
}

/// One way to recognize an application.
///
/// Within a fingerprint the semantics mirror [`AddressMatch`]: union within a
/// kind, intersection across kinds. So a fingerprint naming two paths and one
/// signer means "either path, *and* that signer".
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppFingerprint {
    pub paths: Vec<PathPattern>,
    pub sha256: Vec<[u8; 32]>,
    pub signers: Vec<String>,
    pub team_ids: Vec<String>,
    pub bundle_ids: Vec<String>,
}

impl AppFingerprint {
    pub fn is_empty(&self) -> bool {
        self.paths.is_empty()
            && self.sha256.is_empty()
            && self.signers.is_empty()
            && self.team_ids.is_empty()
            && self.bundle_ids.is_empty()
    }

    pub fn matches(&self, id: &AppIdentity) -> bool {
        if !self.paths.is_empty() && !self.paths.iter().any(|p| p.matches(&id.path)) {
            return false;
        }
        if !self.sha256.is_empty() {
            match &id.sha256 {
                Some(d) => {
                    if !self.sha256.iter().any(|h| h == d) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if !self.signers.is_empty() {
            match &id.signer {
                Some(s) => {
                    if !self.signers.iter().any(|w| w.eq_ignore_ascii_case(s)) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if !self.team_ids.is_empty() {
            match &id.team_id {
                Some(t) => {
                    if !self.team_ids.iter().any(|w| w == t) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if !self.bundle_ids.is_empty() {
            match &id.bundle_id {
                Some(b) => {
                    if !self.bundle_ids.iter().any(|w| w.eq_ignore_ascii_case(b)) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        true
    }

    pub fn pattern_count(&self) -> usize {
        self.paths.len()
            + self.sha256.len()
            + self.signers.len()
            + self.team_ids.len()
            + self.bundle_ids.len()
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.paths.len() as u16);
        for p in &self.paths {
            w.string(&p.pattern);
            w.bool(p.case_insensitive);
        }
        w.u16(self.sha256.len() as u16);
        for d in &self.sha256 {
            w.raw(d);
        }
        w.string_list(&self.signers);
        w.string_list(&self.team_ids);
        w.string_list(&self.bundle_ids);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let n = r.u16()? as usize;
        if n > constants::MAX_APP_PATTERNS_PER_RULE {
            return Err(ProtoError::TooLarge(n));
        }
        let mut paths = Vec::with_capacity(n);
        for _ in 0..n {
            let pattern = r.string()?;
            let ci = r.bool()?;
            paths.push(PathPattern::new(pattern, ci));
        }
        let hn = r.u16()? as usize;
        if hn > constants::MAX_APP_PATTERNS_PER_RULE {
            return Err(ProtoError::TooLarge(hn));
        }
        let mut sha256 = Vec::with_capacity(hn);
        for _ in 0..hn {
            let mut d = [0u8; 32];
            d.copy_from_slice(r.raw(32)?);
            sha256.push(d);
        }
        Ok(AppFingerprint {
            paths,
            sha256,
            signers: r.string_list()?,
            team_ids: r.string_list()?,
            bundle_ids: r.string_list()?,
        })
    }
}

/// Predicate over the resolved application identity.
///
/// # Why fingerprints are a disjunction
///
/// One logical application is a *different binary* on each platform: a signed
/// PE at a Windows path, an ELF at a Linux path, a bundle id and Team ID on
/// macOS. Flattening those into a single fingerprint and intersecting across
/// kinds is wrong in a way that fails closed and is easy to miss — the Linux
/// binary has no Authenticode signer, so a signer requirement contributed by
/// the Windows half of the definition would silently stop the rule matching on
/// Linux. (That is not hypothetical; it is what the first version of this type
/// did, and the integration fixture caught it.)
///
/// So an `AppMatch` holds a *list* of fingerprints and is satisfied when any
/// one of them matches. `trust` and `require_valid_signature` sit outside the
/// list because they are platform-independent properties of the resolved
/// identity, and they apply to whichever fingerprint matched.
///
/// A context with no resolved identity never matches, negated or not.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AppMatch {
    /// Alternatives. Empty means "no fingerprint constraint", i.e. any
    /// identified process.
    pub fingerprints: Vec<AppFingerprint>,
    /// "Unconstrained" is expressed as [`TrustMask::ANY`]; an empty mask
    /// literally matches nothing and the compiler rejects it.
    pub trust: TrustMask,
    pub require_valid_signature: bool,
    pub negate: bool,
}

impl AppMatch {
    pub fn any() -> Self {
        AppMatch {
            trust: TrustMask::ANY,
            ..Default::default()
        }
    }

    /// A predicate with a single fingerprint.
    pub fn single(fingerprint: AppFingerprint) -> Self {
        AppMatch {
            fingerprints: vec![fingerprint],
            ..AppMatch::any()
        }
    }

    /// Whether this predicate constrains nothing at all.
    pub fn is_unconstrained(&self) -> bool {
        self.fingerprints.iter().all(|f| f.is_empty())
            && self.trust.is_any()
            && !self.require_valid_signature
    }

    pub fn pattern_count(&self) -> usize {
        self.fingerprints.iter().map(|f| f.pattern_count()).sum()
    }

    pub fn matches(&self, id: Option<&AppIdentity>) -> bool {
        let Some(id) = id else {
            // Fail closed: an identity predicate over an unknown process is
            // never satisfied, and negating it does not help.
            return false;
        };

        let mut hit = true;
        if !self.fingerprints.is_empty() {
            hit &= self.fingerprints.iter().any(|f| f.matches(id));
        }
        if !self.trust.is_any() {
            hit &= self.trust.contains(id.trust);
        }
        if self.require_valid_signature {
            hit &= id.signature_valid;
        }
        hit != self.negate
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.fingerprints.len() as u16);
        for f in &self.fingerprints {
            f.encode(w);
        }
        w.u8(self.trust.0);
        w.bool(self.require_valid_signature);
        w.bool(self.negate);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let n = r.u16()? as usize;
        if n > constants::MAX_APP_PATTERNS_PER_RULE {
            return Err(ProtoError::TooLarge(n));
        }
        let mut fingerprints = Vec::with_capacity(n);
        for _ in 0..n {
            fingerprints.push(AppFingerprint::decode(r)?);
        }
        Ok(AppMatch {
            fingerprints,
            trust: TrustMask(r.u8()?),
            require_valid_signature: r.bool()?,
            negate: r.bool()?,
        })
    }
}

// ===========================================================================
// DPI matching
// ===========================================================================

/// Predicate over the DPI engine's findings for a flow.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpiMatch {
    /// Signature ids, any of which satisfies the predicate. Empty means the
    /// predicate is satisfied by protocol identification alone.
    pub signatures: Vec<u32>,
    /// Application-layer protocols the flow must have been identified as.
    /// Empty means any.
    pub l7: Vec<L7Protocol>,
    /// Action applied when the predicate is satisfied. Defaults to `Deny`.
    pub on_match: Action,
}

impl DpiMatch {
    pub fn matches(&self, scan: Option<&DpiScan>) -> bool {
        let Some(scan) = scan else {
            // No scan result means no DPI evidence, so a DPI predicate cannot
            // be satisfied. This is why a rule with a DPI clause never fires
            // before the payload has actually been inspected.
            return false;
        };
        if !self.l7.is_empty() && !self.l7.contains(&scan.l7) {
            return false;
        }
        if !self.signatures.is_empty() && !self.signatures.iter().any(|s| scan.hits.contains(s)) {
            return false;
        }
        true
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.signatures.len() as u16);
        for s in &self.signatures {
            w.u32(*s);
        }
        w.u8(self.l7.len() as u8);
        for p in &self.l7 {
            w.u8(*p as u8);
        }
        w.u8(self.on_match as u8);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let n = r.u16()? as usize;
        if n > constants::MAX_SIGNATURES_PER_RULE {
            return Err(ProtoError::TooLarge(n));
        }
        let mut signatures = Vec::with_capacity(n);
        for _ in 0..n {
            signatures.push(r.u32()?);
        }
        let ln = r.u8()? as usize;
        let mut l7 = Vec::with_capacity(ln);
        for _ in 0..ln {
            l7.push(L7Protocol::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad l7"))?);
        }
        let on_match = Action::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad action"))?;
        Ok(DpiMatch {
            signatures,
            l7,
            on_match,
        })
    }
}

/// What the DPI engine found on a flow.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct DpiScan {
    pub l7: L7Protocol,
    /// Signature ids that fired, in match order.
    pub hits: Vec<u32>,
    /// Byte offset of the first hit within the reassembled stream.
    pub first_hit_offset: u64,
    /// Set when the reassembly budget was exhausted before the stream ended,
    /// meaning a negative result is "not found in the inspected prefix" rather
    /// than "not present".
    pub truncated: bool,
}

impl DpiScan {
    pub fn encode(&self, w: &mut Writer) {
        w.u8(self.l7 as u8);
        w.u16(self.hits.len() as u16);
        for h in &self.hits {
            w.u32(*h);
        }
        w.u64(self.first_hit_offset);
        w.bool(self.truncated);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let l7 = L7Protocol::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad l7"))?;
        let n = r.u16()? as usize;
        let mut hits = Vec::with_capacity(n.min(constants::MAX_SIGNATURES_PER_RULE));
        for _ in 0..n {
            hits.push(r.u32()?);
        }
        Ok(DpiScan {
            l7,
            hits,
            first_hit_offset: r.u64()?,
            truncated: r.bool()?,
        })
    }
}

// ===========================================================================
// Schedule
// ===========================================================================

/// A recurring weekly time window, in host-local minutes.
///
/// `start` may exceed `end`, which means the window wraps past midnight into
/// the following day (and, at the week boundary, into Monday).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TimeWindow {
    /// Bit 0 = Monday .. bit 6 = Sunday.
    pub days: u8,
    pub start_minute: u16,
    pub end_minute: u16,
}

impl TimeWindow {
    pub const ALL_DAYS: u8 = 0b0111_1111;

    pub fn contains(&self, minute_of_week: u16) -> bool {
        let day = (minute_of_week / 1440) as u8;
        let minute = minute_of_week % 1440;
        if day > 6 {
            return false;
        }
        if self.days & (1 << day) == 0 {
            // A wrapping window is also active on the day *after* an enabled
            // day, for the portion before `end_minute`.
            if self.start_minute <= self.end_minute {
                return false;
            }
            let prev_day = if day == 0 { 6 } else { day - 1 };
            if self.days & (1 << prev_day) == 0 {
                return false;
            }
            return minute < self.end_minute;
        }
        if self.start_minute <= self.end_minute {
            minute >= self.start_minute && minute < self.end_minute
        } else {
            minute >= self.start_minute || minute < self.end_minute
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u8(self.days);
        w.u16(self.start_minute);
        w.u16(self.end_minute);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        Ok(TimeWindow {
            days: r.u8()?,
            start_minute: r.u16()?,
            end_minute: r.u16()?,
        })
    }
}

/// The time unit of a [`RateLimit`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatePer {
    Second,
    Minute,
    Hour,
}

impl RatePer {
    /// The nftables spelling.
    pub fn as_nft(self) -> &'static str {
        match self {
            RatePer::Second => "second",
            RatePer::Minute => "minute",
            RatePer::Hour => "hour",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s {
            "second" | "sec" | "s" => Some(RatePer::Second),
            "minute" | "min" | "m" => Some(RatePer::Minute),
            "hour" | "hr" | "h" => Some(RatePer::Hour),
            _ => None,
        }
    }
}

/// A per-rule connection-rate cap: SYN-flood and brute-force dampening.
///
/// Deliberately **not** part of the kernel-module wire encoding. Rate limiting
/// is an L3/L4 nftables feature, enforced by a `limit` statement in the
/// generated Linux ruleset rather than by the module — so it is carried to the
/// backend artifacts but never transmitted over the daemon↔module wire, and
/// Windows/macOS (which enforce through the module and the extension) do not
/// yet honour it. It is also **decision-invariant**: neither
/// [`CompiledRule::matches`] nor [`CompiledRule::effective_action`] reads it,
/// which is what keeps cross-platform equivalence green — a rate limit throttles
/// an `allow`, it is never itself a verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// New connections permitted per `per`.
    pub rate: u32,
    pub per: RatePer,
    /// Momentary excess tolerated before the cap engages. 0 means no burst.
    pub burst: u32,
}

// ===========================================================================
// Rules
// ===========================================================================

/// One compiled rule: everything a kernel backend needs to evaluate it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRule {
    /// Stable id derived from the policy and rule names.
    pub id: u32,
    /// Source-level rule name, carried for logging and CLI display.
    pub name: String,
    /// Lower is evaluated first within a layer.
    pub priority: u16,
    pub layer: Layer,
    pub direction: Direction,
    pub action: Action,
    pub protocol: Protocol,
    pub source: AddressMatch,
    pub source_ports: PortMatch,
    pub dest: AddressMatch,
    pub dest_ports: PortMatch,
    /// Identity predicate. `None` means the rule does not constrain identity
    /// and can therefore be evaluated where identity is unavailable.
    pub app: Option<AppMatch>,
    /// DPI predicate. `None` means the rule needs no payload inspection.
    pub dpi: Option<DpiMatch>,
    /// Interfaces the rule applies to. Empty means all.
    pub interfaces: Vec<String>,
    pub schedule: Option<TimeWindow>,
    /// Emit a log event when this rule decides a flow.
    pub log: bool,
    /// Whether conntrack should short-circuit subsequent packets of a flow
    /// this rule allowed.
    pub stateful: bool,
    /// Set by the optimizer: the rule's predicate is expressible entirely in
    /// eBPF (no identity, no DPI, no schedule, no interface names) and can be
    /// pushed to the tc fast path on Linux.
    pub ebpf_eligible: bool,
    /// Free-form tags from the source policy, surfaced in logs.
    pub tags: Vec<String>,
    /// A connection-rate cap, enforced at the nftables layer on Linux. Carried
    /// to the backend artifacts but not over the module wire (see [`RateLimit`]).
    pub rate_limit: Option<RateLimit>,
}

impl CompiledRule {
    /// A minimal rule, used as a builder base in tests and by the compiler.
    pub fn new(id: u32, name: impl Into<String>, layer: Layer, action: Action) -> Self {
        CompiledRule {
            id,
            name: name.into(),
            priority: constants::DEFAULT_PRIORITY,
            layer,
            direction: Direction::Any,
            action,
            protocol: Protocol::Any,
            source: AddressMatch::any(),
            source_ports: PortMatch::any(),
            dest: AddressMatch::any(),
            dest_ports: PortMatch::any(),
            app: None,
            dpi: None,
            interfaces: Vec::new(),
            schedule: None,
            log: true,
            stateful: true,
            ebpf_eligible: false,
            tags: Vec::new(),
            rate_limit: None,
        }
    }

    /// Whether the rule can be evaluated with only L3/L4 header facts.
    pub fn is_header_only(&self) -> bool {
        self.app.is_none()
            && self.dpi.is_none()
            && self.schedule.is_none()
            && self.interfaces.is_empty()
    }

    /// Whether every predicate in this rule matches the given flow.
    ///
    /// `zone_of` classifies an address; it is passed in rather than read from
    /// the policy so that backends can supply their own (possibly precomputed)
    /// classification without duplicating the network profile.
    pub fn matches(&self, ctx: &FlowContext) -> bool {
        // A rule cannot match at a stage that does not run for this protocol,
        // regardless of what its predicates say.
        if !stage_applies(self.layer, ctx.protocol) {
            return false;
        }
        if !self.direction.matches(ctx.direction) {
            return false;
        }
        if !self.protocol.matches(ctx.protocol) {
            return false;
        }
        if !self.source.matches(ctx.src_ip, ctx.src_zone) {
            return false;
        }
        if !self.dest.matches(ctx.dst_ip, ctx.dst_zone) {
            return false;
        }
        if self.protocol.has_ports() || ctx.protocol.has_ports() {
            if !self.source_ports.matches(ctx.src_port) {
                return false;
            }
            if !self.dest_ports.matches(ctx.dst_port) {
                return false;
            }
        } else if !self.source_ports.is_any() || !self.dest_ports.is_any() {
            // Port constraints on a portless protocol can never be satisfied.
            return false;
        }
        if !self.interfaces.is_empty() {
            match ctx.interface {
                Some(iface) => {
                    if !self.interfaces.iter().any(|i| i == iface) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(win) = &self.schedule {
            match ctx.minute_of_week {
                Some(m) => {
                    if !win.contains(m) {
                        return false;
                    }
                }
                None => return false,
            }
        }
        if let Some(app) = &self.app {
            // Application identity is a property of a *socket*, and only the
            // connection-oriented protocols have one that all three platforms
            // can surface at enforcement time. Windows exposes it at the ALE
            // layers and macOS through `NEFilterFlow.sourceAppAuditToken`;
            // neither fires for ICMP, and the packet-level hooks that do fire
            // carry no process context.
            //
            // Linux *could* walk `skb->sk` to a task for a locally generated
            // ICMP packet, so this restriction costs something there. It is
            // still the right rule: a policy that behaved differently on one
            // platform would break the guarantee the whole system exists to
            // provide. The compiler warns when a rule's identity predicate is
            // narrowed away by this.
            if !identity_observable(ctx.protocol) {
                return false;
            }
            if !app.matches(ctx.identity) {
                return false;
            }
        }
        if let Some(dpi) = &self.dpi {
            // Same reasoning for payload inspection: there is a reassembled
            // byte stream for TCP and a datagram payload for UDP, and nothing
            // to inspect for ICMP.
            if !identity_observable(ctx.protocol) {
                return false;
            }
            if !dpi.matches(ctx.dpi.as_ref()) {
                return false;
            }
        }
        true
    }

    /// The action this rule contributes when it matches. A rule with a DPI
    /// clause uses the DPI clause's `on_match`, which is how
    /// `action: allow` + `dpi: {on_match: deny}` expresses "allow unless the
    /// payload trips a signature".
    pub fn effective_action(&self) -> Action {
        match &self.dpi {
            Some(d) => d.on_match,
            None => self.action,
        }
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.id);
        w.string(&self.name);
        w.u16(self.priority);
        w.u8(self.layer as u8);
        w.u8(self.direction as u8);
        w.u8(self.action as u8);
        w.u16(self.protocol.to_u16());
        self.source.encode(w);
        self.source_ports.encode(w);
        self.dest.encode(w);
        self.dest_ports.encode(w);
        match &self.app {
            Some(a) => {
                w.u8(1);
                a.encode(w);
            }
            None => w.u8(0),
        }
        match &self.dpi {
            Some(d) => {
                w.u8(1);
                d.encode(w);
            }
            None => w.u8(0),
        }
        w.string_list(&self.interfaces);
        match &self.schedule {
            Some(s) => {
                w.u8(1);
                s.encode(w);
            }
            None => w.u8(0),
        }
        let mut flags = 0u16;
        if self.log {
            flags |= 1 << 0;
        }
        if self.stateful {
            flags |= 1 << 1;
        }
        if self.ebpf_eligible {
            flags |= 1 << 2;
        }
        w.u16(flags);
        w.string_list(&self.tags);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let id = r.u32()?;
        let name = r.string()?;
        let priority = r.u16()?;
        let layer = Layer::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad layer"))?;
        let direction =
            Direction::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad direction"))?;
        let action = Action::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad action"))?;
        let protocol = Protocol::from_u16(r.u16()?).ok_or(ProtoError::Malformed("bad protocol"))?;
        let source = AddressMatch::decode(r)?;
        let source_ports = PortMatch::decode(r)?;
        let dest = AddressMatch::decode(r)?;
        let dest_ports = PortMatch::decode(r)?;
        let app = if r.u8()? != 0 {
            Some(AppMatch::decode(r)?)
        } else {
            None
        };
        let dpi = if r.u8()? != 0 {
            Some(DpiMatch::decode(r)?)
        } else {
            None
        };
        let interfaces = r.string_list()?;
        let schedule = if r.u8()? != 0 {
            Some(TimeWindow::decode(r)?)
        } else {
            None
        };
        let flags = r.u16()?;
        let tags = r.string_list()?;
        Ok(CompiledRule {
            id,
            name,
            priority,
            layer,
            direction,
            action,
            protocol,
            source,
            source_ports,
            dest,
            dest_ports,
            app,
            dpi,
            interfaces,
            schedule,
            log: flags & (1 << 0) != 0,
            stateful: flags & (1 << 1) != 0,
            ebpf_eligible: flags & (1 << 2) != 0,
            tags,
            // Not on the wire: rate limiting is enforced at the nftables layer,
            // not by the module, so a decoded rule never carries one.
            rate_limit: None,
        })
    }

    pub fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.u64_field("id", self.id as u64);
        w.str_field("name", &self.name);
        w.u64_field("priority", self.priority as u64);
        w.str_field("layer", self.layer.as_str());
        w.str_field("direction", self.direction.as_str());
        w.str_field("action", self.action.as_str());
        w.str_field("protocol", &self.protocol.as_str());
        w.str_field("source", &render_address(&self.source));
        w.str_field("source_ports", &render_ports(&self.source_ports));
        w.str_field("dest", &render_address(&self.dest));
        w.str_field("dest_ports", &render_ports(&self.dest_ports));
        w.bool_field("has_identity_predicate", self.app.is_some());
        w.bool_field("has_dpi_predicate", self.dpi.is_some());
        w.bool_field("ebpf_eligible", self.ebpf_eligible);
        w.bool_field("log", self.log);
        w.str_array_field("tags", self.tags.iter().map(|s| s.as_str()));
        w.end_object();
    }
}

/// Whether a flow of this protocol carries application identity and
/// inspectable payload on every supported platform.
///
/// `Any` is included because an abstract context (one the caller has not
/// narrowed to a concrete protocol) must not be excluded by this test; real
/// enforcement contexts always name a protocol.
pub fn identity_observable(protocol: Protocol) -> bool {
    matches!(protocol, Protocol::Tcp | Protocol::Udp | Protocol::Any)
}

/// Whether a stage's rules apply to a flow of this protocol at all.
///
/// The perimeter and packet stages decide from header fields, which every
/// protocol has. The identity, app-dpi and stream stages need a socket with an
/// owning process and a payload to inspect — neither of which exists for ICMP,
/// and neither of which Windows or macOS can surface for it at any hook.
///
/// This is a property of the *stage*, not of the predicate, and the difference
/// is not academic. A terminal `layer: stream` deny carries no identity or DPI
/// predicate, so the predicate-level gates above never fire for it; without
/// this check the reference model would attribute an ICMP denial to that rule
/// while Windows and macOS attributed it to the default deny. Same verdict,
/// different rule id in the log — which is precisely the kind of disagreement
/// cross-platform log correlation cannot tolerate, and precisely the kind a
/// verdict-only comparison would miss.
pub fn stage_applies(layer: Layer, protocol: Protocol) -> bool {
    match layer {
        Layer::Perimeter | Layer::Packet => true,
        Layer::Identity | Layer::AppDpi | Layer::Stream => identity_observable(protocol),
    }
}

/// Human-readable rendering of an address predicate, used by the CLI and the
/// generated backend sources.
pub fn render_address(m: &AddressMatch) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in &m.cidrs {
        parts.push(c.to_string());
    }
    for z in &m.zones {
        parts.push(format!("zone:{}", z.as_str()));
    }
    if parts.is_empty() {
        return "any".into();
    }
    let joined = parts.join(",");
    if m.negate {
        format!("!{joined}")
    } else {
        joined
    }
}

pub fn render_ports(m: &PortMatch) -> String {
    if m.ranges.is_empty() {
        return "any".into();
    }
    let joined = m
        .ranges
        .iter()
        .map(|r| r.to_string())
        .collect::<Vec<_>>()
        .join(",");
    if m.negate {
        format!("!{joined}")
    } else {
        joined
    }
}

// ===========================================================================
// macOS placement
// ===========================================================================

/// Which `NEFilter` callback carries a rule on macOS.
///
/// This lives here rather than in the macOS backend because two things need
/// it and they run at different times: the compiler, when it emits the
/// build-time rule table, and the extension, when it decodes a policy the
/// daemon pushed over the control socket. A rule placed one way at build time
/// and the other way at runtime is a rule that filters differently depending
/// on how it arrived.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MacosProvider {
    /// `handleNewFlow`, where `sourceAppAuditToken` gives us the process.
    Flow = 0,
    /// `handleNewPacket`, which sees ICMP and everything else without a flow
    /// — and carries no process context at all.
    Packet = 1,
}

/// Which protocols a placement is scoped to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum MacosScope {
    All = 0,
    ConnectionOriented = 1,
    Connectionless = 2,
}

impl MacosProvider {
    pub fn as_str(self) -> &'static str {
        match self {
            MacosProvider::Flow => "flow",
            MacosProvider::Packet => "packet",
        }
    }
}

impl MacosScope {
    pub fn as_str(self) -> &'static str {
        match self {
            MacosScope::All => "any",
            MacosScope::ConnectionOriented => "connectionOriented",
            MacosScope::Connectionless => "connectionless",
        }
    }
}

/// Protocols delivered through `handleNewFlow`.
pub const MACOS_FLOW_PROTOCOLS: [Protocol; 2] = [Protocol::Tcp, Protocol::Udp];

impl CompiledRule {
    /// Where this rule is installed on macOS.
    ///
    /// Usually one placement; a protocol-agnostic rule gets two, because the
    /// flow provider and the packet provider between them cover what one hook
    /// covers on the other platforms. Returning a list rather than a single
    /// value is what makes that expansion explicit instead of a special case
    /// two implementations have to remember.
    ///
    /// An identity-scoped rule is never placed on the packet provider:
    /// `handleNewPacket` has no audit token, so the predicate could not be
    /// evaluated there. Installing it anyway would be a rule that silently
    /// never matches, which is worse than one that is absent.
    pub fn macos_placements(&self) -> Vec<(MacosProvider, MacosScope)> {
        let flow_protocol = MACOS_FLOW_PROTOCOLS.contains(&self.protocol);
        let agnostic = self.protocol == Protocol::Any;

        // Payload inspection only exists for flows, whatever the protocol says.
        if matches!(self.layer, Layer::AppDpi | Layer::Stream) {
            return vec![(MacosProvider::Flow, MacosScope::ConnectionOriented)];
        }

        let mut out = Vec::new();
        if agnostic || flow_protocol {
            out.push((MacosProvider::Flow, MacosScope::ConnectionOriented));
        }
        if (agnostic || !flow_protocol) && self.app.is_none() {
            out.push((MacosProvider::Packet, MacosScope::Connectionless));
        }
        out
    }
}

// ===========================================================================
// Network profile
// ===========================================================================

/// The host's view of its network surroundings, used to classify peers into
/// zones (defense Layer 1).
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct NetworkProfile {
    pub internal: Vec<Cidr>,
    pub perimeter: Vec<Cidr>,
    pub gateways: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    /// When set, an `Allow` rule whose destination can cross the perimeter is
    /// lowered to `AllowInspect` by the compiler, forcing deeper inspection of
    /// everything leaving the trusted network.
    pub perimeter_crossing_requires_dpi: bool,
}

impl NetworkProfile {
    pub fn classify(&self, ip: IpAddr) -> Zone {
        if ip.is_loopback() {
            return Zone::Loopback;
        }
        if self.internal.iter().any(|c| c.contains(ip)) {
            return Zone::Internal;
        }
        if self.perimeter.iter().any(|c| c.contains(ip)) {
            return Zone::Perimeter;
        }
        Zone::External
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.internal.len() as u16);
        for c in &self.internal {
            c.encode(w);
        }
        w.u16(self.perimeter.len() as u16);
        for c in &self.perimeter {
            c.encode(w);
        }
        w.u16(self.gateways.len() as u16);
        for g in &self.gateways {
            encode_ip(w, *g);
        }
        w.u16(self.dns_servers.len() as u16);
        for d in &self.dns_servers {
            encode_ip(w, *d);
        }
        w.bool(self.perimeter_crossing_requires_dpi);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let read_cidrs = |r: &mut Reader<'_>| -> Result<Vec<Cidr>, ProtoError> {
            let n = r.u16()? as usize;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                v.push(Cidr::decode(r)?);
            }
            Ok(v)
        };
        let internal = read_cidrs(r)?;
        let perimeter = read_cidrs(r)?;
        let read_ips = |r: &mut Reader<'_>| -> Result<Vec<IpAddr>, ProtoError> {
            let n = r.u16()? as usize;
            let mut v = Vec::with_capacity(n.min(1024));
            for _ in 0..n {
                v.push(decode_ip(r)?);
            }
            Ok(v)
        };
        let gateways = read_ips(r)?;
        let dns_servers = read_ips(r)?;
        Ok(NetworkProfile {
            internal,
            perimeter,
            gateways,
            dns_servers,
            perimeter_crossing_requires_dpi: r.bool()?,
        })
    }
}

fn encode_ip(w: &mut Writer, ip: IpAddr) {
    match ip {
        IpAddr::V4(a) => {
            w.u8(4);
            w.raw(&a.octets());
        }
        IpAddr::V6(a) => {
            w.u8(6);
            w.raw(&a.octets());
        }
    }
}

fn decode_ip(r: &mut Reader<'_>) -> Result<IpAddr, ProtoError> {
    match r.u8()? {
        4 => {
            let mut o = [0u8; 4];
            o.copy_from_slice(r.raw(4)?);
            Ok(IpAddr::V4(Ipv4Addr::from(o)))
        }
        6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(r.raw(16)?);
            Ok(IpAddr::V6(Ipv6Addr::from(o)))
        }
        _ => Err(ProtoError::Malformed("bad address family")),
    }
}

// ===========================================================================
// Compiled policy
// ===========================================================================

/// The complete artifact the compiler produces and the daemon installs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledPolicy {
    pub wire_version: u16,
    /// Monotonically increasing, assigned by the daemon on each successful
    /// compile. The kernel module rejects an update whose base revision does
    /// not match what it currently has installed.
    pub revision: u64,
    pub name: String,
    /// Applied when no rule reaches a terminal action.
    pub default_action: Decision,
    pub rules: Vec<CompiledRule>,
    pub network_profile: NetworkProfile,
    /// SHA-256 over the canonical encoding of everything above. Both sides of
    /// the IPC channel compute it independently and compare.
    pub ruleset_hash: [u8; 32],
}

impl CompiledPolicy {
    pub fn new(name: impl Into<String>, default_action: Decision) -> Self {
        CompiledPolicy {
            wire_version: constants::POLICY_WIRE_VERSION,
            revision: 0,
            name: name.into(),
            default_action,
            rules: Vec::new(),
            network_profile: NetworkProfile::default(),
            ruleset_hash: [0u8; 32],
        }
    }

    /// Sort rules into evaluation order and recompute the ruleset hash.
    ///
    /// Must be called after any mutation; the compiler calls it once at the
    /// end of code generation and the daemon calls it after applying a delta.
    pub fn finalize(&mut self) {
        self.rules.sort_by(|a, b| {
            a.layer
                .stage_index()
                .cmp(&b.layer.stage_index())
                .then(a.priority.cmp(&b.priority))
                .then(a.id.cmp(&b.id))
        });
        self.ruleset_hash = [0u8; 32];
        let bytes = self.encode();
        self.ruleset_hash = hash::sha256(&bytes);
    }

    pub fn find(&self, id: u32) -> Option<&CompiledRule> {
        self.rules.iter().find(|r| r.id == id)
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut w = Writer::new();
        self.encode_into(&mut w);
        w.finish()
    }

    pub fn encode_into(&self, w: &mut Writer) {
        w.u16(self.wire_version);
        w.u64(self.revision);
        w.string(&self.name);
        w.u8(self.default_action as u8);
        self.network_profile.encode(w);
        w.u32(self.rules.len() as u32);
        for r in &self.rules {
            r.encode(w);
        }
        w.raw(&self.ruleset_hash);
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, ProtoError> {
        let mut r = Reader::new(bytes);
        Self::decode_from(&mut r)
    }

    pub fn decode_from(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let wire_version = r.u16()?;
        if wire_version != constants::POLICY_WIRE_VERSION {
            return Err(ProtoError::UnsupportedVersion(wire_version));
        }
        let revision = r.u64()?;
        let name = r.string()?;
        let default_action =
            Decision::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad default action"))?;
        let network_profile = NetworkProfile::decode(r)?;
        let n = r.u32()? as usize;
        if n > constants::MAX_RULES {
            return Err(ProtoError::TooLarge(n));
        }
        let mut rules = Vec::with_capacity(n.min(4096));
        for _ in 0..n {
            rules.push(CompiledRule::decode(r)?);
        }
        let mut ruleset_hash = [0u8; 32];
        ruleset_hash.copy_from_slice(r.raw(32)?);
        Ok(CompiledPolicy {
            wire_version,
            revision,
            name,
            default_action,
            rules,
            network_profile,
            ruleset_hash,
        })
    }

    /// Hash of the policy's *content*, ignoring its revision number.
    ///
    /// `ruleset_hash` covers the revision, which is what makes it a fingerprint
    /// of a specific installation. Deciding whether a freshly compiled policy
    /// actually differs from the active one needs the opposite: a fingerprint
    /// that is stable across renumbering, so that recompiling an unchanged file
    /// does not churn the kernel.
    pub fn content_hash(&self) -> [u8; 32] {
        let mut probe = self.clone();
        probe.revision = 0;
        probe.ruleset_hash = [0u8; 32];
        hash::sha256(&probe.encode())
    }

    /// Recompute the hash and compare it against the stored one.
    pub fn verify_hash(&self) -> bool {
        let mut probe = self.clone();
        probe.ruleset_hash = [0u8; 32];
        hash::sha256(&probe.encode()) == self.ruleset_hash
    }

    /// The reference semantics. See the module documentation.
    pub fn evaluate(&self, ctx: &FlowContext) -> Evaluation {
        let mut eval = Evaluation {
            decision: self.default_action,
            rule_id: constants::RULE_ID_DEFAULT,
            layer: Layer::Packet,
            terminal_action: None,
            alerts: Vec::new(),
            stages_entered: 0,
        };

        for stage in EVALUATION_ORDER {
            let mut entered = false;
            for rule in self.rules.iter().filter(|r| r.layer == stage) {
                if !entered {
                    entered = true;
                    eval.stages_entered += 1;
                }
                if !rule.matches(ctx) {
                    continue;
                }
                match rule.effective_action() {
                    Action::Allow => {
                        eval.decision = Decision::Allow;
                        eval.rule_id = rule.id;
                        eval.layer = stage;
                        eval.terminal_action = Some(Action::Allow);
                        return eval;
                    }
                    Action::Deny => {
                        eval.decision = Decision::Deny;
                        eval.rule_id = rule.id;
                        eval.layer = stage;
                        eval.terminal_action = Some(Action::Deny);
                        return eval;
                    }
                    Action::AllowInspect => {
                        // Provisional permit: remember it, then move on to the
                        // next stage so deeper inspection can still deny.
                        eval.decision = Decision::Allow;
                        eval.rule_id = rule.id;
                        eval.layer = stage;
                        eval.terminal_action = Some(Action::AllowInspect);
                        break;
                    }
                    Action::Alert => {
                        eval.alerts.push(rule.id);
                    }
                    Action::Continue => {}
                }
            }
        }

        eval
    }
}

/// Everything known about a flow at the point of decision.
///
/// Fields that a given enforcement layer cannot supply are `None`. Rules that
/// depend on them will not match, which is the mechanism behind the staged
/// evaluation model.
#[derive(Debug, Clone)]
pub struct FlowContext<'a> {
    pub direction: Direction,
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
    /// Zone of the source address, classified by the policy's network profile.
    ///
    /// Zones are a property of the address, not of the direction, so both
    /// endpoints are classified independently and a rule's `source:`/`dest:`
    /// zone predicates read the corresponding field. Which of the two is the
    /// *peer* is a separate question, answered by [`FlowContext::remote_zone`].
    pub src_zone: Zone,
    /// Zone of the destination address.
    pub dst_zone: Zone,
    pub identity: Option<&'a AppIdentity>,
    pub dpi: Option<DpiScan>,
    pub interface: Option<&'a str>,
    /// Minutes since Monday 00:00 local time, for scheduled rules.
    pub minute_of_week: Option<u16>,
}

impl<'a> FlowContext<'a> {
    /// Build a context, classifying both endpoints with `profile`.
    pub fn new(
        profile: &NetworkProfile,
        direction: Direction,
        protocol: Protocol,
        src: (IpAddr, u16),
        dst: (IpAddr, u16),
    ) -> Self {
        FlowContext {
            direction,
            protocol,
            src_ip: src.0,
            src_port: src.1,
            dst_ip: dst.0,
            dst_port: dst.1,
            src_zone: profile.classify(src.0),
            dst_zone: profile.classify(dst.0),
            identity: None,
            dpi: None,
            interface: None,
            minute_of_week: None,
        }
    }

    pub fn with_identity(mut self, id: &'a AppIdentity) -> Self {
        self.identity = Some(id);
        self
    }

    pub fn with_dpi(mut self, scan: DpiScan) -> Self {
        self.dpi = Some(scan);
        self
    }

    pub fn with_interface(mut self, iface: &'a str) -> Self {
        self.interface = Some(iface);
        self
    }

    pub fn with_minute_of_week(mut self, m: u16) -> Self {
        self.minute_of_week = Some(m);
        self
    }

    /// The peer address: the source for an inbound flow, the destination
    /// otherwise.
    pub fn remote_ip(&self) -> IpAddr {
        match self.direction {
            Direction::Inbound => self.src_ip,
            _ => self.dst_ip,
        }
    }

    /// Zone of the peer. This is what log enrichment reports as the flow's
    /// network context and what `perimeter_crossing_requires_dpi` keys off.
    pub fn remote_zone(&self) -> Zone {
        match self.direction {
            Direction::Inbound => self.src_zone,
            _ => self.dst_zone,
        }
    }

    /// Whether this flow crosses the network perimeter (defense Layer 1).
    pub fn crosses_perimeter(&self) -> bool {
        self.remote_zone().crosses_perimeter()
    }
}

/// Result of evaluating a policy against a flow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Evaluation {
    pub decision: Decision,
    /// Rule that produced the decision, or [`constants::RULE_ID_DEFAULT`].
    pub rule_id: u32,
    pub layer: Layer,
    /// The action of the deciding rule, or `None` when the default applied.
    pub terminal_action: Option<Action>,
    /// Rules that fired `alert` along the way.
    pub alerts: Vec<u32>,
    /// How many stages contained at least one rule. Diagnostic only; not part
    /// of the equivalence contract.
    pub stages_entered: u8,
}

impl Evaluation {
    /// The pair that all three backends must agree on.
    pub fn verdict(&self) -> (Decision, u32) {
        (self.decision, self.rule_id)
    }

    pub fn matched_default(&self) -> bool {
        self.rule_id == constants::RULE_ID_DEFAULT
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use crate::identity_types::{SignatureType, TrustLevel};

    fn v4(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn profile() -> NetworkProfile {
        NetworkProfile {
            internal: vec![Cidr::parse("10.0.0.0/8").unwrap()],
            perimeter: vec![Cidr::parse("203.0.113.0/24").unwrap()],
            gateways: vec![v4("10.0.0.1")],
            dns_servers: vec![v4("10.0.0.53")],
            perimeter_crossing_requires_dpi: false,
        }
    }

    fn identity(path: &str, trust: TrustLevel) -> AppIdentity {
        let mut id = AppIdentity::unresolved(1234, 0);
        id.path = path.into();
        id.trust = trust;
        id.signature_type = SignatureType::ElfContentHash;
        id.signature_valid = trust >= TrustLevel::Known;
        id
    }

    // --- CIDR -------------------------------------------------------------

    #[test]
    fn cidr_canonicalizes_host_bits() {
        let c = Cidr::parse("10.1.2.3/8").unwrap();
        assert_eq!(c.to_string(), "10.0.0.0/8");
        assert!(c.contains(v4("10.255.255.255")));
        assert!(!c.contains(v4("11.0.0.1")));
    }

    #[test]
    fn cidr_bare_address_is_host_route() {
        assert_eq!(Cidr::parse("1.1.1.1").unwrap().prefix(), 32);
        assert_eq!(Cidr::parse("::1").unwrap().prefix(), 128);
    }

    #[test]
    fn cidr_rejects_oversized_prefix() {
        assert!(Cidr::parse("10.0.0.0/33").is_none());
        assert!(Cidr::parse("::/129").is_none());
    }

    #[test]
    fn cidr_v4_mapped_v6_is_not_an_escape_hatch() {
        let c = Cidr::parse("10.0.0.0/8").unwrap();
        let mapped: IpAddr = "::ffff:10.1.2.3".parse().unwrap();
        assert!(c.contains(mapped));
    }

    #[test]
    fn cidr_coverage() {
        let wide = Cidr::parse("10.0.0.0/8").unwrap();
        let narrow = Cidr::parse("10.1.0.0/16").unwrap();
        assert!(wide.covers(&narrow));
        assert!(!narrow.covers(&wide));
        assert!(!wide.covers(&Cidr::parse("2001:db8::/32").unwrap()));
    }

    #[test]
    fn cidr_prefix_not_multiple_of_eight() {
        let c = Cidr::parse("192.168.4.0/22").unwrap();
        assert!(c.contains(v4("192.168.7.255")));
        assert!(!c.contains(v4("192.168.8.0")));
    }

    // --- ports ------------------------------------------------------------

    #[test]
    fn port_normalization_fuses_ranges() {
        let mut m = PortMatch {
            ranges: vec![
                PortRange::new(100, 200),
                PortRange::new(201, 300),
                PortRange::single(80),
                PortRange::new(150, 160),
            ],
            negate: false,
        };
        m.normalize();
        assert_eq!(
            m.ranges,
            vec![PortRange::single(80), PortRange::new(100, 300)]
        );
    }

    #[test]
    fn port_negation() {
        let m = PortMatch {
            ranges: vec![PortRange::single(22)],
            negate: true,
        };
        assert!(!m.matches(22));
        assert!(m.matches(80));
    }

    #[test]
    fn port_parse_forms() {
        assert_eq!(PortRange::parse("443"), Some(PortRange::single(443)));
        assert_eq!(PortRange::parse("100-200"), Some(PortRange::new(100, 200)));
        // Reversed ranges are normalized rather than rejected.
        assert_eq!(PortRange::parse("200-100"), Some(PortRange::new(100, 200)));
        assert_eq!(PortRange::parse("70000"), None);
    }

    // --- globs ------------------------------------------------------------

    #[test]
    fn glob_basics() {
        assert!(glob_match("/usr/bin/*", "/usr/bin/curl"));
        assert!(glob_match("*.exe", "app.exe"));
        assert!(glob_match("a?c", "abc"));
        assert!(!glob_match("a?c", "ac"));
        assert!(glob_match("*", ""));
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
        assert!(glob_match("/a/*/c", "/a/b/c"));
        // `*` deliberately spans separators.
        assert!(glob_match("/a/*/c", "/a/b/x/c"));
    }

    #[test]
    fn glob_backtracks_without_blowing_up() {
        let pat = "*a*a*a*a*a*a*a*a*b";
        let text = "a".repeat(200);
        assert!(!glob_match(pat, &text));
    }

    #[test]
    fn path_pattern_case_sensitivity_is_explicit() {
        let ci = PathPattern::new(r"C:\Windows\*\svchost.exe", true);
        assert!(ci.matches(r"c:\windows\system32\svchost.exe"));
        let cs = PathPattern::new("/usr/bin/Curl", false);
        assert!(!cs.matches("/usr/bin/curl"));
    }

    // --- app matching -----------------------------------------------------

    #[test]
    fn app_match_intersects_across_kinds() {
        let m = AppMatch {
            fingerprints: vec![AppFingerprint {
                paths: vec![PathPattern::new("/usr/bin/*", false)],
                ..Default::default()
            }],
            trust: TrustMask::from_levels([TrustLevel::Trusted]),
            ..AppMatch::any()
        };
        assert!(m.matches(Some(&identity("/usr/bin/curl", TrustLevel::Trusted))));
        // Right path, wrong trust.
        assert!(!m.matches(Some(&identity("/usr/bin/curl", TrustLevel::Unknown))));
        // Right trust, wrong path.
        assert!(!m.matches(Some(&identity("/opt/x", TrustLevel::Trusted))));
    }

    #[test]
    fn app_match_never_matches_missing_identity() {
        let m = AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Unknown]),
            ..AppMatch::any()
        };
        assert!(!m.matches(None));
        let negated = AppMatch { negate: true, ..m };
        // Negation does not turn "unknown process" into a match.
        assert!(!negated.matches(None));
    }

    #[test]
    fn app_match_absent_field_is_not_a_wildcard() {
        let m = AppMatch::single(AppFingerprint {
            team_ids: vec!["ABCDE12345".into()],
            ..Default::default()
        });
        // A Linux identity has no team id, so a team-id rule cannot match it.
        assert!(!m.matches(Some(&identity("/usr/bin/curl", TrustLevel::Trusted))));
    }

    #[test]
    fn fingerprints_are_alternatives_not_one_flattened_predicate() {
        // A cross-platform application: a signed PE on Windows, a bare path on
        // Linux. Flattening these would make the Linux binary fail the
        // Windows signer requirement, which is exactly the bug this shape
        // exists to prevent.
        let m = AppMatch {
            fingerprints: vec![
                AppFingerprint {
                    paths: vec![PathPattern::new(r"C:\\App\\app.exe", true)],
                    signers: vec!["Contoso Ltd".into()],
                    ..Default::default()
                },
                AppFingerprint {
                    paths: vec![PathPattern::new("/usr/bin/app", false)],
                    ..Default::default()
                },
            ],
            ..AppMatch::any()
        };

        let mut linux = identity("/usr/bin/app", TrustLevel::Trusted);
        linux.signer = None;
        assert!(
            m.matches(Some(&linux)),
            "linux binary must match its own fingerprint"
        );

        let mut windows = identity(r"C:\\App\\app.exe", TrustLevel::Trusted);
        windows.signer = Some("Contoso Ltd".into());
        assert!(m.matches(Some(&windows)));

        // The Windows path without the signer matches neither alternative.
        let mut forged = identity(r"C:\\App\\app.exe", TrustLevel::Trusted);
        forged.signer = Some("Someone Else".into());
        assert!(!m.matches(Some(&forged)));
    }

    #[test]
    fn trust_applies_across_every_fingerprint() {
        let m = AppMatch {
            fingerprints: vec![
                AppFingerprint {
                    paths: vec![PathPattern::new("/a", false)],
                    ..Default::default()
                },
                AppFingerprint {
                    paths: vec![PathPattern::new("/b", false)],
                    ..Default::default()
                },
            ],
            trust: TrustMask::from_levels([TrustLevel::System]),
            ..AppMatch::any()
        };
        assert!(m.matches(Some(&identity("/a", TrustLevel::System))));
        assert!(!m.matches(Some(&identity("/b", TrustLevel::Trusted))));
    }

    // --- schedule ---------------------------------------------------------

    #[test]
    fn schedule_simple_window() {
        // Monday-Friday 09:00-17:00
        let w = TimeWindow {
            days: 0b0001_1111,
            start_minute: 540,
            end_minute: 1020,
        };
        assert!(w.contains(600)); // Mon 10:00
        assert!(!w.contains(400)); // Mon 06:40
        assert!(!w.contains(5 * 1440 + 600)); // Sat 10:00
    }

    #[test]
    fn schedule_wrapping_window_spills_into_next_day() {
        // Friday 22:00 - 02:00
        let w = TimeWindow {
            days: 0b0001_0000,
            start_minute: 1320,
            end_minute: 120,
        };
        assert!(w.contains(4 * 1440 + 1380)); // Fri 23:00
        assert!(w.contains(5 * 1440 + 60)); // Sat 01:00 (spill)
        assert!(!w.contains(5 * 1440 + 180)); // Sat 03:00
        assert!(!w.contains(3 * 1440 + 1380)); // Thu 23:00
    }

    // --- evaluation -------------------------------------------------------

    fn allow_dns_rule() -> CompiledRule {
        let mut r = CompiledRule::new(10, "allow-dns", Layer::Packet, Action::Allow);
        r.priority = 100;
        r.direction = Direction::Outbound;
        r.protocol = Protocol::Udp;
        r.dest_ports = PortMatch {
            ranges: vec![PortRange::single(53)],
            negate: false,
        };
        r
    }

    fn build_policy(rules: Vec<CompiledRule>, default_action: Decision) -> CompiledPolicy {
        let mut p = CompiledPolicy::new("test", default_action);
        p.network_profile = profile();
        p.rules = rules;
        p.finalize();
        p
    }

    #[test]
    fn default_action_applies_when_nothing_matches() {
        let p = build_policy(vec![allow_dns_rule()], Decision::Deny);
        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 40000),
            (v4("1.2.3.4"), 443),
        );
        let e = p.evaluate(&ctx);
        assert_eq!(e.decision, Decision::Deny);
        assert!(e.matched_default());
    }

    #[test]
    fn first_match_by_priority_wins() {
        let mut deny_all = CompiledRule::new(20, "deny-all", Layer::Packet, Action::Deny);
        deny_all.priority = 900;
        let p = build_policy(vec![deny_all, allow_dns_rule()], Decision::Deny);

        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Udp,
            (v4("10.0.0.5"), 40000),
            (v4("10.0.0.53"), 53),
        );
        let e = p.evaluate(&ctx);
        assert_eq!(e.verdict(), (Decision::Allow, 10));
    }

    #[test]
    fn allow_inspect_lets_a_deeper_layer_deny() {
        let mut allow = CompiledRule::new(30, "allow-web", Layer::Packet, Action::AllowInspect);
        allow.priority = 100;
        allow.protocol = Protocol::Tcp;
        allow.dest_ports = PortMatch {
            ranges: vec![PortRange::single(443)],
            negate: false,
        };

        let mut dpi_deny = CompiledRule::new(31, "block-exploit", Layer::Stream, Action::Allow);
        dpi_deny.priority = 10;
        dpi_deny.dpi = Some(DpiMatch {
            signatures: vec![777],
            l7: vec![L7Protocol::Tls],
            on_match: Action::Deny,
        });

        let p = build_policy(vec![allow, dpi_deny], Decision::Deny);

        let base = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 40000),
            (v4("1.2.3.4"), 443),
        );

        // No DPI evidence yet: the provisional allow stands.
        let e = p.evaluate(&base);
        assert_eq!(e.verdict(), (Decision::Allow, 30));

        // Signature fires: the stream layer overrides the packet layer.
        let scanned = base.clone().with_dpi(DpiScan {
            l7: L7Protocol::Tls,
            hits: vec![777],
            first_hit_offset: 12,
            truncated: false,
        });
        let e = p.evaluate(&scanned);
        assert_eq!(e.verdict(), (Decision::Deny, 31));
    }

    #[test]
    fn terminal_allow_short_circuits_deeper_layers() {
        let mut allow = CompiledRule::new(40, "allow-web", Layer::Packet, Action::Allow);
        allow.priority = 100;
        let mut dpi_deny = CompiledRule::new(41, "block-exploit", Layer::Stream, Action::Allow);
        dpi_deny.dpi = Some(DpiMatch {
            signatures: vec![777],
            l7: vec![],
            on_match: Action::Deny,
        });

        let p = build_policy(vec![allow, dpi_deny], Decision::Deny);
        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("1.2.3.4"), 443),
        )
        .with_dpi(DpiScan {
            l7: L7Protocol::Tls,
            hits: vec![777],
            first_hit_offset: 0,
            truncated: false,
        });

        // A plain `allow` means "stop looking", so the DPI rule never runs.
        assert_eq!(p.evaluate(&ctx).verdict(), (Decision::Allow, 40));
    }

    #[test]
    fn identity_stage_runs_before_dpi_stage() {
        let mut ident = CompiledRule::new(50, "deny-untrusted", Layer::Identity, Action::Deny);
        ident.priority = 10;
        ident.app = Some(AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Untrusted, TrustLevel::Unknown]),
            ..AppMatch::any()
        });

        let mut dpi = CompiledRule::new(51, "alert-tls", Layer::AppDpi, Action::Allow);
        dpi.dpi = Some(DpiMatch {
            signatures: vec![],
            l7: vec![L7Protocol::Tls],
            on_match: Action::Allow,
        });

        let p = build_policy(vec![ident, dpi], Decision::Allow);
        let id = identity("/tmp/dropper", TrustLevel::Unknown);
        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("1.2.3.4"), 443),
        )
        .with_identity(&id)
        .with_dpi(DpiScan {
            l7: L7Protocol::Tls,
            hits: vec![],
            first_hit_offset: 0,
            truncated: false,
        });

        assert_eq!(p.evaluate(&ctx).verdict(), (Decision::Deny, 50));
    }

    #[test]
    fn alerts_accumulate_without_deciding() {
        let mut alert = CompiledRule::new(60, "note-it", Layer::Packet, Action::Alert);
        alert.priority = 1;
        let mut allow = CompiledRule::new(61, "allow", Layer::Packet, Action::Allow);
        allow.priority = 2;
        let p = build_policy(vec![alert, allow], Decision::Deny);
        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("1.2.3.4"), 443),
        );
        let e = p.evaluate(&ctx);
        assert_eq!(e.alerts, vec![60]);
        assert_eq!(e.verdict(), (Decision::Allow, 61));
    }

    #[test]
    fn zone_predicates_use_the_network_profile() {
        let mut r = CompiledRule::new(70, "deny-external", Layer::Packet, Action::Deny);
        r.priority = 10;
        r.dest = AddressMatch {
            cidrs: vec![],
            zones: vec![Zone::External],
            negate: false,
        };
        let p = build_policy(vec![r], Decision::Allow);

        let internal = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("10.9.9.9"), 443),
        );
        assert_eq!(p.evaluate(&internal).decision, Decision::Allow);

        let external = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("8.8.8.8"), 443),
        );
        assert_eq!(p.evaluate(&external).verdict(), (Decision::Deny, 70));

        // The declared perimeter range is its own zone, not "external".
        let dmz = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("203.0.113.9"), 443),
        );
        assert_eq!(p.evaluate(&dmz).decision, Decision::Allow);
    }

    #[test]
    fn identity_predicates_do_not_apply_to_portless_protocols() {
        // Windows ALE and the macOS flow provider never fire for ICMP, so the
        // reference must agree that an identity rule does not cover it --
        // otherwise the same policy would behave differently per platform.
        let mut r = CompiledRule::new(90, "deny-untrusted", Layer::Identity, Action::Deny);
        r.app = Some(AppMatch {
            trust: TrustMask::from_levels([TrustLevel::Untrusted]),
            ..AppMatch::any()
        });
        let p = build_policy(vec![r], Decision::Allow);
        let id = identity("/tmp/x", TrustLevel::Untrusted);

        let icmp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Icmp,
            (v4("10.0.0.5"), 0),
            (v4("1.2.3.4"), 0),
        )
        .with_identity(&id);
        assert_eq!(p.evaluate(&icmp).decision, Decision::Allow);

        let tcp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1),
            (v4("1.2.3.4"), 443),
        )
        .with_identity(&id);
        assert_eq!(p.evaluate(&tcp).verdict(), (Decision::Deny, 90));
    }

    #[test]
    fn dpi_predicates_do_not_apply_to_portless_protocols() {
        let mut r = CompiledRule::new(91, "sig", Layer::Stream, Action::Allow);
        r.dpi = Some(DpiMatch {
            signatures: vec![5],
            l7: vec![],
            on_match: Action::Deny,
        });
        let p = build_policy(vec![r], Decision::Allow);
        let scan = DpiScan {
            l7: L7Protocol::Unknown,
            hits: vec![5],
            first_hit_offset: 0,
            truncated: false,
        };

        let icmp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Icmp,
            (v4("10.0.0.5"), 0),
            (v4("1.2.3.4"), 0),
        )
        .with_dpi(scan.clone());
        assert_eq!(p.evaluate(&icmp).decision, Decision::Allow);

        let udp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Udp,
            (v4("10.0.0.5"), 1),
            (v4("1.2.3.4"), 53),
        )
        .with_dpi(scan);
        assert_eq!(p.evaluate(&udp).verdict(), (Decision::Deny, 91));
    }

    #[test]
    fn port_constraints_on_portless_protocols_never_match() {
        let mut r = CompiledRule::new(80, "icmp-with-ports", Layer::Packet, Action::Allow);
        r.protocol = Protocol::Icmp;
        r.dest_ports = PortMatch {
            ranges: vec![PortRange::single(53)],
            negate: false,
        };
        let p = build_policy(vec![r], Decision::Deny);
        let ctx = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Icmp,
            (v4("10.0.0.5"), 0),
            (v4("1.2.3.4"), 0),
        );
        assert_eq!(p.evaluate(&ctx).decision, Decision::Deny);
    }

    #[test]
    fn a_flow_stage_rule_does_not_claim_icmp() {
        // A terminal `layer: stream` deny carries no identity or DPI
        // predicate, so the predicate-level gates never fire for it. Windows
        // and macOS install no stream-stage filter for ICMP, so if the
        // reference model let this rule match, all three would still say
        // "deny" while disagreeing about *which rule* denied it — a
        // divergence a verdict-only comparison cannot see, and one that
        // breaks cross-platform log correlation.
        let terminal = CompiledRule::new(9999, "deny-unnamed", Layer::Stream, Action::Deny);
        let terminal_id = terminal.id;
        let p = build_policy(vec![terminal], Decision::Deny);

        let icmp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Icmp,
            (v4("10.0.0.5"), 0),
            (v4("1.2.3.4"), 0),
        );
        let verdict = p.evaluate(&icmp);
        assert_eq!(verdict.decision, Decision::Deny);
        assert_ne!(
            verdict.rule_id, terminal_id,
            "a stream-stage rule must not be credited with an ICMP denial"
        );

        // The same rule does apply to TCP, which does have a stream.
        let tcp = FlowContext::new(
            &p.network_profile,
            Direction::Outbound,
            Protocol::Tcp,
            (v4("10.0.0.5"), 1234),
            (v4("1.2.3.4"), 443),
        );
        assert_eq!(p.evaluate(&tcp).rule_id, terminal_id);
    }

    #[test]
    fn header_stages_apply_to_every_protocol() {
        for protocol in [Protocol::Tcp, Protocol::Udp, Protocol::Icmp, Protocol::Any] {
            assert!(stage_applies(Layer::Perimeter, protocol), "{protocol:?}");
            assert!(stage_applies(Layer::Packet, protocol), "{protocol:?}");
        }
        for layer in [Layer::Identity, Layer::AppDpi, Layer::Stream] {
            assert!(!stage_applies(layer, Protocol::Icmp), "{layer:?}");
            assert!(stage_applies(layer, Protocol::Tcp), "{layer:?}");
        }
    }

    // --- serialization ----------------------------------------------------

    #[test]
    fn policy_wire_roundtrip() {
        let mut rule = allow_dns_rule();
        rule.app = Some(AppMatch {
            fingerprints: vec![
                AppFingerprint {
                    paths: vec![PathPattern::new("/usr/lib/systemd/*", false)],
                    sha256: vec![hash::sha256(b"x")],
                    ..Default::default()
                },
                AppFingerprint {
                    signers: vec!["Example Ltd".into()],
                    team_ids: vec!["TEAM123456".into()],
                    bundle_ids: vec!["com.example.app".into()],
                    ..Default::default()
                },
            ],
            trust: TrustMask::at_least(TrustLevel::Known),
            require_valid_signature: true,
            negate: false,
        });
        rule.dpi = Some(DpiMatch {
            signatures: vec![1, 2, 3],
            l7: vec![L7Protocol::Dns],
            on_match: Action::Alert,
        });
        rule.interfaces = vec!["eth0".into()];
        rule.schedule = Some(TimeWindow {
            days: 0x7f,
            start_minute: 0,
            end_minute: 1439,
        });
        rule.tags = vec!["baseline".into()];
        rule.ebpf_eligible = true;

        let p = build_policy(vec![rule], Decision::Deny);
        let bytes = p.encode();
        let back = CompiledPolicy::decode(&bytes).unwrap();
        assert_eq!(p, back);
        assert!(back.verify_hash());
    }

    #[test]
    fn hash_changes_when_a_rule_changes() {
        let p1 = build_policy(vec![allow_dns_rule()], Decision::Deny);
        let mut r = allow_dns_rule();
        r.priority = 101;
        let p2 = build_policy(vec![r], Decision::Deny);
        assert_ne!(p1.ruleset_hash, p2.ruleset_hash);
    }

    #[test]
    fn finalize_orders_by_stage_then_priority_then_id() {
        let mut a = CompiledRule::new(3, "a", Layer::Stream, Action::Allow);
        a.priority = 1;
        let mut b = CompiledRule::new(1, "b", Layer::Packet, Action::Allow);
        b.priority = 9;
        let mut c = CompiledRule::new(2, "c", Layer::Packet, Action::Allow);
        c.priority = 9;
        let p = build_policy(vec![a, b, c], Decision::Deny);
        assert_eq!(
            p.rules.iter().map(|r| r.id).collect::<Vec<_>>(),
            vec![1, 2, 3]
        );
    }

    #[test]
    fn decode_rejects_wrong_wire_version() {
        let p = build_policy(vec![], Decision::Deny);
        let mut bytes = p.encode();
        bytes[0] = 0xEE;
        bytes[1] = 0xEE;
        assert!(matches!(
            CompiledPolicy::decode(&bytes),
            Err(ProtoError::UnsupportedVersion(_))
        ));
    }
}
