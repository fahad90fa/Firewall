//! The unified log event schema.
//!
//! One schema for all three platforms. A Windows WFP callout, a Linux
//! netfilter hook and a macOS `NEFilterDataProvider` all describe a decision
//! with the same fields, which is what makes cross-host correlation possible
//! without a platform-aware normalizer downstream.
//!
//! Events carry a **microsecond** UTC timestamp and a monotonically increasing
//! per-host sequence number. The timestamp is what correlates across hosts; the
//! sequence number is what detects loss, because a kernel ring buffer under
//! pressure drops events rather than blocking a packet decision.

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use crate::identity_types::{AppIdentity, TrustLevel};
use crate::json::JsonWriter;
use crate::policy_types::{Decision, Direction, L7Protocol, Layer, Protocol, Zone};
use crate::protocol::{ProtoError, Reader, Writer};

/// Connection 5-tuple.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FiveTuple {
    pub protocol: Protocol,
    pub src_ip: IpAddr,
    pub src_port: u16,
    pub dst_ip: IpAddr,
    pub dst_port: u16,
}

impl Default for FiveTuple {
    fn default() -> Self {
        FiveTuple {
            protocol: Protocol::Any,
            src_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            src_port: 0,
            dst_ip: IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            dst_port: 0,
        }
    }
}

impl fmt::Display for FiveTuple {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{} -> {}:{}",
            self.protocol.as_str(),
            fmt_ip(self.src_ip),
            self.src_port,
            fmt_ip(self.dst_ip),
            self.dst_port
        )
    }
}

/// Bracket IPv6 literals so `addr:port` stays unambiguous.
fn fmt_ip(ip: IpAddr) -> String {
    match ip {
        IpAddr::V4(a) => a.to_string(),
        IpAddr::V6(a) => format!("[{a}]"),
    }
}

impl FiveTuple {
    fn encode(&self, w: &mut Writer) {
        w.u16(self.protocol.to_u16());
        encode_ip(w, self.src_ip);
        w.u16(self.src_port);
        encode_ip(w, self.dst_ip);
        w.u16(self.dst_port);
    }

    fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let protocol = Protocol::from_u16(r.u16()?).ok_or(ProtoError::Malformed("bad protocol"))?;
        let src_ip = decode_ip(r)?;
        let src_port = r.u16()?;
        let dst_ip = decode_ip(r)?;
        let dst_port = r.u16()?;
        Ok(FiveTuple {
            protocol,
            src_ip,
            src_port,
            dst_ip,
            dst_port,
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
            Ok(IpAddr::V4(std::net::Ipv4Addr::from(o)))
        }
        6 => {
            let mut o = [0u8; 16];
            o.copy_from_slice(r.raw(16)?);
            Ok(IpAddr::V6(std::net::Ipv6Addr::from(o)))
        }
        _ => Err(ProtoError::Malformed("bad address family")),
    }
}

/// Why an event was emitted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum EventKind {
    /// A flow was permitted or blocked by a rule (or by the default action).
    FlowDecision = 0,
    /// An `alert`-action rule fired; the flow's own decision is reported
    /// separately.
    Alert = 1,
    /// A DPI signature matched.
    DpiMatch = 2,
    /// Application identity was resolved (or failed to resolve).
    IdentityResolved = 3,
    /// Policy was installed or updated.
    PolicyChange = 4,
    /// The enforcement point itself reported a problem.
    SystemFault = 5,
}

impl EventKind {
    pub fn as_str(self) -> &'static str {
        match self {
            EventKind::FlowDecision => "flow-decision",
            EventKind::Alert => "alert",
            EventKind::DpiMatch => "dpi-match",
            EventKind::IdentityResolved => "identity-resolved",
            EventKind::PolicyChange => "policy-change",
            EventKind::SystemFault => "system-fault",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => EventKind::FlowDecision,
            1 => EventKind::Alert,
            2 => EventKind::DpiMatch,
            3 => EventKind::IdentityResolved,
            4 => EventKind::PolicyChange,
            5 => EventKind::SystemFault,
            _ => return None,
        })
    }
}

/// Severity, mapped onto syslog levels by the syslog sink.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
#[repr(u8)]
pub enum Severity {
    Debug = 0,
    Info = 1,
    Notice = 2,
    Warning = 3,
    Error = 4,
    Critical = 5,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Debug => "debug",
            Severity::Info => "info",
            Severity::Notice => "notice",
            Severity::Warning => "warning",
            Severity::Error => "error",
            Severity::Critical => "critical",
        }
    }

    pub fn from_u8(v: u8) -> Option<Self> {
        Some(match v {
            0 => Severity::Debug,
            1 => Severity::Info,
            2 => Severity::Notice,
            3 => Severity::Warning,
            4 => Severity::Error,
            5 => Severity::Critical,
            _ => return None,
        })
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "debug" => Severity::Debug,
            "info" => Severity::Info,
            "notice" => Severity::Notice,
            "warn" | "warning" => Severity::Warning,
            "error" | "err" => Severity::Error,
            "critical" | "crit" => Severity::Critical,
            _ => return None,
        })
    }

    /// RFC 5424 severity code.
    pub fn syslog_code(self) -> u8 {
        match self {
            Severity::Debug => 7,
            Severity::Info => 6,
            Severity::Notice => 5,
            Severity::Warning => 4,
            Severity::Error => 3,
            Severity::Critical => 2,
        }
    }
}

/// DPI evidence attached to an event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DpiHit {
    pub signature_id: u32,
    pub signature_name: String,
    pub l7: L7Protocol,
    pub stream_offset: u64,
    /// Bounded excerpt of the matched bytes, hex-encoded. Bounded because a
    /// log sink is not a packet capture and because payload can be sensitive.
    pub excerpt_hex: String,
    /// Decoded DNS query name, when `l7 == Dns` and the decoder extracted one.
    /// This is what the DNS-tunnel/exfiltration detector consumes; `None` for a
    /// non-DNS hit or a build whose DPI path does not surface the qname.
    pub dns_qname: Option<String>,
}

/// Compact identity summary carried on a flow event.
///
/// Deliberately not the full [`AppIdentity`]: certificate chains and platform
/// metadata belong in an identity-resolution event, emitted once, not on every
/// flow decision.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentitySummary {
    pub pid: u32,
    pub path: String,
    pub sha256_hex: Option<String>,
    pub signer: Option<String>,
    pub trust: Option<TrustLevel>,
}

impl IdentitySummary {
    pub fn from_identity(id: &AppIdentity) -> Self {
        IdentitySummary {
            pid: id.pid,
            path: id.path.clone(),
            sha256_hex: id.sha256_hex(),
            signer: id.signer.clone(),
            trust: Some(id.trust),
        }
    }
}

/// A single structured event.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LogEvent {
    /// Schema version, so a downstream consumer can tell old events from new.
    pub schema_version: u16,
    /// Microseconds since the UNIX epoch, UTC.
    pub timestamp_us: u64,
    /// Stable identifier for the host that produced this event.
    pub host_id: String,
    /// Per-host monotonically increasing sequence number. Gaps mean drops.
    pub sequence: u64,
    pub kind: EventKind,
    pub severity: Severity,
    /// Policy revision in force when the decision was made.
    pub policy_revision: u64,
    /// Rule that decided, or [`crate::constants::RULE_ID_DEFAULT`].
    pub rule_id: u32,
    pub rule_name: String,
    pub layer: Layer,
    pub decision: Decision,
    pub direction: Direction,
    pub five_tuple: FiveTuple,
    /// Zone of the peer, i.e. the network context of the flow.
    pub remote_zone: Zone,
    /// Whether the flow crossed the network perimeter.
    pub perimeter_crossing: bool,
    pub identity: Option<IdentitySummary>,
    pub dpi: Option<DpiHit>,
    /// Time spent in the enforcement path, for performance regression tracking.
    pub latency_ns: u64,
    /// Free-form message for `SystemFault` and `PolicyChange` events.
    pub message: Option<String>,
    /// Tags copied from the matching rule, for downstream routing.
    pub tags: Vec<String>,
}

impl LogEvent {
    /// Construct a flow-decision event with sensible defaults.
    pub fn new(
        timestamp_us: u64,
        host_id: impl Into<String>,
        decision: Decision,
        rule_id: u32,
        five_tuple: FiveTuple,
    ) -> Self {
        LogEvent {
            schema_version: crate::constants::LOG_SCHEMA_VERSION,
            timestamp_us,
            host_id: host_id.into(),
            sequence: 0,
            kind: EventKind::FlowDecision,
            severity: match decision {
                Decision::Allow => Severity::Info,
                Decision::Deny => Severity::Notice,
            },
            policy_revision: 0,
            rule_id,
            rule_name: String::new(),
            layer: Layer::Packet,
            decision,
            direction: Direction::Any,
            five_tuple,
            remote_zone: Zone::External,
            perimeter_crossing: true,
            identity: None,
            dpi: None,
            latency_ns: 0,
            message: None,
            tags: Vec::new(),
        }
    }

    /// Correlation key: events from different hosts describing the same
    /// blocked activity share this string, which is what lets the aggregator
    /// spot the same denied application/destination pair fanning out across a
    /// fleet.
    pub fn correlation_key(&self) -> String {
        let app = self
            .identity
            .as_ref()
            .map(|i| i.sha256_hex.clone().unwrap_or_else(|| i.path.clone()))
            .unwrap_or_else(|| "-".into());
        format!(
            "{}|{}|{}|{}",
            app,
            fmt_ip(self.five_tuple.dst_ip),
            self.five_tuple.dst_port,
            self.decision.as_str()
        )
    }

    /// One JSON object on one line — the JSONL file sink format and the
    /// on-the-wire format for the SIEM forwarder.
    pub fn to_json(&self) -> String {
        let mut w = JsonWriter::with_capacity(512);
        self.write_json(&mut w);
        w.finish()
    }

    pub fn write_json(&self, w: &mut JsonWriter) {
        w.begin_object();
        w.u64_field("schema", self.schema_version as u64);
        w.str_field("ts", &format_rfc3339_micros(self.timestamp_us));
        w.u64_field("ts_us", self.timestamp_us);
        w.str_field("host", &self.host_id);
        w.u64_field("seq", self.sequence);
        w.str_field("kind", self.kind.as_str());
        w.str_field("severity", self.severity.as_str());
        w.u64_field("policy_revision", self.policy_revision);
        w.u64_field("rule_id", self.rule_id as u64);
        w.str_field("rule", &self.rule_name);
        w.str_field("layer", self.layer.as_str());
        w.str_field("decision", self.decision.as_str());
        w.str_field("direction", self.direction.as_str());

        w.begin_object_field("flow");
        w.str_field("protocol", &self.five_tuple.protocol.as_str());
        w.str_field("src_ip", &self.five_tuple.src_ip.to_string());
        w.u64_field("src_port", self.five_tuple.src_port as u64);
        w.str_field("dst_ip", &self.five_tuple.dst_ip.to_string());
        w.u64_field("dst_port", self.five_tuple.dst_port as u64);
        w.end_object();

        w.begin_object_field("network");
        w.str_field("remote_zone", self.remote_zone.as_str());
        w.bool_field("perimeter_crossing", self.perimeter_crossing);
        w.end_object();

        match &self.identity {
            Some(id) => {
                w.begin_object_field("app");
                w.u64_field("pid", id.pid as u64);
                w.str_field("path", &id.path);
                w.opt_str_field("sha256", id.sha256_hex.as_deref());
                w.opt_str_field("signer", id.signer.as_deref());
                w.opt_str_field("trust", id.trust.map(|t| t.as_str()));
                w.end_object();
            }
            None => w.null_field("app"),
        }

        match &self.dpi {
            Some(d) => {
                w.begin_object_field("dpi");
                w.u64_field("signature_id", d.signature_id as u64);
                w.str_field("signature", &d.signature_name);
                w.str_field("l7", d.l7.as_str());
                w.u64_field("offset", d.stream_offset);
                w.str_field("excerpt", &d.excerpt_hex);
                w.opt_str_field("dns_qname", d.dns_qname.as_deref());
                w.end_object();
            }
            None => w.null_field("dpi"),
        }

        w.u64_field("latency_ns", self.latency_ns);
        w.opt_str_field("message", self.message.as_deref());
        w.str_array_field("tags", self.tags.iter().map(|s| s.as_str()));
        w.str_field("correlation_key", &self.correlation_key());
        w.end_object();
    }

    /// RFC 5424 syslog line. `facility` is the numeric syslog facility
    /// (16 = local0 by convention for this product).
    pub fn to_syslog(&self, facility: u8, app_name: &str) -> String {
        let pri = (facility as u16) * 8 + self.severity.syslog_code() as u16;
        format!(
            "<{pri}>1 {ts} {host} {app} - {kind} - {json}",
            ts = format_rfc3339_micros(self.timestamp_us),
            host = if self.host_id.is_empty() {
                "-"
            } else {
                &self.host_id
            },
            app = app_name,
            kind = self.kind.as_str(),
            json = self.to_json(),
        )
    }

    /// ArcSight CEF line, for SIEMs that prefer it over JSON.
    pub fn to_cef(&self, vendor: &str, product: &str, version: &str) -> String {
        // CEF severity is 0-10; map our six levels onto that range.
        let sev = match self.severity {
            Severity::Debug => 0,
            Severity::Info => 2,
            Severity::Notice => 4,
            Severity::Warning => 6,
            Severity::Error => 8,
            Severity::Critical => 10,
        };
        let mut ext = format!(
            "rt={} src={} spt={} dst={} dpt={} proto={} act={} cs1Label=rule cs1={} cs2Label=zone cs2={}",
            self.timestamp_us / 1000,
            self.five_tuple.src_ip,
            self.five_tuple.src_port,
            self.five_tuple.dst_ip,
            self.five_tuple.dst_port,
            self.five_tuple.protocol.as_str(),
            self.decision.as_str(),
            cef_escape_value(&self.rule_name),
            self.remote_zone.as_str(),
        );
        if let Some(id) = &self.identity {
            ext.push_str(&format!(
                " dproc={} dpid={}",
                cef_escape_value(&id.path),
                id.pid
            ));
        }
        if let Some(d) = &self.dpi {
            ext.push_str(&format!(
                " cs3Label=signature cs3={}",
                cef_escape_value(&d.signature_name)
            ));
        }
        format!(
            "CEF:0|{}|{}|{}|{}|{}|{}|{}",
            cef_escape_header(vendor),
            cef_escape_header(product),
            cef_escape_header(version),
            self.rule_id,
            cef_escape_header(self.kind.as_str()),
            sev,
            ext
        )
    }

    /// Compact single-line rendering for `ufwctl logs stream`.
    pub fn to_text(&self) -> String {
        let app = self
            .identity
            .as_ref()
            .map(|i| {
                let name = i
                    .path
                    .rsplit(['/', '\\'])
                    .next()
                    .filter(|s| !s.is_empty())
                    .unwrap_or("?");
                format!("{name}[{}]", i.pid)
            })
            .unwrap_or_else(|| "-".into());
        let rule = if self.rule_name.is_empty() {
            format!("#{}", self.rule_id)
        } else {
            self.rule_name.clone()
        };
        let dpi = self
            .dpi
            .as_ref()
            .map(|d| format!(" sig={}", d.signature_name))
            .unwrap_or_default();
        format!(
            "{ts} {decision:<5} {dir:<8} {tuple} app={app} rule={rule} zone={zone}{dpi}",
            ts = format_rfc3339_micros(self.timestamp_us),
            decision = self.decision.as_str().to_uppercase(),
            dir = self.direction.as_str(),
            tuple = self.five_tuple,
            zone = self.remote_zone.as_str(),
        )
    }

    pub fn encode(&self, w: &mut Writer) {
        w.u16(self.schema_version);
        w.u64(self.timestamp_us);
        w.string(&self.host_id);
        w.u64(self.sequence);
        w.u8(self.kind as u8);
        w.u8(self.severity as u8);
        w.u64(self.policy_revision);
        w.u32(self.rule_id);
        w.string(&self.rule_name);
        w.u8(self.layer as u8);
        w.u8(self.decision as u8);
        w.u8(self.direction as u8);
        self.five_tuple.encode(w);
        w.u8(self.remote_zone as u8);
        w.bool(self.perimeter_crossing);
        match &self.identity {
            Some(id) => {
                w.u8(1);
                w.u32(id.pid);
                w.string(&id.path);
                w.opt_string(id.sha256_hex.as_deref());
                w.opt_string(id.signer.as_deref());
                match id.trust {
                    Some(t) => {
                        w.u8(1);
                        w.u8(t as u8);
                    }
                    None => w.u8(0),
                }
            }
            None => w.u8(0),
        }
        match &self.dpi {
            Some(d) => {
                w.u8(1);
                w.u32(d.signature_id);
                w.string(&d.signature_name);
                w.u8(d.l7 as u8);
                w.u64(d.stream_offset);
                w.string(&d.excerpt_hex);
                w.opt_string(d.dns_qname.as_deref());
            }
            None => w.u8(0),
        }
        w.u64(self.latency_ns);
        w.opt_string(self.message.as_deref());
        w.string_list(&self.tags);
    }

    pub fn decode(r: &mut Reader<'_>) -> Result<Self, ProtoError> {
        let schema_version = r.u16()?;
        let timestamp_us = r.u64()?;
        let host_id = r.string()?;
        let sequence = r.u64()?;
        let kind = EventKind::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad event kind"))?;
        let severity = Severity::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad severity"))?;
        let policy_revision = r.u64()?;
        let rule_id = r.u32()?;
        let rule_name = r.string()?;
        let layer = Layer::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad layer"))?;
        let decision = Decision::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad decision"))?;
        let direction =
            Direction::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad direction"))?;
        let five_tuple = FiveTuple::decode(r)?;
        let remote_zone = Zone::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad zone"))?;
        let perimeter_crossing = r.bool()?;
        let identity = if r.u8()? != 0 {
            let pid = r.u32()?;
            let path = r.string()?;
            let sha256_hex = r.opt_string()?;
            let signer = r.opt_string()?;
            let trust = if r.u8()? != 0 {
                Some(TrustLevel::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad trust"))?)
            } else {
                None
            };
            Some(IdentitySummary {
                pid,
                path,
                sha256_hex,
                signer,
                trust,
            })
        } else {
            None
        };
        let dpi = if r.u8()? != 0 {
            Some(DpiHit {
                signature_id: r.u32()?,
                signature_name: r.string()?,
                l7: L7Protocol::from_u8(r.u8()?).ok_or(ProtoError::Malformed("bad l7"))?,
                stream_offset: r.u64()?,
                excerpt_hex: r.string()?,
                dns_qname: r.opt_string()?,
            })
        } else {
            None
        };
        Ok(LogEvent {
            schema_version,
            timestamp_us,
            host_id,
            sequence,
            kind,
            severity,
            policy_revision,
            rule_id,
            rule_name,
            layer,
            decision,
            direction,
            five_tuple,
            remote_zone,
            perimeter_crossing,
            identity,
            dpi,
            latency_ns: r.u64()?,
            message: r.opt_string()?,
            tags: r.string_list()?,
        })
    }
}

fn cef_escape_header(s: &str) -> String {
    s.replace('\\', r"\\").replace('|', r"\|")
}

fn cef_escape_value(s: &str) -> String {
    s.replace('\\', r"\\")
        .replace('=', r"\=")
        .replace('\n', r"\n")
}

/// Format microseconds-since-epoch as `YYYY-MM-DDTHH:MM:SS.ffffffZ`.
///
/// Implemented here rather than pulled in: the daemon needs exactly one date
/// format, always UTC, always microseconds. The civil-from-days conversion is
/// Howard Hinnant's algorithm, valid across the full range of a `u64`
/// microsecond count.
pub fn format_rfc3339_micros(us: u64) -> String {
    let secs = (us / 1_000_000) as i64;
    let micros = us % 1_000_000;

    let days = secs.div_euclid(86_400);
    let secs_of_day = secs.rem_euclid(86_400);

    let (y, m, d) = civil_from_days(days);
    let hh = secs_of_day / 3600;
    let mm = (secs_of_day % 3600) / 60;
    let ss = secs_of_day % 60;

    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}.{micros:06}Z")
}

/// Days since 1970-01-01 -> (year, month, day).
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = (z - era * 146_097) as u64; // [0, 146096]
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146_096) / 365; // [0, 399]
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100); // [0, 365]
    let mp = (5 * doy + 2) / 153; // [0, 11]
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32; // [1, 31]
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32; // [1, 12]
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::json;

    fn sample() -> LogEvent {
        let mut e = LogEvent::new(
            1_700_000_000_123_456,
            "host-a",
            Decision::Deny,
            42,
            FiveTuple {
                protocol: Protocol::Tcp,
                src_ip: "10.0.0.5".parse().unwrap(),
                src_port: 51234,
                dst_ip: "93.184.216.34".parse().unwrap(),
                dst_port: 443,
            },
        );
        e.sequence = 9;
        e.rule_name = "block-unsigned-external".into();
        e.layer = Layer::Stream;
        e.direction = Direction::Outbound;
        e.policy_revision = 7;
        e.remote_zone = Zone::External;
        e.identity = Some(IdentitySummary {
            pid: 4242,
            path: "/tmp/dropper".into(),
            sha256_hex: Some("ab".repeat(32)),
            signer: None,
            trust: Some(TrustLevel::Untrusted),
        });
        e.dpi = Some(DpiHit {
            signature_id: 1001,
            signature_name: "http-exploit-post".into(),
            l7: L7Protocol::Http,
            stream_offset: 128,
            excerpt_hex: "504f5354".into(),
            dns_qname: None,
        });
        e.tags = vec!["hardening".into()];
        e.latency_ns = 12_345;
        e
    }

    #[test]
    fn rfc3339_formatting() {
        assert_eq!(format_rfc3339_micros(0), "1970-01-01T00:00:00.000000Z");
        assert_eq!(
            format_rfc3339_micros(1_700_000_000_123_456),
            "2023-11-14T22:13:20.123456Z"
        );
        // Leap day.
        assert_eq!(
            format_rfc3339_micros(1_709_164_800_000_000),
            "2024-02-29T00:00:00.000000Z"
        );
    }

    #[test]
    fn json_is_valid_and_has_expected_fields() {
        let e = sample();
        let text = e.to_json();
        assert!(!text.contains('\n'), "log lines must be single-line");
        let v = json::parse(&text).expect("emitted JSON must parse");
        assert_eq!(v.get("decision").unwrap().as_str(), Some("deny"));
        assert_eq!(v.get("rule_id").unwrap().as_u64(), Some(42));
        assert_eq!(
            v.get("flow").unwrap().get("dst_port").unwrap().as_u64(),
            Some(443)
        );
        assert_eq!(
            v.get("app").unwrap().get("trust").unwrap().as_str(),
            Some("untrusted")
        );
        assert_eq!(
            v.get("dpi").unwrap().get("signature").unwrap().as_str(),
            Some("http-exploit-post")
        );
        assert_eq!(
            v.get("ts").unwrap().as_str(),
            Some("2023-11-14T22:13:20.123456Z")
        );
    }

    #[test]
    fn json_escapes_hostile_strings() {
        let mut e = sample();
        e.rule_name = "evil\"\n{\"injected\":true}".into();
        let text = e.to_json();
        let v = json::parse(&text).expect("must stay valid JSON");
        assert_eq!(
            v.get("rule").unwrap().as_str(),
            Some("evil\"\n{\"injected\":true}")
        );
    }

    #[test]
    fn wire_roundtrip() {
        let e = sample();
        let mut w = Writer::new();
        e.encode(&mut w);
        let buf = w.finish();
        let mut r = Reader::new(&buf);
        assert_eq!(LogEvent::decode(&mut r).unwrap(), e);
        assert_eq!(r.remaining(), 0);
    }

    #[test]
    fn wire_roundtrip_with_empty_optionals() {
        let e = LogEvent::new(1, "h", Decision::Allow, 0, FiveTuple::default());
        let mut w = Writer::new();
        e.encode(&mut w);
        let mut r = Reader::new(w.as_slice());
        assert_eq!(LogEvent::decode(&mut r).unwrap(), e);
    }

    #[test]
    fn correlation_key_is_app_and_destination() {
        let a = sample();
        let mut b = sample();
        b.host_id = "host-b".into();
        b.sequence = 100;
        b.five_tuple.src_port = 40000;
        assert_eq!(
            a.correlation_key(),
            b.correlation_key(),
            "same app+destination on two hosts must correlate"
        );

        let mut c = sample();
        c.five_tuple.dst_port = 80;
        assert_ne!(a.correlation_key(), c.correlation_key());
    }

    #[test]
    fn syslog_line_has_priority_and_payload() {
        let line = sample().to_syslog(16, "unified-firewall");
        // local0 (16) * 8 + notice (5) = 133
        assert!(line.starts_with("<133>1 2023-11-14T22:13:20.123456Z host-a"));
        let json_start = line.find('{').unwrap();
        assert!(json::parse(&line[json_start..]).is_ok());
    }

    #[test]
    fn cef_escapes_pipes_and_equals() {
        let mut e = sample();
        e.rule_name = "a=b".into();
        let line = e.to_cef("Unified|FW", "firewall", "0.1.0");
        assert!(line.starts_with(r"CEF:0|Unified\|FW|firewall|0.1.0|42|"));
        assert!(line.contains(r"cs1=a\=b"));
    }

    #[test]
    fn text_line_is_compact() {
        let line = sample().to_text();
        assert!(line.contains("DENY"));
        assert!(line.contains("dropper[4242]"));
        assert!(line.contains("sig=http-exploit-post"));
    }

    #[test]
    fn ipv6_is_bracketed_in_tuple_display() {
        let t = FiveTuple {
            protocol: Protocol::Tcp,
            src_ip: "2001:db8::1".parse().unwrap(),
            src_port: 1,
            dst_ip: "2001:db8::2".parse().unwrap(),
            dst_port: 443,
        };
        assert_eq!(t.to_string(), "tcp [2001:db8::1]:1 -> [2001:db8::2]:443");
    }
}
