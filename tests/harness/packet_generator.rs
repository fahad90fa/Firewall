//! Controlled flow construction.
//!
//! # Why this builds `FlowContext` rather than bytes on a wire
//!
//! A packet generator that put real frames on a real interface would test the
//! kernel modules — which is the one thing CI cannot load. What it would *not*
//! test is whether the policy means what the author wrote, because a real
//! packet has to survive the whole stack before a verdict is observable, and
//! every layer in between is a place a test can fail for reasons that have
//! nothing to do with the policy.
//!
//! So this generator builds the fact structure the reference evaluator
//! consumes — the same structure the C and Swift classifiers build from their
//! own platform's callbacks. A scenario written against it is asserting on the
//! decision procedure, which is the thing all three platforms share and the
//! thing an operator's policy actually depends on.
//!
//! The real-packet path exists in `tests/docker/`, where a container can load
//! the module. It answers a different question, and it is slower and rarer.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use ufw_shared::identity_types::{AppIdentity, SignatureType, TrustLevel};
use ufw_shared::policy_types::{
    Direction, DpiScan, FlowContext, L7Protocol, NetworkProfile, Protocol,
};

/// A flow under construction.
///
/// Owns the borrowed pieces `FlowContext` needs — the identity and the
/// interface name — so a scenario can build one in a single expression and
/// hold it across the evaluation without arranging lifetimes by hand.
pub struct Flow {
    pub direction: Direction,
    pub protocol: Protocol,
    pub src: (IpAddr, u16),
    pub dst: (IpAddr, u16),
    pub identity: Option<AppIdentity>,
    pub dpi: Option<DpiScan>,
    pub interface: Option<String>,
    pub minute_of_week: Option<u16>,
}

impl Default for Flow {
    fn default() -> Self {
        Flow {
            direction: Direction::Outbound,
            protocol: Protocol::Tcp,
            src: (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), 51234),
            dst: (IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 443),
            identity: None,
            dpi: None,
            interface: None,
            minute_of_week: None,
        }
    }
}

impl Flow {
    pub fn tcp(dst: &str, port: u16) -> Self {
        Flow { dst: (parse_ip(dst), port), protocol: Protocol::Tcp, ..Default::default() }
    }

    pub fn udp(dst: &str, port: u16) -> Self {
        Flow { dst: (parse_ip(dst), port), protocol: Protocol::Udp, ..Default::default() }
    }

    pub fn icmp(dst: &str) -> Self {
        Flow {
            dst: (parse_ip(dst), 0),
            src: (parse_ip("10.0.0.5"), 0),
            protocol: Protocol::Icmp,
            ..Default::default()
        }
    }

    /// Mark the flow inbound.
    ///
    /// Direction only — the addresses are not swapped. An earlier version of
    /// this helper swapped them, on the theory that "inbound" means the peer is
    /// the source, and it composed badly: `.inbound().from(...)` then produced
    /// a flow whose destination port was whatever the default source port had
    /// been, which is not what any reader would predict. `tcp()` always names
    /// the destination and `from()` always names the source, in both
    /// directions; the caller says what it means.
    pub fn inbound(mut self) -> Self {
        self.direction = Direction::Inbound;
        self
    }

    pub fn from(mut self, addr: &str, port: u16) -> Self {
        self.src = (parse_ip(addr), port);
        self
    }

    pub fn with_identity(mut self, identity: AppIdentity) -> Self {
        self.identity = Some(identity);
        self
    }

    /// No identity at all — the state a real flow is in before the resolver has
    /// answered. Scenarios use this to check the fail-closed asymmetry, which
    /// is the property most likely to be broken by a well-meaning change.
    pub fn unidentified(mut self) -> Self {
        self.identity = None;
        self
    }

    pub fn with_dpi(mut self, l7: L7Protocol, signatures: &[u32]) -> Self {
        self.dpi = Some(DpiScan {
            l7,
            hits: signatures.to_vec(),
            first_hit_offset: 0,
            truncated: false,
        });
        self
    }

    /// A scan that hit the reassembly budget. Distinct from a clean miss: the
    /// engine did not finish looking, and rules are supposed to treat the two
    /// differently.
    pub fn with_truncated_dpi(mut self, l7: L7Protocol) -> Self {
        self.dpi = Some(DpiScan {
            l7,
            hits: Vec::new(),
            first_hit_offset: 0,
            truncated: true,
        });
        self
    }

    pub fn on_interface(mut self, name: &str) -> Self {
        self.interface = Some(name.to_string());
        self
    }

    pub fn at_minute(mut self, minute_of_week: u16) -> Self {
        self.minute_of_week = Some(minute_of_week);
        self
    }

    /// Build the context. Borrows from `self`, so the flow must outlive it.
    pub fn context<'a>(&'a self, profile: &NetworkProfile) -> FlowContext<'a> {
        let mut ctx =
            FlowContext::new(profile, self.direction, self.protocol, self.src, self.dst);
        if let Some(identity) = &self.identity {
            ctx = ctx.with_identity(identity);
        }
        if let Some(dpi) = &self.dpi {
            ctx = ctx.with_dpi(dpi.clone());
        }
        if let Some(interface) = &self.interface {
            ctx = ctx.with_interface(interface);
        }
        if let Some(minute) = self.minute_of_week {
            ctx = ctx.with_minute_of_week(minute);
        }
        ctx
    }
}

/// Identities a scenario can hand to a flow.
pub mod identities {
    use super::*;

    /// The fields every fixture identity shares. Kept in one place so adding a
    /// field to `AppIdentity` does not mean editing four near-identical
    /// literals and getting one of them subtly different.
    fn base(path: &str, hash: [u8; 32]) -> AppIdentity {
        AppIdentity {
            pid: 4242,
            start_time_us: 1_700_000_000_000_000,
            path: path.to_string(),
            sha256: Some(hash),
            signature_type: SignatureType::None,
            signature_valid: false,
            signer: None,
            team_id: None,
            bundle_id: None,
            trust: TrustLevel::Unknown,
            user: None,
            platform_meta: Default::default(),
            resolved_at_us: 1_700_000_000_000_000,
            ttl_secs: 300,
        }
    }

    /// A signed binary from a known publisher.
    pub fn signed(path: &str, signer: &str, trust: TrustLevel) -> AppIdentity {
        AppIdentity {
            signature_type: SignatureType::Authenticode,
            signature_valid: true,
            signer: Some(signer.to_string()),
            trust,
            user: Some("1000:1000".to_string()),
            ..base(path, [0xAB; 32])
        }
    }

    /// A macOS-style identity: Team ID and bundle, no signer string.
    pub fn team(path: &str, team_id: &str, bundle_id: &str, trust: TrustLevel) -> AppIdentity {
        AppIdentity {
            signature_type: SignatureType::MachOCodeSign,
            signature_valid: true,
            team_id: Some(team_id.to_string()),
            bundle_id: Some(bundle_id.to_string()),
            trust,
            ..base(path, [0xAB; 32])
        }
    }

    /// Unsigned but readable: `Unknown`, not `Untrusted`. Nothing was claimed
    /// and nothing failed.
    pub fn unsigned(path: &str) -> AppIdentity {
        AppIdentity {
            signature_type: SignatureType::None,
            trust: TrustLevel::Unknown,
            ..base(path, [0xCD; 32])
        }
    }

    /// Signed and broken. Strictly worse than unsigned: something was signed
    /// and then modified.
    pub fn tampered(path: &str, signer: &str) -> AppIdentity {
        AppIdentity {
            signature_type: SignatureType::Authenticode,
            // Present and does not verify: something was signed and then
            // modified, which is why the trust level is worse than unsigned.
            signature_valid: false,
            signer: Some(signer.to_string()),
            trust: TrustLevel::Untrusted,
            ..base(path, [0xEF; 32])
        }
    }
}

fn parse_ip(text: &str) -> IpAddr {
    if let Ok(v4) = text.parse::<Ipv4Addr>() {
        return IpAddr::V4(v4);
    }
    IpAddr::V6(text.parse::<Ipv6Addr>().unwrap_or(Ipv6Addr::UNSPECIFIED))
}
