//! The values `kernel/macos/NetworkExtension/IPCBridge.swift` decodes by hand.
//!
//! The other two kernels get their constants from a generated C header, and
//! `policy-lang/tests/kernel_abi_tests.rs` compiles that header against the
//! kernel's own structures. Swift has neither: the extension decodes the wire
//! with hand-written code, and no Swift toolchain runs in this workspace's CI.
//!
//! So this file is the substitute. Every discriminant and every layout rule
//! the Swift decoder mirrors is asserted here, and each assertion names the
//! Swift symbol it pins. A change to the Rust side that the Swift side has not
//! followed fails `cargo test` with the name of the function to go and fix.
//!
//! It is weaker than compiling the Swift. It is much stronger than nothing,
//! and it catches the failure mode that actually happens: someone renumbers an
//! enum in Rust, every Rust test still passes, and macOS quietly starts
//! filtering a different policy.
//!
//! # The traps this exists for
//!
//! Two of these mappings are *not* the identity, and both look like it:
//!
//!   - `Layer` is numbered by defense layer (AppDpi is L3, Identity is L4) but
//!     evaluated in a different order (identity before payload). `UFWStage` is
//!     numbered by *evaluation order*. So `Layer::AppDpi as u8` is 3 and
//!     `UFWStage.appDPI.rawValue` is 3 by coincidence, while `Layer::Identity`
//!     is 4 and `UFWStage.identity` is 2.
//!   - `Direction` is `Inbound=0, Outbound=1, Any=2`; `UFWDirection` is
//!     `any=0, inbound=1, outbound=2`. Nothing about either ordering is wrong,
//!     and a decoder that assumes they agree silently inverts every
//!     direction-scoped rule.

use ufw_shared::identity_types::TrustLevel;
use ufw_shared::policy_types::{
    Action, CompiledRule, Decision, Direction, L7Protocol, Layer, Protocol, Zone,
};
use ufw_shared::protocol::MessageType;

/// `UFWStage` in RuleEngine.swift, and `stage(fromWireLayer:)` in IPCBridge.swift.
#[test]
fn the_stage_mapping_is_not_the_identity_and_the_swift_knows_it() {
    // (Rust `Layer` discriminant, Swift `UFWStage` raw value)
    let pairs = [
        (Layer::Perimeter, 1u8, 0u8),
        (Layer::Packet, 2, 1),
        (Layer::Identity, 4, 2),
        (Layer::AppDpi, 3, 3),
        (Layer::Stream, 5, 4),
    ];
    for (layer, wire, stage) in pairs {
        assert_eq!(
            layer as u8, wire,
            "Layer::{layer:?} changed discriminant; IPCBridge.swift stage(fromWireLayer:) \
             maps {wire} to UFWStage rawValue {stage} and must be updated"
        );
    }
    // And the evaluation order the Swift buckets rules into.
    let order: Vec<u8> = ufw_shared::policy_types::EVALUATION_ORDER
        .iter()
        .map(|l| pairs.iter().find(|(p, _, _)| p == l).unwrap().2)
        .collect();
    assert_eq!(
        order,
        vec![0, 1, 2, 3, 4],
        "EVALUATION_ORDER no longer matches UFWStage's numbering, so the Swift engine's \
         stage buckets are in the wrong order"
    );
}

/// `UFWDirection` in RuleEngine.swift, and `direction(fromWire:)` in IPCBridge.swift.
#[test]
fn the_direction_mapping_is_not_the_identity_either() {
    assert_eq!(Direction::Inbound as u8, 0);
    assert_eq!(Direction::Outbound as u8, 1);
    assert_eq!(Direction::Any as u8, 2);
    // Swift: any = 0, inbound = 1, outbound = 2. If either side is renumbered
    // this test still passes and the one above it does not — which is why both
    // exist, and why the Swift side spells the mapping out rather than casting.
}

/// `UFWAction` in RuleEngine.swift. This one *is* the identity, and the Swift
/// casts directly, so it is pinned here to keep that cast honest.
#[test]
fn the_action_mapping_is_the_identity_and_the_swift_casts_directly() {
    assert_eq!(Action::Allow as u8, 0);
    assert_eq!(Action::Deny as u8, 1);
    assert_eq!(Action::Alert as u8, 2);
    assert_eq!(Action::Continue as u8, 3);
    assert_eq!(Action::AllowInspect as u8, 4);
    // The policy's default action arrives as a `Decision`, which is the same
    // two values in the same order.
    assert_eq!(Decision::Allow as u8, Action::Allow as u8);
    assert_eq!(Decision::Deny as u8, Action::Deny as u8);
}

/// `UFWZone`, `UFWTrust` and `UFWL7` in RuleEngine.swift. All three are the
/// identity; the Swift casts directly.
#[test]
fn the_zone_trust_and_l7_mappings_are_the_identity() {
    assert_eq!(Zone::Loopback as u8, 0, "UFWZone.local");
    assert_eq!(Zone::Internal as u8, 1);
    assert_eq!(Zone::Perimeter as u8, 2);
    assert_eq!(Zone::External as u8, 3);

    assert_eq!(TrustLevel::Untrusted as u8, 0);
    assert_eq!(TrustLevel::Unknown as u8, 1);
    assert_eq!(TrustLevel::Known as u8, 2);
    assert_eq!(TrustLevel::Trusted as u8, 3);
    assert_eq!(TrustLevel::System as u8, 4);

    assert_eq!(L7Protocol::Unknown as u8, 0);
    assert_eq!(L7Protocol::Http as u8, 1);
    assert_eq!(L7Protocol::Tls as u8, 2);
    assert_eq!(L7Protocol::Dns as u8, 3);
    assert_eq!(L7Protocol::Ssh as u8, 4);
    assert_eq!(L7Protocol::Smtp as u8, 5);
    assert_eq!(L7Protocol::Quic as u8, 6);
}

/// `ipProtocol(fromWire:)` in IPCBridge.swift.
///
/// `Protocol` is carried as a `u16` because `Any` needs a value outside the
/// IP protocol-number space. The Swift stores an 8-bit protocol number and
/// zero for "any", matching `UFWRule.ipProtocol`.
#[test]
fn the_protocol_encoding_reserves_a_value_for_any() {
    assert_eq!(
        Protocol::Any.to_u16(),
        0xFFFF,
        "UFWRule.ipProtocol uses 0 for any"
    );
    assert_eq!(Protocol::Icmp.to_u16(), 1);
    assert_eq!(Protocol::Tcp.to_u16(), 6);
    assert_eq!(Protocol::Udp.to_u16(), 17);
    assert_eq!(Protocol::IcmpV6.to_u16(), 58);
}

/// `UFWControlSocket.dispatch` in IPCBridge.swift.
#[test]
fn the_message_types_the_extension_answers_have_not_moved() {
    for (ty, code) in [
        (MessageType::Hello, 1u16),
        (MessageType::HelloAck, 2),
        (MessageType::PolicyInstall, 10),
        (MessageType::PolicyInstallAck, 11),
        (MessageType::PolicyUpdate, 12),
        (MessageType::PolicyUpdateAck, 13),
        (MessageType::PolicyFlush, 14),
        (MessageType::LogEvents, 30),
        (MessageType::StatsRequest, 40),
        (MessageType::StatsResponse, 41),
        (MessageType::SetMode, 50),
        (MessageType::ModeAck, 51),
        (MessageType::SignatureInstall, 60),
        (MessageType::SignatureInstallAck, 61),
        (MessageType::Error, 99),
    ] {
        assert_eq!(
            ty as u16, code,
            "{ty:?} changed code; UFWControlSocket.dispatch switches on the numeric value"
        );
    }
}

/// `UFWControlSocket.readFrame` in IPCBridge.swift.
#[test]
fn the_frame_header_is_sixteen_bytes_in_the_order_the_swift_reads_them() {
    use ufw_shared::constants;
    use ufw_shared::protocol::Message;

    assert_eq!(constants::HEADER_LEN, 16);

    let frame = Message::StatsRequest.encode(0x1234_5678);
    assert_eq!(
        frame.len(),
        constants::HEADER_LEN,
        "StatsRequest has no payload"
    );

    // magic (u32), version (u16), type (u16), seq (u32), payload_len (u32),
    // all little-endian. The Swift reads them in exactly this order.
    assert_eq!(
        u32::from_le_bytes(frame[0..4].try_into().unwrap()),
        constants::PROTOCOL_MAGIC
    );
    assert_eq!(
        u16::from_le_bytes(frame[4..6].try_into().unwrap()),
        constants::PROTOCOL_VERSION
    );
    assert_eq!(
        u16::from_le_bytes(frame[6..8].try_into().unwrap()),
        MessageType::StatsRequest as u16
    );
    assert_eq!(
        u32::from_le_bytes(frame[8..12].try_into().unwrap()),
        0x1234_5678
    );
    assert_eq!(u32::from_le_bytes(frame[12..16].try_into().unwrap()), 0);
}

/// `UFWControlSocket.decodePolicy` in IPCBridge.swift.
///
/// Not a field-by-field mirror — that would be this file reimplementing the
/// decoder — but the leading fields, which is where a layout change shows up
/// first and where a wrong guess desynchronises everything after it.
#[test]
fn a_policy_payload_starts_with_the_fields_the_swift_reads_first() {
    use ufw_shared::constants;
    use ufw_shared::policy_types::CompiledPolicy;
    use ufw_shared::protocol::{Message, Writer};

    let policy = CompiledPolicy::new("contract", Decision::Deny);
    let mut w = Writer::new();
    policy.encode_into(&mut w);
    let bytes = w.finish();

    assert_eq!(
        u16::from_le_bytes(bytes[0..2].try_into().unwrap()),
        constants::POLICY_WIRE_VERSION,
        "the Swift refuses a policy whose wire version it does not know"
    );
    assert_eq!(
        u64::from_le_bytes(bytes[2..10].try_into().unwrap()),
        policy.revision
    );
    // Then a u16-length-prefixed name, then the default action.
    let name_len = u16::from_le_bytes(bytes[10..12].try_into().unwrap()) as usize;
    assert_eq!(&bytes[12..12 + name_len], b"contract");
    assert_eq!(bytes[12 + name_len], Decision::Deny as u8);

    // And the frame the extension actually sees wraps it.
    let frame = Message::PolicyInstall(Box::new(policy)).encode(1);
    assert_eq!(
        &frame[constants::HEADER_LEN..],
        &bytes[..],
        "PolicyInstall's payload is exactly encode_into's output"
    );
}

/// `UFWControlSocket.placements(for:)` in IPCBridge.swift.
///
/// Exhaustive over every (layer, protocol, has-identity) combination, because
/// the expansion — one rule becoming two placements — is the part a second
/// implementation forgets.
#[test]
fn every_placement_the_swift_must_reproduce() {
    let protocols = [
        (Protocol::Any, "any"),
        (Protocol::Tcp, "tcp"),
        (Protocol::Udp, "udp"),
        (Protocol::Icmp, "icmp"),
        (Protocol::IcmpV6, "icmpv6"),
        (Protocol::Other(47), "gre"),
    ];
    let mut table = Vec::new();
    for layer in ufw_shared::policy_types::EVALUATION_ORDER {
        for (protocol, pname) in protocols {
            for has_app in [false, true] {
                let mut rule = CompiledRule::new(1, "r", layer, Action::Allow);
                rule.protocol = protocol;
                if has_app {
                    rule.app = Some(Default::default());
                }
                let placements: Vec<String> = rule
                    .macos_placements()
                    .into_iter()
                    .map(|(p, s)| format!("{}:{}", p.as_str(), s.as_str()))
                    .collect();
                table.push(format!(
                    "{} {pname} app={} -> [{}]",
                    layer.as_str(),
                    u8::from(has_app),
                    placements.join(", ")
                ));
            }
        }
    }

    let expected = "\
perimeter any app=0 -> [flow:connectionOriented, packet:connectionless]
perimeter any app=1 -> [flow:connectionOriented]
perimeter tcp app=0 -> [flow:connectionOriented]
perimeter tcp app=1 -> [flow:connectionOriented]
perimeter udp app=0 -> [flow:connectionOriented]
perimeter udp app=1 -> [flow:connectionOriented]
perimeter icmp app=0 -> [packet:connectionless]
perimeter icmp app=1 -> []
perimeter icmpv6 app=0 -> [packet:connectionless]
perimeter icmpv6 app=1 -> []
perimeter gre app=0 -> [packet:connectionless]
perimeter gre app=1 -> []
packet any app=0 -> [flow:connectionOriented, packet:connectionless]
packet any app=1 -> [flow:connectionOriented]
packet tcp app=0 -> [flow:connectionOriented]
packet tcp app=1 -> [flow:connectionOriented]
packet udp app=0 -> [flow:connectionOriented]
packet udp app=1 -> [flow:connectionOriented]
packet icmp app=0 -> [packet:connectionless]
packet icmp app=1 -> []
packet icmpv6 app=0 -> [packet:connectionless]
packet icmpv6 app=1 -> []
packet gre app=0 -> [packet:connectionless]
packet gre app=1 -> []
identity any app=0 -> [flow:connectionOriented, packet:connectionless]
identity any app=1 -> [flow:connectionOriented]
identity tcp app=0 -> [flow:connectionOriented]
identity tcp app=1 -> [flow:connectionOriented]
identity udp app=0 -> [flow:connectionOriented]
identity udp app=1 -> [flow:connectionOriented]
identity icmp app=0 -> [packet:connectionless]
identity icmp app=1 -> []
identity icmpv6 app=0 -> [packet:connectionless]
identity icmpv6 app=1 -> []
identity gre app=0 -> [packet:connectionless]
identity gre app=1 -> []
app-dpi any app=0 -> [flow:connectionOriented]
app-dpi any app=1 -> [flow:connectionOriented]
app-dpi tcp app=0 -> [flow:connectionOriented]
app-dpi tcp app=1 -> [flow:connectionOriented]
app-dpi udp app=0 -> [flow:connectionOriented]
app-dpi udp app=1 -> [flow:connectionOriented]
app-dpi icmp app=0 -> [flow:connectionOriented]
app-dpi icmp app=1 -> [flow:connectionOriented]
app-dpi icmpv6 app=0 -> [flow:connectionOriented]
app-dpi icmpv6 app=1 -> [flow:connectionOriented]
app-dpi gre app=0 -> [flow:connectionOriented]
app-dpi gre app=1 -> [flow:connectionOriented]
stream any app=0 -> [flow:connectionOriented]
stream any app=1 -> [flow:connectionOriented]
stream tcp app=0 -> [flow:connectionOriented]
stream tcp app=1 -> [flow:connectionOriented]
stream udp app=0 -> [flow:connectionOriented]
stream udp app=1 -> [flow:connectionOriented]
stream icmp app=0 -> [flow:connectionOriented]
stream icmp app=1 -> [flow:connectionOriented]
stream icmpv6 app=0 -> [flow:connectionOriented]
stream icmpv6 app=1 -> [flow:connectionOriented]
stream gre app=0 -> [flow:connectionOriented]
stream gre app=1 -> [flow:connectionOriented]";

    assert_eq!(
        table.join("\n"),
        expected,
        "macOS placement changed. `UFWControlSocket.placements(for:)` in \
         kernel/macos/NetworkExtension/IPCBridge.swift mirrors this table by hand and must \
         be updated in the same commit."
    );
}

/// An identity rule on a connectionless protocol is placed *nowhere*, and that
/// is deliberate — but it is surprising enough to state on its own, because a
/// reader of the table above could take the empty list for a bug.
#[test]
fn an_identity_rule_on_a_connectionless_protocol_is_placed_nowhere() {
    let mut rule = CompiledRule::new(1, "icmp-by-app", Layer::Packet, Action::Deny);
    rule.protocol = Protocol::Icmp;
    rule.app = Some(Default::default());

    assert!(
        rule.macos_placements().is_empty(),
        "the flow provider never sees ICMP and the packet provider has no audit token, so \
         there is nowhere this rule could be evaluated. Installing it somewhere anyway would \
         be a rule that silently never fires — which the compiler reports as a note rather \
         than hiding."
    );
}
