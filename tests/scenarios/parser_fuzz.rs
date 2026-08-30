//! Scenario: the Rust parsers that face the network and the fleet channel do
//! not crash on hostile bytes.
//!
//! The C ring-0 decoders have a libFuzzer campaign (`fuzz/`, and the always-on
//! `kcore-equivalence` gate). The Rust parsers had none, and they are no less
//! exposed: the IPC wire protocol decodes whatever a peer on the control socket
//! sends, and the policy compiler parses whatever a fleet bundle carries. A
//! panic in either is a denial of service at best — an `unwrap` on a length
//! field, an overflow on a count — so the property under test is the minimal
//! one a parser owes a caller it does not trust: *it returns an error, it does
//! not unwind the process.*
//!
//! See `harness/fuzz.rs` for the driver. It is deterministic (fixed seeds), so
//! a crash here is a stable, replayable red — the offending input is printed in
//! hex — not a heisenbug. Open-ended coverage-guided search stays in the
//! scheduled libFuzzer campaign; this is the tripwire that rides in every
//! `cargo test`.

use ufw_e2e::fuzz::no_panic_over_bytes;
use ufw_e2e::BASELINE;

use ufw_shared::protocol::{
    EnforcementMode, ErrorMessage, Message, MessageHeader, SignatureInstall, SignatureInstallAck,
};

/// Valid frames spanning empty-bodied and variable-length message types. The
/// fuzzer mutates these — flipping the type discriminant redirects the bytes
/// into a *different* body decoder, and corrupting the length field drives each
/// decoder with a truncated or overlong body — so a handful of seeds exercises
/// the whole dispatch table, not just the types listed here.
fn wire_seeds() -> Vec<Vec<u8>> {
    vec![
        Message::PolicyFlush.encode(1),
        Message::StatsRequest.encode(7),
        Message::SetMode(EnforcementMode::Enforce).encode(3),
        Message::ModeAck(EnforcementMode::Monitor).encode(4),
        Message::Error(ErrorMessage {
            code: 42,
            detail: "boom".into(),
        })
        .encode(9),
        Message::SignatureInstall(Box::new(SignatureInstall {
            payload: vec![1, 2, 3, 4, 5, 6, 7, 8],
        }))
        .encode(11),
        Message::SignatureInstallAck(SignatureInstallAck::default()).encode(12),
        Message::LogEvents(vec![]).encode(13),
    ]
}

#[test]
fn the_wire_protocol_decoder_never_panics() {
    let seeds = wire_seeds();
    let seed_refs: Vec<&[u8]> = seeds.iter().map(|v| v.as_slice()).collect();
    no_panic_over_bytes(
        "protocol::Message::decode",
        &seed_refs,
        20_000,
        1024,
        |bytes| {
            // The whole point: any bytes in, a Result out, no unwind.
            let _ = Message::decode(bytes);
        },
    );
}

#[test]
fn the_frame_header_parser_never_panics() {
    // The header is fixed-size and parsed before any body; feed it short and
    // malformed buffers, which is where an off-by-one on the length field lives.
    let seeds = wire_seeds();
    let seed_refs: Vec<&[u8]> = seeds.iter().map(|v| v.as_slice()).collect();
    no_panic_over_bytes(
        "protocol::MessageHeader::parse",
        &seed_refs,
        20_000,
        64,
        |bytes| {
            let _ = MessageHeader::parse(bytes);
        },
    );
}

#[test]
fn a_decoded_frame_re_encodes_to_the_same_bytes() {
    // A different property, checked on the inputs that *do* decode: the codec is
    // a bijection on valid frames. If decode accepts bytes that encode would not
    // reproduce, some field is being dropped or reinterpreted — a latent parsing
    // bug even though nothing panicked.
    let seeds = wire_seeds();
    for seed in &seeds {
        let (msg, seq) = Message::decode(seed).expect("a seed frame decodes");
        let again = msg.encode(seq);
        assert_eq!(
            &again,
            seed,
            "re-encoding a decoded frame changed its bytes for {:?}",
            msg.msg_type()
        );
    }
}

#[test]
fn the_policy_compiler_never_panics() {
    // The compiler is the largest hand-rolled parser in the tree (a YAML subset
    // plus a semantic analyzer) and it parses fleet-distributed source. Mutating
    // a valid policy reaches the semantic phase; random bytes stress the lexer.
    let extra = "\
version: 1
metadata:
  name: fuzz-seed-2
defaults:
  action: allow
address_groups:
  g: [10.0.0.0/8, 2001:db8::/32]
rules:
  - id: r
    priority: 5
    layer: identity
    action: allow-inspect
    protocol: tcp
    destination:
      ports: [443]
";
    let seeds: [&[u8]; 2] = [BASELINE.as_bytes(), extra.as_bytes()];
    no_panic_over_bytes("policy_lang::compile_str", &seeds, 8_000, 512, |bytes| {
        let text = String::from_utf8_lossy(bytes);
        let _ = ufw_policy_lang::compile_str(
            "fuzz",
            &text,
            &ufw_policy_lang::CompileOptions::default(),
        );
    });
}

#[test]
fn the_policy_compiler_is_deterministic() {
    // Determinism is what makes a fuzz failure replayable and a signed fleet
    // bundle reproducible: the same source must compile to the same diagnostics
    // and the same artifact bytes every time.
    let cases = [
        BASELINE,
        "version: 1\nmetadata:\n  name: x\ndefaults:\n  action: deny\nrules: []\n",
        "not: even: valid: yaml: at: all",
        "",
    ];
    for src in cases {
        let a = ufw_policy_lang::compile_str("d", src, &Default::default());
        let b = ufw_policy_lang::compile_str("d", src, &Default::default());
        assert_eq!(a.render(), b.render(), "diagnostics differ across runs");
        assert_eq!(
            a.is_ok(),
            b.is_ok(),
            "compile success differs across runs for the same source"
        );
    }
}
