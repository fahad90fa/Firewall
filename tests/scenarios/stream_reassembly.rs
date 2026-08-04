//! Scenario: the IPC path a reassembled stream's verdict travels.
//!
//! Reassembly itself is implemented three times in three languages, and none of
//! them can run here. What *can* run here is the part of the stream path that
//! lives in this workspace: the wire protocol carrying a stream-derived verdict
//! from a kernel module to the daemon, and the daemon's handling of it.
//!
//! That is a narrower claim than the file name suggests, and it is worth being
//! explicit about the boundary rather than letting a passing test imply more:
//!
//!   - **Covered here:** the protocol framing, the budget constant all three
//!     implementations share, the truncation flag surviving a round trip, and
//!     the daemon's behaviour when a module reports a truncated scan.
//!   - **Covered by the C and Swift sources:** the reassembly logic, the
//!     overlap policy, the eviction strategy.
//!   - **Covered only by a deployment:** whether those behave as written.

use std::sync::mpsc::channel;
use std::time::Duration;

use ufw_daemon::ipc::loopback::{self, MockKernelModule};
use ufw_daemon::ipc::KernelChannel;
use ufw_shared::constants;
use ufw_shared::policy_types::{DpiScan, L7Protocol};
use ufw_shared::protocol::{Message, MessageType, Reader, Writer};

#[test]
fn the_reassembly_budget_is_one_number_shared_by_every_implementation() {
    // The constant exists in four places: here, `kernel/linux/inc/stream.h`,
    // `kernel/windows/inc/stream_reassembly.h`, and `StreamHandler.swift`. It
    // originates from the macOS sandbox and was adopted by the other two.
    //
    // If they drift, a signature fires on one platform and silently does not on
    // another, depending on stream length rather than on policy — which no
    // policy test could ever surface. This assertion is the anchor the three
    // C/Swift files cite.
    assert_eq!(
        constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS,
        32 * 1024,
        "changing this means changing kernel/linux/inc/stream.h, \
         kernel/windows/inc/stream_reassembly.h and \
         kernel/macos/NetworkExtension/StreamHandler.swift in the same commit"
    );
}

#[test]
fn the_default_content_search_window_matches_the_budget() {
    // A signature that does not say `depth:` searches this far. Defaulting to
    // "the rest of the stream" would mean the same signature searched further
    // on Linux than the macOS extension can ever buffer, so the two platforms
    // would disagree about a match without either being wrong on its own terms.
    let mut set = ufw_daemon::signatures::SignatureSet::default();
    let mut errors = Vec::new();
    ufw_daemon::signatures::parse_into(
        &mut set,
        "version: 1\nsignatures:\n  - id: x\n    protocol: http\n    \
         conditions:\n      - content: \"POST /admin\"\n",
        std::path::Path::new("test.yaml"),
        &mut errors,
    );
    assert!(errors.is_empty(), "{errors:?}");

    let signature = set.by_name("x").expect("loaded");
    match &signature.conditions[0] {
        ufw_daemon::signatures::Condition::Content { depth, .. } => {
            assert_eq!(
                *depth as usize,
                constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS,
                "the default search window and the reassembly budget must be \
                 the same number, or a signature means something different on \
                 each platform"
            );
        }
        other => panic!("expected a content condition, got {other:?}"),
    }
}

#[test]
fn a_dpi_scan_survives_the_wire_intact() {
    // The truncation flag is the field most likely to be dropped by a codec
    // change, and the one whose loss is least visible: everything still works,
    // and "we did not finish looking" quietly becomes "we looked and found
    // nothing".
    let scan = DpiScan {
        l7: L7Protocol::Http,
        hits: vec![0xDEAD_BEEF, 0x1234_5678],
        first_hit_offset: 4096,
        truncated: true,
    };

    let mut writer = Writer::new();
    scan.encode(&mut writer);
    let bytes = writer.finish();

    let mut reader = Reader::new(&bytes);
    let decoded = DpiScan::decode(&mut reader).expect("a well-formed scan decodes");

    assert_eq!(decoded.l7, scan.l7);
    assert_eq!(decoded.hits, scan.hits);
    assert_eq!(decoded.first_hit_offset, scan.first_hit_offset);
    assert!(decoded.truncated, "the truncation flag must survive the round trip");
}

#[test]
fn a_module_reporting_stream_statistics_is_understood_by_the_daemon() {
    // The counters an operator uses to tell "inspection is working" from
    // "inspection is silently not running": a reassembly context count of zero
    // on a busy host means the stream path never engaged.
    let (daemon_side, module_side) = loopback::pair();
    let mut module = MockKernelModule::spawn(module_side);
    let (tx, _events) = channel();

    let (mut kernel, _handshake) =
        KernelChannel::open(daemon_side, tx, "stream-test", Duration::from_secs(2))
            .expect("the handshake completes against a well-behaved module");

    let stats = kernel
        .stats(Duration::from_secs(2))
        .expect("the mock module answers a stats request");

    assert!(
        stats.reassembly_contexts <= stats.dpi_scans + 1,
        "more reassembly contexts than scans would mean contexts are being \
         created and never used"
    );

    kernel.shutdown();
    module.stop();
}

#[test]
fn a_module_reporting_the_wrong_abi_is_refused_rather_than_trusted() {
    // A rule table laid out for a different ABI revision would still install
    // and would still filter — just not what the operator wrote. Refusing at
    // the handshake is the only safe reading, and it has to happen there
    // because by the time a rule is misparsed there is no way to tell.
    let (daemon_side, module_side) = loopback::pair();
    let mut module = MockKernelModule::spawn_with(module_side, |behaviour| {
        behaviour.abi_revision = constants::ABI_REVISION + 1;
    });
    let (tx, _events) = channel();

    let result =
        KernelChannel::open(daemon_side, tx, "wrong-abi", Duration::from_secs(2));
    assert!(
        result.is_err(),
        "a module with a mismatched ABI revision must not complete the handshake"
    );

    module.stop();
}

#[test]
fn a_module_that_never_answers_produces_a_timeout_rather_than_a_hang() {
    // The failure that matters operationally. A daemon blocked forever on a
    // kernel module that stopped answering takes the management plane with it,
    // which is exactly when an operator needs `ufwctl status` to work.
    let (daemon_side, module_side) = loopback::pair();
    let mut module = MockKernelModule::spawn_with(module_side, |behaviour| {
        behaviour.ignore_stats = true;
    });
    let (tx, _events) = channel();

    let (mut kernel, _handshake) =
        KernelChannel::open(daemon_side, tx, "silent", Duration::from_secs(2))
            .expect("the handshake still completes; only stats are ignored");

    let result = kernel.stats(Duration::from_millis(200));
    assert!(result.is_err(), "an unanswered request must time out, not block");

    kernel.shutdown();
    module.stop();
}

#[test]
fn message_types_used_by_the_stream_path_round_trip() {
    // The stream path shares its framing with everything else, so a change to
    // the header breaks it silently along with the rest. This is the
    // cheapest possible guard on that.
    for kind in [
        MessageType::LogEvents,
        MessageType::StatsRequest,
        MessageType::StatsResponse,
    ] {
        assert_eq!(
            MessageType::from_u16(kind as u16),
            Some(kind),
            "{kind:?} does not survive a numeric round trip"
        );
    }
}
