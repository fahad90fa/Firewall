//! The evasion checks, driven through the attacks they exist for.
//!
//! `kernel/linux/inc/evasion.h` handles the classic IDS-evasion set: TTL
//! insertion, IP fragment overlap, forged RST, PAWS replay. Every one of those
//! paths is, by construction, never taken by ordinary traffic — which means
//! ordinary testing does not reach them, and a bug there is invisible until
//! somebody uses it.
//!
//! So this drives each attack directly, and each *legitimate* pattern that
//! resembles it, because a check that fires on retransmissions and route flap
//! is a check that gets disabled and then the attack works anyway.
//!
//! Under sanitizers, like the decoders: this is per-flow state driven by
//! attacker-chosen sequence numbers, which is the other place a memory bug in
//! ring 0 would live.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn c_compiler() -> Option<&'static str> {
    ["cc", "gcc", "clang"]
        .into_iter()
        .find(|&candidate| {
            Command::new(candidate)
                .arg("--version")
                .output()
                .map(|o| o.status.success())
                .unwrap_or(false)
        })
        .map(|v| v as _)
}

/// Compile and run a fragment of C against the header, returning its stdout.
/// Every case is a few lines of driver, so inlining them keeps the attack and
/// its expected outcome in the same place.
fn run(body: &str) -> Option<String> {
    let cc = c_compiler()?;
    let inc = repo_root().join("kernel/linux/inc");
    if !inc.join("evasion.h").exists() {
        return None;
    }
    // These cases run on parallel threads that all share this process's pid,
    // and `now_us()` is only microsecond-resolved — two threads entering here in
    // the same microsecond would otherwise land on the same directory and clobber
    // each other's `t.c` and `t` binary (a corrupt source, or a case running the
    // wrong binary). A process-wide counter makes every invocation's path unique
    // regardless of timing.
    static SEQ: AtomicU64 = AtomicU64::new(0);
    let dir = std::env::temp_dir().join(format!(
        "ufw-evade-{}-{}-{}",
        std::process::id(),
        ufw_shared::now_us(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let source = dir.join("t.c");
    std::fs::write(
        &source,
        format!(
            r#"
#include <stdint.h>
#include <stdio.h>
#include "evasion.h"

int main(void)
{{
        struct ufw_evasion e;

        ufw_evasion_init(&e);
{body}
        printf("findings=%u\n", (unsigned)ufw_evasion_findings(&e));
        return 0;
}}
"#
        ),
    )
    .unwrap();

    let binary = dir.join("t");
    let build = Command::new(cc)
        .args([
            "-std=c11",
            "-Wall",
            "-Wextra",
            "-Werror",
            "-g",
            "-fsanitize=address,undefined",
            "-fno-sanitize-recover=all",
        ])
        .arg("-I")
        .arg(&inc)
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("compiler");
    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr).to_string();
        if stderr.contains("libasan") {
            eprintln!("no sanitizer runtime; skipping");
            return None;
        }
        panic!("{stderr}");
    }

    let out = Command::new(&binary).output().expect("run");
    assert!(
        out.status.success(),
        "the evasion checks crashed on this sequence:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    Some(text)
}

fn findings(body: &str) -> Option<u32> {
    let out = run(body)?;
    let value = out
        .lines()
        .find_map(|l| l.strip_prefix("findings="))
        .expect("findings line");
    Some(value.trim().parse().expect("number"))
}

const TTL_INSERTION: u32 = 0x0001;
const FRAG_OVERLAP: u32 = 0x0002;
const FRAG_OVERSIZE: u32 = 0x0004;
const BAD_RST: u32 = 0x0008;
const PAWS_REPLAY: u32 = 0x0010;
const SYN_MISMATCH: u32 = 0x0020;

#[test]
fn a_segment_with_a_ttl_too_low_to_reach_the_endpoint_is_reported() {
    // Ptacek and Newsham's insertion attack: a packet crafted to expire
    // between this firewall and the host it protects. The firewall scans it,
    // the endpoint never sees it, and any signature it evaded is defeated.
    let Some(f) = findings(
        "        ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 3);",
    ) else {
        return;
    };
    assert_eq!(f & TTL_INSERTION, TTL_INSERTION);
}

#[test]
fn ordinary_ttl_variation_is_not_reported() {
    // ECMP and route flap move the path length by a hop or two constantly. A
    // check that fires on that is a check somebody disables, and then the
    // attack above works.
    let Some(f) = findings(
        "        ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 63);\n\
         \x20       ufw_evasion_ttl(&e, 62);\n\
         \x20       ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 61);",
    ) else {
        return;
    };
    assert_eq!(f, 0, "normal path-length jitter must not read as an attack");
}

#[test]
fn the_ttl_baseline_is_the_highest_seen_not_the_first() {
    // A flow whose very first packet is the attack would otherwise calibrate
    // against the attack and never report it.
    let Some(f) = findings(
        "        ufw_evasion_ttl(&e, 3);\n\
         \x20       ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 3);",
    ) else {
        return;
    };
    assert_eq!(f & TTL_INSERTION, TTL_INSERTION);
}

#[test]
fn overlapping_fragments_carrying_different_bytes_are_reported() {
    // The same trick as TCP overlap, one layer down, and with worse
    // disagreement between stacks: Linux prefers the first copy, older
    // Windows the last.
    let Some(f) = findings(
        "        const __u8 a[8] = { 1, 1, 1, 1, 1, 1, 1, 1 };\n\
         \x20       const __u8 b[8] = { 2, 2, 2, 2, 2, 2, 2, 2 };\n\
         \x20       ufw_evasion_fragment(&e, 7, 0, a, 8);\n\
         \x20       ufw_evasion_fragment(&e, 7, 4, b, 8);",
    ) else {
        return;
    };
    assert_eq!(f & FRAG_OVERLAP, FRAG_OVERLAP);
}

#[test]
fn an_identical_retransmitted_fragment_is_not_an_attack() {
    // Retransmission is normal and looks exactly like overlap. Reporting it
    // would bury the real signal in noise from every lossy link.
    let Some(f) = findings(
        "        const __u8 a[8] = { 9, 8, 7, 6, 5, 4, 3, 2 };\n\
         \x20       ufw_evasion_fragment(&e, 7, 0, a, 8);\n\
         \x20       ufw_evasion_fragment(&e, 7, 0, a, 8);",
    ) else {
        return;
    };
    assert_eq!(f, 0);
}

#[test]
fn fragments_of_a_new_datagram_do_not_overlap_the_previous_one() {
    let Some(f) = findings(
        "        const __u8 a[8] = { 1 };\n\
         \x20       const __u8 b[8] = { 2 };\n\
         \x20       ufw_evasion_fragment(&e, 7, 0, a, 8);\n\
         \x20       ufw_evasion_fragment(&e, 8, 0, b, 8);",
    ) else {
        return;
    };
    assert_eq!(f, 0, "different IP ids are different datagrams");
}

#[test]
fn a_fragment_claiming_to_end_past_the_datagram_ceiling_is_refused() {
    // Teardrop. 65535 is what the IP header's length field can express; a
    // fragment ending past it cannot be reassembled by anything.
    let Some(f) = findings(
        "        const __u8 a[8] = { 0 };\n\
         \x20       ufw_evasion_fragment(&e, 7, 65530, a, 8);",
    ) else {
        return;
    };
    assert_eq!(f & FRAG_OVERSIZE, FRAG_OVERSIZE);
}

#[test]
fn more_fragments_than_any_real_datagram_needs_is_refused() {
    // Refusing to track further is not the same as accepting: the flow
    // carries the finding from that point on.
    let Some(f) = findings(
        "        const __u8 a[4] = { 0 };\n\
         \x20       unsigned i;\n\
         \x20       for (i = 0; i < 64; i++)\n\
         \x20               ufw_evasion_fragment(&e, 7, i * 8, a, 4);",
    ) else {
        return;
    };
    assert_eq!(f & FRAG_OVERSIZE, FRAG_OVERSIZE);
}

#[test]
fn a_reset_outside_the_window_does_not_tear_down_the_flow() {
    // RFC 5961. The endpoint ignores this RST; a firewall that acts on it
    // stops watching a connection that is still running, which is a better
    // outcome for an attacker than being blocked.
    let Some(f) = findings(
        "        ufw_evasion_window(&e, 1000, 500);\n\
         \x20       ufw_evasion_rst(&e, 900000);",
    ) else {
        return;
    };
    assert_eq!(f & BAD_RST, BAD_RST);
}

#[test]
fn a_reset_inside_the_window_is_accepted() {
    let Some(f) = findings(
        "        ufw_evasion_window(&e, 1000, 500);\n\
         \x20       ufw_evasion_rst(&e, 1200);",
    ) else {
        return;
    };
    assert_eq!(f, 0);
}

#[test]
fn window_validation_survives_sequence_wraparound() {
    // A connection that has transferred 4 GiB wraps, and a comparison written
    // with `<` instead of a signed difference starts rejecting every valid
    // segment at exactly that point. Long-lived connections are the ones
    // worth watching, so this is not an edge case.
    let Some(f) = findings(
        "        ufw_evasion_window(&e, 0xFFFFFF00u, 1024);\n\
         \x20       ufw_evasion_rst(&e, 0x00000100u);",
    ) else {
        return;
    };
    assert_eq!(f, 0, "a RST just past the wrap point is in window");
}

#[test]
fn a_timestamp_going_backwards_is_a_paws_replay() {
    // RFC 7323: the endpoint drops it. A firewall that inspects it is
    // inspecting bytes that will never be processed — TTL insertion arriving
    // through a different door.
    let Some(f) = findings(
        "        ufw_evasion_timestamp(&e, 5000);\n\
         \x20       ufw_evasion_timestamp(&e, 6000);\n\
         \x20       ufw_evasion_timestamp(&e, 4000);",
    ) else {
        return;
    };
    assert_eq!(f & PAWS_REPLAY, PAWS_REPLAY);
}

#[test]
fn a_repeated_timestamp_is_not_a_replay() {
    // Two segments in the same clock tick share a timestamp constantly.
    let Some(f) = findings(
        "        ufw_evasion_timestamp(&e, 5000);\n\
         \x20       ufw_evasion_timestamp(&e, 5000);",
    ) else {
        return;
    };
    assert_eq!(f, 0);
}

#[test]
fn a_second_syn_with_a_different_initial_sequence_is_reported() {
    // Either a new connection reusing the tuple — in which case everything
    // this flow accumulated describes a different connection — or an
    // injection. Folding it silently into the existing state is wrong either
    // way.
    let Some(f) = findings(
        "        ufw_evasion_syn(&e, 1000);\n\
         \x20       ufw_evasion_syn(&e, 9999);",
    ) else {
        return;
    };
    assert_eq!(f & SYN_MISMATCH, SYN_MISMATCH);
}

#[test]
fn a_retransmitted_syn_is_not_reported() {
    let Some(f) = findings(
        "        ufw_evasion_syn(&e, 1000);\n\
         \x20       ufw_evasion_syn(&e, 1000);",
    ) else {
        return;
    };
    assert_eq!(f, 0);
}

#[test]
fn findings_accumulate_rather_than_replacing_each_other() {
    // "Low TTL *and* an overlapping fragment" is a deliberate evasion
    // attempt; either alone is occasionally a misconfigured network. The
    // combination is the thing an analyst wants to see, so one finding must
    // not overwrite another.
    let Some(f) = findings(
        "        const __u8 a[8] = { 1 };\n\
         \x20       const __u8 b[8] = { 2 };\n\
         \x20       ufw_evasion_ttl(&e, 64);\n\
         \x20       ufw_evasion_ttl(&e, 2);\n\
         \x20       ufw_evasion_fragment(&e, 7, 0, a, 8);\n\
         \x20       ufw_evasion_fragment(&e, 7, 4, b, 8);",
    ) else {
        return;
    };
    assert_eq!(f & TTL_INSERTION, TTL_INSERTION);
    assert_eq!(f & FRAG_OVERLAP, FRAG_OVERLAP);
}
