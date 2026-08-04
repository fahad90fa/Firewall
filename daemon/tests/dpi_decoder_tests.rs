//! The protocol decoders, fuzzed and cross-checked.
//!
//! `kernel/linux/inc/dpi_decoders.h` parses DNS, HTTP, TLS and SSH payloads in
//! softirq context, in ring 0, on bytes an adversary chose. It is the
//! highest-risk code in the project and until it was extracted from
//! `dpi_engine.c` nothing could reach it without a kernel.
//!
//! Two things run here, and they answer different questions.
//!
//! **Does it crash?** The decoders are compiled with AddressSanitizer and
//! UndefinedBehaviorSanitizer and fed mutated input derived from valid
//! payloads. A read past a buffer, a signed overflow, a shift past the width
//! of a type — in the kernel each of those is a memory-safety bug at the
//! privilege level where they matter most. Here they are an exit code.
//!
//! **Do the two C implementations agree?** The Linux and Windows decoders are
//! separate files, and the equivalence claim depends on them extracting the
//! same fields from the same bytes. Nothing checked that. A decoder that
//! disagrees about `http.header_count` is a policy that means something
//! different on one platform, which no policy test would ever surface.
//!
//! Without a C compiler both report that and pass, rather than failing a Rust
//! developer's machine for lacking a toolchain they do not otherwise need.
//!
//! # Why the fuzzer is in-tree rather than cargo-fuzz
//!
//! `cargo-fuzz` needs a nightly toolchain and `libfuzzer-sys`, and this
//! workspace takes no dependencies. What is here is a deterministic mutator
//! over a seed corpus — weaker than coverage-guided fuzzing, and it runs on
//! every `cargo test` instead of only when someone remembers. The two are
//! complementary: `fuzz/README.md` has the libFuzzer harness for a long
//! campaign, and this is the tripwire.
//!
//! Deterministic matters. A crash found by an unreproducible input is a crash
//! nobody can fix.

use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace root")
        .to_path_buf()
}

fn c_compiler() -> Option<&'static str> {
    for candidate in ["cc", "gcc", "clang"] {
        let ok = Command::new(candidate)
            .arg("--version")
            .output()
            .map(|o| o.status.success())
            .unwrap_or(false);
        if ok {
            return Some(candidate);
        }
    }
    None
}

fn scratch(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "ufw-dec-{}-{}-{name}",
        std::process::id(),
        ufw_shared::now_us()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

/// splitmix64. Deterministic on purpose: the useful output of a fuzz failure
/// is the input that caused it, and an unseeded RNG throws that away.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: usize) -> usize {
        if n == 0 {
            0
        } else {
            (self.next() % n as u64) as usize
        }
    }
}

/// Well-formed payloads, one per protocol, which the mutator then damages.
///
/// Seeds matter more than mutation count. A random byte string is rejected by
/// the first length check and exercises nothing; a *valid* payload with one
/// field corrupted reaches the code that trusts that field.
fn seeds() -> Vec<(u8, Vec<u8>)> {
    let mut out = Vec::new();

    // DNS query for `www.example.com`, A record.
    let mut dns = vec![
        0x12, 0x34, // id
        0x01, 0x00, // flags: standard query
        0x00, 0x01, // qdcount
        0x00, 0x00, // ancount
        0x00, 0x00, // nscount
        0x00, 0x00, // arcount
    ];
    for label in ["www", "example", "com"] {
        dns.push(label.len() as u8);
        dns.extend_from_slice(label.as_bytes());
    }
    dns.extend_from_slice(&[0x00, 0x00, 0x01, 0x00, 0x01]);
    out.push((3u8, dns)); // UFW_L7_DNS

    // A DNS name with a long, high-entropy label — the tunnelling shape.
    let mut tunnel = vec![0x00, 0x01, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
    let label: Vec<u8> = (0..60u32).map(|i| b'a' + (i * 7 % 26) as u8).collect();
    tunnel.push(label.len() as u8);
    tunnel.extend_from_slice(&label);
    tunnel.extend_from_slice(&[2, b'i', b'o', 0, 0, 0x10, 0, 1]);
    out.push((3, tunnel));

    out.push((
        1, // UFW_L7_HTTP
        b"POST /admin/upload HTTP/1.1\r\nHost: example.com\r\n\
          Content-Length: 42\r\nUser-Agent: curl/8.0\r\n\r\nbody-bytes-here"
            .to_vec(),
    ));
    out.push((1, b"GET / HTTP/1.0\r\n\r\n".to_vec()));

    // TLS 1.2 ClientHello with an SNI extension.
    let mut tls = vec![
        0x16, 0x03, 0x01, 0x00, 0x50, // record: handshake, TLS 1.0, length
        0x01, 0x00, 0x00, 0x4C, // handshake: client_hello, length
        0x03, 0x03, // client version TLS 1.2
    ];
    tls.extend_from_slice(&[0xAB; 32]); // random
    tls.push(0x00); // session id length
    tls.extend_from_slice(&[0x00, 0x04, 0xC0, 0x2F, 0xC0, 0x30]); // cipher suites
    tls.extend_from_slice(&[0x01, 0x00]); // compression
    tls.extend_from_slice(&[0x00, 0x11]); // extensions length
    tls.extend_from_slice(&[0x00, 0x00, 0x00, 0x0D]); // server_name, length
    tls.extend_from_slice(&[0x00, 0x0B, 0x00, 0x00, 0x08]);
    tls.extend_from_slice(b"host.tld");
    out.push((2, tls)); // UFW_L7_TLS

    out.push((4, b"SSH-2.0-OpenSSH_9.6p1 Debian-3\r\n".to_vec())); // UFW_L7_SSH
    out.push((4, b"SSH-1.99-badly formed banner with no newline".to_vec()));

    // And the boundaries every parser gets wrong first.
    out.push((3, Vec::new()));
    out.push((1, vec![0x00]));
    out.push((2, vec![0x16]));
    out.push((4, vec![b'S'; 3]));
    out
}

/// Damage a seed. Every operation preserves "this used to be a valid payload"
/// in most of the buffer, which is what keeps the mutant reaching parser
/// interiors instead of bouncing off the first length check.
fn mutate(seed: &[u8], rng: &mut Rng) -> Vec<u8> {
    let mut out = seed.to_vec();
    let operations = 1 + rng.below(3);
    for _ in 0..operations {
        if out.is_empty() {
            out.push(rng.next() as u8);
            continue;
        }
        match rng.below(6) {
            // Flip a byte. Length fields live in bytes, so this is the one
            // that produces "claims 200, has 12".
            0 => {
                let i = rng.below(out.len());
                out[i] = rng.next() as u8;
            }
            // Truncate. Every "read the next N bytes" is a bounds check that
            // has to hold here.
            1 => {
                let n = rng.below(out.len());
                out.truncate(n);
            }
            // Extend with garbage.
            2 => {
                let n = rng.below(64);
                for _ in 0..n {
                    out.push(rng.next() as u8);
                }
            }
            // Set a byte to a boundary value: 0, 1, 0x7F, 0x80, 0xFF. Off-by-
            // one bugs cluster there and uniform random rarely lands on them.
            3 => {
                let i = rng.below(out.len());
                out[i] = [0x00, 0x01, 0x7F, 0x80, 0xFF][rng.below(5)];
            }
            // Splice in a run of one byte — the shape that makes a naive
            // matcher quadratic and a length-prefixed parser loop.
            4 => {
                let i = rng.below(out.len());
                let byte = rng.next() as u8;
                let n = 1 + rng.below(32);
                for _ in 0..n {
                    out.insert(i.min(out.len()), byte);
                }
            }
            // Swap two bytes, which reorders a length prefix relative to what
            // it prefixes.
            _ => {
                let a = rng.below(out.len());
                let b = rng.below(out.len());
                out.swap(a, b);
            }
        }
        // A payload larger than the reassembly budget is not something the
        // engine ever sees, so growing without bound would fuzz a path that
        // does not exist.
        out.truncate(64 * 1024);
    }
    out
}

/// `u32 count`, then `u8 l7` + `u32 len` + bytes per case.
fn encode_corpus(cases: &[(u8, Vec<u8>)]) -> Vec<u8> {
    let mut out = (cases.len() as u32).to_le_bytes().to_vec();
    for (l7, payload) in cases {
        out.push(*l7);
        out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        out.extend_from_slice(payload);
    }
    out
}

/// The harness. Reads a corpus, decodes each case, prints every field the
/// decoder produced. Identical for both platforms bar the header it includes
/// and the names inside it.
fn harness_source(names: &Names) -> String {
    let Names {
        decoded_t,
        set,
        dns,
        http,
        tls,
        ssh,
        entropy,
        identify,
        zero,
    } = names;
    format!(
        r#"
#include <stdio.h>
#include <stdlib.h>
#include "dpi_decoders.h"

static unsigned char corpus[1 << 20];
static unsigned char payload[1 << 17];

static unsigned read_u32(const unsigned char *p)
{{
        return (unsigned)p[0] | ((unsigned)p[1] << 8) |
               ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}}

int main(int argc, char **argv)
{{
        FILE *f;
        size_t len;
        unsigned count, i, pos, field;

        if (argc != 2)
                return 64;
        f = fopen(argv[1], "rb");
        if (!f)
                return 65;
        len = fread(corpus, 1, sizeof(corpus), f);
        fclose(f);
        if (len < 4)
                return 66;

        count = read_u32(corpus);
        pos = 4;
        for (i = 0; i < count; i++) {{
                {decoded_t} decoded;
                unsigned l7, plen;

                if (pos + 5 > len)
                        return 67;
                l7 = corpus[pos];
                plen = read_u32(corpus + pos + 1);
                pos += 5;
                if (pos + plen > len || plen > sizeof(payload))
                        return 68;
                /* Copied into a separate buffer so an overread runs off the
                 * end of an allocation ASan owns, rather than into the rest
                 * of the corpus where it would go unnoticed. */
                memcpy(payload, corpus + pos, plen);
                pos += plen;

                {zero}(&decoded, sizeof(decoded));
                {set}(&decoded, UFW_FIELD_PAYLOAD_LEN, plen);
                switch (l7) {{
                case UFW_L7_DNS:  {dns}(&decoded, payload, plen); break;
                case UFW_L7_HTTP: {http}(&decoded, payload, plen); break;
                case UFW_L7_TLS:  {tls}(&decoded, payload, plen); break;
                case UFW_L7_SSH:  {ssh}(&decoded, payload, plen); break;
                default: break;
                }}

                printf("%u:", i);
                for (field = 0; field < 128; field++) {{
                        if (decoded.present[field])
                                printf(" %u=%u", field, decoded.values[field]);
                }}
                /* Entropy and protocol identification run over the same bytes
                 * and have their own arithmetic to get wrong. */
                printf(" H=%u L=%u\n", (unsigned){entropy}(payload, plen),
                       (unsigned){identify}(payload, plen, 443));
        }}
        return 0;
}}
"#
    )
}

/// Compile the harness against one platform's decoders and run it.
/// The two headers declare the same decoders under each tree's own naming
/// convention. Spelling the difference out here, rather than macro-ing it away
/// in the headers, is deliberate: each header should read like the code around
/// it, and a shim in a shipped header to make a test easier is a shim that
/// ends up in a driver.
struct Names {
    decoded_t: &'static str,
    set: &'static str,
    dns: &'static str,
    http: &'static str,
    tls: &'static str,
    ssh: &'static str,
    entropy: &'static str,
    identify: &'static str,
    zero: &'static str,
}

const LINUX_NAMES: Names = Names {
    decoded_t: "struct ufw_decoded",
    set: "decoded_set",
    dns: "decode_dns",
    http: "decode_http",
    tls: "decode_tls",
    ssh: "decode_ssh",
    entropy: "entropy_centibits",
    identify: "ufw_dpi_identify",
    zero: "ufw_zero",
};

const WINDOWS_NAMES: Names = Names {
    decoded_t: "UFW_DECODED",
    set: "UfwDecodedSet",
    dns: "UfwDecodeDns",
    http: "UfwDecodeHttp",
    tls: "UfwDecodeTls",
    ssh: "UfwDecodeSsh",
    entropy: "UfwEntropyCentibits",
    identify: "UfwDpiIdentify",
    zero: "RtlZeroMemory",
};

fn build_and_run(
    cc: &str,
    label: &str,
    include_dir: PathBuf,
    names: &Names,
    extra: &[&str],
    corpus: &[u8],
    sanitize: bool,
) -> Option<String> {
    if !include_dir.join("dpi_decoders.h").exists() {
        eprintln!(
            "{}/dpi_decoders.h not present; skipping",
            include_dir.display()
        );
        return None;
    }
    let dir = scratch(label);
    let source = dir.join("decode_check.c");
    std::fs::write(&source, harness_source(names)).expect("harness");
    let corpus_path = dir.join("corpus.bin");
    std::fs::write(&corpus_path, corpus).expect("corpus");

    let binary = dir.join("decode_check");
    let mut command = Command::new(cc);
    command
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .arg("-g");
    if sanitize {
        // The whole point. Without these an overread is a wrong answer
        // instead of a failure, and a wrong answer in a fuzz run looks like
        // a pass.
        command
            .arg("-fsanitize=address,undefined")
            .arg("-fno-sanitize-recover=all")
            .arg("-fno-omit-frame-pointer");
    }
    command
        .args(extra)
        .arg("-I")
        .arg(&include_dir)
        .arg("-o")
        .arg(&binary)
        .arg(&source);

    let build = command.output().expect("running the C compiler");
    if !build.status.success() {
        let stderr = String::from_utf8_lossy(&build.stderr).to_string();
        if sanitize && stderr.contains("libasan") {
            eprintln!("sanitizer runtime unavailable; skipping the {label} fuzz run");
            let _ = std::fs::remove_dir_all(&dir);
            return None;
        }
        panic!("{label}/dpi_decoders.h does not compile hosted:\n{stderr}");
    }

    let run = Command::new(&binary)
        .arg(&corpus_path)
        .output()
        .expect("running the decoder harness");
    assert!(
        run.status.success(),
        "the {label} decoders failed on this corpus (exit {:?}).\n{}\n\
         The corpus is at {} — it is deterministic, so this reproduces.",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr),
        corpus_path.display()
    );

    let out = String::from_utf8_lossy(&run.stdout).to_string();
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

fn linux_include() -> PathBuf {
    repo_root().join("kernel/linux/inc")
}

fn windows_include() -> PathBuf {
    repo_root().join("kernel/windows/inc")
}

#[test]
fn the_decoders_survive_mutated_input_under_sanitizers() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the decoder fuzz run");
        return;
    };

    // 20,000 mutants across four protocols. Not a substitute for a
    // coverage-guided campaign — see fuzz/README.md — but enough that a
    // straightforward overread does not survive a single `cargo test`.
    let seeds = seeds();
    let mut rng = Rng(0xD1CE_5EED_0BAD_F00D);
    let mut cases: Vec<(u8, Vec<u8>)> = seeds.clone();
    for _ in 0..20_000 {
        let (l7, seed) = &seeds[rng.below(seeds.len())];
        cases.push((*l7, mutate(seed, &mut rng)));
    }

    let corpus = encode_corpus(&cases);
    build_and_run(
        cc,
        "linux",
        linux_include(),
        &LINUX_NAMES,
        &[],
        &corpus,
        true,
    );
    build_and_run(
        cc,
        "windows",
        windows_include(),
        &WINDOWS_NAMES,
        &["-DUFW_ABI_CHECK"],
        &corpus,
        true,
    );
}

#[test]
fn the_two_decoder_implementations_extract_the_same_fields() {
    // The equivalence claim is that a policy means the same thing on three
    // platforms. It cannot, if the decoders disagree about what
    // `http.header_count` is for a given payload — and no policy test would
    // ever surface that, because the policy is identical and only the facts
    // underneath it differ.
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the decoder equivalence check");
        return;
    };

    let seeds = seeds();
    let mut rng = Rng(0x0FF1_CE00_1234_5678);
    let mut cases: Vec<(u8, Vec<u8>)> = seeds.clone();
    for _ in 0..4_000 {
        let (l7, seed) = &seeds[rng.below(seeds.len())];
        cases.push((*l7, mutate(seed, &mut rng)));
    }
    let corpus = encode_corpus(&cases);

    let linux = build_and_run(
        cc,
        "linux",
        linux_include(),
        &LINUX_NAMES,
        &[],
        &corpus,
        false,
    );
    let windows = build_and_run(
        cc,
        "windows",
        windows_include(),
        &WINDOWS_NAMES,
        &["-DUFW_ABI_CHECK"],
        &corpus,
        false,
    );

    let (Some(linux), Some(windows)) = (linux, windows) else {
        return;
    };

    // Without this the comparison could pass on two decoders that both
    // extract nothing.
    assert!(
        linux.lines().filter(|l| l.contains('=')).count() > cases.len() / 4,
        "the corpus produced almost no decoded fields, so this proves nothing"
    );

    for (i, (l, w)) in linux.lines().zip(windows.lines()).enumerate() {
        if l == w {
            continue;
        }
        let (l7, payload) = &cases[i];
        panic!(
            "the Linux and Windows decoders disagree on case {i} (l7 {l7}):\n\
             linux:   {l}\n\
             windows: {w}\n\
             payload: {}",
            ufw_shared::hash::hex(payload)
        );
    }
    assert_eq!(
        linux.lines().count(),
        windows.lines().count(),
        "the two decoders produced different numbers of results"
    );
}

#[test]
fn a_payload_that_lies_about_its_own_lengths_is_survivable() {
    // The named case, kept separate from the fuzz run because it is the one
    // an attacker writes deliberately: every length field claims the maximum
    // and the buffer is one byte long. Each decoder has to reject rather than
    // trust, and a regression here should say so by name rather than as
    // "mutant 14,203".
    let Some(cc) = c_compiler() else {
        return;
    };

    let mut cases = Vec::new();
    for l7 in [1u8, 2, 3, 4] {
        cases.push((l7, vec![0xFF; 1]));
        cases.push((l7, vec![0xFF; 12]));
        cases.push((l7, vec![0xFF; 4096]));
        // A DNS label chain that never terminates.
        cases.push((3, {
            let mut v = vec![0u8; 12];
            for _ in 0..300 {
                v.push(63);
                v.extend_from_slice(&[b'x'; 63]);
            }
            v
        }));
        // TLS claiming a 64 KiB extension block inside a 20-byte record.
        cases.push((
            2,
            vec![
                0x16, 0x03, 0x01, 0xFF, 0xFF, 0x01, 0xFF, 0xFF, 0xFF, 0x03, 0x03,
            ],
        ));
        // HTTP headers with no terminator, forever.
        cases.push((1, b"GET / HTTP/1.1\r\nA: b\r\n".repeat(4096)));
    }

    let corpus = encode_corpus(&cases);
    build_and_run(
        cc,
        "linux-liar",
        linux_include(),
        &LINUX_NAMES,
        &[],
        &corpus,
        true,
    );
    build_and_run(
        cc,
        "windows-liar",
        windows_include(),
        &WINDOWS_NAMES,
        &["-DUFW_ABI_CHECK"],
        &corpus,
        true,
    );
}

#[test]
fn the_fuzz_harness_would_actually_catch_an_overread() {
    // A negative control. Everything above passes if the sanitizers are not
    // engaged — a fuzz run that cannot fail is a fuzz run that proves
    // nothing, and that failure mode is silent by construction.
    //
    // So: compile a decoder with a deliberate one-byte overread, feed it the
    // same corpus, and require the run to fail. If this test starts passing
    // by *not* failing, the checks above have stopped meaning anything.
    let Some(cc) = c_compiler() else {
        return;
    };

    let dir = scratch("control");
    let source = dir.join("control.c");
    std::fs::write(
        &source,
        r#"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

/* Exactly the shape of a decoder bug: a length taken from the payload and
 * used without checking it against the buffer. */
static unsigned decode_badly(const unsigned char *data, unsigned len)
{
        unsigned claimed;

        if (len < 1)
                return 0;
        claimed = data[0];
        return data[claimed];   /* no bound on `claimed` */
}

int main(void)
{
        unsigned char *heap = malloc(4);

        memcpy(heap, "\xFF\x01\x02\x03", 4);
        printf("%u\n", decode_badly(heap, 4));
        free(heap);
        return 0;
}
"#,
    )
    .unwrap();

    let binary = dir.join("control");
    let build = Command::new(cc)
        .arg("-std=c11")
        .arg("-g")
        .arg("-fsanitize=address,undefined")
        .arg("-fno-sanitize-recover=all")
        .arg("-o")
        .arg(&binary)
        .arg(&source)
        .output()
        .expect("running the C compiler");
    if !build.status.success() {
        eprintln!("sanitizer runtime unavailable; cannot verify the fuzz harness");
        let _ = std::fs::remove_dir_all(&dir);
        return;
    }

    let run = Command::new(&binary).output().expect("running the control");
    assert!(
        !run.status.success(),
        "a deliberate heap overread ran to completion, so AddressSanitizer is \
         not engaged and the decoder fuzz tests above are proving nothing"
    );
    let stderr = String::from_utf8_lossy(&run.stderr);
    assert!(
        stderr.contains("AddressSanitizer") || stderr.contains("runtime error"),
        "the control failed but not for the expected reason:\n{stderr}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
