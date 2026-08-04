//! The kernels' table walk must agree with the one that built the table.
//!
//! `daemon/src/automaton.rs` constructs an Aho-Corasick automaton and ships
//! it; `kernel/linux/inc/dpi_automaton.h` and
//! `kernel/windows/inc/dpi_automaton.h` decode and walk it. Nothing else
//! checks that the three agree. The Rust side has unit tests, and the C sides
//! compile — right up until someone builds a kernel module, on a machine with
//! kernel headers, which CI for a Rust workspace has not got.
//!
//! So this test does the one thing that catches a divergence: compiles both
//! headers with a hosted compiler, runs them over the same table and the same
//! corpus as the Rust reference, and compares verdict for verdict.
//!
//! Both headers are deliberately free of every kernel API — no allocation, no
//! locking, no WDK or `linux/` call — which is what makes that possible. If a
//! future edit adds one, this test stops compiling, and that is the intended
//! signal rather than an inconvenience.
//!
//! Without a C compiler the test reports that and passes, rather than failing
//! a Rust developer's machine for lacking a toolchain they do not otherwise
//! need.

use std::path::{Path, PathBuf};
use std::process::Command;

use ufw_daemon::automaton::{self, Automaton, Pattern};

/// The window grid every pattern is tested over. Small offsets and depths,
/// because the interesting cases — a window that starts after the first hit,
/// a window too short for the pattern, `depth == 0` meaning "to the end" —
/// all live in the first handful of bytes.
const OFFSETS: [u32; 7] = [0, 1, 2, 3, 4, 5, 6];
const DEPTHS: [u32; 7] = [0, 1, 2, 3, 5, 8, 40];

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
        "ufw-ac-{}-{}-{name}",
        std::process::id(),
        ufw_shared::now_us()
    ));
    std::fs::create_dir_all(&dir).expect("scratch directory");
    dir
}

fn pat(s: &str) -> Pattern {
    Pattern { bytes: s.as_bytes().to_vec(), nocase: false }
}

fn ipat(s: &str) -> Pattern {
    Pattern { bytes: s.as_bytes().to_vec(), nocase: true }
}

/// Patterns chosen for the ways an Aho-Corasick implementation goes wrong:
/// one pattern a suffix of another, one a prefix of another, a repeated
/// single byte, and a case-folded pattern whose bytes collide with a
/// case-sensitive one.
fn corpus_patterns() -> Vec<Pattern> {
    vec![
        pat("he"),
        pat("she"),
        pat("his"),
        pat("hers"),
        pat("a"),
        pat("aa"),
        ipat("POST"),
        pat("POST"),
        pat("\x16\x03\x01"),
    ]
}

/// Buffers chosen for the same reasons, plus the boundaries: empty, one byte,
/// a match at offset zero, a match at the very end, and a buffer where a
/// pattern repeats so the "more than one occurrence" arm is exercised.
fn corpus_buffers() -> Vec<Vec<u8>> {
    let mut out: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"a".to_vec(),
        b"ushers".to_vec(),
        b"she".to_vec(),
        b"aaaa".to_vec(),
        b"hishers".to_vec(),
        b"POST /admin".to_vec(),
        b"post /admin".to_vec(),
        b"PoSt /admin".to_vec(),
        b"----he----he".to_vec(),
        b"zzzzzzzz".to_vec(),
        b"hehehehe".to_vec(),
        vec![0x16, 0x03, 0x01, 0x00, 0x01],
        vec![0x00, 0x16, 0x03, 0x01],
    ];
    // A long buffer, so the traversal is exercised past anything a hand-run
    // trace would cover.
    let mut long = Vec::new();
    for i in 0..600u32 {
        long.push(b"ash"[(i % 3) as usize]);
    }
    out.push(long);
    out
}

/// `u32 count`, then `u32 len` + bytes per buffer.
fn encode_buffers(buffers: &[Vec<u8>]) -> Vec<u8> {
    let mut out = Vec::new();
    out.extend_from_slice(&(buffers.len() as u32).to_le_bytes());
    for b in buffers {
        out.extend_from_slice(&(b.len() as u32).to_le_bytes());
        out.extend_from_slice(b);
    }
    out
}

/// What the C harness prints: one line per buffer, one character per
/// (pattern, offset, depth) in that order.
fn reference_output(automaton: &Automaton, buffers: &[Vec<u8>]) -> String {
    let mut out = String::new();
    for data in buffers {
        let table = automaton.scan(data);
        for (id, pattern) in automaton.patterns().iter().enumerate() {
            for offset in OFFSETS {
                for depth in DEPTHS {
                    let verdict = automaton::content_matches(
                        &pattern.bytes,
                        pattern.nocase,
                        offset,
                        depth,
                        table.hit(id as u32),
                        data,
                    );
                    out.push(if verdict { '1' } else { '0' });
                }
            }
        }
        out.push('\n');
    }
    out
}

/// The C harness, in the flavour of whichever header it includes.
///
/// It also checks the C's *own* two paths against each other on every cell —
/// `ufw_ac_content_matches` against `ufw_ac_naive_contains` — and exits 80 if
/// they ever disagree. That is a stronger check than the Rust comparison
/// alone: it fails on the input that broke it rather than on a mismatched
/// output string.
fn harness_source(platform: Platform) -> String {
    let (include, prefix) = match platform {
        Platform::Linux => ("dpi_automaton.h", Names::linux()),
        Platform::Windows => ("dpi_automaton.h", Names::windows()),
    };
    format!(
        r#"
#include <stdio.h>
#include <stdlib.h>
#include "{include}"

static unsigned char table_buf[1 << 20];
static unsigned char data_buf[1 << 16];
static {pattern_t} patterns[UFW_AC_MAX_PATTERNS];
static {state_t} states[UFW_AC_MAX_STATES];
static {transition_t} transitions[UFW_AC_MAX_STATES];
static unsigned short outputs[UFW_AC_MAX_OUTPUTS];
static {hit_t} hits[UFW_AC_MAX_PATTERNS];

static const unsigned OFFSETS[] = {{ 0, 1, 2, 3, 4, 5, 6 }};
static const unsigned DEPTHS[] = {{ 0, 1, 2, 3, 5, 8, 40 }};

static unsigned read_u32(const unsigned char *p)
{{
        return (unsigned)p[0] | ((unsigned)p[1] << 8) |
               ((unsigned)p[2] << 16) | ((unsigned)p[3] << 24);
}}

int main(int argc, char **argv)
{{
        FILE *f;
        size_t table_len, corpus_len;
        static unsigned char corpus[1 << 20];
        {ac_t} ac;
        {cursor_t} cur;
        {sizes_t} sizes;
        unsigned buffers, b, p, oi, di, pos;

        if (argc != 3)
                return 64;

        f = fopen(argv[1], "rb");
        if (!f)
                return 65;
        table_len = fread(table_buf, 1, sizeof(table_buf), f);
        fclose(f);

        cur.data = table_buf;
        cur.{cursor_len} = table_len;
        cur.{cursor_pos} = 0;
        if (!{sizes_of}(&cur, &sizes))
                return 66;
        if (sizes.patterns > UFW_AC_MAX_PATTERNS ||
            sizes.states > UFW_AC_MAX_STATES ||
            sizes.transitions > UFW_AC_MAX_STATES ||
            sizes.outputs > UFW_AC_MAX_OUTPUTS)
                return 67;
        ac.patterns = patterns;
        ac.states = states;
        ac.transitions = transitions;
        ac.outputs = outputs;
        if (!{load}(&cur, &ac))
                return 68;

        f = fopen(argv[2], "rb");
        if (!f)
                return 69;
        corpus_len = fread(corpus, 1, sizeof(corpus), f);
        fclose(f);
        if (corpus_len < 4)
                return 70;

        buffers = read_u32(corpus);
        pos = 4;
        for (b = 0; b < buffers; b++) {{
                unsigned len;

                if (pos + 4 > corpus_len)
                        return 71;
                len = read_u32(corpus + pos);
                pos += 4;
                if (pos + len > corpus_len || len > sizeof(data_buf))
                        return 72;
                if (len)
                        memcpy(data_buf, corpus + pos, len);
                pos += len;

                {scan}(&ac, data_buf, len, hits);

                for (p = 0; p < ac.{pattern_count}; p++) {{
                        for (oi = 0; oi < 7; oi++) {{
                                for (di = 0; di < 7; di++) {{
                                        int fast = {content_matches}(
                                                patterns[p].bytes,
                                                patterns[p].len,
                                                patterns[p].nocase,
                                                OFFSETS[oi], DEPTHS[di],
                                                hits[p], data_buf, len) ? 1 : 0;
                                        int slow = {naive}(
                                                patterns[p].bytes,
                                                patterns[p].len,
                                                patterns[p].nocase,
                                                data_buf, len,
                                                OFFSETS[oi], DEPTHS[di]) ? 1 : 0;

                                        /* The table walk and the search it
                                         * replaces must decide identically.
                                         * Failing here names the cell. */
                                        if (fast != slow) {{
                                                fprintf(stderr,
                                                        "buffer %u pattern %u "
                                                        "offset %u depth %u: "
                                                        "table=%d naive=%d\n",
                                                        b, p, OFFSETS[oi],
                                                        DEPTHS[di], fast, slow);
                                                return 80;
                                        }}
                                        putchar(fast ? '1' : '0');
                                }}
                        }}
                }}
                putchar('\n');
        }}
        return 0;
}}
"#,
        include = include,
        pattern_t = prefix.pattern_t,
        state_t = prefix.state_t,
        transition_t = prefix.transition_t,
        hit_t = prefix.hit_t,
        ac_t = prefix.ac_t,
        cursor_t = prefix.cursor_t,
        sizes_t = prefix.sizes_t,
        cursor_len = prefix.cursor_len,
        cursor_pos = prefix.cursor_pos,
        sizes_of = prefix.sizes_of,
        load = prefix.load,
        scan = prefix.scan,
        content_matches = prefix.content_matches,
        naive = prefix.naive,
        pattern_count = prefix.pattern_count,
    )
}

#[derive(Clone, Copy)]
enum Platform {
    Linux,
    Windows,
}

/// The two headers declare the same shapes under each tree's own naming
/// convention. Spelling the difference out here, rather than macro-ing it
/// away in the headers, is deliberate: each header should read like the code
/// around it.
struct Names {
    pattern_t: &'static str,
    state_t: &'static str,
    transition_t: &'static str,
    hit_t: &'static str,
    ac_t: &'static str,
    cursor_t: &'static str,
    sizes_t: &'static str,
    cursor_len: &'static str,
    cursor_pos: &'static str,
    sizes_of: &'static str,
    load: &'static str,
    scan: &'static str,
    content_matches: &'static str,
    naive: &'static str,
    pattern_count: &'static str,
}

impl Names {
    fn linux() -> Self {
        Names {
            pattern_t: "struct ufw_ac_pattern",
            state_t: "struct ufw_ac_state",
            transition_t: "struct ufw_ac_transition",
            hit_t: "struct ufw_ac_hit",
            ac_t: "struct ufw_ac",
            cursor_t: "struct ufw_ac_cursor",
            sizes_t: "struct ufw_ac_sizes",
            cursor_len: "len",
            cursor_pos: "pos",
            sizes_of: "ufw_ac_sizes_of",
            load: "ufw_ac_load",
            scan: "ufw_ac_scan",
            content_matches: "ufw_ac_content_matches",
            naive: "ufw_ac_naive_contains",
            pattern_count: "pattern_count",
        }
    }

    fn windows() -> Self {
        Names {
            pattern_t: "UFW_AC_PATTERN",
            state_t: "UFW_AC_STATE",
            transition_t: "UFW_AC_TRANSITION",
            hit_t: "UFW_AC_HIT",
            ac_t: "UFW_AC",
            cursor_t: "UFW_AC_CURSOR",
            sizes_t: "UFW_AC_SIZES",
            cursor_len: "length",
            cursor_pos: "position",
            sizes_of: "UfwAcSizesOf",
            load: "UfwAcLoad",
            scan: "UfwAcScan",
            content_matches: "UfwAcContentMatches",
            naive: "UfwAcNaiveContains",
            pattern_count: "patternCount",
        }
    }
}

/// Compile the harness against one platform's header and run it over the
/// corpus, returning what it printed.
fn run_platform(cc: &str, platform: Platform, table: &[u8], corpus: &[u8]) -> Option<String> {
    let (inc, label, extra) = match platform {
        Platform::Linux => (repo_root().join("kernel/linux/inc"), "linux", Vec::new()),
        Platform::Windows => (
            repo_root().join("kernel/windows/inc"),
            "windows",
            vec!["-DUFW_ABI_CHECK".to_string()],
        ),
    };
    if !inc.join("dpi_automaton.h").exists() {
        eprintln!("{}/dpi_automaton.h not present; skipping", inc.display());
        return None;
    }

    let dir = scratch(label);
    let source = dir.join("ac_check.c");
    std::fs::write(&source, harness_source(platform)).expect("harness source");
    let table_path = dir.join("table.bin");
    let corpus_path = dir.join("corpus.bin");
    std::fs::write(&table_path, table).expect("table");
    std::fs::write(&corpus_path, corpus).expect("corpus");

    let binary = dir.join("ac_check");
    let mut command = Command::new(cc);
    command
        .arg("-std=c11")
        .arg("-Wall")
        .arg("-Wextra")
        .arg("-Werror")
        .args(&extra)
        .arg("-I")
        .arg(&inc)
        .arg("-o")
        .arg(&binary)
        .arg(&source);
    let build = command.output().expect("running the C compiler");
    assert!(
        build.status.success(),
        "{label}/dpi_automaton.h does not compile hosted:\n{}",
        String::from_utf8_lossy(&build.stderr)
    );

    let run = Command::new(&binary)
        .arg(&table_path)
        .arg(&corpus_path)
        .output()
        .expect("running the automaton check");
    assert!(
        run.status.success(),
        "the {label} table walk failed (exit {:?}). 80 means its own two paths \
         disagreed; see the harness source for the rest.\n{}",
        run.status.code(),
        String::from_utf8_lossy(&run.stderr)
    );

    let out = String::from_utf8(run.stdout).expect("ASCII output");
    let _ = std::fs::remove_dir_all(&dir);
    Some(out)
}

/// Report the first differing cell rather than a diff of two 4000-character
/// strings, because the useful output of a divergence is the input.
fn compare(label: &str, reference: &str, actual: &str, automaton: &Automaton) {
    if reference == actual {
        return;
    }
    let patterns = automaton.patterns();
    let per_pattern = OFFSETS.len() * DEPTHS.len();
    for (buffer, (want, got)) in reference.lines().zip(actual.lines()).enumerate() {
        let Some(column) = want
            .chars()
            .zip(got.chars())
            .position(|(a, b)| a != b)
            .or_else(|| (want.len() != got.len()).then_some(want.len().min(got.len())))
        else {
            continue;
        };
        let pattern = column / per_pattern;
        let within = column % per_pattern;
        let offset = OFFSETS[within / DEPTHS.len()];
        let depth = DEPTHS[within % DEPTHS.len()];
        panic!(
            "{label} disagrees with the reference on buffer {buffer}, pattern {pattern} \
             ({:?}), offset {offset}, depth {depth}: reference says {}, {label} says {}",
            patterns.get(pattern),
            want.chars().nth(column).unwrap_or('?'),
            got.chars().nth(column).unwrap_or('?'),
        );
    }
    panic!("{label} produced a different number of lines than the reference");
}

#[test]
fn the_kernel_table_walks_agree_with_the_builder() {
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the automaton equivalence check");
        return;
    };

    let patterns = corpus_patterns();
    let automaton = Automaton::build(&patterns).expect("the corpus builds");
    let mut writer = ufw_shared::protocol::Writer::new();
    automaton.encode(&mut writer);
    let table = writer.finish();

    let buffers = corpus_buffers();
    let corpus = encode_buffers(&buffers);
    let reference = reference_output(&automaton, &buffers);

    // Without this the comparison below could pass on two implementations
    // that both find nothing.
    assert!(
        reference.contains('1'),
        "the corpus produced no matches at all, so it proves nothing"
    );

    if let Some(actual) = run_platform(cc, Platform::Linux, &table, &corpus) {
        compare("linux", &reference, &actual, &automaton);
    }
    if let Some(actual) = run_platform(cc, Platform::Windows, &table, &corpus) {
        compare("windows", &reference, &actual, &automaton);
    }
}

#[test]
fn the_two_headers_decode_the_same_table_identically() {
    // Not implied by the test above: both could agree with the reference on
    // this corpus while decoding a different table. Comparing them to each
    // other catches a divergence in the decoder that the corpus happens not
    // to reach.
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the cross-header check");
        return;
    };

    let patterns = corpus_patterns();
    let automaton = Automaton::build(&patterns).expect("built");
    let mut writer = ufw_shared::protocol::Writer::new();
    automaton.encode(&mut writer);
    let table = writer.finish();
    let corpus = encode_buffers(&corpus_buffers());

    let linux = run_platform(cc, Platform::Linux, &table, &corpus);
    let windows = run_platform(cc, Platform::Windows, &table, &corpus);
    if let (Some(l), Some(w)) = (linux, windows) {
        assert_eq!(l, w, "the two kernel headers walked the same table differently");
    }
}

#[test]
fn a_truncated_table_is_refused_rather_than_walked() {
    // The table arrives from the daemon over netlink or IOCTL. The daemon is
    // trusted to be the daemon and not trusted to be correct, so a short read
    // must fail the decode rather than index past the buffer.
    let Some(cc) = c_compiler() else {
        eprintln!("no C compiler found; skipping the truncation check");
        return;
    };

    let automaton = Automaton::build(&corpus_patterns()).expect("built");
    let mut writer = ufw_shared::protocol::Writer::new();
    automaton.encode(&mut writer);
    let table = writer.finish();
    let corpus = encode_buffers(&[b"ushers".to_vec()]);

    for cut in [1usize, 4, 16, table.len() / 2, table.len() - 1] {
        let truncated = &table[..cut];
        for platform in [Platform::Linux, Platform::Windows] {
            let (inc, extra) = match platform {
                Platform::Linux => (repo_root().join("kernel/linux/inc"), Vec::new()),
                Platform::Windows => (
                    repo_root().join("kernel/windows/inc"),
                    vec!["-DUFW_ABI_CHECK".to_string()],
                ),
            };
            if !inc.join("dpi_automaton.h").exists() {
                continue;
            }
            let dir = scratch("truncated");
            let source = dir.join("ac_check.c");
            std::fs::write(&source, harness_source(platform)).unwrap();
            std::fs::write(dir.join("table.bin"), truncated).unwrap();
            std::fs::write(dir.join("corpus.bin"), &corpus).unwrap();
            let binary = dir.join("ac_check");
            let build = Command::new(cc)
                .arg("-std=c11")
                .arg("-Wall")
                .arg("-Wextra")
                .arg("-Werror")
                .args(&extra)
                .arg("-I")
                .arg(&inc)
                .arg("-o")
                .arg(&binary)
                .arg(&source)
                .output()
                .expect("running the C compiler");
            assert!(build.status.success(), "{}", String::from_utf8_lossy(&build.stderr));

            let run = Command::new(&binary)
                .arg(dir.join("table.bin"))
                .arg(dir.join("corpus.bin"))
                .output()
                .expect("running the truncation check");
            // 66 and 68 are "the size pass refused it" and "the load pass
            // refused it". Either is correct; walking it is not.
            assert!(
                matches!(run.status.code(), Some(66) | Some(68)),
                "a table cut to {cut} bytes was not refused (exit {:?})",
                run.status.code()
            );
            let _ = std::fs::remove_dir_all(&dir);
        }
    }
}
