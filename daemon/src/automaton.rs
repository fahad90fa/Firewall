//! Multi-pattern search: build the automaton once, ship the table.
//!
//! Every `content:` condition across the whole signature set names a byte
//! pattern. Scanning a reassembled stream once per signature costs
//! `signatures × window`; scanning it once for *all* of them costs `window`.
//! This module is the "once" half.
//!
//! # Why the table is built here and not in the kernel
//!
//! Aho-Corasick is not a hard algorithm, and that is exactly the problem. It
//! is easy enough that writing it three times — twice in C, once in Swift —
//! looks reasonable, and just subtle enough (failure links, output-set
//! merging, the root self-loop) that the three would not agree. This project
//! exists to make "the three platforms behave identically" a checked property
//! rather than an intention, so the construction happens once, in one
//! language, and the kernels receive a finished table.
//!
//! What each kernel then runs is a loop with no construction in it at all:
//! follow a transition, fall back along a failure link if there is none,
//! record whatever the state outputs. That is small enough to read side by
//! side across three files and see that it is the same loop.
//!
//! # What a scan produces
//!
//! Not "which conditions matched" — the automaton does not know about
//! conditions, only patterns. It produces, per pattern, the offset of the
//! *first* occurrence in the scanned buffer and whether there was more than
//! one. [`content_matches`] turns that into a condition verdict:
//!
//!   - no occurrence anywhere ⇒ no occurrence in any sub-window. Decided.
//!   - the first occurrence lies inside the condition's window. Decided.
//!   - exactly one occurrence and it lies outside the window. Decided.
//!   - otherwise fall back to the bounded naive search for that one pattern.
//!
//! The fallback is what keeps this *exactly* equivalent to the per-signature
//! search it replaces rather than approximately equivalent. It is reached
//! only by a pattern that occurs repeatedly in one stream *and* is scoped to
//! a window that excludes the first hit, which is rare in real signatures and
//! bounded when it happens.
//!
//! # Limits
//!
//! A signature set that exceeds [`MAX_PATTERNS`], [`MAX_STATES`] or
//! [`MAX_OUTPUTS`] gets no automaton at all, and every kernel falls back to
//! the per-signature search. That is a performance cliff, never a behavioural
//! one — which is the right way round, because the alternative is a table
//! that silently stops covering some patterns.

use std::collections::{BTreeMap, VecDeque};

use ufw_shared::protocol::Writer;

/// Distinct byte patterns the automaton can carry.
///
/// The bound exists because the per-scan result table is one entry per
/// pattern and is preallocated in each kernel — see the scratch buffers in
/// `kernel/linux/src/dpi_engine.c` and its Windows counterpart. 512 entries
/// is 4 KiB there, which is a per-CPU allocation rather than a stack frame.
pub const MAX_PATTERNS: usize = 512;

/// Trie nodes across both automatons.
///
/// 16384 states is 16 KiB of pattern text — 256 patterns at the 64-byte
/// maximum, or a couple of thousand realistic ones. The kernel-side table is
/// about 256 KiB at that ceiling.
pub const MAX_STATES: usize = 16_384;

/// Total entries in all output lists after failure-link merging.
///
/// Merging is what makes a pattern that is a suffix of another still report,
/// and it is also the step that can multiply: N patterns where each is a
/// suffix of the next produces N²/2 output entries. Bounding it bounds the
/// shipped table.
pub const MAX_OUTPUTS: usize = 8_192;

/// A content condition whose pattern has no automaton entry.
pub const NO_PATTERN: u32 = u32::MAX;

/// ASCII case folding, and only ASCII.
///
/// The naive matcher this replaces folds `A..Z` and nothing else, so this
/// folds `A..Z` and nothing else. Doing something more correct here — UTF-8
/// case folding, a locale table — would be a divergence dressed as an
/// improvement: the two paths have to agree, and the one that runs in three
/// kernels is the one that cannot grow a Unicode table.
#[inline]
pub fn fold_byte(b: u8) -> u8 {
    if b.is_ascii_uppercase() {
        b + 32
    } else {
        b
    }
}

/// One searchable pattern. Identity is `(bytes, nocase)`: two conditions
/// naming the same bytes with the same case sensitivity share an id, which is
/// why a signature set with fifty rules over the same handful of strings pays
/// for the strings once.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pattern {
    pub bytes: Vec<u8>,
    pub nocase: bool,
}

/// What one pattern did in one scan.
///
/// `count` saturates at 2 because that is all any decision below needs: zero
/// occurrences, one occurrence at a known offset, or "more than one, ask the
/// slow path". Storing every offset would make the table unbounded in
/// attacker-chosen input, which is the thing this whole subsystem avoids.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct PatternHit {
    pub first_start: u32,
    pub count: u8,
}

impl PatternHit {
    pub fn is_absent(self) -> bool {
        self.count == 0
    }
}

/// Per-pattern results from one pass over one buffer.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MatchTable {
    hits: Vec<PatternHit>,
}

impl MatchTable {
    pub fn hit(&self, pattern_id: u32) -> PatternHit {
        self.hits
            .get(pattern_id as usize)
            .copied()
            .unwrap_or_default()
    }

    pub fn len(&self) -> usize {
        self.hits.len()
    }

    pub fn is_empty(&self) -> bool {
        self.hits.is_empty()
    }

    fn record(&mut self, pattern_id: usize, start: u32) {
        let Some(hit) = self.hits.get_mut(pattern_id) else {
            return;
        };
        // Matches arrive in increasing end offset, and a pattern has a fixed
        // length, so they also arrive in increasing start offset. The first
        // one recorded is therefore the earliest, which is what the window
        // test below relies on.
        if hit.count == 0 {
            hit.first_start = start;
            hit.count = 1;
        } else if hit.count == 1 {
            hit.count = 2;
        }
    }
}

/// One flattened trie: sparse transitions, failure links, merged outputs.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Trie {
    /// Whether input bytes are ASCII-folded before traversal. The patterns in
    /// a folded trie are stored folded too, so `nocase` costs one `or` per
    /// byte rather than a second comparison per pattern.
    fold: bool,
    fail: Vec<u32>,
    trans_start: Vec<u32>,
    trans_count: Vec<u16>,
    out_start: Vec<u32>,
    out_count: Vec<u16>,
    /// `(byte, next_state)`, sorted by byte within each state's slice so the
    /// kernels can binary-search rather than scan a root with 256 children on
    /// every input byte.
    transitions: Vec<(u8, u32)>,
    outputs: Vec<u16>,
}

impl Trie {
    fn states(&self) -> usize {
        self.fail.len()
    }

    fn transition(&self, state: u32, byte: u8) -> Option<u32> {
        let start = self.trans_start[state as usize] as usize;
        let count = self.trans_count[state as usize] as usize;
        let slice = &self.transitions[start..start + count];
        slice
            .binary_search_by_key(&byte, |&(b, _)| b)
            .ok()
            .map(|i| slice[i].1)
    }

    /// The one place a failure link is followed. Amortised O(1) per input
    /// byte: each fallback strictly decreases depth, and depth rises by at
    /// most one per byte.
    fn step(&self, mut state: u32, byte: u8) -> u32 {
        loop {
            if let Some(next) = self.transition(state, byte) {
                return next;
            }
            if state == 0 {
                return 0;
            }
            state = self.fail[state as usize];
        }
    }
}

/// The shipped table: the patterns, and one trie per case-sensitivity.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Automaton {
    patterns: Vec<Pattern>,
    /// At most two — case-sensitive and case-folded. Both are traversed in
    /// the same loop over the same bytes, so "two automatons" is still one
    /// pass over the data.
    tries: Vec<Trie>,
}

impl Automaton {
    /// Build over `patterns`, which must already be deduplicated: index in
    /// this slice *is* the pattern id, and the kernels index the result table
    /// by it.
    ///
    /// Returns `None` when the set exceeds the shipped limits. The caller
    /// ships no automaton in that case and every kernel falls back to the
    /// per-signature search, which is slower and identical.
    pub fn build(patterns: &[Pattern]) -> Option<Self> {
        if patterns.is_empty() || patterns.len() > MAX_PATTERNS {
            return None;
        }
        if patterns.iter().any(|p| p.bytes.is_empty()) {
            // An empty pattern matches at every offset, which would make the
            // output list as long as the input. The signature loader already
            // rejects one; refusing here too means a future caller cannot
            // reintroduce it through this door.
            return None;
        }

        let mut budget = MAX_STATES;
        let mut tries = Vec::new();
        for fold in [false, true] {
            let members: Vec<(u16, &Pattern)> = patterns
                .iter()
                .enumerate()
                .filter(|(_, p)| p.nocase == fold)
                .map(|(i, p)| (i as u16, p))
                .collect();
            if members.is_empty() {
                continue;
            }
            let trie = build_trie(fold, &members, &mut budget)?;
            tries.push(trie);
        }

        let outputs: usize = tries.iter().map(|t| t.outputs.len()).sum();
        if outputs > MAX_OUTPUTS {
            return None;
        }

        Some(Automaton { patterns: patterns.to_vec(), tries })
    }

    pub fn patterns(&self) -> &[Pattern] {
        &self.patterns
    }

    pub fn state_count(&self) -> usize {
        self.tries.iter().map(Trie::states).sum()
    }

    pub fn output_count(&self) -> usize {
        self.tries.iter().map(|t| t.outputs.len()).sum()
    }

    /// One pass over `data`, both tries advancing together.
    pub fn scan(&self, data: &[u8]) -> MatchTable {
        let mut table = MatchTable { hits: vec![PatternHit::default(); self.patterns.len()] };
        if data.is_empty() {
            return table;
        }
        for trie in &self.tries {
            let mut state = 0u32;
            for (i, &raw) in data.iter().enumerate() {
                let byte = if trie.fold { fold_byte(raw) } else { raw };
                state = trie.step(state, byte);
                let count = trie.out_count[state as usize] as usize;
                if count == 0 {
                    continue;
                }
                let start = trie.out_start[state as usize] as usize;
                for &pid in &trie.outputs[start..start + count] {
                    let plen = self.patterns[pid as usize].bytes.len();
                    // `i` is the index of the last byte of the match.
                    table.record(pid as usize, (i + 1 - plen) as u32);
                }
            }
        }
        table
    }

    /// Wire encoding, appended to the signature payload.
    ///
    /// Little-endian throughout, like every other structure on this wire, and
    /// laid out so a kernel decoder can size its allocation from the counts
    /// before reading any of the arrays.
    pub fn encode(&self, w: &mut Writer) {
        w.u32(self.patterns.len() as u32);
        for p in &self.patterns {
            w.u8(u8::from(p.nocase));
            w.u32(p.bytes.len() as u32);
            w.raw(&p.bytes);
        }
        w.u8(self.tries.len() as u8);
        for trie in &self.tries {
            w.u8(u8::from(trie.fold));
            w.u32(trie.states() as u32);
            w.u32(trie.transitions.len() as u32);
            w.u32(trie.outputs.len() as u32);
            for s in 0..trie.states() {
                w.u32(trie.fail[s]);
                w.u32(trie.trans_start[s]);
                w.u16(trie.trans_count[s]);
                w.u32(trie.out_start[s]);
                w.u16(trie.out_count[s]);
            }
            for &(byte, next) in &trie.transitions {
                w.u8(byte);
                w.u32(next);
            }
            for &pid in &trie.outputs {
                w.u16(pid);
            }
        }
    }
}

/// Node under construction. Dropped once the trie is flattened, because a
/// `BTreeMap` per state is the wrong shape to ship and the wrong shape to
/// traverse.
#[derive(Default, Clone)]
struct BuildNode {
    next: BTreeMap<u8, u32>,
    fail: u32,
    out: Vec<u16>,
}

fn build_trie(fold: bool, members: &[(u16, &Pattern)], budget: &mut usize) -> Option<Trie> {
    let mut nodes: Vec<BuildNode> = vec![BuildNode::default()];
    if *budget == 0 {
        return None;
    }
    *budget -= 1;

    for &(id, pattern) in members {
        let mut cur = 0usize;
        for &raw in &pattern.bytes {
            let byte = if fold { fold_byte(raw) } else { raw };
            cur = match nodes[cur].next.get(&byte) {
                Some(&next) => next as usize,
                None => {
                    if *budget == 0 {
                        return None;
                    }
                    *budget -= 1;
                    nodes.push(BuildNode::default());
                    let next = nodes.len() - 1;
                    nodes[cur].next.insert(byte, next as u32);
                    next
                }
            };
        }
        // A duplicate id here would mean the caller passed the same pattern
        // twice; dedup is the caller's job and the encoding depends on it.
        if !nodes[cur].out.contains(&id) {
            nodes[cur].out.push(id);
        }
    }

    // Failure links, breadth-first. Depth-1 nodes fail to the root; every
    // deeper node fails to the longest proper suffix that is also a prefix of
    // some pattern.
    let mut queue: VecDeque<u32> = VecDeque::new();
    let root_children: Vec<u32> = nodes[0].next.values().copied().collect();
    for child in root_children {
        nodes[child as usize].fail = 0;
        queue.push_back(child);
    }
    while let Some(state) = queue.pop_front() {
        let children: Vec<(u8, u32)> = nodes[state as usize]
            .next
            .iter()
            .map(|(&b, &n)| (b, n))
            .collect();
        for (byte, child) in children {
            let mut f = nodes[state as usize].fail;
            let target = loop {
                if let Some(&t) = nodes[f as usize].next.get(&byte) {
                    break t;
                }
                if f == 0 {
                    break 0;
                }
                f = nodes[f as usize].fail;
            };
            // `target` is always shallower than `child` — the fail chain
            // strictly decreases depth — so it can never be `child` itself,
            // which is what would turn traversal into an infinite loop.
            nodes[child as usize].fail = target;

            let inherited = nodes[target as usize].out.clone();
            for id in inherited {
                if !nodes[child as usize].out.contains(&id) {
                    nodes[child as usize].out.push(id);
                }
            }
            queue.push_back(child);
        }
    }

    let count = nodes.len();
    let mut trie = Trie {
        fold,
        fail: Vec::with_capacity(count),
        trans_start: Vec::with_capacity(count),
        trans_count: Vec::with_capacity(count),
        out_start: Vec::with_capacity(count),
        out_count: Vec::with_capacity(count),
        transitions: Vec::new(),
        outputs: Vec::new(),
    };
    for node in &nodes {
        trie.fail.push(node.fail);
        trie.trans_start.push(trie.transitions.len() as u32);
        trie.trans_count.push(node.next.len() as u16);
        // BTreeMap iterates in byte order, which is what makes the shipped
        // slice binary-searchable and the encoding byte-stable across builds.
        for (&byte, &next) in &node.next {
            trie.transitions.push((byte, next));
        }
        trie.out_start.push(trie.outputs.len() as u32);
        trie.out_count.push(node.out.len() as u16);
        trie.outputs.extend_from_slice(&node.out);
    }
    Some(trie)
}

/// The bounded search the automaton replaces, kept for the fallback path and
/// as the definition the automaton path is checked against.
///
/// Byte for byte the same window arithmetic as `content_match` in
/// `kernel/linux/src/dpi_engine.c`, including `depth == 0` meaning "to the
/// end of the buffer" rather than "an empty window".
pub fn naive_contains(pattern: &[u8], nocase: bool, data: &[u8], offset: u32, depth: u32) -> bool {
    let len = data.len() as u32;
    let plen = pattern.len() as u32;
    if plen == 0 || offset >= len {
        return false;
    }
    let mut end = if depth != 0 { offset.saturating_add(depth) } else { len };
    if end > len {
        end = len;
    }
    if end < offset + plen {
        return false;
    }
    let mut i = offset;
    while i + plen <= end {
        let mut j = 0u32;
        while j < plen {
            let mut a = data[(i + j) as usize];
            let mut b = pattern[j as usize];
            if nocase {
                a = fold_byte(a);
                b = fold_byte(b);
            }
            if a != b {
                break;
            }
            j += 1;
        }
        if j == plen {
            return true;
        }
        i += 1;
    }
    false
}

/// Decide one content condition from a scan result.
///
/// Exactly equivalent to [`naive_contains`] over the same arguments — that is
/// the property `the_two_paths_agree_on_random_input` checks, and the reason
/// the last arm exists.
pub fn content_matches(
    pattern: &[u8],
    nocase: bool,
    offset: u32,
    depth: u32,
    hit: PatternHit,
    data: &[u8],
) -> bool {
    if hit.is_absent() {
        // Not present anywhere in the buffer, so not present in any window
        // inside it. This is the arm that pays for the whole design: the
        // common case for a signature set is that almost nothing matches.
        return false;
    }
    let len = data.len() as u32;
    let plen = pattern.len() as u32;
    if plen == 0 || offset >= len {
        return false;
    }
    let mut end = if depth != 0 { offset.saturating_add(depth) } else { len };
    if end > len {
        end = len;
    }
    if end < offset + plen {
        return false;
    }
    if hit.first_start >= offset && hit.first_start + plen <= end {
        return true;
    }
    if hit.count == 1 {
        // The single occurrence is outside the window.
        return false;
    }
    naive_contains(pattern, nocase, data, offset, depth)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(s: &str) -> Pattern {
        Pattern { bytes: s.as_bytes().to_vec(), nocase: false }
    }

    fn ipat(s: &str) -> Pattern {
        Pattern { bytes: s.as_bytes().to_vec(), nocase: true }
    }

    #[test]
    fn one_pass_finds_every_pattern() {
        let patterns = vec![pat("he"), pat("she"), pat("his"), pat("hers")];
        let a = Automaton::build(&patterns).expect("built");
        let table = a.scan(b"ushers");
        // "she" at 1, "he" at 2, "hers" at 2. "his" never.
        assert_eq!(table.hit(0), PatternHit { first_start: 2, count: 1 });
        assert_eq!(table.hit(1), PatternHit { first_start: 1, count: 1 });
        assert_eq!(table.hit(2), PatternHit::default());
        assert_eq!(table.hit(3), PatternHit { first_start: 2, count: 1 });
    }

    #[test]
    fn a_pattern_that_is_a_suffix_of_another_still_reports() {
        // The classic way a hand-written Aho-Corasick goes wrong: forgetting
        // to merge output sets along failure links, so "he" inside "she" is
        // never reported.
        let patterns = vec![pat("she"), pat("he"), pat("e")];
        let a = Automaton::build(&patterns).expect("built");
        let table = a.scan(b"she");
        assert_eq!(table.hit(0).count, 1);
        assert_eq!(table.hit(1).count, 1, "`he` inside `she` was not reported");
        assert_eq!(table.hit(2).count, 1, "`e` inside `she` was not reported");
    }

    #[test]
    fn overlapping_occurrences_of_one_pattern_are_counted_but_not_listed() {
        let a = Automaton::build(&[pat("aa")]).expect("built");
        let table = a.scan(b"aaaa");
        assert_eq!(table.hit(0).first_start, 0);
        assert_eq!(table.hit(0).count, 2, "count saturates rather than growing");
    }

    #[test]
    fn case_folded_and_case_sensitive_patterns_do_not_leak_into_each_other() {
        let patterns = vec![pat("POST"), ipat("post")];
        let a = Automaton::build(&patterns).expect("built");

        let upper = a.scan(b"POST /");
        assert_eq!(upper.hit(0).count, 1, "the exact pattern matched");
        assert_eq!(upper.hit(1).count, 1, "the folded pattern matched too");

        let lower = a.scan(b"post /");
        assert_eq!(lower.hit(0).count, 0, "a case-sensitive pattern must not fold");
        assert_eq!(lower.hit(1).count, 1);
    }

    #[test]
    fn the_first_recorded_offset_is_the_earliest_one() {
        let a = Automaton::build(&[pat("x")]).expect("built");
        let table = a.scan(b"---x--x");
        assert_eq!(table.hit(0).first_start, 3);
        assert_eq!(table.hit(0).count, 2);
    }

    #[test]
    fn a_window_the_first_hit_misses_falls_back_rather_than_guessing() {
        let a = Automaton::build(&[pat("ab")]).expect("built");
        let data = b"ab....ab";
        let table = a.scan(data);
        assert_eq!(table.hit(0), PatternHit { first_start: 0, count: 2 });

        // The window excludes the first occurrence but contains the second.
        // Only the fallback can know that.
        assert!(content_matches(b"ab", false, 4, 4, table.hit(0), data));
        // And a window containing neither is still a non-match.
        assert!(!content_matches(b"ab", false, 2, 4, table.hit(0), data));
    }

    #[test]
    fn a_single_occurrence_outside_the_window_needs_no_fallback() {
        let a = Automaton::build(&[pat("ab")]).expect("built");
        let data = b"------ab";
        let table = a.scan(data);
        assert_eq!(table.hit(0).count, 1);
        assert!(!content_matches(b"ab", false, 0, 4, table.hit(0), data));
        assert!(content_matches(b"ab", false, 6, 2, table.hit(0), data));
    }

    #[test]
    fn depth_zero_means_to_the_end_in_both_paths() {
        // The kernel's `end = c->depth ? start + c->depth : len` is easy to
        // read as "an empty window". It is not, and both paths agree.
        let a = Automaton::build(&[pat("z")]).expect("built");
        let data = b"----z";
        let table = a.scan(data);
        assert!(content_matches(b"z", false, 0, 0, table.hit(0), data));
        assert!(naive_contains(b"z", false, data, 0, 0));
    }

    /// A deterministic scrambler. `Math.random` would make a failure here
    /// unreproducible, which for a differential test is the one thing that
    /// must not happen: the interesting output of this test is the input that
    /// broke it.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            // splitmix64
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    #[test]
    fn the_two_paths_agree_on_random_input() {
        // The whole justification for the automaton is that it decides the
        // same conditions the per-signature search decided. This is that
        // claim, over an alphabet small enough that overlaps, repeats and
        // suffix relationships happen constantly.
        let mut rng = Rng(0x5EED_1234_5678_9ABC);
        let alphabet = b"abAB";

        for round in 0..400u32 {
            let pattern_count = 1 + rng.below(6) as usize;
            let mut patterns: Vec<Pattern> = Vec::new();
            for _ in 0..pattern_count {
                let len = 1 + rng.below(4) as usize;
                let bytes: Vec<u8> = (0..len)
                    .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
                    .collect();
                let nocase = rng.below(2) == 1;
                let candidate = Pattern { bytes, nocase };
                if !patterns.contains(&candidate) {
                    patterns.push(candidate);
                }
            }

            let data_len = rng.below(40) as usize;
            let data: Vec<u8> = (0..data_len)
                .map(|_| alphabet[rng.below(alphabet.len() as u64) as usize])
                .collect();

            let automaton = Automaton::build(&patterns).expect("built");
            let table = automaton.scan(&data);

            for (id, pattern) in patterns.iter().enumerate() {
                for offset in 0..=6u32 {
                    for depth in [0u32, 1, 2, 3, 5, 8, 40] {
                        let fast = content_matches(
                            &pattern.bytes,
                            pattern.nocase,
                            offset,
                            depth,
                            table.hit(id as u32),
                            &data,
                        );
                        let slow =
                            naive_contains(&pattern.bytes, pattern.nocase, &data, offset, depth);
                        assert_eq!(
                            fast,
                            slow,
                            "round {round}: pattern {pattern:?} offset {offset} depth {depth} \
                             over {data:?}"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn an_oversized_set_declines_to_build_rather_than_truncating() {
        // Silently covering the first N patterns would be a firewall that
        // reports a clean scan for signatures it never looked at.
        let many: Vec<Pattern> = (0..MAX_PATTERNS + 1)
            .map(|i| Pattern { bytes: format!("p{i:04}").into_bytes(), nocase: false })
            .collect();
        assert!(Automaton::build(&many).is_none());

        // And a set whose trie exceeds the state budget.
        let wide: Vec<Pattern> = (0..64)
            .map(|i| Pattern { bytes: vec![i as u8; 64], nocase: false })
            .collect();
        assert!(Automaton::build(&wide).is_some(), "64 x 64 bytes fits");

        let long: Vec<Pattern> = (0..MAX_PATTERNS)
            .map(|i| {
                let mut bytes = vec![0u8; 64];
                bytes[..2].copy_from_slice(&(i as u16).to_le_bytes());
                Pattern { bytes, nocase: false }
            })
            .collect();
        // 512 patterns x ~64 distinct states each exceeds MAX_STATES.
        assert!(Automaton::build(&long).is_none());
    }

    #[test]
    fn an_empty_pattern_is_refused() {
        assert!(Automaton::build(&[Pattern { bytes: Vec::new(), nocase: false }]).is_none());
    }

    #[test]
    fn the_encoding_is_stable_across_builds() {
        // The kernels decide whether a reload changed anything by comparing a
        // hash of this payload, so two builds of the same patterns must
        // produce the same bytes.
        let patterns = vec![pat("alpha"), ipat("BETA"), pat("gamma")];
        let a = Automaton::build(&patterns).expect("built");
        let b = Automaton::build(&patterns).expect("built");
        let mut wa = Writer::new();
        let mut wb = Writer::new();
        a.encode(&mut wa);
        b.encode(&mut wb);
        assert_eq!(wa.finish(), wb.finish());
    }

    #[test]
    fn the_root_never_traps() {
        // A byte with no transition from the root must leave the automaton at
        // the root, not wedge it. The traversal is a loop with an exit
        // condition on `state == 0`, and this is that exit condition.
        let a = Automaton::build(&[pat("abc")]).expect("built");
        let table = a.scan(b"zzzzabc");
        assert_eq!(table.hit(0), PatternHit { first_start: 4, count: 1 });
    }
}
