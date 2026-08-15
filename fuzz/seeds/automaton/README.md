# Automaton seed tables

Three valid Aho-Corasick tables, in the exact wire format
`ufw_ac_load` (`kernel/linux/inc/dpi_automaton.h`) decodes. They exist so the
`automaton` fuzz target reaches the *load-success and scan* path from its first
run, instead of spending a short campaign bouncing off the sizing check — random
bytes almost never form a table that decodes.

- `table-1` — one pattern `A`, one two-state trie.
- `table-2` — one case-folded pattern `POST`, a five-state chain.
- `table-3` — two patterns `AB`/`AC` sharing a root, so a state carries a
  multi-transition (binary-searched) slice and the output set holds two ids.
- `hang-fail-cycle` — a regression seed: a table that decodes and loads but
  whose failure links form a cycle that never reaches the root. Before the
  `ufw_ac_step` hop cap it spun forever in the traversal (a ring-0 hang the
  fuzzer found); it is kept so the smoke tier always re-checks that a cyclic
  fail link terminates instead of looping.

The layout, little-endian, is: `u32 pattern_count`; per pattern `u8 nocase`,
`u32 len`, `len` bytes; `u8 trie_count`; per trie `u8 fold`, `u32 state_count`,
`u32 trans_count`, `u32 out_count`, then the states (`u32 fail`,
`u32 trans_start`, `u16 trans_count`, `u32 out_start`, `u16 out_count`), the
transitions (`u8 byte`, `u32 next`, sorted by byte within each state), and the
outputs (`u16 pattern_id`). It mirrors the encoder in `daemon/src/automaton.rs`;
these three were hand-built to that spec and confirmed to decode, load and scan.

The fuzz workflow copies these into the working `corpus-automaton/` before a
run; libFuzzer then owns and grows that directory. Keep these minimal — a seed
corpus is a starting point for mutation, not a coverage target.
