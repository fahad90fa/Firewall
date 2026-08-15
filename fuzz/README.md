# Fuzzing

Three things here read bytes the kernel did not build itself, in ring 0, which
makes them the highest-risk code in the tree:

- the protocol decoders in `kernel/{linux,windows}/inc/dpi_decoders.h`,
- the stream reassembler's placement arithmetic in
  `kernel/linux/inc/stream_place.h`, and
- the Aho-Corasick table decoder and scan in
  `kernel/linux/inc/dpi_automaton.h`.

All three are deliberately free of every kernel API so that a hosted compiler
can reach them, and each has its own harness because the risk has three shapes:

- **`decoders.c`** — a decoder sees **one buffer** of payload.
- **`reassembly.c`** — the reassembler holds per-flow state and indexes a fixed
  buffer with an attacker-influenced offset, so its bug is one that needs a
  particular *sequence* of segments — an overlap that rewinds the write cursor,
  a gap, a sequence number that wraps the u32, a segment straddling the 32 KiB
  budget. `decoders.c` cannot express those.
- **`automaton.c`** — the daemon ships a compiled multi-pattern table over
  netlink; the kernel decodes it and walks it over the reassembled stream. The
  decoder is a length-prefixed binary parser with per-state transition and
  output slices — an off-by-one there is an out-of-bounds index — and the peer
  is trusted to be the daemon but not to be correct. The harness allocates the
  table arrays at exactly the reported size, so a stray index is an ASan abort,
  and drives the scan and per-condition decision on top.

## Three tiers, on purpose

| | Runs | Finds |
| --- | --- | --- |
| `daemon/tests/dpi_decoder_tests.rs` | every `cargo test` | the regression somebody pushed on Tuesday |
| `fuzz.yml` **smoke** | every push and pull request | a harness that no longer compiles, or a crash shallow enough to surface in a minute |
| `fuzz.yml` **campaign** | nightly, for half an hour a target | the bug needing a nine-byte prefix nobody would guess |

The in-tree one is deterministic and takes under a second. The smoke tier builds
every harness under the sanitizers and runs a short campaign, so a decoder or
reassembler signature drifting out from under its harness fails the PR that
caused it rather than a nightly run nobody is watching. The campaign is
coverage-guided with a corpus that persists between runs, which is why it stays
off the per-PR path.

## Running the campaigns

```sh
cd fuzz
mkdir -p corpus corpus-reassembly corpus-automaton

# Decoders — one corpus serves both, since they are meant to be equivalent, so
# coverage found against one is coverage worth trying against the other.
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -I ../kernel/linux/inc -o fuzz-linux decoders.c
./fuzz-linux corpus/ -max_len=65536 -jobs=$(nproc)

clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -DUFW_ABI_CHECK -DUFW_FUZZ_WINDOWS \
      -I ../kernel/windows/inc -o fuzz-windows decoders.c
./fuzz-windows corpus/ -max_len=65536 -jobs=$(nproc)

# Reassembler — a separate corpus, because the input grammar is a segment
# sequence, not a single payload. The leading byte of each segment selects how
# the offset is formed (raw offset / TCP sequence / in-order append / reset).
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -I ../kernel/linux/inc -o fuzz-reassembly reassembly.c
./fuzz-reassembly corpus-reassembly/ -max_len=65536 -jobs=$(nproc)

# Automaton — seeded from valid tables, because random bytes almost never form
# one that decodes. Start the corpus from the committed seeds (see
# seeds/automaton/README.md for the format), then let the fuzzer grow it.
cp -n seeds/automaton/table-* corpus-automaton/ 2>/dev/null || true
clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -I ../kernel/linux/inc -o fuzz-automaton automaton.c
./fuzz-automaton corpus-automaton/ -max_len=65536 -jobs=$(nproc)
```

## Seeding

Start from real traffic, not random bytes. A random byte string dies at the
first length check; a valid ClientHello with one field corrupted reaches the
code that trusted that field.

```sh
tshark -r capture.pcap -Y 'tls.handshake.type == 1' -T fields -e tls.handshake \
    | while read -r hex; do printf '\x02'; echo "$hex" | xxd -r -p; done > corpus/hello
```

The leading byte selects the protocol — `1` HTTP, `2` TLS, `3` DNS, `4` SSH.

## When it finds something

libFuzzer writes `crash-<sha1>` in the working directory. That file is the
whole reproduction:

```sh
./fuzz-linux crash-abc123
```

Fix it, then **add the file to `corpus/`**. A crash input that is not kept is a
regression waiting to be reintroduced.

## What is not fuzzed yet

- The netlink and IOCTL message decoders. Lower risk — the peer is the daemon,
  which is not an arbitrary process — but not zero.
- The YAML policy and signature parsers. They run in userland at load time, so
  a crash is a failed load rather than a kernel bug, but a hang is a denial of
  service on reload.
- The reassembler's *state machine* around placement — flow keying, context
  allocation and reclaim, the TCP/UDP header parse. `reassembly.c` fuzzes the
  placement arithmetic those feed (`ufw_stream_place` and
  `ufw_stream_seq_offset`, the code that indexes the buffer), which is where an
  out-of-bounds write would live; the surrounding scaffolding needs the kernel
  types it is built from and is exercised only by a deployment.

Listed rather than quietly omitted, because "we fuzz the decoders" reads as
"we fuzz the parsers" if nobody says otherwise.
