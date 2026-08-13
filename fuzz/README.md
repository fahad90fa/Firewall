# Fuzzing

Two things here read attacker-chosen bytes in ring 0, which makes them the
highest-risk code in the tree:

- the protocol decoders in `kernel/{linux,windows}/inc/dpi_decoders.h`, and
- the stream reassembler's placement arithmetic in
  `kernel/linux/inc/stream_place.h`.

Both are deliberately free of every kernel API so that a hosted compiler can
reach them. Each has its own harness, because the risk has two shapes: a decoder
sees **one buffer**, while the reassembler holds per-flow state and indexes a
fixed buffer with an attacker-influenced offset, so its bug is one that needs a
particular *sequence* of segments — an overlap that rewinds the write cursor, a
gap, a sequence number that wraps the u32, a segment straddling the 32 KiB
budget. `reassembly.c` replays such sequences; `decoders.c` cannot express them.

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
mkdir -p corpus corpus-reassembly

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
