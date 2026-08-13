# Fuzzing

The decoders in `kernel/{linux,windows}/inc/dpi_decoders.h` parse
attacker-chosen bytes in ring 0. They are the highest-risk code here, and both
headers are deliberately free of every kernel API so that a hosted compiler can
reach them.

## Three tiers, on purpose

| | Runs | Finds |
| --- | --- | --- |
| `daemon/tests/dpi_decoder_tests.rs` | every `cargo test` | the regression somebody pushed on Tuesday |
| `fuzz.yml` **smoke** | every push and pull request | a harness that no longer compiles, or a crash shallow enough to surface in a minute |
| `fuzz.yml` **campaign** | nightly, for half an hour a target | the bug needing a nine-byte prefix nobody would guess |

The in-tree one is deterministic and takes under a second. The smoke tier
builds both decoder fuzzers under the sanitizers and runs a short campaign, so a
decoder signature drifting out from under `fuzz/decoders.c` fails the PR that
caused it rather than a nightly run nobody is watching. The campaign is
coverage-guided with a corpus that persists between runs, which is why it stays
off the per-PR path.

## Running the campaign

```sh
cd fuzz
mkdir -p corpus

clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -I ../kernel/linux/inc -o fuzz-linux decoders.c
./fuzz-linux corpus/ -max_len=65536 -jobs=$(nproc)

clang -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all \
      -DUFW_ABI_CHECK -DUFW_FUZZ_WINDOWS \
      -I ../kernel/windows/inc -o fuzz-windows decoders.c
./fuzz-windows corpus/ -max_len=65536 -jobs=$(nproc)
```

One corpus serves both: the decoders are meant to be equivalent, so coverage
found against one is coverage worth trying against the other.

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

- The stream reassembler. It holds per-flow state across calls, so it needs a
  stateful harness that replays segment sequences rather than one buffer. Its
  length and offset arithmetic has been reviewed and hardened to be
  overflow-safe on its own rather than only under the caller's clamping
  (`place()` compares `len <= ctx->len - offset` instead of forming
  `offset + len`; the TCP/UDP payload lengths are validated before the
  subtraction that would otherwise underflow), but that is review, not fuzzing.
- The netlink and IOCTL message decoders. Lower risk — the peer is the daemon,
  which is not an arbitrary process — but not zero.
- The YAML policy and signature parsers. They run in userland at load time, so
  a crash is a failed load rather than a kernel bug, but a hang is a denial of
  service on reload.

Listed rather than quietly omitted, because "we fuzz the decoders" reads as
"we fuzz the parsers" if nobody says otherwise.
