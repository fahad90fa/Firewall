# Testing

```sh
cargo test --workspace     # 742 tests
make check                 # + fmt + ABI drift + every shipped policy
make docker-test           # + the kernel C and the real eBPF verifier
```

## What is covered, and what is not

Stated first, because a green suite that implies more than it checks is worse
than a smaller one.

| | |
| --- | --- |
| Compiler — every phase, diagnostics, optimizer | ✅ |
| Cross-platform equivalence | ✅ against every backend's decision model |
| Daemon — policy store, IPC, identity, logging, all three APIs | ✅ |
| CLI — the real binary, real exit codes, stdout/stderr split | ✅ |
| Generated C against the kernel's own headers | ✅ |
| Kernel C compiles; eBPF passes the verifier | ✅ in Docker |
| **Kernel modules' runtime behaviour** | ❌ needs a deployment |
| **The macOS extension end-to-end** | ❌ needs signed code on real hardware |
| **Absolute throughput** | ❌ needs known hardware |

## Layers

### Unit tests

In-file, throughout. The compiler has the most: every token, every syntax error,
every semantic rejection, every optimizer transformation.

### Cross-platform equivalence

The one that matters most.

Each backend emits its artifacts *and* a `DecisionModel`. The verifier runs all
three, plus the reference evaluator, over a corpus derived from the policy — every
address, port, protocol and identity the rules mention becomes an axis — and fails
on any input where they differ.

It runs automatically on every compile, including in `ufwctl policy validate`.

**It has caught real bugs.** Identity predicates matching ICMP under the reference
but not on Windows or macOS (260 of 1872 scenarios). A cross-platform application
flattening its per-platform fingerprints so a Linux binary was required to carry
an Authenticode signature. Neither was visible in review.

The corpus is checked for size, because a verifier that samples three scenarios
and passes is worse than none — it looks like coverage.

### ABI drift

`policy-lang/tests/kernel_abi_tests.rs` compiles the generated headers against
the hand-written kernel structures and runs bounds checks over the emitted tables.

Nothing else catches this: the Rust side compiles fine with a field the C struct
does not have, and the C side only fails on a machine with kernel headers or the
WDK — which CI for a Rust workspace has not got. Both kernel headers are
deliberately self-contained (`#ifndef __KERNEL__`, `UFW_ABI_CHECK`) so the check
runs anywhere with a C compiler.

Extending it to Windows found four real mismatches, one of them a defect: the
emitter collapsed source and destination negation into a single flag, so "source
is not internal" and "destination is not internal" arrived at the driver
identical.

### End-to-end scenarios

`tests/scenarios/` — seven, over a three-part harness.

The harness draws one line: **everything above the kernel boundary is real**, and
the kernel module is the only substitution. Compiler, policy store, IPC framing,
identity trust logic, log pipeline — all real. What a mock kernel could get wrong
about *policy* is checked against the reference evaluator instead.

Two design notes. The packet generator builds flow facts rather than frames,
because a real packet has to survive the whole stack before a verdict is
observable and a failure would rarely be about the policy. And every assertion
reports the rule that decided — in a system where a rule can be shadowed by an
earlier *stage*, "some other rule matched first" is the likeliest explanation and
a bare `assert_eq!` hides it.

### Performance

Asserts **shape**, not magnitude:

- Evaluation is linear, not quadratic, in rule count.
- The stage index really bounds the scan — 500 stream rules must not slow down a
  flow decided at the packet stage.
- The optimizer's output is not slower than its input.

No absolute thresholds. "Under 10 microseconds" passes on a laptop and fails on a
loaded runner, and the response is always to raise it until it stops failing —
after two rounds the test asserts nothing and everyone has learned to ignore it.

### Containerised

```sh
docker compose -f tests/docker/docker-compose.yml --profile verify up
```

Three profiles, because they need different privileges:

| | |
| --- | --- |
| `build` | Compiles everything. No privileges. **Gates the merge.** |
| `verify` | + the real eBPF verifier. Privileged. |
| `traffic` | + loads the module and moves packets. Privileged, needs a matching kernel. |

`traffic` will not run on every CI provider, and that is expected.

## Writing a test

**Name it as a claim.** `an_unresolved_identity_matches_nothing`, not
`test_identity_3`. A failing test name should say what broke.

**Say why it exists** when the reason is not obvious. Most tests here carry a
comment explaining the failure they prevent, and several name the real bug they
were written for.

**Make failures diagnosable.** Print the flow, the expected verdict, the actual
verdict and the rule that decided. `assert_eq!(d, Deny)` tells you the verdict was
wrong and nothing about why.

**No sleeps, no fixed ports, no wall-clock dependencies.** A flaky test is worse
than a missing one: it trains people to re-run until it passes.

## Changing the decision procedure

It exists four times. Change all four in the same commit:

```
shared/src/policy_types.rs                        (reference)
kernel/linux/src/classify.c
kernel/windows/src/classify.c
kernel/macos/NetworkExtension/RuleEngine.swift
```

The equivalence verifier catches the reference-versus-model half automatically.
The C-and-Swift half is caught by reading them side by side, which is why they are
written to the same structure.

## Fuzzing

The protocol decoders are compiled with AddressSanitizer and
UndefinedBehaviorSanitizer and fed 20,000 mutated payloads on every
`cargo test`. That run also compares the Linux and Windows decoders field for
field, because the equivalence claim depends on them extracting the same facts
from the same bytes and nothing else checks it.

The test includes a negative control — a deliberate heap overread that must
fail — so a missing sanitizer runtime shows up as a failure rather than as a
green run that proved nothing.

For the coverage-guided campaign, see [`fuzz/README.md`](../../fuzz/README.md).
It lists what is *not* fuzzed yet, which is the more useful half.
