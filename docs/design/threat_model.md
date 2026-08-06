# Threat model

What this system is trying to stop, what it is not, and where an auditor should
look first.

Written for two readers: someone deciding whether to deploy it, and someone
paid to break it. Both are better served by a list of known weaknesses than by
a list of features.

## What it defends

| Adversary | Capability assumed | Handled by |
| --- | --- | --- |
| Malware already running as the user | Can execute, cannot sign code as your vendor | Layer 4 — rules match the code signature, not the path |
| Malware that replaced a binary in place | Can write to a path a rule names | Layer 4 — the signature no longer validates, so the rule stops matching |
| Data exfiltration over an allowed port | Speaks TLS on 443 like everything else | Layer 4 narrows *which application* may; Layer 3/5 inspect what it sends |
| An attack split across TCP segments | Controls segmentation and ordering | Layer 5 — reassembly with a first-copy-wins overlap policy |
| A remote host scanning or probing | Arbitrary packets at the interface | Layer 2, and eBPF at tc for the volume case |

## What it does not defend

Stated plainly, because a firewall's most dangerous property is being trusted
for something it does not do.

- **Anything with kernel privileges.** Code in ring 0 can unload the module.
  There is no self-protection, no tamper detection, no anti-unload. A rootkit
  is out of scope, and any claim otherwise would be theatre.
- **A compromised daemon.** The daemon installs policy. Whoever controls it
  controls what the machine may talk to. The management API's auth token and
  the socket's peer check are the boundary, and they are the whole boundary.
- **A signing key in the wrong hands.** Layer 4's guarantee is exactly "signed
  by this key". A stolen key is an application the policy trusts.
- **Encrypted payload content.** The DPI engine sees TLS records, not
  plaintext. It can act on framing, SNI, size and timing; it cannot read the
  body, and this project does not do TLS interception.
- **A malicious policy.** A policy that allows everything allows everything.
  The compiler warns about broad allows; it does not refuse them.
- **Physical access, firmware, the hypervisor, the supply chain of the OS.**

## Trust boundaries

```
    remote peer ──── hostile ────► kernel module (ring 0)
                                      ▲          │
                          daemon ─────┘          │ log events
                        (policy, identity)       ▼
    operator ──── authenticated ──► management API
```

Three boundaries, in order of how much a mistake costs:

1. **Hostile bytes → kernel.** The decoders, the reassembler, the automaton
   loader. A memory bug here is a ring-0 compromise reachable from the
   network. Everything in `fuzz/` exists for this boundary.
2. **Daemon → kernel.** The daemon is trusted to be the daemon, not trusted to
   be correct. Every wire decoder bounds-checks and refuses rather than
   assuming — see `ufw_ac_load` for the shape.
3. **Operator → daemon.** Token on the API, peer credentials on the local
   socket (uid on Linux, audit token on macOS, handle access flags on Windows).

## Where to look first

An auditor with a week should spend it here, in this order:

1. `kernel/{linux,windows}/inc/dpi_decoders.h` — attacker-controlled parsing in
   ring 0. Highest risk in the project by a wide margin. On Linux this C is
   now mirrored by memory-safe Rust (`kernel/linux/rust/ufw_kcore`) proven to
   behave identically, so an auditor's time on the Linux path is better spent
   confirming the differential test's corpus is broad enough than hunting
   overreads the type system already precludes. The Windows C has no such
   backstop.
2. `kernel/{linux,windows}/src/stream_reassembly.c` — per-flow state driven by
   attacker-chosen sequence numbers, and *not yet fuzzed* because it needs a
   stateful harness.
3. `kernel/{linux,windows}/inc/dpi_automaton.h` — a table from the daemon walked
   on the packet path. Bounds are checked at load; the traversal assumes they
   were.
4. `kernel/windows/src/callouts/` — WFP classify functions. A wrong verdict is
   a policy failure; a wrong `classifyOut->rights` is a bugcheck.
5. `daemon/src/management_api/rest.rs` — the only network-facing userland
   parser.

## Known weaknesses, unfixed

Kept here rather than in an issue tracker, because a threat model that lists
only what is handled is marketing.

- **No runtime hours.** No kernel module here has filtered a real packet. This
  is the dominant risk and no code change addresses it. It, and the other
  reasons this is a verified codebase rather than a deployable product, are laid
  out in [`production_readiness.md`](production_readiness.md).
- **Hand-written C in ring 0.** The Linux DPI decoders — the highest-risk
  parsers — have been ported to memory-safe `no_std` Rust in
  `kernel/linux/rust/ufw_kcore`, which forbids `unsafe`, reads every byte
  through `slice::get`, and is checked byte-for-byte against the C it replaces.
  That removes the memory-safety class of bug from the parsing on Linux. The
  Rust-for-Linux module glue around it builds only in a `CONFIG_RUST` kernel
  tree. The **Windows driver has no Rust path** and remains hand-written C —
  fuzzed at the decoders, and that is the mitigation, not memory safety. The
  reassembler and the netlink/IOCTL message decoders are still C on both
  platforms and are not yet ported.
- **The Swift is not compiled by this workspace's tests.** Pinned by
  `shared/tests/macos_wire_contract.rs` and type-checked by the `macos-extension`
  CI job, which is weaker than a full build.
- **Identity has a TTL.** A cached identity is a window in which a process that
  changed underneath is judged on what it used to be.
- **Linux identity is resolved asynchronously.** A flow whose identity query
  has not returned is decided on the rules that do not need it.
- **No evasion resistance below TCP.** IP fragment overlap, TTL-based
  insertion and PAWS games are not handled. Reassembly overlap is.
- **`emergency-allow` exists.** It stops all filtering, requires `--yes`, and
  is logged at critical severity. It is also exactly what an attacker with API
  access would call first.

## Reporting

Security issues to the repository's security contact rather than a public
issue. There is no bounty and no SLA; saying so is more honest than implying
one exists.
