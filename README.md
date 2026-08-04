# Unified Firewall

A host firewall that compiles **one policy file** into kernel-level filtering on
Windows, Linux and macOS — and checks, at build time, that the three agree.

```yaml
# One file. Three kernels. Same verdict.
rules:
  - id: browser-web
    action: allow
    protocol: tcp
    application: managed_browser    # by signature, not by path
    destination:
      ports: [80, 443]
```

That rule becomes a WFP callout filter, an eBPF program plus a netfilter table,
and a Network Extension rule set. Every backend also emits a model of how it
will evaluate, and the compiler runs all three against a scenario corpus derived
from the policy. If they disagree, the build fails and names the input.

```
$ ufwctl policy validate policies/hardening/zero_trust.yaml
policies/hardening/zero_trust.yaml is valid: 11 rules, 0 warning(s)
  ruleset      sha256:29be8dc378a3d1ecd571829965232dff5e9db5515e4a98dd881c5f7830483058
  optimizer    0 rule(s) removed, 5 eligible for the eBPF fast path
  equivalence  verified across 2006 scenarios on windows, linux, macos
```

## What makes it different

**It filters by who, not by where.** A rule names an *application*, identified
by its code signature — Authenticode subject on Windows, Team ID on macOS, path
and content hash on Linux. "Allow 443 outbound" permits every exfiltration tool
ever written, because they all speak TLS on 443. "Allow 443 outbound from a
binary carrying a valid signature from the vendor we deployed" is a different
statement.

**Absent facts never match.** An unresolved identity does not satisfy an
application predicate — and does not satisfy a *negated* one either. Otherwise
"deny anything that is not our signed binary" would be satisfied by any process
the resolver could not inspect, which is exactly the set an attacker can arrange
to be in.

**Equivalence is checked, not asserted.** Three kernel implementations in two
languages will drift. The verifier is what turns "they should behave the same"
into a build failure with a specific diverging input. Where an algorithm is too
subtle to write three times — the multi-pattern automaton the DPI engine scans
with — it is built once in the daemon and shipped as a table, so all three
kernels run the same short traversal instead of three implementations of the
same idea.

## Try it in two minutes

No daemon, no kernel module, no privileges — the compiler runs anywhere.

```sh
cargo build --release

# Does this policy say what I think it says?
./target/release/ufwctl policy explain \
    policies/test/regression_basic.yaml tcp:10.0.0.5:443:out
```

```
tcp outbound -> 10.0.0.5:443
  decision   ALLOW
  rule       allow-internal-https (id 2683297754)
  layer      packet at priority 200
  zone       internal

per-platform verdict:
PLATFORM  DECISION  RULE
windows   allow     allow-internal-https
linux     allow     allow-internal-https
macos     allow     allow-internal-https
```

That last table is the whole thesis in four lines.

```sh
# Generate the per-platform artifacts.
make generate POLICY=policies/base/default_deny.yaml
ls build/generated/*/
```

## Installing

```sh
make                    # the Rust workspace
make kernel-linux       # or kernel-windows / kernel-macos
sudo make install
```

The install deliberately does **not** activate a policy. A firewall package that
picks one either chooses something permissive — security theatre — or something
restrictive, which takes the machine off the network during a routine upgrade.
The daemon refuses to start until you name a policy.

If this fleet's egress has never been catalogued, start with
`policies/base/default_allow.yaml` in monitor mode, read the logs, write the
allow rules that inventory implies, and only then switch to default-deny.
Switching cold produces an outage and a rollback, and the rollback is what
people remember. That sequence is written out at the top of the file.

Platform specifics — driver signing, DKMS, System Extension approval — are in
[`docs/deployment/`](docs/deployment/).

## How it fits together

```
policy.yaml
    │
    ▼
┌─────────────────────────────────────────┐
│ policy-lang   lex → parse → analyze →   │
│               optimize → 3 backends     │
│                     │                   │
│               equivalence verifier ─────┼──▶ build fails on divergence
└─────────────────────┬───────────────────┘
                      ▼
┌─────────────────────────────────────────┐
│ daemon        policy store, identity    │
│               resolution, log fan-out,  │
│               REST + gRPC + CLI socket  │
└─────────────────────┬───────────────────┘
         IPC (IOCTL / netlink / XPC)
                      ▼
┌──────────────┬──────────────┬───────────┐
│ WFP callout  │ netfilter +  │ Network   │
│ driver       │ eBPF         │ Extension │
└──────────────┴──────────────┴───────────┘
```

The daemon never decides a packet. Every verdict is reached in the kernel, or —
on macOS, where there is no kernel option — in a sandboxed extension the system
consults before the connection completes.

[`ARCHITECTURE.md`](ARCHITECTURE.md) has the design in full, including the
platform hazards that shaped it.

## Five layers

| Layer | What it decides | Where |
| --- | --- | --- |
| 1. Perimeter | Is this internal, perimeter-crossing, or external? | Zone classification, everywhere |
| 2. Packet | L3/L4 headers | eBPF / WFP IP layers / NEFilterPacket |
| 3. App DPI | Protocol-aware payload inspection | Stream layer / reassembly / flow data |
| 4. Identity | Which signed application | ALE / netfilter LOCAL_OUT / audit token |
| 5. Stream + IPS | Reassembled streams, signature matching | All three, within a shared 32 KiB budget |

Stages are evaluated **Perimeter → Packet → Identity → App-DPI → Stream**, and
`priority:` orders rules *within* a stage — it does not order the stages. A
catch-all deny written at the packet layer therefore pre-empts every application
rule beneath it whatever its priority. This is the single most common way to
misread the language, and the compiler warns about it.

## Repository layout

| Path | |
| --- | --- |
| [`policy-lang/`](policy-lang/) | The compiler: lexer, parser, analyzer, optimizer, three backends, equivalence verifier |
| [`daemon/`](daemon/) | `ufwd` — policy store, identity resolution, logging, management API |
| [`cli/`](cli/) | `ufwctl` — validate, compile, explain, install, roll back |
| [`shared/`](shared/) | Wire protocol, policy types, identity types, log schema |
| [`kernel/`](kernel/) | The three enforcement points: C, C, Swift |
| [`sig-rules/`](sig-rules/) | DPI signatures, and [where to put your own](sig-rules/custom/README.md) |
| [`policies/`](policies/) | Worked examples: baselines, per-application, hardening |
| [`tests/`](tests/) | End-to-end scenarios and the containerised Linux environment |
| [`docs/`](docs/) | Language reference, protocol, deployment, API |

## Zero dependencies

`cargo build` pulls nothing. Not "few" — nothing.

Everything here lands in the trusted computing base of a kernel-mode filtering
decision, and a supply-chain compromise in a transitive dependency would be a
compromise of what the machine is allowed to talk to. The cost is a hand-written
YAML subset, JSON codec, SHA-256, HTTP/1.1 server and protobuf framing. The
benefit is that `cargo vendor` produces nothing and the build is reproducible
offline.

There is exactly one opt-in exception, and it is opt-in because the alternative
is worse:

```sh
make tls    # cargo build --features ufw-daemon/tls  → rustls
```

Hand-rolled crypto in a security product is strictly worse than no TLS at all —
it looks like protection and is not. So an operator who needs the management API
on a routable address accepts rustls and its tree, and one who terminates at a
proxy or stays on loopback pays nothing. A build without it **refuses to start**
when the configuration asks for TLS, rather than quietly serving plaintext on a
port configured as encrypted.

## Status

Every layer above the kernel boundary is implemented and tested: 712 tests
covering the compiler, the daemon, the CLI, the wire protocol and end-to-end
scenarios, plus ABI checks that compile the generated C against the kernel's own
headers.

The kernel sources are complete and reviewed, and the containerised Linux
environment compiles them and runs the real eBPF verifier. What no test here
covers is the three modules' *runtime* behaviour on a live kernel — that needs a
deployment, and the testing documentation says so rather than implying
otherwise.

## Contributing

See [`docs/development/contributing.md`](docs/development/contributing.md). The
short version: a change to the decision procedure must be made in all three
classifiers in the same commit, and the equivalence verifier will tell you if
you missed one.

## License

Apache-2.0. See [`LICENSE`](LICENSE).
