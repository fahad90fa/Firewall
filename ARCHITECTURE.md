# Architecture

This document is about the decisions, not the inventory. Where a design choice
had a real alternative, the alternative is named and the reason for rejecting it
is given — including the ones where the trade is genuinely uncomfortable.

For what each file does, read the file: every source file in this tree opens
with a header explaining why it exists and what would break if it were written
differently.

---

## 1. The one hard problem

Three kernels. Three filtering APIs that share no vocabulary. One policy that
has to mean the same thing on all of them.

Everything below follows from taking that requirement literally.

### Why not three policies?

Because the failure mode is silent. A Windows rule and a Linux rule that were
written to mean the same thing, and drifted, produce a fleet where the same
machine posture is enforced differently depending on the OS — and nobody finds
out until an incident, when the answer to "was this blocked?" turns out to be
"on some hosts".

### Why not one policy, three hand-written translations?

Same problem, one layer down. A translation is code, code drifts, and a
translation bug looks exactly like a policy that means what it says.

### What is actually done

One compiler, three backends, and a **verifier that checks the backends agree**.

Each backend emits its artifacts *and* a `DecisionModel` — its own account of how
it will evaluate the rules it was given. The verifier runs all three models, plus
a reference evaluator, over a scenario corpus derived from the policy, and fails
the build on any input where they differ.

```
                       ┌─▶ windows backend ─┬─▶ artifacts
policy ─▶ CompiledPolicy ─▶ linux backend  ─┼─▶ artifacts
   │                   └─▶ macos backend   ─┴─▶ artifacts
   │                              │
   └──────────▶ reference ────────┴──▶ equivalence verifier
                evaluate()
```

**What this catches.** Two real bugs found during development, both invisible in
review:

- Identity and DPI predicates matched ICMP under the reference, but Windows and
  macOS install identity rules only at flow hooks. 260 of 1872 scenarios
  diverged.
- A cross-platform application unioned its per-platform fingerprints and then
  intersected across kinds, so a Linux binary was required to satisfy a Windows
  signer requirement. Every rule still looked correct.

**What this does not catch.** Whether each backend's emitted code matches its own
model. That gap is closed elsewhere — the three classifiers are written to the
same structure so they can be read side by side, `policy-lang/tests/kernel_abi_tests.rs`
compiles the generated tables against the real kernel headers, and ultimately a
deployment. This document does not pretend the verifier closes it.

---

## 2. Evaluation semantics

### Stages, not layers

```rust
EVALUATION_ORDER = [Perimeter, Packet, Identity, AppDpi, Stream]
```

Note this is **not** the numeric order of the five defense layers. Identity is
stage 2 and DPI is stage 3, because the process behind a socket is known before
its payload has been seen: an identity rule that would deny a flow should not
first pay for reassembly and a signature scan.

`priority:` orders rules *within* a stage. It does not order the stages.

This is the single most common way to misread the language, and it produced two
bugs in this repository's own example policies. A catch-all deny written at the
packet layer is reached before identity resolution, so it silently pre-empts
every application rule beneath it whatever its priority:

```yaml
# WRONG: this deny is evaluated before any identity rule, whatever the numbers say.
- id: deny-unnamed
  priority: 9999
  layer: packet      # ← the problem
  action: deny

# RIGHT: at the last stage, so it is genuinely last.
- id: deny-unnamed
  priority: 9999
  layer: stream
  action: deny
```

The compiler emits `W0300` when a rule can never match because of this, which is
how both instances were found. `policies/hardening/zero_trust.yaml` carries the
full explanation at the point where it matters.

### `allow-inspect`

A provisional permit: the flow proceeds, but evaluation does not stop, so a later
stage can still deny.

This is what makes layered inspection meaningful. Without it, a packet-stage
`allow` is a final verdict reached before the payload exists, and every
stream-stage rule beneath it is dead. With it, "permit this connection, but kill
it if the payload trips a signature" is expressible.

The compiler silently lowers a perimeter-crossing `allow` into `allow-inspect`
and emits `N0403` saying so, because a policy that inspects at the perimeter and
also permits unconditionally is a policy whose author did not mean the second
half.

### Fail-closed asymmetry

Absent facts are never wildcards.

An unresolved identity does not match an application predicate — **and does not
match a negated one either**. This is the property most likely to be broken by a
change that looks like a simplification, so it is worth stating why:

If an absent identity matched a negated predicate, then

```yaml
application:
  trust: [untrusted, unknown]
  negate: false
```

would be satisfied by any process the resolver could not inspect. On every
platform, identity resolution is asynchronous and can miss. So the set of
processes that would satisfy "deny anything that is not our signed binary" would
be exactly the set an attacker can arrange to be in: new ones.

The same rule applies to ports on portless protocols. "Port is not 53" is not
vacuously true for ICMP — it is *unanswerable*, and an unanswerable predicate
must not permit.

### Stage gating

Identity, app-DPI and stream all need a socket with an owning process and a
payload. ICMP has neither, and Windows and macOS cannot surface either for it at
any hook.

The gate is on the **stage**, not the predicate — which matters for a rule that
sits at one of those stages without carrying an app or DPI clause, such as a
terminal `layer: stream` deny. Gating only on predicates let the reference model
attribute an ICMP denial to that rule while Windows and macOS attributed it to
the policy default. Same verdict everywhere, different rule id in the log: a
divergence a verdict-only comparison cannot see, and one that breaks the
cross-platform correlation the log schema exists for.

### Stable rule ids

A rule's id is `sha256("ufw-rule" ‖ policy_name ‖ rule_name)[0..4]`.

Derived from the **name**, not the position. Two consequences, both load-bearing:

- Inserting a rule at the top of a file produces a one-rule delta, not a whole-
  table rewrite. Hot reload is genuinely incremental rather than a full swap
  wearing a diff's clothes.
- The same policy yields the same id on Windows, Linux and macOS. That is the
  entire mechanism behind cross-platform log correlation.

The cost: renaming a rule is a removal plus an addition, not a modification.
That is the honest reading — an operator who renames a rule has changed what the
logs will say about it, and merging the two histories would hide that.

---

## 3. Platform hazards

Each backend exists in the shape it does because of one specific hazard.

### Windows: direction-dependent layer ordering

WFP layers do not fire in the same relative order in both directions:

```
outbound:  ALE_AUTH_CONNECT  →  OUTBOUND_IPPACKET
inbound:   INBOUND_IPPACKET  →  ALE_AUTH_RECV_ACCEPT
```

Split a policy naively — packet rules at the IP layers, identity rules at ALE —
and identity is evaluated first for outbound traffic and second for inbound. The
same policy means two different things depending on which way the packet travels,
and neither matches Linux or macOS.

**Resolution:** the two layer families *partition* the traffic rather than
layering over it. Every connection-oriented flow is decided at ALE, where the
five-tuple and the owning process are both available. The IP packet layers carry
the same table scoped to what ALE never sees — ICMP and the other portless
protocols. No flow is decided twice, so the firing order stops mattering.

Filter weight is `u64::MAX - evaluation_order_key(rule)`, so WFP's descending
order reproduces the reference's ascending one. The order key puts stage above
priority; getting that wrong would make Windows evaluate stages backwards while
every individual filter still looked correct.

**Matching happens in the driver, not in WFP's condition engine.** That gives up
WFP's indexing and buys something worth more: "the three platforms agree" becomes
a claim about ~400 lines of C that can be read beside their Linux and Swift
counterparts, rather than a claim about WFP's condition semantics being
reproducible in Swift.

### Linux: tc runs before netfilter inbound, after it outbound

So the eBPF fast path sees inbound packets netfilter has not seen yet, and
outbound packets it has already decided.

**Resolution:** the fast path is ingress-only, and carries the longest **prefix**
of the rule table that is inbound-relevant and L3/L4-expressible — never an
arbitrary subset.

The prefix property is what makes it safe. A match inside a prefix is provably
the match the complete table would have produced, because every rule that could
have matched earlier is also in the program. With an arbitrary subset that stops
being true: a rule the program does not carry might have matched first, and the
fast path would return a verdict the full table disagrees with.

Anything the fast path does not decide falls through to netfilter, which
evaluates everything. It can accelerate a decision; it cannot change one.

The hooks are `LOCAL_IN`/`LOCAL_OUT`, not `PRE_ROUTING`/`POST_ROUTING`. This is a
host firewall: a forwarded packet has no local process, so every identity rule
would fail closed and drop transit traffic. Choosing the local hooks makes that
impossibility structural rather than a documented caveat.

### macOS: a deadline instead of an IRQL

A Network Extension is a sandboxed userland process the system consults. If
`handleNewFlow` does not answer in time, the system applies its own default and
the flow proceeds without our opinion — silently, permissively, with no error.

**Resolution:** the same rule the two kernel implementations follow for different
reasons. Nothing on the verdict path waits. Identity comes from a cache filled
off the critical path; a miss returns nothing and the fail-closed semantics
apply.

The honest cost: the first flow of a never-before-seen process is decided without
identity. Under default-deny that means denied, which is the safe direction and
why it is tolerable. Under default-allow it means permitted — one more reason
default-allow is a rollout phase rather than a destination.

The flow and packet callbacks partition the same way Windows partitions ALE from
the IP packet layers, for the same reason.

---

## 4. Shared constraints

### The 32 KiB reassembly budget

One number, in four places: `shared/src/constants.rs`, `kernel/linux/inc/stream.h`,
`kernel/windows/inc/stream_reassembly.h`, `StreamHandler.swift`.

It originates from the macOS sandbox, and the other two platforms adopted it
rather than imposing their own. A larger Linux budget would produce a signature
that fires on Linux and silently does not on macOS — an equivalence failure that
depends on **stream length rather than on policy**, so no policy test would ever
surface it.

The default `depth:` for a content signature is the same number, for the same
reason.

Truncation is reported rather than hidden:

- A rule that **denies** on a signature treats a truncated miss as a non-match,
  because no match was seen. The log records the truncation, so "nothing fired"
  stays distinguishable from "we stopped looking".
- A rule that **alerts** reports the truncation itself, because "this flow could
  not be fully inspected" is a finding.

Blocking on truncation alone would fail every connection exceeding the budget —
an outage with a security-sounding name.

### Integer entropy

Shannon entropy is computed in hundredths of a bit, with an integer log2
approximation shared bit-for-bit by all three implementations.

No kernel environment here has floating point available without explicit
save/restore, and a threshold that rounds differently on each platform is an
equivalence failure that depends on payload content — which no policy test could
ever surface either.

### A deliberately weak signature language

Conditions are a conjunction of field comparisons, bounded byte searches and
entropy thresholds. No alternation, no grouping, no regular expressions.

Two reasons:

1. Every construct runs in time linear in a bounded window. A signature language
   with backtracking hands an adversary a way to spend the kernel's time on a
   packet they crafted — a denial of service that arrives looking like ordinary
   traffic.
2. The evaluator exists three times, twice in C and once in Swift. Every
   construct is paid for three times and is a place the three can disagree.

Disjunction lives in `signature_groups:` instead: two signatures, one group, one
line.

Signatures that *cannot* fire are load errors, not warnings — a field belonging
to another protocol's decoder, a `depth` narrower than its pattern, an entropy
floor above 8.0 bits. A signature that can never match is worse than a missing
one, because somebody is relying on it.

### The automaton is built once and shipped

Every `content:` pattern across the whole signature set goes into one
Aho-Corasick automaton, built in the daemon and transmitted as a finished table:
goto edges, failure links, merged output sets. A scan is then one pass over the
payload for all patterns at once, rather than a search per signature.

The construction lives in exactly one place, and that is the design decision
rather than an implementation detail. Aho-Corasick is easy enough that writing
it in the Linux module, the Windows driver and the Swift extension looks
reasonable, and subtle enough — output-set merging, the root self-loop, the
argument for why a failure chain terminates — that the three would not agree.
Reason 2 above applies to it more sharply than to anything else in the engine.

What each kernel runs instead is a loop with no construction in it, short enough
to read side by side across three files. `daemon/tests/dpi_automaton_tests.rs`
compiles both C headers with a hosted compiler and checks them against the Rust
builder over a corpus, so a divergence fails a `cargo test` rather than waiting
for a kernel.

A scan records, per pattern, the first match offset and whether there was more
than one — never every offset, which would be a table sized by attacker-chosen
input. Those two facts decide almost every window; the case they cannot decide
falls back to the bounded search, which is what makes the fast path *exactly*
equivalent rather than approximately. A signature set past the shipped table
limits (512 patterns, 16384 states) ships without an automaton and every
condition takes that search. Performance cliff, never a behavioural one.

### Back-pressure stops at the daemon

A packet never waits for a log event. Not for the daemon, not for the queue, not
for an allocation.

The cost is explicit: a SIEM collector that stops reading causes the daemon's
socket to fill, which causes it to stop draining the kernel's queue, which causes
events to be dropped. **Logs are lost.** The alternative — letting back-pressure
reach the classifier — means a collector outage becomes a network outage on every
host that ships to it, which is a far larger incident and one where the firewall
is the cause.

Queues drop **oldest-first** and count the drops. During an incident the
interesting events are the ones happening now; newest-first would preferentially
discard exactly those while retaining a backlog from before anything happened.

### Identity cache keys

`(pid, start_time)` on Linux, `(pid, socket cookie)` in the kernel module,
`(audit token)` on macOS, `(pid, flow id)` on Windows.

Never a bare pid. Pids are reused, and a reused pid is the difference between
"the browser may reach the internet" and "whatever inherited the browser's pid
may reach the internet". Keying on a pair makes a stale entry **miss** — resolved
correctly a moment later — rather than answer wrongly.

---

## 5. Zero dependencies, and the one exception

`cargo build` pulls no external crates.

Everything in this tree lands in the trusted computing base of a kernel-mode
filtering decision. A supply-chain compromise in a transitive dependency would be
a compromise of what the machine is allowed to talk to, and the blast radius of
`serde`'s dependency tree is not a risk this particular product should be taking
in exchange for saving a YAML parser.

What that costs: a hand-written YAML subset, a JSON emitter and parser, SHA-256,
a TOML subset, an HTTP/1.1 server, a protobuf codec with gRPC-Web framing, and
argument parsing.

What it buys: `cargo vendor` produces nothing, the build is reproducible offline,
and the answer to "what is in this binary" is "this repository".

A few consequences are visible in the design. The daemon has no `SIGTERM`
handler, because installing one needs `libc` — shutdown goes through the control
socket instead, which is what the systemd unit's `ExecStop` invokes. The
management API speaks gRPC-Web over HTTP/1.1 rather than gRPC over HTTP/2. The
REST server refuses chunked transfer-encoding, header continuations, keep-alive
and pipelining: most of the request-smuggling surface, none of it needed here.

### The exception: TLS

`--features tls` pulls `rustls`, and it is the only dependency in the tree.

The reasoning above says a dependency is a risk to the filtering decision. It
does not say a *hand-written* substitute is safer, and for TLS it plainly is
not: hand-rolled crypto in a security product looks like protection and is not.
Neither answer is unconditionally right, so the decision is the operator's and
both are supported deployments:

| | Build | What protects the API |
| --- | --- | --- |
| Loopback only | default | the kernel |
| Proxy terminates TLS | default + `allow_plaintext = true` | the proxy |
| Daemon terminates TLS | `--features tls` | rustls |

The property preserved in every case is that a build which *cannot* do TLS
refuses to start when the configuration asks for it. There is no path where the
operator believes a port is encrypted and it is not. The same applies to the
SIEM sink: configured for TLS and unable to establish it, it declines to connect
rather than shipping the host's activity record in the clear.

---

## 6. Subsystems

### policy-lang

```
text → lexer → parser → semantic → optimizer → 3 backends → verifier
```

Each phase collects diagnostics rather than failing at the first problem, so one
run reports everything wrong with a policy. Diagnostics carry source spans and
render with a caret; unknown keys are hard errors with "did you mean?"
suggestions, because a silently ignored key in a firewall policy is a hole.

The optimizer's `merge_adjacent` is **off by default**. Merging two rules
produces one rule with one id, and an operator asking "why was this blocked?"
gets the name of a rule they did not write. Rule elimination is on, because a
rule that can never match is worth removing and worth being told about (`N0401`).

### daemon

Startup order is `config → logging → identity → state → signatures → kernel →
policy → APIs`, and the order is the design. Logging is second so everything
after it can report its own failures through the pipeline an operator is already
watching. The kernel connection precedes policy compilation so a successful
compile is followed immediately by an install. The APIs come last, because an API
that answers `status` before the daemon knows its own status is worse than one
that is briefly unavailable.

`require_kernel_module = true` by default: the daemon exits rather than running
with nothing enforcing. A firewall that is up but not filtering, and does not say
so, is the worst outcome available — worse than one that failed to start, because
the latter gets noticed.

### The three management surfaces

CLI socket, REST and gRPC-Web all dispatch through one `Router` against one
`Request` enum, so they cannot drift. `ufwctl policy validate`, `compile` and
`explain` run entirely locally and never open a socket — that is what makes them
usable in CI on a machine with no daemon, no kernel module and no privileges.

Unknown commands and `--help` also resolve without a daemon. Help you can only
read when the service is up is help you cannot read when you need it.

---

## 7. What is not covered

Stated plainly, because a green test suite that implies more than it checks is
worse than a smaller one:

- **The kernel modules' runtime behaviour.** The sources are complete and the
  containerised Linux environment compiles them and runs the real eBPF verifier.
  Whether they behave as written on a live kernel needs a deployment.
- **The macOS extension end-to-end.** Needs signed, notarised code on real
  hardware.
- **Absolute performance.** The performance scenario asserts *shape* — linear
  rather than quadratic growth, and that the stage index really bounds the scan.
  Throughput numbers belong to a benchmark on known hardware, not to CI, where an
  absolute threshold gets raised until it stops failing and then asserts nothing.

Everything above the kernel boundary is real and tested: 722 tests across the
compiler, daemon, CLI, wire protocol and end-to-end scenarios, plus ABI checks
that compile the generated C against the kernel's own headers.
