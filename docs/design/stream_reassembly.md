# Stream reassembly and payload inspection

## Why reassemble

A signature matching `POST /admin` does not match a stream where the client sent
`POST /ad` and `min` in two segments. An attacker who knows a firewall matches
per-packet only has to split the pattern, which costs them nothing.

Per-packet matching on a stream protocol is not a weaker form of inspection. It
is inspection an adversary can switch off.

## Why 32 KiB, everywhere

The budget is `32 * 1024` bytes per flow, and it is the same number in four
places:

| | |
| --- | --- |
| `shared/src/constants.rs` | `STREAM_REASSEMBLY_MAX_BYTES_MACOS` |
| `kernel/linux/inc/stream.h` | `UFW_STREAM_MAX_BYTES` |
| `kernel/windows/inc/stream_reassembly.h` | `UFW_STREAM_MAX_BYTES` |
| `StreamHandler.swift` | `budgetBytes` |

It originates from the macOS Network Extension sandbox, and Linux and Windows
adopted it rather than choosing their own.

That is the interesting part. A larger Linux budget would be entirely reasonable
on its own terms — and would produce a signature that fires on Linux and silently
does not on macOS. The divergence would depend on **stream length rather than on
policy**, so no policy test could surface it and the equivalence verifier would
not see it either: both platforms would be behaving correctly according to their
own configuration.

The cheapest fix was to make the tightest platform's limit the shared one, and to
say so in all four files. `tests/scenarios/stream_reassembly.rs` asserts the
constant, so a change in one place fails the build rather than drifting.

The same number is the default `depth:` for a content signature that does not
specify one — for the same reason.

## Bounding the memory

Reassembly means holding attacker-controlled bytes, keyed by an attacker-chosen
flow. Unbounded, that is a remote memory-exhaustion primitive: open ten thousand
connections, send one byte on each, never close them.

Three bounds, on all three platforms:

- **Per-flow budget** — 32 KiB, above.
- **Context count** — 4096 (1024 on macOS, where the sandbox is tighter).
- **Idle timeout** — 30 seconds.

Reclamation prefers idle contexts over active ones. A flow quiet for 30 seconds
has already shown the engine its interesting prefix — signatures are anchored
near the start of a stream precisely so they resolve inside this window — whereas
evicting an active flow loses inspection on one still carrying data.

## Truncation is a finding, not a gap

When a flow exceeds its budget the context is marked **truncated** and stops
growing. That marker travels with the scan result, and the distinction it draws
is the whole point:

- A rule that **denies** on a signature treats a truncated miss as a non-match,
  because no match was seen. But the log records the truncation, so "nothing
  fired" stays distinguishable from "we stopped looking".
- A rule that **alerts** reports the truncation itself, because "this flow could
  not be fully inspected" is a finding.

Blocking on truncation alone would fail every connection that exceeded the
budget — which is every long-lived connection. That is not a security control; it
is an outage with a security-sounding name.

## Overlapping segments

A TCP overlap attack sends two segments covering the same sequence range with
different bytes, relying on the firewall and the endpoint resolving the overlap
differently: the firewall scans benign content, the endpoint receives the
payload.

There is no resolution policy correct for every endpoint, because the endpoints
disagree — Linux prefers the first copy, some stacks the last. Any choice this
engine makes is wrong for some peer.

So it makes none. The **first** copy of any byte already seen is kept, and a
later segment attempting to rewrite it marks the context truncated. That converts
"the firewall was fooled" into "the firewall said it could not be sure", which is
a state an analyst can act on.

A gap — a segment arriving before the bytes preceding it — is handled the same
way. Appending across a gap would produce a byte sequence that never appeared on
the wire, which is a source of both false positives and, worse, false negatives
where a pattern spans the boundary.

## Per-platform mechanics

**Windows.** WFP's stream layer delivers in-order bytes, so there is no
sequencing work — only accumulation and the budget. The driver terminates a
condemned flow with `FWPS_STREAM_ACTION_DROP_CONNECTION` rather than dropping
silently: a silently dropped stream leaves the application waiting on a
connection that will never answer, which presents to a user as a hang and to an
operator as "the network is slow".

**Linux.** Full reassembly from `sk_buff`s: sequence tracking relative to the
flow's first observed sequence number, with the placement rules above. UDP is
scanned per datagram, because a datagram is self-contained and accumulating them
would fabricate boundaries the receiving application never sees.

**macOS.** `handleInboundData` / `handleOutboundData` deliver ordered bytes like
WFP does. The extension returns `.drop()` on a condemned flow and releases the
context, so the rest of the conversation is not permitted merely because the
offending bytes already passed.

## The signature engine

Deliberately weak: conditions are a **conjunction** of

- a comparison against a decoded protocol field,
- a bounded byte search,
- an entropy threshold,

with no alternation, no grouping and no regular expressions.

Two reasons. Every construct runs in time linear in a bounded window, so the
worst case is a constant an operator can compute (signatures × 32 KiB) — a
signature language with backtracking hands an adversary a way to spend the
kernel's time on a packet they crafted. And the evaluator exists three times,
twice in C and once in Swift; every construct is paid for three times and is a
place the three can disagree.

Disjunction lives in `signature_groups:` instead. Two signatures, one group, one
line.

### One pass, every pattern

A signature set names byte patterns; a stream has to be searched for all of
them. Searching once per signature costs `signatures × window`. Searching once
for all of them costs `window`.

The automaton that does that — Aho-Corasick — is built **in the daemon**, once,
and shipped as a finished table. Each kernel receives goto edges, failure links
and merged output sets, and runs a loop with no construction in it: follow a
transition, fall back along a failure link if there is none, record what the
state outputs.

That split is the whole point. Aho-Corasick is easy enough that writing it
three times looks reasonable, and just subtle enough — output-set merging, the
root self-loop, the fail-chain depth argument — that the three would not agree.
Building it once means there is one implementation to get right and three
traversals to check against it, which is what
`daemon/tests/dpi_automaton_tests.rs` does: it compiles both C headers with a
hosted compiler and runs them against the Rust builder on a shared corpus.

A scan produces, per pattern, the offset of the **first** occurrence and
whether there was more than one. Not every offset — that would be a table whose
size an attacker chooses. A condition's `offset`/`depth` window is then decided
from those two facts:

| | |
| --- | --- |
| no occurrence in the buffer | no occurrence in any window inside it |
| first occurrence inside the window | match |
| exactly one occurrence, outside the window | no match |
| several, none of them the first | search that one pattern directly |

The last row is why this is *exactly* equivalent to the per-signature search
rather than approximately. It is reached only by a pattern that repeats within
one stream and is scoped to a window excluding its first hit.

Case sensitivity is two automatons, not two comparisons: patterns marked
`nocase` go into a trie over ASCII-folded bytes, the rest into a trie over raw
bytes, and both advance in the same loop over the same input. One pass either
way.

The table is bounded — 512 distinct patterns, 16384 states, 8192 output entries.
A set that exceeds any of them ships **without** an automaton, and every content
condition falls back to the bounded search. That is a performance cliff and
never a behavioural one, which is the right way round: a table that silently
stopped covering some patterns would report a clean scan of a stream nothing
had looked at.

### Fields, not offsets

A `field:` condition names a value the decoder already extracted —
`dns.max_label_length`, `tls.sni_length`, `http.header_count`. Not an offset into
the payload.

An offset is only meaningful if the signature author's model of the framing
matches the decoder's, and every place those two models can disagree is a place
an attacker can put bytes that the firewall reads as one field and the endpoint
reads as another. The field set is closed; a signature naming anything else
fails to load rather than silently never matching.

**An absent field fails its condition.** The decoder not producing a value — a
malformed payload, or a field belonging to another protocol — is not zero. Absent
fails, which fails the signature: the safe direction.

### Integer entropy

Shannon entropy in hundredths of a bit, using `H = log2(n) - (1/n)·Σ cᵢ·log2(cᵢ)`
with an integer log2 approximation shared bit-for-bit by all three
implementations.

No kernel environment here has floating point available without explicit
save/restore, and a threshold rounding differently per platform is an equivalence
failure that depends on payload content — which, like the budget, no policy test
could surface.

### Protocol identification

Prefix checks first — TLS `16 03`, `SSH-`, an HTTP method — then, on the packet
path only, the destination port.

DNS has no distinctive prefix, so it falls back to the port and is deliberately
last. A signature scoped to `protocols: [dns]` on a non-standard port will not
fire: a documented limitation, rather than a guess that could be wrong in the
permissive direction.
