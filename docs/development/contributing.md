# Contributing

## Before anything else

Two facts about this codebase determine most of what a change looks like.

**The decision procedure exists four times.**

```
shared/src/policy_types.rs                        the reference
kernel/linux/src/classify.c
kernel/windows/src/classify.c
kernel/macos/NetworkExtension/RuleEngine.swift
```

A change to matching semantics is a change to all four, in the same commit. The
equivalence verifier catches the reference-versus-model half automatically; the
rest is caught by the four being written to the same structure so they can be
read beside each other.

**Absent facts never match.** An unresolved identity does not satisfy an
application predicate, including a negated one. A port constraint never matches a
portless protocol, including negated. These look like special cases that could be
simplified away. They cannot: each one is what stops a fail-open path.

## Workflow

```sh
cargo test --workspace
make check                 # + fmt + ABI drift + every shipped policy
```

Branch, commit, open a PR. Keep commits focused — a commit that changes semantics
and reformats is a commit nobody can review.

## Commit messages

Say **why**, not what. The diff says what.

> `classify: gate flow stages on protocol, not on predicate`
>
> A terminal `layer: stream` deny carries no identity or DPI predicate, so
> the predicate-level ICMP gates never fired for it. Windows and macOS
> install no stream-stage filter for ICMP, so all three said "deny" while
> disagreeing about *which rule* denied it. The verdict matched, so only a
> rule-attribution comparison could see it — and cross-platform log
> correlation is exactly what it would have broken.

That is a real commit from this repository. The value is in the second paragraph.

## Code

**Comment the decision, not the mechanism.** `// increment the counter` is noise.
`// oldest-first, because during an incident the interesting events are the ones
happening now` is the reason somebody will need in two years.

**Say what you rejected.** Where a choice had a real alternative, name it. Half
the headers in this tree are a paragraph explaining what would break if the file
were written the obvious way.

**Be honest about costs.** `identity.c` says plainly that the first UDP datagram
of a new flow is decided without identity. `README.md` says plainly what the
tests do not cover. A codebase that only documents its strengths is one you
cannot trust about its weaknesses.

**No external dependencies.** Not "few". None. Everything here lands in the
trusted computing base of a kernel-mode filtering decision. If you need
functionality that is not there, write it or make the case for changing the
policy — do not add a crate.

## Tests

Every behavioural change needs one. Name it as a claim
(`an_unresolved_identity_matches_nothing`), explain the failure it prevents when
that is not obvious, and make the failure message diagnosable.

No sleeps, no fixed ports, no wall-clock dependencies.

## Adding to the policy language

1. `ast.rs` — the node and its `*_KEYS` entry, so unknown-key suggestions work
2. `parser.rs`
3. `semantic.rs` — lowering, with a diagnostic for every rejection
4. All three backends **and** their decision models
5. All four classifiers, if it affects matching
6. `docs/design/policy_language_spec.md`
7. A fixture exercising it, so the equivalence corpus covers it

Steps 4 and 5 are where a language change becomes real work. That is intentional:
a construct that is expensive to add across three platforms is a construct worth
being sure about.

## Adding a signature

Put local rules in `sig-rules/custom/` — see the README there. Do not edit the
shipped files: a local edit survives until the next upgrade and then silently
does not, which is the worst of both outcomes.

Signatures that cannot fire are load errors, not warnings. A signature that can
never match is worse than a missing one, because somebody is relying on it.

## Security issues

Do not open a public issue. Email the maintainers with reproduction steps.

The parts most worth attacking, and where the reasoning lives:

- The IPC channel, which carries the rule table (`docs/design/ipc_protocol.md`)
- The signature engine, which parses attacker-controlled bytes in kernel context
  (`kernel/*/src/dpi_engine.c`)
- Stream reassembly, which holds them (`docs/design/stream_reassembly.md`)
- Identity resolution, where a wrong answer is a policy bypass
  (`docs/design/identity_model.md`)

## License

Apache-2.0. Contributions are accepted under the same terms.
