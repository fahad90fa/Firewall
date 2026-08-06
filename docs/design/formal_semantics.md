# Formal semantics of the policy language

What a policy *means*, independent of any implementation.

This exists because "the three backends agree" and "the three backends are
right" are different claims, and only the first was checkable. The equivalence
proof shows the compiler's outputs match each other and the reference
evaluator — but the reference evaluator is code, so what it proves is internal
consistency. If the reference is wrong, all four are wrong together and every
test passes.

So: the denotation below is the definition, `CompiledPolicy::evaluate` is an
implementation of it, and `policy-lang/tests/semantics_conformance_tests.rs`
checks the implementation against the definition rather than against itself.

## Domains

```
Addr    = IPv4 ∪ IPv6
Port    = { 0 … 65535 }
Proto   = { any, tcp, udp, icmp, icmpv6, other(n) }
Dir     = { inbound, outbound }
Zone    = { loopback, internal, perimeter, external }
Trust   = { untrusted < unknown < known < trusted < system }

Ident   = ⊥ ∪ { path, sha256, signer, team, bundle, trust, valid }
Scan    = ⊥ ∪ { l7, hits ⊆ SigId, truncated }

Flow    = Proto × Dir × (Addr × Port) × (Addr × Port) × Ident × Scan
Verdict = allow ∪ deny
```

`⊥` is not a value of `Ident`; it is the *absence* of one, and the distinction
carries the whole fail-closed property. See **Absence** below.

## Stages

```
Stage   = perimeter < packet < identity < app-dpi < stream
```

Rules are partitioned by stage. `priority` orders rules **within** a stage and
has no effect across stages, which is the language's most common
misunderstanding and the reason the ordering is written here rather than left
to be inferred from the evaluator.

```
order(r) = (stage(r), priority(r), id(r))
```

The tuple is total: `id` is derived from the rule's name and is unique within
a policy, so no two rules compare equal and evaluation order is deterministic
rather than dependent on the order rules appear in the file.

## Predicate

A rule `r` matches a flow `f` when every clause holds:

```
match(r, f) ⟺ stage_applies(stage(r), proto(f))
            ∧ proto(r)  ≼ proto(f)
            ∧ dir(r)    ≼ dir(f)
            ∧ addr(src(r), src(f))
            ∧ port(sport(r), sport(f))
            ∧ addr(dst(r), dst(f))
            ∧ port(dport(r), dport(f))
            ∧ app(r, ident(f))
            ∧ dpi(r, scan(f))
```

with

```
proto(r) ≼ p    ⟺  proto(r) = any ∨ proto(r) = p
dir(r)   ≼ d    ⟺  dir(r)   = any ∨ dir(r)   = d

addr(m, a)      ⟺  (cidrs(m) = ∅ ∧ zones(m) = ∅)
                   ∨ ((∃c ∈ cidrs(m). a ∈ c) ∨ (zone(a) ∈ zones(m))) ⊕ negate(m)

port(m, p)      ⟺  ranges(m) = ∅
                   ∨ (has_ports(proto) ∧ (∃[lo,hi] ∈ ranges(m). lo ≤ p ≤ hi) ⊕ negate(m))
```

`⊕` is exclusive-or, which is how negation is expressed: a negated match
inverts a positive one. An empty selector matches everything and is *not*
inverted by negation, because `!∅` would mean "matches nothing" and no policy
ever wants a clause that cannot hold.

## Absence

Two rules, and they are the reason this document exists.

```
app(r, ⊥) = false               for every r with an application clause,
                                including a negated one

port(m, p) = false              when proto(f) has no port concept,
                                including a negated m
```

An unresolved identity satisfies **no** application predicate. Not the positive
one, and not the negation. The consequence is deliberate: `deny anything that
is not our signed binary` does not fire on a process the resolver could not
inspect — because if it did, the rule would be satisfied by exactly the set an
attacker can arrange to be in, simply by being new.

The same shape applies to ports on ICMP. A negated port clause on a protocol
without ports is not vacuously true.

```
stage_applies(s, p) ⟺ s ∈ {perimeter, packet} ∨ identity_observable(p)
```

Gating on the *stage* rather than on the predicate is what makes a terminal
`layer: stream` deny with no predicates at all behave correctly for ICMP.

## Verdict

```
fired(f)     = ⟨ r ∈ rules | match(r, f) ⟩, ordered by order(r)

verdict(f)   = first terminal action in fired(f), or default(policy)

terminal(a)  ⟺ a ∈ { allow, deny }
```

`allow-inspect`, `alert` and `continue` are **not** terminal. Evaluation
proceeds past them, which is what lets a later stage deny a flow an earlier one
provisionally permitted:

```
verdict(f) = deny   when ∃ r₁ ≺ r₂ ∈ fired(f)
                    with action(r₁) = allow-inspect ∧ action(r₂) = deny
```

`allow` is terminal, so an `allow` at the packet stage cannot be overridden by
a deny at the stream stage. That asymmetry is the point of having two permit
actions, and it is why a perimeter-crossing `allow` is lowered to
`allow-inspect` by the compiler rather than left as written.

## Attribution

```
rule(f) = id of the rule that produced the terminal action,
          or RULE_ID_DEFAULT when the default applied
```

Attribution is part of the contract, not a diagnostic. Two backends that reach
the same verdict by different rules disagree, because the rule id is what the
log event carries and what an operator correlates on. The equivalence proof
compares `(verdict, rule)` pairs for this reason.

## What is deliberately not in the semantics

- **Time.** A `schedule:` clause reads the host's clock, which is not part of
  the flow. Two hosts in different timezones evaluating the same policy on the
  same flow can legitimately differ, so schedules are excluded from the
  equivalence claim rather than pretended into it.
- **Interfaces.** Available on Linux and Windows, not reliably on a
  `NEFilterFlow`. A rule scoped to an interface does not narrow on macOS, and
  `interface-match` is absent from that platform's advertised capabilities.
- **Connection state.** The semantics are per-flow. Statefulness is an
  optimisation — subsequent packets inherit the first packet's verdict — and
  does not change what any flow means.
