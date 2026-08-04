# Local signatures

Deployment-specific signatures go here. Everything under this directory is
loaded exactly like the shipped rules in `../protocols/` and `../exploits/`,
and nothing in the project writes to it, so an upgrade will not touch your
files.

Keep local rules here rather than editing the shipped ones. A local edit to
a shipped file survives until the next upgrade and then silently does not,
which is the worst of both outcomes: the signature is gone and the policy
that references it still compiles.

## Writing one

```yaml
version: 1

metadata:
  name: acme-local
  description: "Signatures for the Acme deployment"
  revision: 1

signatures:
  - id: acme-legacy-agent-egress
    description: "The unsupported inventory agent reaching its old collector"
    protocol: http
    severity: medium
    conditions:
      - content: "AcmeAgent/2.", offset: 0, depth: 256
      - field: http.method == 2
    references: ["INTERNAL-1482"]
```

Reference it from a policy by name:

```yaml
signature_groups:
  local: [acme-legacy-agent-egress]

rules:
  - id: watch-legacy-agent
    priority: 400
    layer: stream
    action: allow
    protocol: tcp
    dpi:
      signatures: [local]
      protocols: [http]
      on_match: alert
```

The id in the signature file and the name in the policy are joined by a hash
of the name, so the two files never need to agree on a number. A policy that
names a signature nobody defines is reported at load time rather than
silently never firing — `ufwctl debug signatures` lists any such references.

## Conditions

Every condition in a signature must hold; there is no `or`. To express a
disjunction, write two signatures and put both in one `signature_groups:`
entry.

| Form | Example |
| --- | --- |
| Field comparison | `- field: dns.max_label_length >= 40` |
| Field comparison, long form | `- field: http.uri_length, op: ">=", value: 2048` |
| Byte pattern, hex | `- content: \|16 03 01\|, offset: 0, depth: 8` |
| Byte pattern, ASCII | `- content: "POST /admin", depth: 4096, nocase: true` |
| Entropy, bits per byte | `- entropy: dns.name_length, min: 4.2` |

`depth` bounds the search window and defaults to 32 KiB — the macOS
extension's per-flow reassembly budget. A wider default would be a window
that quietly means something different on one platform.

Run `ufwctl debug signatures --validate` after editing. Signatures that could
never match — a field belonging to another protocol's decoder, a `depth`
narrower than the pattern, an entropy minimum above 8.0 — are load errors
rather than warnings, because a signature that cannot fire is worse than a
missing one: somebody is relying on it.
