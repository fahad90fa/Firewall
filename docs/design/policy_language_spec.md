# Policy language reference

A policy is a YAML document. The language is a strict subset — no anchors, no
multi-document files, no flow-style mappings — because a firewall policy is read
under pressure and every construct that can surprise a reader is a construct
that can hide a hole.

Unknown keys are **hard errors**, with a "did you mean?" suggestion. A silently
ignored key in a firewall policy is a rule that does not do what it says.

## Document structure

```yaml
version: 1                # required
metadata: {...}           # name, description, revision, author
defaults: {...}           # action, log, layer, priority, stateful
include: [...]            # other policy files, merged in
address_groups: {...}
port_groups: {...}
applications: {...}
signature_groups: {...}
network_profile: {...}
rules: [...]              # the only section that decides anything
```

## The evaluation model

**This is the part to read twice.** Rules are evaluated in *stage* order:

```
Perimeter → Packet → Identity → App-DPI → Stream
```

`priority:` orders rules **within** a stage. It does not order the stages.

A stage is inferred from a rule's predicates unless `layer:` says otherwise:

| The rule has… | Stage |
| --- | --- |
| only header predicates | `packet` |
| an `application:` clause | `identity` |
| a `dpi:` clause with `protocols:` only | `app-dpi` |
| a `dpi:` clause with `signatures:` | `stream` |

### The mistake this language makes easiest

```yaml
- id: allow-browser         # identity stage
  priority: 100
  application: browser
  action: allow

- id: deny-everything       # packet stage — evaluated FIRST
  priority: 9999
  layer: packet
  action: deny
```

`deny-everything` wins. Packet is an earlier stage than identity, so it is
reached before the browser rule is ever considered, whatever the priorities say.

The compiler reports this as `W0300` — *"rule X can never match: Y is evaluated
first"*. Two of this repository's own example policies contained it.

The fix is to put a terminal rule at the **last** stage:

```yaml
- id: deny-unnamed
  priority: 9999
  layer: stream             # genuinely last
  action: deny
```

## Actions

| Action | Terminal? | Meaning |
| --- | --- | --- |
| `allow` | yes | Permit. Evaluation stops. |
| `deny` | yes | Block. Evaluation stops. |
| `allow-inspect` | **no** | Provisional permit. Evaluation continues; a later stage may still deny. |
| `alert` | no | Record and continue. Not a verdict. |
| `continue` | no | Explicitly contribute nothing. |

`allow-inspect` is what makes layered inspection meaningful. A packet-stage
`allow` is a final verdict reached before the payload exists; `allow-inspect`
lets a stream-stage signature still condemn the flow.

The compiler lowers a perimeter-crossing `allow` into `allow-inspect`
automatically and says so (`N0403`), because a policy that inspects at the
perimeter *and* permits unconditionally did not mean the second half.

## Rules

```yaml
rules:
  - id: allow-internal-web        # required, unique; the log's join key
    description: "..."
    priority: 200                 # within the stage; lower is earlier
    layer: packet                 # override the inferred stage
    direction: outbound           # inbound | outbound | any
    action: allow
    protocol: tcp                 # tcp | udp | icmp | icmpv6 | any | <number>
    source: {...}                 # endpoint
    destination: {...}            # endpoint, or a bare CIDR
    application: browser          # a name, a list, or an inline selector
    dpi: {...}
    interfaces: [tun0, utun3]
    schedule: {...}
    log: true
    tags: [baseline]
```

`id` is the rule's **name**, and the numeric id the kernel and the logs use is
derived from it: `sha256("ufw-rule" ‖ policy ‖ name)`. Two consequences —
inserting a rule produces a one-rule hot-reload delta rather than a whole-table
rewrite, and the same policy yields the same id on all three platforms, which is
what makes cross-platform log correlation work.

Renaming a rule is therefore a removal plus an addition, not a modification.

### Endpoints

```yaml
destination:
  addresses: [10.0.0.0/8, corp_dns]   # CIDRs and/or group names
  zone: external                       # local | internal | perimeter | external
  ports: [80, 443, 8000-8100]          # or a port group name
  negate: true                         # invert the whole endpoint
```

A bare string is shorthand for a single address: `destination: 127.0.0.0/8`.

**A port constraint on a portless protocol never matches, not even negated.**
"Port is not 53" is not vacuously true for ICMP — it is unanswerable, and an
unanswerable predicate must not permit.

## Applications

The reason this system exists. An application is a *disjunction of per-platform
fingerprints*, each of which is a conjunction of its own criteria.

```yaml
applications:
  managed_browser:
    description: "The browser endpoint management deployed"
    trust: [">= trusted"]           # or an explicit list
    require_valid_signature: true
    platforms:
      windows:
        path: "C:\\Program Files\\Contoso Browser\\browser.exe"
        signer: "Contoso Ltd"       # Authenticode subject
      linux:
        paths: [/usr/lib/contoso-browser/browser, /opt/contoso/browser]
      macos:
        bundle_id: com.contoso.browser
        team_id: ABCDE12345
```

Read the nesting carefully: the Windows fingerprint requires **both** the path
and the signer. The Linux fingerprint requires only a path. A binary satisfies
the application if it satisfies **any one** fingerprint.

That disjunction is not a convenience — flattening it means a Linux binary is
required to carry an Authenticode signature, which makes the application
unmatchable on Linux while every rule still looks correct. It was a real bug.

### Trust levels

Ordered: `untrusted < unknown < known < trusted < system`.

| Level | Means |
| --- | --- |
| `system` | Platform-signed, inside the sealed system volume or equivalent |
| `trusted` | Signed by a publisher in the trust database |
| `known` | Validly signed by a publisher not in the database |
| `unknown` | Unsigned but readable. Nothing claimed, nothing failed. |
| `untrusted` | A signature is present and **does not verify** — signed then modified — or the process could not be inspected at all. |

`untrusted` is strictly worse than `unknown`. Operators get this backwards more
than any other distinction in the language, which is why `ufwctl identity
resolve` explains it in the output.

### Inline selectors

```yaml
application:
  trust: [untrusted, unknown]
  negate: true
```

**An unresolved identity matches nothing — including a negated predicate.** If
it did not, "deny anything that is not our signed binary" would be satisfied by
any process the resolver could not inspect, which is exactly the set an attacker
can arrange to be in.

## DPI

```yaml
dpi:
  signatures: [exfiltration]      # signature ids or group names
  protocols: [dns, http, tls]
  on_match: deny                  # deny | alert | allow
```

`action: allow` with `on_match: deny` means "permit unless the payload trips" —
the flow proceeds until a signature fires.

Signature names resolve to ids by the same hash the signature files use, so a
policy never names a number. A reference that resolves to nothing is reported by
`ufwctl debug signatures`, because otherwise the rule installs cleanly and never
fires.

## Schedules

```yaml
schedule:
  days: [weekdays]                # mon..sun, weekdays, weekends, daily
  start: "07:00"                  # local time
  end: "20:00"                    # wraps midnight if end < start
```

Local time, not UTC — "business hours" is a statement about the operator's
clock. The daemon pushes the current offset on every reload rather than the
kernel computing it.

A scheduled rule whose window cannot be evaluated stands down rather than
applying at the wrong time.

## Network profile

```yaml
network_profile:
  internal: [10.0.0.0/8]
  perimeter: [203.0.113.0/24]
  gateways: [10.0.0.1]
  dns_servers: [10.10.0.53]
  perimeter_crossing_requires_dpi: true
```

Drives zone classification, and hence `zone:` predicates and the `internal` /
`perimeter-crossing` / `external` field on every log event. Perimeter is checked
before internal, because a DMZ range is usually inside RFC1918 and the more
specific classification is the one the operator meant.

## Includes

```yaml
include: [fragments/common_groups.yaml]
```

Merged into the including document; `defaults:` and `network_profile:` belong to
the *including* policy and are ignored in a fragment. Paths are relative and may
not contain `..` — a policy that can include `../../etc/shadow` is a
file-disclosure primitive wearing a config file's clothes.

Unreferenced definitions from an include are not reported: a shared library that
every consumer used in full would not be worth sharing.

## Diagnostic codes

| Code | |
| --- | --- |
| `E01xx` | Lexical |
| `E02xx` | Syntax — unknown key, malformed value |
| `E03xx` | Semantic — undefined reference, type mismatch, layer mismatch |
| `E0501` | The backends disagreed. Always a compiler defect, never a policy one. |
| `W0300` | A rule can never match |
| `W0303` | A definition is never referenced |
| `W0304` | A broad allow that shadows everything below it |
| `N0402` | Rules offloaded to the eBPF fast path |
| `N0403` | A perimeter-crossing allow was lowered to `allow-inspect` |
| `N0404` | Rules needing payload inspection, against the 32 KiB budget |

`--deny-warnings` turns warnings into a nonzero exit, for CI. Notes never do:
`N0404` fires on any policy that inspects payload at all, and making that fail
CI would teach operators to turn the flag off.

## Checking a policy

```sh
ufwctl policy validate policy.yaml           # diagnostics; exit 1 on error
ufwctl policy explain policy.yaml tcp:1.2.3.4:443:out
ufwctl policy compile policy.yaml --out ./generated
```

All three run locally — no daemon, no kernel module, no privileges.
