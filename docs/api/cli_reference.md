# `ufwctl` reference

```
ufwctl [GLOBAL OPTIONS] <COMMAND> [ARGS]
```

## Exit codes

| | |
| --- | --- |
| `0` | Success |
| `1` | The operation failed |
| `2` | Usage error |
| `3` | The daemon could not be reached |

`2` and `3` are distinct on purpose: a script that retries on an unreachable
daemon should not retry a typo. An unknown command exits `2` without opening a
socket, so `ufwctl teleport` on a host whose daemon is down is still a usage
error.

## Global options

| | |
| --- | --- |
| `-s, --socket <PATH>` | Daemon control socket |
| `-o, --output <FMT>` | `table` \| `json` \| `yaml` |
| `-t, --timeout <SECS>` | Default 10 |
| `-q, --quiet` | Suppress non-essential output |

`--output json` prints the daemon's response **verbatim**, so a script parsing it
sees exactly what the REST API would return.

## Commands that need no daemon

`policy validate`, `policy compile`, `policy explain` and every `--help` run
entirely locally — no daemon, no kernel module, no privileges. That is what makes
them usable in CI, and why help resolves offline: help you can only read when the
service is up is help you cannot read when you need it.

### `policy validate <FILE> [--deny-warnings]`

```
$ ufwctl policy validate policies/hardening/zero_trust.yaml
policies/hardening/zero_trust.yaml is valid: 11 rules, 0 warning(s)
  ruleset      sha256:29be8dc378a3d1ecd571829965232dff5e9db5515e4a98dd881c5f7830483058
  optimizer    0 rule(s) removed, 5 eligible for the eBPF fast path
  equivalence  verified across 2006 scenarios on windows, linux, macos
```

Diagnostics go to **stderr**, so `ufwctl policy validate p.yaml > report` does
not capture them into a file meant to hold output.

`--deny-warnings` makes warnings a nonzero exit. Notes never fail: `N0404` fires
on any policy that inspects payload, and making that fail CI would teach people
to turn the flag off.

### `policy compile <FILE> [--out DIR] [--platform P]`

Writes the nine artifacts — three per platform. `--platform` restricts to one and
skips equivalence verification, which needs all three to mean anything.

### `policy explain <FILE> <FLOW>`

The command to reach for when a rule does not do what you expected.

```
$ ufwctl policy explain policies/test/regression_basic.yaml tcp:10.0.0.5:443:out
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

Flow syntax: `<proto>:<addr>:<port>:<in|out>`.

The per-platform table is the point. If the three ever disagree, this is where
you see it.

## Commands that need the daemon

### `status [--watch SECS]`

Health, installed revision, kernel connection, counters.

### `policy reload | diff | rollback <REV> | flush`

`rollback` moves **forward** to a new revision whose content matches an old one.
Reusing a revision number would make two different rule sets indistinguishable in
the log.

`flush` removes every rule, leaving the default action — which is deny.

### `rules list [--filter X] | get <NAME|ID>`

`--filter` matches a substring of the name, a tag, or an exact id.

### `identity resolve <PID>`

Runs the platform resolver against a live process — the same path a kernel cache
miss takes. The fastest way to answer "why does this binary not match my rule?".

It explains `untrusted` versus `unknown` in the output, because that is the
distinction operators get backwards most often: `untrusted` means a signature was
present and failed, or the process could not be inspected. It is not the same as
unsigned.

### `identity trust`

The trust database and identity cache statistics. A hit rate near zero means
something is churning processes and every flow is being decided without identity.

### `logs [--follow] [--action A] [--rule R] [--since T]`

### `debug stats | signatures | dump | mode <MODE>`

`debug signatures [--validate]` lists what is loaded **and any DPI references the
policy makes that resolve to nothing**. That second part is why the command
exists: a rule naming a signature nobody shipped compiles, installs and never
fires, so the only symptom is traffic that was supposed to be inspected and
silently was not.

`debug mode emergency-allow --yes` stops all filtering. It requires `--yes` and is
recorded at critical severity. It exists because a firewall that cannot be turned
off during an outage gets turned off by uninstalling it — which loses the logs as
well as the filtering.

## In CI

```yaml
- run: ufwctl policy validate policies/production.yaml --deny-warnings
- run: ufwctl policy compile policies/production.yaml --out artifacts/
```

No daemon required. A policy that stops compiling, or whose backends stop
agreeing, fails the build.
