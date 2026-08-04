# Daemon ↔ kernel protocol

One message format, three transports. The transports differ because the
platforms give no choice; the messages do not.

| Platform | Transport | Why |
| --- | --- | --- |
| Linux | Generic netlink (`ufw_ctrl`) | Per-message credentials, message-oriented, multicast for pushes |
| Windows | IOCTL on `\\.\UnifiedFirewall` | Access flags enforced by the I/O manager; inverted calls for pushes |
| macOS | XPC to `com.unifiedfirewall.daemon` | The only sanctioned channel from a sandboxed extension; carries the peer's code signature |

Each choice buys the same thing: the channel carries the rule table, so
**who is on the other end** is the security boundary. Netlink supplies the
sender's uid, IOCTL access flags are checked against the handle the caller
opened, and XPC exposes the peer's audit token so the extension can verify the
daemon's Team ID before accepting a policy from it.

## Framing

```
┌────────┬─────────┬────────┬────────┬───────────┐
│ magic  │ version │  type  │  seq   │  length   │   payload
│ u32    │  u16    │  u16   │  u32   │   u32     │   length bytes
└────────┴─────────┴────────┴────────┴───────────┘
        16-byte header, little-endian throughout
```

`magic` is `0x0157_4655`. Little-endian everywhere: every platform this runs on
is little-endian, and byte-swapping on both sides to agree on a convention
neither uses natively is work in exchange for nothing.

`seq` routes replies. The daemon's channel is a multiplexer: a reader thread
demultiplexes by sequence number, so an asynchronous log push arriving between a
request and its reply does not get mistaken for the reply.

## Messages

| Type | Direction | |
| --- | --- | --- |
| `Hello` / `HelloAck` | → / ← | Version and capability handshake |
| `PolicyInstall` / `Ack` | → / ← | Full rule table |
| `PolicyUpdate` / `Ack` | → / ← | Incremental delta |
| `PolicyFlush` | → | Remove every rule |
| `IdentityQuery` | ← | Kernel asks who owns a socket |
| `IdentityResponse` | → | Daemon answers |
| `LogEvents` | ← | Batched decisions |
| `StatsRequest` / `Response` | → / ← | Counters |
| `SetMode` / `ModeAck` | → / ← | enforce / monitor / emergency-allow |
| `SignatureInstall` / `Ack` | → / ← | DPI signature set and its shared pattern table |
| `Error` | ← | Structured failure |

## The handshake decides everything else

```
daemon                              module
  │── Hello(abi=1, host_id) ──────────▶
  │◀─ HelloAck(abi, version, caps) ────
```

If the ABI revisions differ, the daemon **refuses to install**. This matters more
than it looks: a rule table laid out for a different ABI would still install and
would still filter — just not what the operator wrote. There is no error at
install time and no symptom until an incident. Refusing at the handshake is the
only point where the mismatch is detectable.

Capabilities (`IDENTITY`, `DPI`, `STREAM`, `IPV6`, `SCHEDULE`) let the daemon
report at startup that a policy uses a feature the loaded module does not
implement, rather than installing rules that silently never fire.

## Policy installation is atomic

A policy arrives as one message, is validated in full, is built into a complete
new table, and only then replaces the published pointer — an RCU swap on Linux,
an exclusive `EX_SPIN_LOCK` acquire on Windows.

There is no incremental path that mutates the live table, and there will not be
one. An in-place edit has a window during which the table is neither the old
policy nor the new one, and a packet arriving in that window is decided by a
policy nobody wrote.

Hot reload is still incremental **on the wire** — the daemon sends a delta — but
the module expands it against the current table into a whole new table before
publishing. The saving is bandwidth and daemon-side work, not a shortcut through
the swap.

```
daemon                              module
  │── PolicyUpdate(base=7, delta) ────▶
  │                                     base matches? expand : reject
  │◀─ Ack(revision=8, rules=142) ──────
```

`base_revision` is what makes the delta safe. A module that has drifted — because
a previous update was lost, or because something else flushed it — rejects the
delta rather than applying it to the wrong base, and the daemon falls back to a
full install.

The daemon also sends a full install rather than a delta when the delta is large
enough that the diff costs more than the table.

## Identity queries are asynchronous, and that is visible

```
module                              daemon
  │── IdentityQuery(pid, key) ────────▶
  │                                     resolve: path, hash, signature
  │◀─ IdentityResponse(identity) ──────
  │  cache it; the NEXT packet benefits
```

The module does not wait, and the packet that missed is **not** replayed. It is
classified without identity, which means every identity rule fails to match and
the policy's fail-closed semantics apply.

The honest consequence: the first packet of a flow from a never-before-seen
process is decided without knowing the process. For TCP this is nearly invisible,
because the decision that matters is taken at connect time where the socket is
available and the answer is usually already cached. For the first UDP datagram of
a new flow it is real. The mitigation is in policy — pair a UDP identity rule
with a packet-stage rule constraining the destination — not in code, because
queueing packets in softirq context waiting on userspace is the thing this design
exists to avoid.

Queries are rate-limited per socket, and suppressed entirely when no daemon is
attached, so a daemon crash does not fill the event queue with requests and drop
the log events behind them.

## Log delivery is lossy by design

The kernel queues events in a preallocated ring and drops **oldest-first** when
it is full, counting the drops.

A packet never waits for a log event. The cost is explicit: a SIEM collector that
stops reading causes the daemon's socket to fill, which causes it to stop
draining the ring, which causes events to be dropped. Logs are lost. The
alternative — back-pressure reaching the classifier — means a collector outage
becomes a network outage on every host that ships to it.

Oldest-first because during an incident the interesting events are the ones
happening now; newest-first would preferentially discard exactly those.

## Failure modes

| What happens | What the daemon does |
| --- | --- |
| Module absent | Exits, unless `require_kernel_module = false`. A firewall that is up and not filtering, and does not say so, is the worst outcome available. |
| ABI mismatch | Refuses to install; reports both revisions. |
| Module stops answering | Times out and reports. Never blocks — `ufwctl status` must work when a module has wedged. |
| Module sends garbage | Reports and continues. A daemon that dies on malformed kernel input takes the management plane down exactly when somebody needs it. |
| Install rejected | Keeps the previously installed policy. A failed install must never leave the machine unfiltered. |

The loopback transport in `daemon/src/ipc/loopback.rs` implements a module that
can be told to do each of these on purpose, which is how they are tested without
a kernel.
