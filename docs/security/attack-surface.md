# Attack surface

Every externally-reachable entry point, its exposure, its hardening, and its
audit status. "Audited" here means **externally** audited; internal tests are
noted separately. Nothing is externally audited yet.

| # | Entry point | Reachable by | Privilege of the code | Hardening | Ext. audit |
| --- | --- | --- | --- | --- | --- |
| 1 | **`ufw.ko` packet parsers** (decoders, stream reassembly, DPI automaton) | any host that can send this machine a packet | **ring 0** | bounds-checked; fuzzed (sanitizer, coverage-guided) in CI + nightly; Rust `ufw_kcore` differential twin; `-Werror -Wvla`, 512B frame cap | ❌ (highest priority) |
| 2 | **eBPF programs** (XDP filter, conntrack, metering, identity LSM) | network / LSM hooks | kernel (verifier-checked) | verifier rejects unbounded loops/OOB; `bpftool prog load` gate in `make check` | ❌ |
| 3 | **nftables ruleset** (`inet ufw`) | network | kernel netfilter (mature) | compiled artifact validated by `nft -c` before commit; confined to one table so `revert` is exact | n/a (kernel's own) |
| 4 | **Policy compiler** (`ufw-policy-lang`) | whoever authors/ships a policy | user-space, runs as root at `apply` | untranslatable rules dropped, never weakened; extensive unit tests; **parser fuzzed** (no-panic on hostile bytes); the **emitted nft is packet-checked against a real kernel** (netns conformance) so what it enforces = what you wrote; kernel validates output before load | ❌ (internal tests only) |
| 5 | **Web console** (`ufw-nft dashboard`, `:8787`) | **loopback only** | root (reads tables/logs; one loopback-gated write) | binds `127.0.0.1`; read-only except `Contain`, which is gated on the request arriving over loopback and audited; **request-head parser fuzzed** (the class the unauth crash was in); optional mTLS + RBAC (`--features tls`) with client-cert→role mapping | ❌ |
| 6 | **Daemon REST + wire protocol** (`ufwd`, `:9600`) | loopback / fleet plane | root (daemon) | request-path subprocesses bounded; fault-isolated handlers; **wire-protocol decoder fuzzed**; fleet messages HMAC-authenticated (`fleet_secret` ≥32 chars), and **Ed25519-signed** with `--features tls` + `api.fleet_ed25519_pubkey`; privilege-reduced, boot-ordered systemd unit | ❌ |
| 7 | **Daemon ↔ module netlink** | local root / daemon | ring 0 receives policy | policy integrity checked before apply; module defaults to monitor | ❌ |
| 8 | **CLIs** (`ufw-nft`, `ufwctl`, `firewall`) | local root | root | re-exec under sudo with one prompt; `revert`/`trial` lockout-safety | n/a |
| 9 | **Licensing: `activate` / `validate` edge functions** | public internet (verify_jwt=false) | service role (server-side) | authenticate the key value; node-lock; every call audited; no DB access beyond the functions | ❌ |
| 10 | **Licensing: `admin` edge function** | public internet (verify_jwt=true) | service role | requires Supabase Auth JWT **and** `admin_users` allowlist; browser never touches license tables (RLS deny-all) | ❌ |
| 11 | **Licensing client** (`firewall license *`) | local root | root | machine id sent as salted SHA-256 (raw id never leaves); store root-only `0600`; token is a deterrent (HMAC) | n/a |
| 12 | **`.deb` maintainer scripts** (postinst/prerm/postrm) | install/remove time | root | idempotent; DKMS build is best-effort and never aborts install; purge scoped to package dirs | ❌ |
| 13 | **DKMS module build** | install / kernel upgrade | root, invokes compiler on module source | builds only `ufw.ko` via Kbuild (`modules` target), not the eBPF `all`; fails soft (packet layer keeps working); Secure Boot fails closed | ❌ |

## Notes on the highest-risk rows

- **#1 is the one that matters most.** It is the only place attacker-controlled
  bytes are parsed in the kernel. It is opt-in (the module is off by default),
  fuzzed, and mirrored by a memory-safe Rust twin — but **not externally
  audited**, which is the single biggest gap between this being "hardened" and
  "trustworthy for a fleet."
- **#5/#6** assume the loopback trust zone is trusted. If it isn't (shared host,
  multiple local users), treat console/daemon access as privileged and use the
  mTLS build.
- **#9/#10** are internet-facing. Their defense is that the sensitive tables are
  unreachable except through the service role inside the functions, and `admin`
  is doubly gated (JWT + allowlist).

## Reducing your own surface

- Don't build the kernel module unless you need identity/DPI enforcement (#1,
  #2, #7, #13 all disappear).
- Keep the console and daemon on loopback; reach them via SSH tunnel.
- Rotate `fleet_secret`; never expose the Supabase service-role key.
- Verify the published SHA-256 of the `.deb` until signed releases land.
