# Server-role policies

The baselines in `policies/base/` and the hardening profiles in
`policies/hardening/` describe a **workstation**: a host that initiates
connections and accepts almost none. A server is the opposite shape — it
exists to be connected to — and that inverts how the policy reads. The
deliberate openings are on the inbound side, and every one of them is a named
service, not a relaxation of the default.

These two policies are worked examples of that inversion. They are meant to be
read, adapted, and renamed for a real deployment — the addresses, ports, and
application identities are placeholders — not applied as-is.

| Policy | The host it describes | The idea it demonstrates |
| --- | --- | --- |
| [`web_server.yaml`](web_server.yaml) | A public HTTP/HTTPS server | Open service ports that stay **inspectable**, identity-gated egress, and an inbound IPS on the exposed listener |
| [`database_server.yaml`](database_server.yaml) | A data-tier host | **Source-scoped** inbound (only the app tier may connect) and near-zero egress — segmentation as the primary control |

## The two mechanisms worth taking away

**`allow-inspect` is how you open a port without going blind on it.** A plain
`allow` at the packet stage is terminal: the connection is permitted and no
later stage runs, so a stream-layer IPS never sees the traffic. `allow-inspect`
permits the connection *provisionally* and lets evaluation continue, so an
`on_match: deny` at the stream stage can still stop an exploit riding that
permitted connection. `web_server.yaml` opens 80/443 with `allow-inspect`
precisely so the inbound web IPS has something to inspect. This is the one
knob that makes "open to the world but not defenceless" expressible.

**The terminal is `defaults.action: deny`, not a catch-all `deny` rule.**
`hardening/zero_trust.yaml` ends with an explicit `deny-unnamed` at the stream
stage, and it can, because every flow it permits is terminal — nothing legitimate
is still provisional by the time evaluation reaches the stream stage. A server
that uses `allow-inspect` for its inbound service *does* have a legitimate,
still-provisional flow reaching the stream stage: the clean web request. A
blanket stream deny would catch it and deny every page load. So these policies
lean on the default action as the terminal — a provisional allow that no stream
rule overrides stands, and everything unnamed falls to the default. Copying the
`deny-unnamed` idiom from the zero-trust file into a server policy is the most
likely way to break it.

## What these policies are not

They are a **host-layer** control: which ports are open, to whom, and a catch
for the handful of inbound exploitation primitives that are unambiguous on the
wire (see `sig-rules/exploits/web_attacks.yaml`). They are **not** a web
application firewall, DDoS mitigation, or a CDN — those live in front of the
origin and are a different class of system. Where the host layer ends and those
begin is set out in
[`docs/design/protection_roadmap.md`](../../docs/design/protection_roadmap.md).

## Verifying a change

Both policies compile and pass cross-platform equivalence, and CI holds them to
it (`the_example_policies_shipped_with_the_project_all_compile` and
`the_shipped_policies_are_all_verified`). After editing, check locally:

```sh
ufwctl policy validate policies/server/web_server.yaml
ufwctl policy explain  policies/server/web_server.yaml tcp:203.0.113.9:443:in
```

Note the explain limitation: it evaluates a bare 5-tuple with a fixed source
address, so it cannot exercise a *source-scoped* inbound rule (like the
database server's app-tier restriction) or simulate a DPI signature match.
Inspect the generated artifact to confirm those compiled as intended:

```sh
ufwctl policy compile policies/server/database_server.yaml --platform linux --out /tmp/db
grep postgres /tmp/db/linux/ufw.nft   # saddr scoped to the app tier
```
