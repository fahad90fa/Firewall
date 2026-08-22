# Licensing & activation

The site sells **node-locked, time-limited keys**. One key activates **one
machine** for a fixed period (monthly by default). The firewall phones home to
activate and then re-checks periodically; when a key expires — or an admin
suspends or blocks it — the firewall stops enforcing and reverts the machine to
unprotected, with a warning (that revert lives in the Rust agent; see
[Part 2](#part-2--the-firewall-side) below).

Everything money-and-access lives **server-side**. The browser never touches the
license tables — Row-Level Security denies it — so the only way in is through
three Supabase Edge Functions that act with the service role.

```
  buyer's machine                  Supabase (edge, service-role)        admin
  ───────────────                  ─────────────────────────────       ─────
  firewall activate ─ key,mid ──▶  activate  ─┐
  firewall validate ─ key,mid ──▶  validate  ─┼─▶  licenses  ◀── admin (#admin)
       (periodic)                             │    activation_events
                              signed token ◀──┘    admin_users
```

## What's in this repo

| Path | What it is |
| --- | --- |
| `supabase/migrations/0002_licensing.sql` | `licenses`, `activation_events`, `admin_users` tables. RLS on, **no** anon/authenticated policies → service-role only. |
| `supabase/functions/activate/` | First activation. Node-locks the key to the calling machine; refuses a second machine. |
| `supabase/functions/validate/` | Periodic re-check. Same rules, never creates a binding; refreshes `last_seen_at`. |
| `supabase/functions/admin/` | The admin dashboard's backend. Requires a signed-in email listed in `admin_users`. |
| `supabase/functions/_shared/util.ts` | Shared helpers (service client, key generation, HMAC token, admin check). |
| `src/components/AdminPage.tsx` + `src/lib/admin.ts` | The `#admin` console — list, generate, suspend, block, reactivate, extend, release. |

## Security model

- **Service role never reaches the browser.** All privileged reads/writes happen
  inside the edge functions. The public site only calls them.
- **RLS denies by default.** The three tables have RLS enabled and zero
  policies, so every anon/authenticated key is refused; only the service role
  (used inside the functions) can touch them.
- **Admin is gated twice.** Sign-in is Supabase Auth (email + password); the
  `admin` function *also* re-checks the caller's email against `admin_users` on
  every request — a valid login that isn't an admin gets `403`.
- **One key, one machine.** `activate` binds the key to the first machine's id.
  Any other machine is refused (`409 machine_mismatch`). An admin can **Release**
  a key to move it to a new machine.
- **Offline grace, honestly scoped.** The signed token (HMAC-SHA256) lets the
  firewall keep enforcing for a bounded window (72h) between online re-checks, so
  a transient network blip doesn't drop protection. This is a *deterrent*, not
  DRM: the signing secret is symmetric and server-side, and the agent runs on the
  customer's own root machine, so a determined owner can bypass it. Ed25519
  (client verifies, cannot forge) is the documented upgrade if that matters.

## Deploy

Project ref: **`bpcylnfjdsjouqoezbpa`** (region eu-central-1).

**Live now** (applied directly to the project):
- ✅ Migrations `0001_init` + `0002_licensing` — `waitlist`, `leads`, `licenses`,
  `activation_events`, `admin_users`, all with RLS on (the three licensing
  tables have no policies → service-role only).
- ✅ Edge functions deployed and ACTIVE: `activate` and `validate`
  (`verify_jwt=false`), `admin` (`verify_jwt=true`).
- ✅ First admin seeded into `admin_users`.

**Two operator steps remain** — neither can be done from code, and the site is
not fully wired until they are:

1. **Set the signing secret** (server-only; never in the browser). Dashboard →
   **Project Settings → Edge Functions → Secrets → Add**, or:
   ```sh
   supabase secrets set LICENSE_SIGNING_SECRET="$(openssl rand -hex 32)"
   ```
   Until it is set, `activate`/`validate` sign tokens with a weak built-in
   fallback. `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY`
   are injected automatically — do not set those by hand.

2. **Give the seeded admin a password.** The `admin_users` row authorizes the
   email; the person still needs an Auth account to sign in. Dashboard →
   **Authentication → Users → Add user** (tick *Auto Confirm*). Then sign in at
   `/#admin`.

**Point the site at the project** — copy `.env.example` to `.env.local`:
```
VITE_SUPABASE_URL=https://bpcylnfjdsjouqoezbpa.supabase.co
VITE_SUPABASE_ANON_KEY=<anon public key>   # Dashboard → Project Settings → API → anon/public
```
Until these are set, `/#admin` shows a "Backend not configured" notice instead
of the console.

### Re-deploying from source

The committed `supabase/migrations/*` and `supabase/functions/*` are the source
of truth. To reproduce or update the deployment with the CLI:
```sh
supabase link --project-ref bpcylnfjdsjouqoezbpa
supabase db push                       # migrations
supabase functions deploy activate     # + validate, admin
```
The `config.toml` pins `verify_jwt=false` for `activate`/`validate` and
`verify_jwt=true` for `admin`.

## The admin console (`/#admin`)

- **Generate** a key: pick plan + duration (months) + optional buyer email/notes;
  the key is shown once — copy it and send it to the customer.
- Each row shows **who bought it, which machine it's bound to, its status, expiry,
  and when it was last seen** phoning home. Expand **activity** for the audit
  trail (`activate` / `validate` / `reject` with reason + IP).
- Per-key actions: **Suspend** (reversible pause), **Block** (hard kill),
  **Resume/Unblock**, **+1 mo** (extend), **Release** (clear the machine binding
  so the key can move).

## Part 2 — the firewall side (implemented)

The Rust agent (`cli/src/bin/ufw-nft/license.rs`) consumes this backend:

- `firewall license activate <KEY>` → `POST /functions/v1/activate` with the key
  and a **salted SHA-256 of `/etc/machine-id`** (the raw id never leaves the
  box), stores the returned signed verdict at `/var/lib/unified-firewall/license.json`
  (root-only, 0600).
- `firewall license status [--refresh]` shows the cached state; `--refresh`
  re-checks online first.
- `firewall license check` → `POST /functions/v1/validate`. A systemd timer
  (`ufw-license-check.timer`, ~every 6h + at boot) runs it; on `expired` /
  `suspended` / `blocked` it **reverts `table inet ufw` and warns**, per the
  product's "revert to unprotected + warn" behaviour. A 72h offline grace window
  means a transient network blip never drops protection on its own.
- `apply`, `boot-apply` and `trial` are gated: with a valid license they proceed;
  otherwise enforcement is refused (at boot the machine comes up unprotected and
  says so, rather than restoring stale rules).

**Opt-in by construction.** Gating turns on only when
`/etc/unified-firewall/license.conf` exists — the `.deb` ships it, so packaged
installs are gated; a source/CI build has no such file and stays ungated, so the
project's tests and `scripts/live-run.sh` are unaffected.

The `.deb` phones home with `curl` (a declared dependency) and installs the
config template + the re-check timer. Configure `endpoint`/`apikey` in
`license.conf`; deploy the edge functions and set `LICENSE_SIGNING_SECRET` as
above.
