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

> The Supabase MCP server in `.mcp.json` is **not authenticated in this
> environment**, so migrations and functions were authored here but must be
> deployed by you with the Supabase CLI (or dashboard).

1. **Apply the migrations**
   ```sh
   supabase link --project-ref bpcylnfjdsjouqoezbpa
   supabase db push          # applies 0001_init.sql + 0002_licensing.sql
   ```

2. **Set the function secrets** (server-only; never in the browser)
   ```sh
   # a strong random value — this signs activation tokens
   supabase secrets set LICENSE_SIGNING_SECRET="$(openssl rand -hex 32)"
   ```
   `SUPABASE_URL`, `SUPABASE_ANON_KEY`, and `SUPABASE_SERVICE_ROLE_KEY` are
   injected into the function runtime automatically — do not set them by hand.

3. **Deploy the functions**
   ```sh
   supabase functions deploy activate
   supabase functions deploy validate
   supabase functions deploy admin
   ```

4. **Seed the first admin** (SQL editor or `psql`)
   ```sql
   insert into public.admin_users (email) values ('you@example.com');
   ```
   Then create that user in **Authentication → Users** with a password. Sign in
   at `/#admin`.

5. **Point the site at the project** — copy `.env.example` to `.env.local`:
   ```
   VITE_SUPABASE_URL=https://bpcylnfjdsjouqoezbpa.supabase.co
   VITE_SUPABASE_ANON_KEY=<anon public key>
   ```
   Until these are set, `/#admin` shows a "Backend not configured" notice
   instead of the console.

## The admin console (`/#admin`)

- **Generate** a key: pick plan + duration (months) + optional buyer email/notes;
  the key is shown once — copy it and send it to the customer.
- Each row shows **who bought it, which machine it's bound to, its status, expiry,
  and when it was last seen** phoning home. Expand **activity** for the audit
  trail (`activate` / `validate` / `reject` with reason + IP).
- Per-key actions: **Suspend** (reversible pause), **Block** (hard kill),
  **Resume/Unblock**, **+1 mo** (extend), **Release** (clear the machine binding
  so the key can move).

## Part 2 — the firewall side

The Rust agent consumes this backend:

- `firewall license activate <KEY>` → `POST /functions/v1/activate` with the key
  and a stable machine id (`/etc/machine-id`), stores the returned signed token.
- A periodic re-check → `POST /functions/v1/validate`; on `expired` / `suspended`
  / `blocked` (or a token past its grace window with no reachable server), the
  agent **reverts the nftables table and warns**, per the product's
  "revert to unprotected + warn" behaviour.
- `apply` / boot-apply are gated on a currently-valid license.

That agent-side wiring is tracked separately from this website change.
