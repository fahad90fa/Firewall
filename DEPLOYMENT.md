# Deployment

How the paid product ships end to end: a Supabase backend (licensing +
activation), a Vercel-hosted marketing/admin site, and the `.deb` that installs
the firewall on a customer's machine.

```
  customer's Linux box            Supabase (bpcylnfjdsjouqoezbpa)        you
  ────────────────────            ──────────────────────────────       ───
  install .deb  ───────────┐      activate / validate  ─┐
  firewall license activate│─────▶  edge functions      ├─▶ licenses      admin
  firewall license check   │      (service role)        │   activation_events
        (systemd timer) ───┘                            └── admin_users ◀── /#admin
                                                                          (Vercel site)
```

Nothing secret lives in this repo. The Supabase **anon key** is committed on
purpose — it is public by design (protected by Row-Level Security, not secrecy).
The **service-role key**, the **`LICENSE_SIGNING_SECRET`**, and any **license
keys** are set in the Supabase dashboard and never committed.

---

## 1. Backend — Supabase (already live)

Project ref **`bpcylnfjdsjouqoezbpa`** (region eu-central-1).

Deployed and verified:
- Migrations `0001_init` + `0002_licensing` — `waitlist`, `leads`, `licenses`,
  `activation_events`, `admin_users`; all RLS-on (the three licensing tables
  have no policies → service-role only).
- Edge functions **ACTIVE**: `activate` & `validate` (`verify_jwt=false`,
  machine-facing), `admin` (`verify_jwt=true`, people-facing).
- First admin seeded into `admin_users`.

Two operator steps (Supabase dashboard — cannot be done from code):

1. **Signing secret.** Project Settings → Edge Functions → Secrets → add
   `LICENSE_SIGNING_SECRET` = a long random value
   (`openssl rand -hex 32`). Until set, tokens sign with a weak fallback.
2. **Admin password.** Authentication → Users → Add user →
   `metaversefilix@gmail.com` + a password + *Auto Confirm*. (The `admin_users`
   row only authorizes the email; this gives it a login.)

Re-deploy from source (the committed `website/supabase/*` is the source of
truth):

```sh
supabase link --project-ref bpcylnfjdsjouqoezbpa
supabase db push                                  # migrations
supabase functions deploy activate                # + validate, admin
```

`config.toml` pins `verify_jwt=false` for activate/validate and `true` for
admin. Full detail: [`website/LICENSING.md`](website/LICENSING.md).

---

## 2. Frontend — Vercel

The site (`website/`) is a Vite + React SPA with hash routing (`#admin`,
`#download`). `website/vercel.json` and `website/.env.production` make it deploy
with zero configuration.

1. [vercel.com](https://vercel.com) → sign in with GitHub → **Add New → Project**.
2. **Import** `fahad90fa/Firewall`.
3. Set **Root Directory = `website`** — the one required setting.
4. Framework auto-detects **Vite**. No environment variables needed (the public
   Supabase values are baked in; add `VITE_SUPABASE_URL` / `VITE_SUPABASE_ANON_KEY`
   in Vercel only to override).
5. **Deploy.**

After deploy:

| Route | Purpose |
| --- | --- |
| `/` | Landing page |
| `/#download` | Download the `.deb` (served static from `/downloads/…`) |
| `/#admin` | Admin console — sign in with the admin email + password |

Custom domain: Vercel → Project → Settings → Domains.

---

## 3. The firewall `.deb`

Built by [`build/linux/build-deb.sh`](build/linux/build-deb.sh) and served from
the site at `/downloads/unified-firewall_<version>_amd64.deb`. On install it runs
in monitor mode; **enforcement requires an activated license** (gating is on
because the package ships `/etc/unified-firewall/license.conf`).

```sh
sudo apt install ./unified-firewall_0.1.0_amd64.deb
sudo firewall license activate <KEY>       # node-locks this machine
firewall license status
sudo firewall apply default_allow          # enforce once activated
```

A systemd timer re-checks the license periodically; on expiry / suspend / block
it reverts the nftables table (monitor-only) and warns.

---

## 4. End-to-end smoke test

1. Deploy the site (§2). Open `/#admin`, sign in.
2. Generate a key in the console (or use one already listed).
3. On a Linux box: install the `.deb` from `/#download`, then
   `sudo firewall license activate <KEY>`.
4. Back in `/#admin`, the key shows the bound machine and a fresh **last-seen** —
   the loop works. Try **Suspend**/**Block** and run `firewall license check` on
   the box to see enforcement revert.
