# Unified Firewall — marketing website

A React + TypeScript single-page marketing site for Unified Firewall, styled as a
dark security operations console: animated packet-flow hero, a live threat feed,
identity/detection/fleet capabilities, per-host pricing, and platform
availability (Linux live; Windows & macOS "coming soon" with a waitlist).

Backend is **Supabase** — the coming-soon **waitlist** and sales **leads** are
stored there. The site renders and animates fully without a backend; only the
submit actions need one, and they say so when it's missing.

## Stack

- **Vite + React 18 + TypeScript**
- **Tailwind CSS** (custom tactical-console theme)
- **@supabase/supabase-js** (write-only anon inserts, RLS-protected)
- Canvas hero + IntersectionObserver reveals — no animation library, respects
  `prefers-reduced-motion`

## Run it

```sh
cd website
npm install
cp .env.example .env.local     # then fill in your Supabase anon key
npm run dev                    # http://localhost:5173
```

Build for production:

```sh
npm run build      # tsc typecheck + vite build → dist/
npm run preview    # serve the build locally
```

## Supabase setup

1. **Env** — copy `.env.example` → `.env.local` and set:
   - `VITE_SUPABASE_URL` (default: `https://bpcylnfjdsjouqoezbpa.supabase.co`)
   - `VITE_SUPABASE_ANON_KEY` — from Supabase → Project Settings → API
2. **Schema** — apply `supabase/migrations/0001_init.sql` (SQL editor, the
   Supabase CLI, or the MCP server below). It creates two tables:
   - `waitlist (email, platform)` — coming-soon notify signups
   - `leads (email, company, plan, message)` — pricing / contact interest

   Both have Row-Level Security **on** with an **insert-only** policy for the
   `anon` role: the browser can add a row but can never read the table back, so
   a visitor's email is never exposed to the next visitor. Read them from the
   Supabase dashboard or a server-side service-role key.

### MCP server (for AI-assisted development)

The repo root's `.mcp.json` already registers the Supabase MCP server (project
scope). To use it:

```sh
# from the repo root, in a real terminal (not an IDE extension):
claude /mcp        # select "supabase", then Authenticate
```

Optionally add the Supabase agent skills:

```sh
npx skills add supabase/agent-skills
```

Authentication is an interactive browser OAuth flow, so it has to be run by you
locally — it can't be completed in a headless/CI session.

## The Linux download (.deb)

The "Download for Linux" buttons serve a real Debian package straight from the
site — `public/downloads/unified-firewall_<ver>_<arch>.deb` (checksum alongside
it). Because it lives under `public/`, `vite build` copies it into `dist/` and a
static host serves it directly; the site links to the file, not to a repo.

Rebuild the package (from the repo root) after changing the binaries or bumping
the version, then refresh the copy here:

```sh
sh build/linux/build-deb.sh                       # -> dist/unified-firewall_<ver>_<arch>.deb
cp dist/unified-firewall_*_amd64.deb website/public/downloads/
sha256sum website/public/downloads/unified-firewall_*_amd64.deb   # update LINUX_DEB in src/lib/content.ts
```

The package installs `ufw-nft`, `ufwctl`, `ufw-daemon`, `ufw-waf` and the
`firewall` wrapper to `/usr/bin`, the systemd units, and monitor-mode config —
and starts in monitor mode (observes, never blocks). Update `LINUX_DEB` in
`src/lib/content.ts` (version, size, sha256) when you replace the file.

It embeds AppStream metadata (`/usr/share/metainfo/…metainfo.xml`), a
machine-readable Apache-2.0 copyright, and a Debian changelog, so a software
centre (GNOME Software, KDE Discover) shows the name, **Apache-2.0 license**, and
**release notes** rather than "Unknown License / No details for this release".

One warning a sideloaded `.deb` always shows — **"Potentially unsafe · provided
by a third party"** — is about *provenance*, not metadata: a software centre
trusts only packages from configured, signed apt repositories. Metadata can't
remove it. To remove it for real, publish through a **signed apt repository** (an
`apt-get update`-able source whose `Release` file is GPG-signed with your key),
or ship a detached signature (`gpg --detach-sign`) with published verification
steps. Both need *your* signing key, so they're a deliberate release step, not
something baked into this build.

## What's real vs. illustrative

The **capabilities** described are the real features of the engine in this repo
(identity filtering, kernel enforcement, IDS/IPS, beaconing detection, SOAR,
signed staged rollout, RBAC + mTLS, zero-dependency build). The **live threat
feed** is an illustrative animation of the *kind* of events the engine
attributes, and the **prices** and the **blocked-threats counter** are
placeholders for this preview — wire them to real figures before launch. No
payment details are collected anywhere on the site.

## Layout

```
website/
  index.html            fonts, favicon, meta
  src/
    main.tsx  App.tsx    entry + composition
    index.css           theme tokens, ground, reveal + focus styles
    lib/
      supabase.ts        client + joinWaitlist() / submitLead()
      content.ts         features, steps, plans, feed lines (edit copy here)
    components/          Nav, Hero, PacketCanvas, ThreatFeed, Features,
                         HowItWorks, Platforms, Pricing, SignupForm, Footer, ui
  supabase/migrations/  0001_init.sql
```
