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
