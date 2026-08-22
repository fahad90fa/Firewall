-- Unified Firewall — marketing site schema.
--
-- Two write-only tables the public site inserts into with the anon key:
--   waitlist — "notify me when macOS / Windows ships"
--   leads    — plan interest / demo / contact requests
--
-- Row-Level Security is ON and the only public grant is INSERT. The anonymous
-- key can add a row but can never read the table back, so an email address a
-- visitor submits is not exposed to the next visitor. Reading is done from the
-- Supabase dashboard or a server-side service-role key, never the browser.

-- ---------------------------------------------------------------------------
-- waitlist
-- ---------------------------------------------------------------------------
create table if not exists public.waitlist (
  id         uuid primary key default gen_random_uuid(),
  email      text not null check (position('@' in email) > 1 and length(email) <= 320),
  platform   text not null check (platform in ('linux', 'macos', 'windows')),
  created_at timestamptz not null default now(),
  unique (email, platform)
);

alter table public.waitlist enable row level security;

drop policy if exists "anon can join waitlist" on public.waitlist;
create policy "anon can join waitlist"
  on public.waitlist for insert
  to anon
  with check (
    position('@' in email) > 1
    and length(email) <= 320
    and platform in ('linux', 'macos', 'windows')
  );

-- ---------------------------------------------------------------------------
-- leads
-- ---------------------------------------------------------------------------
create table if not exists public.leads (
  id         uuid primary key default gen_random_uuid(),
  email      text not null check (position('@' in email) > 1 and length(email) <= 320),
  company    text check (length(company) <= 200),
  plan       text check (length(plan) <= 60),
  message    text check (length(message) <= 4000),
  created_at timestamptz not null default now()
);

alter table public.leads enable row level security;

drop policy if exists "anon can submit lead" on public.leads;
create policy "anon can submit lead"
  on public.leads for insert
  to anon
  with check (position('@' in email) > 1 and length(email) <= 320);

-- Helpful indexes for whoever reads these from the dashboard.
create index if not exists waitlist_platform_idx on public.waitlist (platform, created_at desc);
create index if not exists leads_created_idx on public.leads (created_at desc);
