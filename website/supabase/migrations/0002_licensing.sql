-- Unified Firewall — licensing.
--
-- One key activates one machine for a fixed period (monthly). The firewall
-- phones home to activate and to re-check; an admin can suspend or block a key.
--
-- Security model: these tables carry the money-and-access truth, so NOTHING
-- client-facing is allowed to touch them. RLS is ON with **no anon/authenticated
-- policies**, which denies every browser key by default — only the service role
-- (used exclusively inside the edge functions in supabase/functions/) can read
-- or write. The public site never queries these directly; it calls the edge
-- functions, which validate and act with the service role.

-- ---------------------------------------------------------------------------
-- licenses
-- ---------------------------------------------------------------------------
create table if not exists public.licenses (
  id            uuid primary key default gen_random_uuid(),
  license_key   text not null unique,
  plan          text not null default 'pro' check (plan in ('community', 'pro', 'enterprise')),
  customer_email text,
  -- lifecycle
  status        text not null default 'active'
                  check (status in ('active', 'suspended', 'blocked', 'expired')),
  expires_at    timestamptz not null,
  -- node-lock: bound to the first machine that activates it, then fixed
  machine_id    text,
  machine_label text,
  activated_at  timestamptz,
  last_seen_at  timestamptz,
  -- bookkeeping
  notes         text,
  created_at    timestamptz not null default now()
);

alter table public.licenses enable row level security;
-- No policies on purpose: only the service role (edge functions) may access it.

create index if not exists licenses_status_idx  on public.licenses (status, expires_at);
create index if not exists licenses_email_idx   on public.licenses (customer_email);
create index if not exists licenses_machine_idx on public.licenses (machine_id);

-- ---------------------------------------------------------------------------
-- activation_events — an audit trail of every activate / validate / rejection
-- ---------------------------------------------------------------------------
create table if not exists public.activation_events (
  id          uuid primary key default gen_random_uuid(),
  license_id  uuid references public.licenses (id) on delete set null,
  license_key text,
  kind        text not null check (kind in ('activate', 'validate', 'reject')),
  machine_id  text,
  machine_label text,
  reason      text,
  ip          text,
  created_at  timestamptz not null default now()
);

alter table public.activation_events enable row level security;
-- No policies: service role only.

create index if not exists activation_events_license_idx on public.activation_events (license_id, created_at desc);

-- ---------------------------------------------------------------------------
-- admin_users — who may drive the admin dashboard (checked inside the `admin`
-- edge function against the caller's authenticated email)
-- ---------------------------------------------------------------------------
create table if not exists public.admin_users (
  email      text primary key,
  created_at timestamptz not null default now()
);

alter table public.admin_users enable row level security;
-- No policies: service role only. Seed the first admin from the SQL editor:
--   insert into public.admin_users (email) values ('you@example.com');

-- Convenience: mark a license expired the moment it is read past its date.
create or replace function public.license_effective_status(l public.licenses)
returns text
language sql
stable
as $$
  select case
    when l.status in ('suspended', 'blocked') then l.status
    when l.expires_at < now() then 'expired'
    else l.status
  end;
$$;
