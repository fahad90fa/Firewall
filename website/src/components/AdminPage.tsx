import { useCallback, useEffect, useMemo, useState, type FormEvent, type ReactNode } from "react";
import { Button, Label, ShieldMark } from "./ui";
import {
  actOnLicense,
  currentEmail,
  extendLicense,
  generateLicense,
  isSupabaseConfigured,
  licenseEvents,
  listLicenses,
  signIn,
  signOut,
  type ActivationEvent,
  type License,
} from "../lib/admin";

/**
 * The admin console (route `#admin`). Shows every license — who bought it, on
 * which machine, its status and expiry — and lets an authenticated admin mint
 * keys and suspend / block / reactivate / release them. All privileged work
 * happens in the `admin` edge function; this page only presents it.
 */
export default function AdminPage() {
  const [email, setEmail] = useState<string | null>(null);
  const [checking, setChecking] = useState(true);

  useEffect(() => {
    let alive = true;
    currentEmail()
      .then((e) => alive && setEmail(e))
      .finally(() => alive && setChecking(false));
    return () => {
      alive = false;
    };
  }, []);

  if (!isSupabaseConfigured) return <Shell><NotConfigured /></Shell>;
  if (checking) return <Shell><Centered>Checking session…</Centered></Shell>;
  if (!email) return <Shell><LoginCard onSignedIn={setEmail} /></Shell>;
  return <Shell><Console email={email} onSignOut={() => setEmail(null)} /></Shell>;
}

function Shell({ children }: { children: ReactNode }) {
  return <div className="mx-auto max-w-content px-5 pb-24 pt-28">{children}</div>;
}

function Centered({ children }: { children: ReactNode }) {
  return <div className="py-24 text-center font-mono text-sm text-muted">{children}</div>;
}

function NotConfigured() {
  return (
    <div className="mx-auto max-w-lg rounded-2xl border border-warn/30 bg-panel p-8 text-center">
      <Label tone="threat">ADMIN</Label>
      <h1 className="mt-4 font-display text-2xl font-bold text-ink">Backend not configured</h1>
      <p className="mt-3 text-sm leading-relaxed text-muted">
        Set <span className="font-mono text-ink">VITE_SUPABASE_URL</span> and{" "}
        <span className="font-mono text-ink">VITE_SUPABASE_ANON_KEY</span>, deploy the migrations and
        the <span className="font-mono text-ink">activate / validate / admin</span> edge functions, then
        add your email to <span className="font-mono text-ink">admin_users</span>.
      </p>
    </div>
  );
}

function LoginCard({ onSignedIn }: { onSignedIn: (email: string) => void }) {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState<string | null>(null);

  async function submit(e: FormEvent) {
    e.preventDefault();
    setBusy(true);
    setErr(null);
    try {
      await signIn(email.trim(), password);
      const who = await currentEmail();
      onSignedIn(who ?? email.trim());
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Sign-in failed");
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="mx-auto max-w-md rounded-2xl border border-line bg-panel p-8 shadow-panel">
      <div className="flex items-center gap-3">
        <ShieldMark className="h-8 w-8" />
        <div>
          <Label>ADMIN CONSOLE</Label>
          <h1 className="mt-1 font-display text-2xl font-bold text-ink">Sign in</h1>
        </div>
      </div>
      <form onSubmit={submit} className="mt-6 space-y-3">
        <Field label="Email" type="email" value={email} onChange={setEmail} autoComplete="username" />
        <Field label="Password" type="password" value={password} onChange={setPassword} autoComplete="current-password" />
        {err && <p className="font-mono text-xs text-threat">{err}</p>}
        <Button type="submit" disabled={busy} className="w-full">
          {busy ? "Signing in…" : "Sign in"}
        </Button>
      </form>
      <p className="mt-5 font-mono text-[11px] leading-relaxed text-muted/70">
        Access is limited to emails listed in <span className="text-ink">admin_users</span>. Sign-in uses
        Supabase Auth; the license tables are never exposed to the browser.
      </p>
    </div>
  );
}

function Console({ email, onSignOut }: { email: string; onSignOut: () => void }) {
  const [rows, setRows] = useState<License[] | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [q, setQ] = useState("");
  const [busyId, setBusyId] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setErr(null);
    try {
      setRows(await listLicenses());
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Failed to load");
    }
  }, []);

  useEffect(() => {
    void refresh();
  }, [refresh]);

  const filtered = useMemo(() => {
    if (!rows) return null;
    const needle = q.trim().toLowerCase();
    if (!needle) return rows;
    return rows.filter((l) =>
      [l.license_key, l.customer_email, l.machine_label, l.machine_id, l.plan]
        .filter(Boolean)
        .some((v) => String(v).toLowerCase().includes(needle)),
    );
  }, [rows, q]);

  async function act(fn: () => Promise<License>, id: string) {
    setBusyId(id);
    setErr(null);
    try {
      const updated = await fn();
      setRows((prev) => (prev ? prev.map((r) => (r.id === updated.id ? updated : r)) : prev));
    } catch (ex) {
      setErr(ex instanceof Error ? ex.message : "Action failed");
    } finally {
      setBusyId(null);
    }
  }

  const stats = useMemo(() => summarize(rows), [rows]);

  return (
    <div>
      <div className="flex flex-wrap items-end justify-between gap-4">
        <div>
          <Label>ADMIN CONSOLE</Label>
          <h1 className="mt-2 font-display text-3xl font-bold tracking-tight text-ink">Licenses</h1>
          <p className="mt-1 font-mono text-xs text-muted">
            signed in as <span className="text-ink">{email}</span>
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="ghost" onClick={() => void refresh()}>Refresh</Button>
          <Button
            variant="ghost"
            onClick={async () => {
              await signOut();
              onSignOut();
            }}
          >
            Sign out
          </Button>
        </div>
      </div>

      {/* stat strip */}
      <div className="mt-6 grid grid-cols-2 gap-px overflow-hidden rounded-xl border border-line bg-line/60 sm:grid-cols-5">
        <Stat k="Total" v={stats.total} />
        <Stat k="Active" v={stats.active} tone="safe" />
        <Stat k="Suspended" v={stats.suspended} tone="warn" />
        <Stat k="Blocked" v={stats.blocked} tone="threat" />
        <Stat k="Expired" v={stats.expired} tone="muted" />
      </div>

      <GeneratePanel onCreated={(l) => setRows((prev) => (prev ? [l, ...prev] : [l]))} onError={setErr} />

      <div className="mt-8 flex items-center justify-between gap-3">
        <input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Filter by key, email, machine…"
          className="w-full max-w-sm rounded-lg border border-line bg-void/70 px-3 py-2 font-mono text-[13px] text-ink outline-none placeholder:text-muted/50 focus:border-signal/60"
        />
        {filtered && (
          <span className="shrink-0 font-mono text-xs text-muted">{filtered.length} shown</span>
        )}
      </div>

      {err && <p className="mt-4 font-mono text-xs text-threat">{err}</p>}

      <div className="mt-4 space-y-3">
        {filtered === null ? (
          <Centered>Loading licenses…</Centered>
        ) : filtered.length === 0 ? (
          <Centered>No licenses yet. Generate one above.</Centered>
        ) : (
          filtered.map((l) => (
            <LicenseRow
              key={l.id}
              lic={l}
              busy={busyId === l.id}
              onSuspend={() => act(() => actOnLicense("suspend", l.id), l.id)}
              onBlock={() => act(() => actOnLicense("block", l.id), l.id)}
              onReactivate={() => act(() => actOnLicense("reactivate", l.id), l.id)}
              onRelease={() => act(() => actOnLicense("release", l.id), l.id)}
              onExtend={(m) => act(() => extendLicense(l.id, m), l.id)}
            />
          ))
        )}
      </div>
    </div>
  );
}

function GeneratePanel({
  onCreated,
  onError,
}: {
  onCreated: (l: License) => void;
  onError: (msg: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const [plan, setPlan] = useState("pro");
  const [months, setMonths] = useState(1);
  const [customer, setCustomer] = useState("");
  const [notes, setNotes] = useState("");
  const [busy, setBusy] = useState(false);
  const [minted, setMinted] = useState<License | null>(null);
  const [copied, setCopied] = useState(false);

  async function mint() {
    setBusy(true);
    try {
      const lic = await generateLicense({
        plan,
        months,
        customer_email: customer.trim() || undefined,
        notes: notes.trim() || undefined,
      });
      setMinted(lic);
      onCreated(lic);
      setCustomer("");
      setNotes("");
    } catch (ex) {
      onError(ex instanceof Error ? ex.message : "Generate failed");
    } finally {
      setBusy(false);
    }
  }

  async function copyKey() {
    if (!minted) return;
    try {
      await navigator.clipboard.writeText(minted.license_key);
      setCopied(true);
      window.setTimeout(() => setCopied(false), 1400);
    } catch {
      /* ignore */
    }
  }

  return (
    <div className="mt-6 rounded-xl border border-signal/30 bg-panel p-5">
      <button
        onClick={() => setOpen((v) => !v)}
        className="flex w-full items-center justify-between font-display text-base font-semibold text-ink"
      >
        <span className="flex items-center gap-2">
          <span className="text-signal">+</span> Generate a license key
        </span>
        <span className="font-mono text-xs text-muted">{open ? "hide" : "show"}</span>
      </button>

      {open && (
        <div className="mt-5 space-y-4">
          <div className="grid gap-3 sm:grid-cols-4">
            <div>
              <FieldLabel>Plan</FieldLabel>
              <select
                value={plan}
                onChange={(e) => setPlan(e.target.value)}
                className="mt-1 w-full rounded-lg border border-line bg-void/70 px-3 py-2 font-mono text-[13px] text-ink outline-none focus:border-signal/60"
              >
                <option value="community">community</option>
                <option value="pro">pro</option>
                <option value="enterprise">enterprise</option>
              </select>
            </div>
            <div>
              <FieldLabel>Months</FieldLabel>
              <input
                type="number"
                min={1}
                max={60}
                value={months}
                onChange={(e) => setMonths(Math.max(1, Math.min(60, Number(e.target.value) || 1)))}
                className="mt-1 w-full rounded-lg border border-line bg-void/70 px-3 py-2 font-mono text-[13px] text-ink outline-none focus:border-signal/60"
              />
            </div>
            <div className="sm:col-span-2">
              <FieldLabel>Customer email (optional)</FieldLabel>
              <input
                value={customer}
                onChange={(e) => setCustomer(e.target.value)}
                placeholder="buyer@company.com"
                className="mt-1 w-full rounded-lg border border-line bg-void/70 px-3 py-2 font-mono text-[13px] text-ink outline-none placeholder:text-muted/50 focus:border-signal/60"
              />
            </div>
          </div>
          <div>
            <FieldLabel>Notes (optional)</FieldLabel>
            <input
              value={notes}
              onChange={(e) => setNotes(e.target.value)}
              placeholder="order #, reseller, anything"
              className="mt-1 w-full rounded-lg border border-line bg-void/70 px-3 py-2 font-mono text-[13px] text-ink outline-none placeholder:text-muted/50 focus:border-signal/60"
            />
          </div>
          <Button onClick={mint} disabled={busy}>
            {busy ? "Minting…" : "Mint key"}
          </Button>

          {minted && (
            <div className="rounded-lg border border-safe/40 bg-safe/5 p-4">
              <p className="font-mono text-[11px] tracking-wider text-safe">NEW KEY — copy it now</p>
              <div className="mt-2 flex items-center gap-2">
                <code className="flex-1 overflow-x-auto whitespace-nowrap font-mono text-sm text-ink">
                  {minted.license_key}
                </code>
                <button
                  onClick={copyKey}
                  className="shrink-0 rounded-md border border-line px-2.5 py-1 font-mono text-[11px] text-muted hover:border-signal/60 hover:text-signal"
                >
                  {copied ? "copied ✓" : "copy"}
                </button>
              </div>
              <p className="mt-2 font-mono text-[11px] text-muted">
                {minted.plan} · expires {fmtDate(minted.expires_at)} · not yet bound to a machine
              </p>
            </div>
          )}
        </div>
      )}
    </div>
  );
}

function LicenseRow({
  lic,
  busy,
  onSuspend,
  onBlock,
  onReactivate,
  onRelease,
  onExtend,
}: {
  lic: License;
  busy: boolean;
  onSuspend: () => void;
  onBlock: () => void;
  onReactivate: () => void;
  onRelease: () => void;
  onExtend: (months: number) => void;
}) {
  const [showEvents, setShowEvents] = useState(false);
  const status = lic.effective_status ?? lic.status;

  return (
    <div className="rounded-xl border border-line bg-panel p-4">
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div className="min-w-0">
          <div className="flex items-center gap-2.5">
            <StatusPill status={status} />
            <code className="font-mono text-sm text-ink">{lic.license_key}</code>
            <span className="font-mono text-[11px] text-muted">{lic.plan}</span>
          </div>
          <div className="mt-2 grid gap-x-6 gap-y-1 font-mono text-[12px] text-muted sm:grid-cols-2">
            <Kv k="buyer" v={lic.customer_email ?? "—"} />
            <Kv k="expires" v={fmtDate(lic.expires_at)} />
            <Kv k="machine" v={lic.machine_label ?? lic.machine_id ?? "not activated"} />
            <Kv k="last seen" v={lic.last_seen_at ? fmtRel(lic.last_seen_at) : "never"} />
          </div>
          {lic.machine_id && (
            <p className="mt-1 break-all font-mono text-[10px] text-muted/50">id {lic.machine_id}</p>
          )}
        </div>

        <div className="flex flex-wrap items-center gap-1.5">
          {status === "active" && <Action label="Suspend" tone="warn" onClick={onSuspend} busy={busy} />}
          {status === "suspended" && <Action label="Resume" tone="safe" onClick={onReactivate} busy={busy} />}
          {status !== "blocked" ? (
            <Action label="Block" tone="threat" onClick={onBlock} busy={busy} />
          ) : (
            <Action label="Unblock" tone="safe" onClick={onReactivate} busy={busy} />
          )}
          <Action label="+1 mo" tone="signal" onClick={() => onExtend(1)} busy={busy} />
          {lic.machine_id && <Action label="Release" tone="muted" onClick={onRelease} busy={busy} />}
        </div>
      </div>

      <button
        onClick={() => setShowEvents((v) => !v)}
        className="mt-3 font-mono text-[11px] text-muted/70 hover:text-signal"
      >
        {showEvents ? "▾ hide activity" : "▸ activity"}
      </button>
      {showEvents && <EventList licenseId={lic.id} />}
    </div>
  );
}

function EventList({ licenseId }: { licenseId: string }) {
  const [events, setEvents] = useState<ActivationEvent[] | null>(null);
  const [err, setErr] = useState<string | null>(null);

  useEffect(() => {
    let alive = true;
    licenseEvents(licenseId)
      .then((e) => alive && setEvents(e))
      .catch((ex) => alive && setErr(ex instanceof Error ? ex.message : "failed"));
    return () => {
      alive = false;
    };
  }, [licenseId]);

  if (err) return <p className="mt-2 font-mono text-[11px] text-threat">{err}</p>;
  if (!events) return <p className="mt-2 font-mono text-[11px] text-muted">loading…</p>;
  if (events.length === 0) return <p className="mt-2 font-mono text-[11px] text-muted">no activity yet</p>;

  return (
    <div className="mt-2 space-y-1 rounded-lg border border-line bg-void/40 p-3">
      {events.map((e) => (
        <div key={e.id} className="flex flex-wrap items-center gap-x-3 font-mono text-[11px]">
          <span className={eventColor(e.kind)}>{e.kind}</span>
          <span className="text-muted">{fmtDate(e.created_at, true)}</span>
          {e.reason && <span className="text-muted/70">{e.reason}</span>}
          {e.ip && <span className="text-muted/50">{e.ip}</span>}
        </div>
      ))}
    </div>
  );
}

/* ---------- small pieces ---------- */

function Field({
  label,
  type,
  value,
  onChange,
  autoComplete,
}: {
  label: string;
  type: string;
  value: string;
  onChange: (v: string) => void;
  autoComplete?: string;
}) {
  return (
    <label className="block">
      <FieldLabel>{label}</FieldLabel>
      <input
        type={type}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        autoComplete={autoComplete}
        required
        className="mt-1 w-full rounded-lg border border-line bg-void/70 px-3 py-2.5 font-mono text-[13px] text-ink outline-none focus:border-signal/60"
      />
    </label>
  );
}

function FieldLabel({ children }: { children: ReactNode }) {
  return <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-muted">{children}</span>;
}

function Stat({ k, v, tone = "signal" }: { k: string; v: number; tone?: string }) {
  const c =
    tone === "safe" ? "text-safe" : tone === "warn" ? "text-warn" : tone === "threat" ? "text-threat" : tone === "muted" ? "text-muted" : "text-signal";
  return (
    <div className="bg-panel px-4 py-3">
      <div className="font-mono text-[10px] uppercase tracking-[0.16em] text-muted">{k}</div>
      <div className={`mt-0.5 font-display text-2xl font-bold ${c}`}>{v}</div>
    </div>
  );
}

function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div className="flex gap-2">
      <span className="text-muted/60">{k}</span>
      <span className="min-w-0 truncate text-ink/90">{v}</span>
    </div>
  );
}

function StatusPill({ status }: { status: string }) {
  const map: Record<string, string> = {
    active: "border-safe/40 bg-safe/10 text-safe",
    suspended: "border-warn/40 bg-warn/10 text-warn",
    blocked: "border-threat/40 bg-threat/10 text-threat",
    expired: "border-line bg-line/30 text-muted",
  };
  return (
    <span className={`rounded-full border px-2.5 py-0.5 font-mono text-[10px] font-bold uppercase tracking-wider ${map[status] ?? map.expired}`}>
      {status}
    </span>
  );
}

function Action({ label, tone, onClick, busy }: { label: string; tone: string; onClick: () => void; busy: boolean }) {
  const c =
    tone === "safe" ? "hover:border-safe/60 hover:text-safe" :
    tone === "warn" ? "hover:border-warn/60 hover:text-warn" :
    tone === "threat" ? "hover:border-threat/60 hover:text-threat" :
    tone === "muted" ? "hover:border-muted hover:text-ink" :
    "hover:border-signal/60 hover:text-signal";
  return (
    <button
      onClick={onClick}
      disabled={busy}
      className={`rounded-md border border-line px-2.5 py-1 font-mono text-[11px] text-muted transition-colors disabled:opacity-40 ${c}`}
    >
      {label}
    </button>
  );
}

function eventColor(kind: string): string {
  return kind === "activate" ? "text-safe" : kind === "validate" ? "text-signal" : "text-threat";
}

/* ---------- helpers ---------- */

function summarize(rows: License[] | null) {
  const s = { total: 0, active: 0, suspended: 0, blocked: 0, expired: 0 };
  if (!rows) return s;
  s.total = rows.length;
  for (const l of rows) {
    const st = l.effective_status ?? l.status;
    if (st === "active") s.active++;
    else if (st === "suspended") s.suspended++;
    else if (st === "blocked") s.blocked++;
    else if (st === "expired") s.expired++;
  }
  return s;
}

function fmtDate(iso: string, withTime = false): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  const date = d.toISOString().slice(0, 10);
  return withTime ? `${date} ${d.toISOString().slice(11, 16)}` : date;
}

function fmtRel(iso: string): string {
  const then = new Date(iso).getTime();
  if (Number.isNaN(then)) return iso;
  const secs = Math.max(0, (Date.now() - then) / 1000);
  if (secs < 90) return "just now";
  const mins = secs / 60;
  if (mins < 90) return `${Math.round(mins)}m ago`;
  const hrs = mins / 60;
  if (hrs < 36) return `${Math.round(hrs)}h ago`;
  return `${Math.round(hrs / 24)}d ago`;
}
