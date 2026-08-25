// Client for the admin dashboard (route #admin).
//
// The browser never touches the licenses table — RLS denies it. Everything
// goes through the `admin` edge function, which re-checks that the signed-in
// email is in admin_users before doing anything. Auth is Supabase email +
// password; supabase-js attaches the session JWT to functions.invoke calls
// automatically.

import { supabase, isSupabaseConfigured } from "./supabase";

export { isSupabaseConfigured };

export interface License {
  id: string;
  license_key: string;
  plan: string;
  customer_email: string | null;
  status: string;
  effective_status?: string;
  expires_at: string;
  machine_id: string | null;
  machine_label: string | null;
  activated_at: string | null;
  last_seen_at: string | null;
  notes: string | null;
  created_at: string;
}

export interface ActivationEvent {
  id: string;
  kind: string;
  machine_id: string | null;
  machine_label: string | null;
  reason: string | null;
  ip: string | null;
  created_at: string;
}

export interface Session {
  email: string | null;
}

function ensure() {
  if (!supabase) throw new Error("Backend not configured — set VITE_SUPABASE_* in .env.local.");
  return supabase;
}

export async function currentEmail(): Promise<string | null> {
  if (!supabase) return null;
  const { data } = await supabase.auth.getUser();
  return data.user?.email ?? null;
}

export async function signIn(email: string, password: string): Promise<void> {
  const sb = ensure();
  const { error } = await sb.auth.signInWithPassword({ email, password });
  if (error) throw new Error(error.message);
}

export async function signOut(): Promise<void> {
  if (!supabase) return;
  await supabase.auth.signOut();
}

/** Invoke the admin edge function with the signed-in user's JWT. */
async function call<T = unknown>(action: string, args: Record<string, unknown> = {}): Promise<T> {
  const sb = ensure();
  // Attach the signed-in user's access token explicitly. Without this, a stale
  // or unset functions-client auth header could send the anon key, which the
  // admin function rejects as "not an admin" (403).
  const {
    data: { session },
  } = await sb.auth.getSession();
  if (!session) throw new Error("You are signed out — please sign in again.");

  const { data, error } = await sb.functions.invoke("admin", {
    body: { action, ...args },
    headers: { Authorization: `Bearer ${session.access_token}` },
  });
  if (error) {
    // supabase-js wraps non-2xx as FunctionsHttpError; surface the JSON reason.
    const ctx = (error as { context?: Response }).context;
    const status = ctx?.status;
    let reason = error.message;
    if (ctx && typeof ctx.json === "function") {
      try {
        const j = await ctx.json();
        reason = j.error ?? j.reason ?? reason;
      } catch {
        /* keep the default message */
      }
    }
    if (status === 403 || reason === "forbidden") {
      const who = session.user.email ?? "this account";
      throw new Error(
        `${who} is not an admin. Add its exact email to the admin_users table in Supabase, then retry.`,
      );
    }
    throw new Error(reason);
  }
  return data as T;
}

export async function listLicenses(): Promise<License[]> {
  const r = await call<{ licenses: License[] }>("list");
  return r.licenses ?? [];
}

export async function licenseEvents(licenseId: string): Promise<ActivationEvent[]> {
  const r = await call<{ events: ActivationEvent[] }>("events", { license_id: licenseId });
  return r.events ?? [];
}

export async function generateLicense(input: {
  plan: string;
  customer_email?: string;
  months: number;
  notes?: string;
}): Promise<License> {
  const r = await call<{ license: License }>("generate", input);
  return r.license;
}

export type LicenseAction = "suspend" | "block" | "reactivate" | "release";

export async function actOnLicense(action: LicenseAction, id: string): Promise<License> {
  const r = await call<{ license: License }>(action, { id });
  return r.license;
}

export async function extendLicense(id: string, months: number): Promise<License> {
  const r = await call<{ license: License }>("extend", { id, months });
  return r.license;
}
