// POST /functions/v1/admin
//
// The admin dashboard's only backend. Every call must carry a Supabase Auth
// JWT (the admin signed in with email + password); we resolve that to an email
// and require it to be listed in admin_users before doing anything. All data
// access is via the service role, so the browser never touches the licenses
// table directly.
//
// Body: { action, ...args }. Actions:
//   list        — every license (+ effective status, recent event count)
//   events      — recent activation_events for one license  { license_id }
//   generate    — mint a new key        { plan?, customer_email?, months?, machine_label?, notes? }
//   suspend     — pause enforcement      { id }   (reversible)
//   block       — hard kill a key        { id }   (reversible by reactivate)
//   reactivate  — return to active       { id }
//   extend      — add months to expiry   { id, months }
//   release     — clear the machine bind { id }   (lets the key move to a new machine)

import { serviceClient, callerEmail, isAdmin, generateKey, json, CORS } from "../_shared/util.ts";

interface Body {
  action?: string;
  id?: string;
  license_id?: string;
  plan?: string;
  customer_email?: string;
  machine_label?: string;
  notes?: string;
  months?: number;
}

function effectiveStatus(l: { status: string; expires_at: string }): string {
  if (l.status === "suspended" || l.status === "blocked") return l.status;
  if (new Date(l.expires_at).getTime() < Date.now()) return "expired";
  return l.status;
}

function addMonths(from: Date, months: number): Date {
  const d = new Date(from);
  d.setMonth(d.getMonth() + months);
  return d;
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  const svc = serviceClient();

  // --- authorize ---
  const email = await callerEmail(req);
  if (!(await isAdmin(svc, email))) return json({ error: "forbidden" }, 403);

  let body: Body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }
  const action = body.action ?? "";
  const id = body.id ?? "";

  switch (action) {
    case "list": {
      const { data, error } = await svc
        .from("licenses")
        .select("*")
        .order("created_at", { ascending: false });
      if (error) return json({ error: "query_failed" }, 500);
      const rows = (data ?? []).map((l) => ({ ...l, effective_status: effectiveStatus(l) }));
      return json({ ok: true, licenses: rows });
    }

    case "events": {
      const licenseId = body.license_id ?? id;
      if (!licenseId) return json({ error: "missing_id" }, 400);
      const { data, error } = await svc
        .from("activation_events")
        .select("*")
        .eq("license_id", licenseId)
        .order("created_at", { ascending: false })
        .limit(50);
      if (error) return json({ error: "query_failed" }, 500);
      return json({ ok: true, events: data ?? [] });
    }

    case "generate": {
      const months = Math.max(1, Math.min(60, Number(body.months) || 1));
      const expires = addMonths(new Date(), months).toISOString();
      const plan = ["community", "pro", "enterprise"].includes(body.plan ?? "") ? body.plan : "pro";

      // Retry a couple of times on the (astronomically unlikely) key collision.
      let lastErr: unknown = null;
      for (let attempt = 0; attempt < 3; attempt++) {
        const key = generateKey();
        const { data, error } = await svc
          .from("licenses")
          .insert({
            license_key: key,
            plan,
            customer_email: body.customer_email?.trim() || null,
            machine_label: body.machine_label?.trim() || null,
            notes: body.notes?.trim() || null,
            status: "active",
            expires_at: expires,
          })
          .select()
          .single();
        if (!error) return json({ ok: true, license: data });
        lastErr = error;
        // 23505 = unique_violation → try a new key; anything else → stop.
        if ((error as { code?: string }).code !== "23505") break;
      }
      return json({ error: "generate_failed", detail: String(lastErr) }, 500);
    }

    case "suspend":
    case "block":
    case "reactivate": {
      if (!id) return json({ error: "missing_id" }, 400);
      const status = action === "reactivate" ? "active" : action === "block" ? "blocked" : "suspended";
      const { data, error } = await svc
        .from("licenses")
        .update({ status })
        .eq("id", id)
        .select()
        .single();
      if (error) return json({ error: "update_failed" }, 500);
      return json({ ok: true, license: { ...data, effective_status: effectiveStatus(data) } });
    }

    case "extend": {
      if (!id) return json({ error: "missing_id" }, 400);
      const months = Math.max(1, Math.min(60, Number(body.months) || 1));
      const { data: cur, error: e1 } = await svc.from("licenses").select("*").eq("id", id).single();
      if (e1 || !cur) return json({ error: "not_found" }, 404);
      // Extend from whichever is later: now, or the current expiry.
      const base = new Date(Math.max(Date.now(), new Date(cur.expires_at).getTime()));
      const next = addMonths(base, months).toISOString();
      // If it had lapsed, bringing it back into the future re-activates it.
      const status = cur.status === "expired" ? "active" : cur.status;
      const { data, error } = await svc
        .from("licenses")
        .update({ expires_at: next, status })
        .eq("id", id)
        .select()
        .single();
      if (error) return json({ error: "update_failed" }, 500);
      return json({ ok: true, license: { ...data, effective_status: effectiveStatus(data) } });
    }

    case "release": {
      if (!id) return json({ error: "missing_id" }, 400);
      const { data, error } = await svc
        .from("licenses")
        .update({ machine_id: null, machine_label: null, activated_at: null })
        .eq("id", id)
        .select()
        .single();
      if (error) return json({ error: "update_failed" }, 500);
      return json({ ok: true, license: { ...data, effective_status: effectiveStatus(data) } });
    }

    default:
      return json({ error: "unknown_action" }, 400);
  }
});
