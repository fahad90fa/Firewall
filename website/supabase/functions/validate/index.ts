// POST /functions/v1/validate
//
// The firewall calls this periodically (the daemon's re-check loop) to confirm
// a previously-activated key is still good. It enforces the same rules as
// activate — status, expiry, machine binding — but never *creates* a binding:
// a key that hasn't been activated yet is simply "not_active" here.
//
// On success it refreshes last_seen_at (so the admin dashboard shows liveness)
// and returns a fresh signed token extending the offline grace window.

import { serviceClient, json, signToken, clientIp, CORS } from "../_shared/util.ts";

interface Body {
  license_key?: string;
  machine_id?: string;
}

const GRACE_HOURS = 72;

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "method_not_allowed" }, 405);

  let body: Body;
  try {
    body = await req.json();
  } catch {
    return json({ error: "bad_json" }, 400);
  }

  const key = (body.license_key ?? "").trim().toUpperCase();
  const machineId = (body.machine_id ?? "").trim();
  if (!key || !machineId) return json({ error: "missing_fields" }, 400);

  const svc = serviceClient();
  const ip = clientIp(req);

  const { data: lic, error } = await svc
    .from("licenses")
    .select("*")
    .eq("license_key", key)
    .maybeSingle();

  if (error) return json({ error: "lookup_failed" }, 500);

  async function reject(status: string, reason: string, code = 403, extra: Record<string, unknown> = {}) {
    await svc.from("activation_events").insert({
      license_id: lic?.id ?? null,
      license_key: key,
      kind: "reject",
      machine_id: machineId,
      reason,
      ip,
    });
    return json({ ok: false, valid: false, status, reason, ...extra }, code);
  }

  if (!lic) return reject("invalid", "unknown_key", 404);
  if (lic.status === "blocked" || lic.status === "suspended") return reject(lic.status, lic.status);

  const now = Date.now();
  if (new Date(lic.expires_at).getTime() < now) {
    if (lic.status !== "expired") {
      await svc.from("licenses").update({ status: "expired" }).eq("id", lic.id);
    }
    return reject("expired", "expired", 403, { expires_at: lic.expires_at });
  }

  // Must already be bound, and to THIS machine.
  if (!lic.machine_id) return reject("not_active", "not_activated", 409);
  if (lic.machine_id !== machineId) return reject("machine_mismatch", "key_bound_to_another_machine", 409);

  await svc.from("licenses").update({ last_seen_at: new Date(now).toISOString() }).eq("id", lic.id);
  await svc.from("activation_events").insert({
    license_id: lic.id,
    license_key: key,
    kind: "validate",
    machine_id: machineId,
    reason: "ok",
    ip,
  });

  const recheckByMs = now + GRACE_HOURS * 3600 * 1000;
  const recheckBy = new Date(recheckByMs).toISOString();
  const expiresUnix = Math.floor(new Date(lic.expires_at).getTime() / 1000);
  const recheckUnix = Math.floor(recheckByMs / 1000);
  const token = await signToken({
    key,
    machine_id: machineId,
    plan: lic.plan,
    status: "active",
    expires_at: lic.expires_at,
    expires_at_unix: expiresUnix,
    recheck_by: recheckBy,
    recheck_by_unix: recheckUnix,
    issued_at: new Date(now).toISOString(),
  });

  return json({
    ok: true,
    valid: true,
    status: "active",
    plan: lic.plan,
    expires_at: lic.expires_at,
    expires_at_unix: expiresUnix,
    recheck_by: recheckBy,
    recheck_by_unix: recheckUnix,
    grace_hours: GRACE_HOURS,
    token,
  });
});
