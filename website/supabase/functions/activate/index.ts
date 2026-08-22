// POST /functions/v1/activate
//
// The firewall calls this once, at install/activation time, with the license
// key the customer bought and a stable machine fingerprint. We:
//   1. look the key up (service role — bypasses RLS),
//   2. reject blocked/suspended/expired keys,
//   3. node-lock: bind the key to the FIRST machine that activates it; any
//      later machine is refused ("one key, one machine"),
//   4. stamp activated_at / last_seen_at,
//   5. return a short-lived signed token the client can trust offline until
//      its next online re-check.
//
// Every call — success or refusal — is written to activation_events.

import { serviceClient, json, signToken, clientIp, CORS } from "../_shared/util.ts";

interface Body {
  license_key?: string;
  machine_id?: string;
  machine_label?: string;
}

// How long the signed token is honoured offline before the client must
// re-validate online. Kept short so a suspend/block takes effect quickly.
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
  const machineLabel = (body.machine_label ?? "").trim() || null;
  if (!key || !machineId) return json({ error: "missing_fields" }, 400);

  const svc = serviceClient();
  const ip = clientIp(req);

  async function audit(kind: "activate" | "reject", licenseId: string | null, reason: string) {
    await svc.from("activation_events").insert({
      license_id: licenseId,
      license_key: key,
      kind,
      machine_id: machineId,
      machine_label: machineLabel,
      reason,
      ip,
    });
  }

  const { data: lic, error } = await svc
    .from("licenses")
    .select("*")
    .eq("license_key", key)
    .maybeSingle();

  if (error) return json({ error: "lookup_failed" }, 500);
  if (!lic) {
    await audit("reject", null, "unknown_key");
    return json({ ok: false, status: "invalid", reason: "unknown_key" }, 404);
  }

  // Hard stops set by an admin.
  if (lic.status === "blocked" || lic.status === "suspended") {
    await audit("reject", lic.id, lic.status);
    return json({ ok: false, status: lic.status, reason: lic.status }, 403);
  }

  // Expiry.
  const now = Date.now();
  const expiresAt = new Date(lic.expires_at).getTime();
  if (expiresAt < now) {
    if (lic.status !== "expired") {
      await svc.from("licenses").update({ status: "expired" }).eq("id", lic.id);
    }
    await audit("reject", lic.id, "expired");
    return json({ ok: false, status: "expired", reason: "expired", expires_at: lic.expires_at }, 403);
  }

  // Node-lock. First activation binds the machine; later ones must match.
  if (lic.machine_id && lic.machine_id !== machineId) {
    await audit("reject", lic.id, "machine_mismatch");
    return json(
      { ok: false, status: "machine_mismatch", reason: "key_bound_to_another_machine" },
      409,
    );
  }

  const bind = {
    machine_id: machineId,
    machine_label: machineLabel ?? lic.machine_label,
    activated_at: lic.activated_at ?? new Date(now).toISOString(),
    last_seen_at: new Date(now).toISOString(),
  };
  const { error: upErr } = await svc.from("licenses").update(bind).eq("id", lic.id);
  if (upErr) return json({ error: "bind_failed" }, 500);

  await audit("activate", lic.id, lic.machine_id ? "reactivate" : "first_activation");

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
