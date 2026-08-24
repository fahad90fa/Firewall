// Shared helpers for the licensing edge functions.
//
// These run server-side on Supabase Edge (Deno). They use the SERVICE ROLE key,
// which is present in the function environment and MUST never reach a browser —
// it bypasses Row-Level Security, which is exactly why all license logic lives
// here and not in the client.

import { createClient, type SupabaseClient } from "https://esm.sh/@supabase/supabase-js@2.45.4";

export const CORS: Record<string, string> = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, x-client-info, apikey, content-type",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};

export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...CORS, "Content-Type": "application/json" },
  });
}

/** A service-role client — full access, server-side only. */
export function serviceClient(): SupabaseClient {
  const url = Deno.env.get("SUPABASE_URL")!;
  const key = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!;
  return createClient(url, key, { auth: { persistSession: false } });
}

/** Resolve the authenticated caller's email from the request's JWT. */
export async function callerEmail(req: Request): Promise<string | null> {
  const auth = req.headers.get("Authorization");
  if (!auth) return null;
  const url = Deno.env.get("SUPABASE_URL")!;
  const anon = Deno.env.get("SUPABASE_ANON_KEY")!;
  const client = createClient(url, anon, {
    global: { headers: { Authorization: auth } },
    auth: { persistSession: false },
  });
  const { data } = await client.auth.getUser();
  return data.user?.email ?? null;
}

/** Is this email listed in admin_users? */
export async function isAdmin(svc: SupabaseClient, email: string | null): Promise<boolean> {
  if (!email) return false;
  const { data } = await svc.from("admin_users").select("email").eq("email", email).maybeSingle();
  return Boolean(data);
}

const ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"; // no ambiguous chars

/** A grouped license key like UFW-4KD2-9QMT-... (5 groups of 4). */
export function generateKey(): string {
  const bytes = new Uint8Array(20);
  crypto.getRandomValues(bytes);
  const chars = Array.from(bytes, (b) => ALPHABET[b % ALPHABET.length]);
  const groups: string[] = [];
  for (let i = 0; i < 20; i += 4) groups.push(chars.slice(i, i + 4).join(""));
  return "UFW-" + groups.join("-");
}

/** base64url without padding. */
function b64url(bytes: Uint8Array): string {
  let s = btoa(String.fromCharCode(...bytes));
  return s.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A signed activation token: base64url(payload).base64url(HMAC-SHA256).
 * Lets the client carry an offline grace period between online re-checks. The
 * secret is server-only; offline *forgery* resistance would want Ed25519 (a
 * public key the client can verify but not sign with) — a documented upgrade.
 */
export async function signToken(payload: Record<string, unknown>): Promise<string> {
  const secret = Deno.env.get("LICENSE_SIGNING_SECRET") ?? "dev-unsigned-secret-change-me";
  const enc = new TextEncoder();
  const body = b64url(enc.encode(JSON.stringify(payload)));
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, enc.encode(body)));
  return body + "." + b64url(sig);
}

/**
 * Detached Ed25519 signature (base64url) over a token's payload part — the
 * `body` before the "." in signToken()'s output. The private key is a server
 * secret (LICENSE_ED25519_PKCS8, PKCS8 DER base64); a `--features tls` firewall
 * verifies this with only the PUBLIC key, so it can trust the grant offline and
 * cannot forge one. Returns "" when no key is configured (HMAC-only fallback).
 */
export async function signBodyEd25519(token: string): Promise<string> {
  const b64 = Deno.env.get("LICENSE_ED25519_PKCS8");
  if (!b64) return "";
  const body = token.split(".")[0] ?? "";
  if (!body) return "";
  const pkcs8 = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  const key = await crypto.subtle.importKey("pkcs8", pkcs8, { name: "Ed25519" }, false, ["sign"]);
  const sig = new Uint8Array(
    await crypto.subtle.sign({ name: "Ed25519" }, key, new TextEncoder().encode(body)),
  );
  return b64url(sig);
}

/** Best-effort client IP for the audit log. */
export function clientIp(req: Request): string | null {
  return (
    req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() ??
    req.headers.get("x-real-ip") ??
    null
  );
}
