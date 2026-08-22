import { createClient, type SupabaseClient } from "@supabase/supabase-js";

const url = import.meta.env.VITE_SUPABASE_URL as string | undefined;
const anonKey = import.meta.env.VITE_SUPABASE_ANON_KEY as string | undefined;

/**
 * Whether Supabase credentials are present. The site renders and animates fully
 * without them; only the submit actions need a configured backend, and they say
 * so instead of throwing when it is missing.
 */
export const isSupabaseConfigured = Boolean(url && anonKey && !anonKey.startsWith("your-"));

export const supabase: SupabaseClient | null = isSupabaseConfigured
  ? createClient(url as string, anonKey as string)
  : null;

export type Platform = "linux" | "macos" | "windows";

/** Record a "notify me when it ships" signup for a not-yet-released platform. */
export async function joinWaitlist(email: string, platform: Platform): Promise<void> {
  if (!supabase) throw new Error("Backend not configured yet — set VITE_SUPABASE_* in .env.local.");
  const { error } = await supabase.from("waitlist").insert({ email, platform });
  if (error) {
    // A unique-violation means they already signed up — treat that as success.
    if (error.code === "23505") return;
    throw new Error(error.message);
  }
}

/** Record a sales / plan-interest lead from the pricing or contact CTAs. */
export async function submitLead(input: {
  email: string;
  company?: string;
  plan?: string;
  message?: string;
}): Promise<void> {
  if (!supabase) throw new Error("Backend not configured yet — set VITE_SUPABASE_* in .env.local.");
  const { error } = await supabase.from("leads").insert({
    email: input.email,
    company: input.company ?? null,
    plan: input.plan ?? null,
    message: input.message ?? null,
  });
  if (error) throw new Error(error.message);
}
