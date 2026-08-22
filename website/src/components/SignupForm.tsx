import { useState, type FormEvent } from "react";
import { isSupabaseConfigured } from "../lib/supabase";

type Status = "idle" | "loading" | "done" | "error";

/**
 * A compact email capture used for the coming-soon waitlist and the sales
 * leads. Fully client-validated, announces its state, and degrades to a clear
 * message when the backend env vars aren't set rather than failing silently.
 */
export default function SignupForm({
  onSubmit,
  cta,
  placeholder = "you@company.com",
  doneMsg = "You're on the list — we'll be in touch.",
  compact = false,
  tone = "signal",
}: {
  onSubmit: (email: string) => Promise<void>;
  cta: string;
  placeholder?: string;
  doneMsg?: string;
  compact?: boolean;
  tone?: "signal" | "safe" | "warn";
}) {
  const [email, setEmail] = useState("");
  const [status, setStatus] = useState<Status>("idle");
  const [msg, setMsg] = useState("");

  const btn =
    tone === "safe" ? "bg-safe text-void" : tone === "warn" ? "bg-warn text-void" : "bg-signal text-void";

  async function handle(e: FormEvent) {
    e.preventDefault();
    const value = email.trim();
    if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(value)) {
      setStatus("error");
      setMsg("Enter a valid email address.");
      return;
    }
    setStatus("loading");
    setMsg("");
    try {
      await onSubmit(value);
      setStatus("done");
      setEmail("");
    } catch (err) {
      setStatus("error");
      setMsg(err instanceof Error ? err.message : "Something went wrong. Try again.");
    }
  }

  if (status === "done") {
    return (
      <p className="flex items-center gap-2 rounded-lg border border-safe/40 bg-safe/10 px-4 py-3 text-sm text-safe" role="status">
        <span aria-hidden="true">✓</span> {doneMsg}
      </p>
    );
  }

  return (
    <form onSubmit={handle} className="w-full" noValidate>
      <div className={`flex gap-2 ${compact ? "" : "flex-col sm:flex-row"}`}>
        <input
          type="email"
          inputMode="email"
          autoComplete="email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          placeholder={placeholder}
          aria-label="Email address"
          className="min-w-0 flex-1 rounded-lg border border-line bg-void px-4 py-3 font-mono text-sm text-ink placeholder:text-muted/60 focus:border-signal focus:outline-none"
        />
        <button
          type="submit"
          disabled={status === "loading"}
          className={`shrink-0 rounded-lg px-5 py-3 font-display text-sm font-semibold tracking-wide transition-all duration-200 hover:-translate-y-0.5 disabled:opacity-60 ${btn}`}
        >
          {status === "loading" ? "Sending…" : cta}
        </button>
      </div>
      {status === "error" && (
        <p className="mt-2 text-xs text-threat" role="alert">
          {msg}
        </p>
      )}
      {!isSupabaseConfigured && status !== "error" && (
        <p className="mt-2 font-mono text-[11px] text-muted/70">
          demo mode · connect Supabase (see website/README.md) to store signups
        </p>
      )}
    </form>
  );
}
