import { type ReactNode } from "react";
import { Button, Label, Reveal } from "./ui";
import SignupForm from "./SignupForm";
import { joinWaitlist, type Platform } from "../lib/supabase";
import { LINUX_DOWNLOAD_URL } from "../lib/content";

export default function Platforms() {
  return (
    <section id="platforms" className="relative mx-auto max-w-content px-5 py-20">
      <Reveal className="max-w-2xl">
        <Label>PLATFORMS</Label>
        <h2 className="mt-4 font-display text-4xl font-bold tracking-tight text-ink text-balance">
          Live on Linux today. Windows and macOS are next.
        </h2>
        <p className="mt-4 text-lg text-muted">
          The engine is cross-platform by design — one policy already compiles to all three. Linux ships
          now with real kernel enforcement; the Windows and macOS agents are in hardening. Get notified the
          day they land.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-4 md:grid-cols-3">
        {/* Linux — available */}
        <Reveal className="flex flex-col rounded-2xl border border-safe/30 bg-panel p-7 shadow-panel">
          <div className="flex items-center justify-between">
            <TuxGlyph />
            <span className="inline-flex items-center gap-1.5 rounded-full border border-safe/40 bg-safe/10 px-3 py-1 font-mono text-[10px] font-bold tracking-wider text-safe">
              <span className="h-1.5 w-1.5 rounded-full bg-safe animate-blip" /> AVAILABLE
            </span>
          </div>
          <h3 className="mt-5 font-display text-xl font-bold text-ink">Linux</h3>
          <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">
            Debian, Ubuntu, Parrot, Kali and friends. Packet-layer policy enforces today via nftables — no
            kernel module required — with eBPF for the identity and DPI fast path.
          </p>
          <div className="mt-6">
            <Button href={LINUX_DOWNLOAD_URL} variant="ghost" className="w-full border-safe/40 text-safe hover:border-safe hover:text-safe">
              Download for Linux ↗
            </Button>
          </div>
        </Reveal>

        {/* Windows — coming soon */}
        <ComingSoon
          name="Windows"
          glyph={<WindowsGlyph />}
          blurb="A WFP callout driver brings the same identity-aware verdicts to Windows, gated on driver signing and runtime hardening."
          platform="windows"
        />

        {/* macOS — coming soon */}
        <ComingSoon
          name="macOS"
          glyph={<AppleGlyph />}
          blurb="A Network/System Extension enforces the same policy on macOS, pending the notarization and approval flow."
          platform="macos"
        />
      </div>
    </section>
  );
}

function ComingSoon({
  name,
  glyph,
  blurb,
  platform,
}: {
  name: string;
  glyph: ReactNode;
  blurb: string;
  platform: Platform;
}) {
  return (
    <Reveal className="flex flex-col rounded-2xl border border-line bg-panel/60 p-7">
      <div className="flex items-center justify-between">
        <span className="text-muted">{glyph}</span>
        <span className="inline-flex items-center gap-1.5 rounded-full border border-warn/40 bg-warn/10 px-3 py-1 font-mono text-[10px] font-bold tracking-wider text-warn">
          COMING SOON
        </span>
      </div>
      <h3 className="mt-5 font-display text-xl font-bold text-ink">{name}</h3>
      <p className="mt-2 flex-1 text-sm leading-relaxed text-muted">{blurb}</p>
      <div className="mt-6">
        <SignupForm
          tone="warn"
          cta="Notify me"
          placeholder="you@company.com"
          doneMsg={`We'll email you when ${name} ships.`}
          onSubmit={(email) => joinWaitlist(email, platform)}
        />
      </div>
    </Reveal>
  );
}

/* --- glyphs --- */
function TuxGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="h-8 w-8 text-safe" fill="currentColor" aria-hidden="true">
      <path d="M12 2c-2 0-3 1.7-3 3.6 0 1 .2 1.7.2 2.4 0 .8-1.2 2-2 3.4C6.2 13 5 14.5 5 16.4c0 .8.3 1.3.9 1.7-.2.6.1 1.2.7 1.5.7.3 1.8.2 2.6-.3.6.4 1.4.6 2.3.6s1.7-.2 2.3-.6c.8.5 1.9.6 2.6.3.6-.3.9-.9.7-1.5.6-.4.9-.9.9-1.7 0-1.9-1.2-3.4-2.2-5-.8-1.4-2-2.6-2-3.4 0-.7.2-1.4.2-2.4C15 3.7 14 2 12 2Zm-1.3 4.1c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Zm2.6 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Z" />
    </svg>
  );
}
function WindowsGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="h-7 w-7" fill="currentColor" aria-hidden="true">
      <path d="M3 5.5 10.5 4.4v6.8H3zM10.5 12.8v6.8L3 18.5v-5.7zM11.6 4.2 21 3v8.2h-9.4zM21 12.8V21l-9.4-1.3v-6.9z" />
    </svg>
  );
}
function AppleGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="h-7 w-7" fill="currentColor" aria-hidden="true">
      <path d="M16.4 12.7c0-2.3 1.9-3.4 2-3.5-1.1-1.6-2.8-1.8-3.4-1.8-1.4-.1-2.8.9-3.5.9s-1.8-.8-3-.8c-1.5 0-2.9.9-3.7 2.3-1.6 2.7-.4 6.8 1.1 9 .7 1.1 1.6 2.3 2.8 2.3 1.1 0 1.5-.7 2.9-.7s1.7.7 2.9.7 2-1.1 2.7-2.1c.9-1.2 1.2-2.4 1.2-2.5-.1 0-2.4-.9-2.4-3.6zM14.2 5.8c.6-.8 1-1.8.9-2.9-.9 0-2 .6-2.6 1.3-.6.7-1.1 1.7-1 2.7 1 .1 2-.4 2.7-1.1z" />
    </svg>
  );
}
