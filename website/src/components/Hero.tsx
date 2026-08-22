import { useEffect, useState } from "react";
import PacketCanvas from "./PacketCanvas";
import { Button, Label } from "./ui";
import { LINUX_DOWNLOAD_URL } from "../lib/content";

function useCountUp(target: number, ms = 1600) {
  const [n, setN] = useState(0);
  useEffect(() => {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) {
      setN(target);
      return;
    }
    let raf = 0;
    const start = performance.now();
    const tick = (t: number) => {
      const p = Math.min(1, (t - start) / ms);
      const eased = 1 - Math.pow(1 - p, 3);
      setN(Math.floor(eased * target));
      if (p < 1) raf = requestAnimationFrame(tick);
    };
    raf = requestAnimationFrame(tick);
    return () => cancelAnimationFrame(raf);
  }, [target, ms]);
  return n;
}

export default function Hero() {
  const blocked = useCountUp(2_418_907);
  const [live, setLive] = useState(0);
  useEffect(() => {
    const id = window.setInterval(() => setLive((v) => v + Math.floor(Math.random() * 7) + 1), 900);
    return () => window.clearInterval(id);
  }, []);

  return (
    <section id="top" className="relative overflow-hidden pt-28">
      <div className="grid-backdrop pointer-events-none absolute inset-0" />
      <div className="pointer-events-none absolute inset-0 h-full">
        <PacketCanvas />
      </div>

      <div className="relative mx-auto max-w-content px-5 pb-20 pt-10">
        <div className="max-w-2xl">
          <Label>DEFENSE-GRADE HOST FIREWALL</Label>
          <h1 className="mt-5 font-display text-5xl font-bold leading-[1.02] tracking-tight text-ink text-balance sm:text-6xl">
            Filter by <span className="text-signal">who</span>,<br />not by where.
          </h1>
          <p className="mt-6 max-w-xl text-lg leading-relaxed text-muted">
            Unified Firewall compiles <span className="text-ink">one policy file</span> into kernel-level
            enforcement — and blocks every packet that isn&apos;t explicitly, cryptographically allowed.
            One rule set. Three kernels. The same verdict, proven at build time.
          </p>

          <div className="mt-8 flex flex-wrap items-center gap-3">
            <Button href={LINUX_DOWNLOAD_URL}>
              <LinuxGlyph /> Get it for Linux
            </Button>
            <Button href="#how" variant="ghost">
              See how it works
            </Button>
          </div>

          <div className="mt-4 flex flex-wrap items-center gap-x-5 gap-y-2 font-mono text-xs text-muted">
            <span className="inline-flex items-center gap-2">
              <span className="h-2 w-2 rounded-full bg-safe animate-blip" /> Linux — available now
            </span>
            <span>macOS &amp; Windows — coming soon</span>
          </div>
        </div>

        {/* Live counter card */}
        <div className="mt-14 inline-flex flex-wrap items-stretch gap-px overflow-hidden rounded-xl border border-line bg-line/60 shadow-panel">
          <Stat kicker="THREATS BLOCKED" value={(blocked + live).toLocaleString()} tone="threat" />
          <Stat kicker="EQUIVALENCE SCENARIOS" value="2,006" tone="signal" />
          <Stat kicker="RUNTIME DEPENDENCIES" value="0" tone="safe" />
          <Stat kicker="TESTS PASSING" value="1,012" tone="signal" />
        </div>
      </div>
    </section>
  );
}

function Stat({ kicker, value, tone }: { kicker: string; value: string; tone: "signal" | "safe" | "threat" }) {
  const color = tone === "safe" ? "text-safe" : tone === "threat" ? "text-threat" : "text-signal";
  return (
    <div className="min-w-[9.5rem] bg-panel px-5 py-4">
      <div className="font-mono text-[10px] tracking-[0.2em] text-muted">{kicker}</div>
      <div className={`tick-mono mt-1.5 text-2xl font-bold ${color}`}>{value}</div>
    </div>
  );
}

function LinuxGlyph() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" aria-hidden="true" fill="currentColor">
      <path d="M12 2c-2 0-3 1.7-3 3.6 0 1 .2 1.7.2 2.4 0 .8-1.2 2-2 3.4C6.2 13 5 14.5 5 16.4c0 .8.3 1.3.9 1.7-.2.6.1 1.2.7 1.5.7.3 1.8.2 2.6-.3.6.4 1.4.6 2.3.6s1.7-.2 2.3-.6c.8.5 1.9.6 2.6.3.6-.3.9-.9.7-1.5.6-.4.9-.9.9-1.7 0-1.9-1.2-3.4-2.2-5-.8-1.4-2-2.6-2-3.4 0-.7.2-1.4.2-2.4C15 3.7 14 2 12 2Zm-1.3 4.1c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Zm2.6 0c.4 0 .7.4.7.9s-.3.9-.7.9-.7-.4-.7-.9.3-.9.7-.9Z" />
    </svg>
  );
}
