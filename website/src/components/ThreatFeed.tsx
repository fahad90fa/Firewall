import { useEffect, useRef, useState } from "react";
import { FEED_LINES } from "../lib/content";
import { Label, Reveal } from "./ui";

type Row = { id: number; verb: string; detail: string; verdict: string; t: string };

const VERDICT_STYLE: Record<string, string> = {
  BLOCKED: "text-threat border-threat/40 bg-threat/10",
  DROPPED: "text-threat border-threat/40 bg-threat/10",
  CONTAINED: "text-warn border-warn/40 bg-warn/10",
  ALLOWED: "text-safe border-safe/40 bg-safe/10",
};

function clock() {
  const d = new Date();
  const p = (x: number) => String(x).padStart(2, "0");
  return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

export default function ThreatFeed() {
  const [rows, setRows] = useState<Row[]>([]);
  const idRef = useRef(0);

  useEffect(() => {
    const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    // seed
    const seed: Row[] = FEED_LINES.slice(0, 6).map((l) => ({
      ...l,
      id: idRef.current++,
      t: clock(),
    }));
    setRows(seed);
    if (reduced) return;
    const id = window.setInterval(() => {
      const l = FEED_LINES[Math.floor(Math.random() * FEED_LINES.length)];
      setRows((prev) => [{ ...l, id: idRef.current++, t: clock() }, ...prev].slice(0, 8));
    }, 1500);
    return () => window.clearInterval(id);
  }, []);

  return (
    <section className="relative mx-auto max-w-content px-5 py-16">
      <Reveal className="overflow-hidden rounded-2xl border border-line bg-panel shadow-panel">
        {/* terminal chrome */}
        <div className="flex items-center gap-3 border-b border-line px-4 py-3">
          <div className="flex gap-1.5">
            <span className="h-3 w-3 rounded-full bg-threat/70" />
            <span className="h-3 w-3 rounded-full bg-warn/70" />
            <span className="h-3 w-3 rounded-full bg-safe/70" />
          </div>
          <span className="font-mono text-xs text-muted">ufw-nft · live enforcement</span>
          <span className="ml-auto inline-flex items-center gap-2 font-mono text-xs text-safe">
            <span className="h-2 w-2 rounded-full bg-safe animate-blip" /> streaming
          </span>
        </div>

        <div className="grid gap-8 p-6 md:grid-cols-[1.2fr_1fr] md:p-8">
          {/* the feed */}
          <div>
            <Label tone="threat">LIVE THREAT FEED</Label>
            <ul className="mt-4 space-y-1.5 font-mono text-[13px]">
              {rows.map((r, i) => (
                <li
                  key={r.id}
                  className="flex items-center gap-3 rounded-md px-2 py-1.5 transition-colors"
                  style={i === 0 ? { animation: "rise .5s ease-out" } : undefined}
                >
                  <span className="tick-mono shrink-0 text-muted/70">{r.t}</span>
                  <span className="shrink-0 text-ink">{r.verb}</span>
                  <span className="truncate text-muted">{r.detail}</span>
                  <span
                    className={`ml-auto shrink-0 rounded border px-2 py-0.5 text-[10px] font-bold tracking-wider ${
                      VERDICT_STYLE[r.verdict] ?? "text-muted border-line"
                    }`}
                  >
                    {r.verdict}
                  </span>
                </li>
              ))}
            </ul>
          </div>

          {/* the thesis beside it */}
          <div className="flex flex-col justify-center border-t border-line pt-6 md:border-l md:border-t-0 md:pl-8 md:pt-0">
            <h3 className="font-display text-2xl font-bold leading-tight text-ink text-balance">
              Every packet is a decision, and every decision is attributed.
            </h3>
            <p className="mt-3 text-[15px] leading-relaxed text-muted">
              Denied, alerted, contained — each event carries the source, the port, the service, and the
              exact rule and reason that stopped it. Not a black box that says <span className="text-ink">blocked</span>;
              a record you can act on.
            </p>
            <p className="mt-4 font-mono text-xs text-muted">
              <span className="text-signal">$</span> firewall status
              <span className="animate-caret text-signal">▊</span>
            </p>
          </div>
        </div>
      </Reveal>
    </section>
  );
}
