import { FEATURES } from "../lib/content";
import { Label, Reveal } from "./ui";

const DOT: Record<string, string> = {
  signal: "bg-signal",
  safe: "bg-safe",
  threat: "bg-threat",
};
const EDGE: Record<string, string> = {
  signal: "hover:border-signal/50",
  safe: "hover:border-safe/50",
  threat: "hover:border-threat/50",
};

export default function Features() {
  return (
    <section id="features" className="relative mx-auto max-w-content px-5 py-20">
      <Reveal className="max-w-2xl">
        <Label>CAPABILITIES</Label>
        <h2 className="mt-4 font-display text-4xl font-bold tracking-tight text-ink text-balance">
          A perimeter, an inspector, and a responder — on every host.
        </h2>
        <p className="mt-4 text-lg text-muted">
          Not a packet filter with a rules file. A full host-security layer: identity-aware enforcement,
          intrusion prevention, egress anomaly detection, and automated response — all decided in the kernel.
        </p>
      </Reveal>

      <div className="mt-12 grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
        {FEATURES.map((f, i) => (
          <Reveal
            key={f.title}
            as="article"
            delay={(i % 3) * 90}
            className={`group rounded-xl border border-line bg-panel p-6 transition-all duration-200 hover:-translate-y-1 hover:bg-raised ${EDGE[f.tone]}`}
          >
            <div className="flex items-center gap-2">
              <span className={`h-1.5 w-1.5 rounded-full ${DOT[f.tone]}`} />
              <span className="font-mono text-[11px] tracking-[0.22em] text-muted">{f.tag}</span>
            </div>
            <h3 className="mt-3 font-display text-lg font-semibold text-ink">{f.title}</h3>
            <p className="mt-2 text-[14.5px] leading-relaxed text-muted">{f.body}</p>
          </Reveal>
        ))}
      </div>
    </section>
  );
}
