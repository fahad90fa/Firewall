import { STEPS } from "../lib/content";
import { Label, Reveal } from "./ui";

const POLICY = `rules:
  - id: browser-web
    action: allow
    protocol: tcp
    application: managed_browser   # by signature, not path
    destination:
      ports: [80, 443]

  - id: default
    action: deny                   # everything else, denied`;

const VERDICT = `tcp outbound -> 10.0.0.5:443
  decision   ALLOW
  rule       allow-internal-https

PLATFORM  DECISION  RULE
windows   allow     allow-internal-https
linux     allow     allow-internal-https
macos     allow     allow-internal-https`;

export default function HowItWorks() {
  return (
    <section id="how" className="relative border-y border-line bg-void/40 py-20">
      <div className="mx-auto max-w-content px-5">
        <Reveal className="max-w-2xl">
          <Label tone="safe">HOW IT WORKS</Label>
          <h2 className="mt-4 font-display text-4xl font-bold tracking-tight text-ink text-balance">
            One file becomes three kernels — and the build proves they agree.
          </h2>
        </Reveal>

        <div className="mt-12 grid gap-10 lg:grid-cols-[1fr_1.05fr] lg:items-center">
          {/* steps — a real sequence, so numbering is earned */}
          <ol className="space-y-2">
            {STEPS.map((s, i) => (
              <Reveal as="li" key={s.n} delay={i * 80} className="flex gap-4 rounded-xl border border-transparent p-4 transition-colors hover:border-line hover:bg-panel">
                <div className="tick-mono select-none pt-0.5 text-2xl font-bold text-signal/40">{s.n}</div>
                <div>
                  <div className="font-mono text-[11px] tracking-[0.22em] text-muted">{s.label}</div>
                  <h3 className="mt-1 font-display text-lg font-semibold text-ink">{s.title}</h3>
                  <p className="mt-1 text-[14.5px] leading-relaxed text-muted">{s.body}</p>
                </div>
              </Reveal>
            ))}
          </ol>

          {/* the artifact: policy in, verified verdict out */}
          <Reveal className="space-y-3">
            <CodePanel title="policy.yaml" tone="signal" code={POLICY} />
            <div className="flex justify-center">
              <span className="font-mono text-xs text-muted">compile · verify · enforce ↓</span>
            </div>
            <CodePanel title="ufwctl policy explain" tone="safe" code={VERDICT} />
          </Reveal>
        </div>
      </div>
    </section>
  );
}

function CodePanel({ title, code, tone }: { title: string; code: string; tone: "signal" | "safe" }) {
  const dot = tone === "safe" ? "bg-safe" : "bg-signal";
  return (
    <div className="overflow-hidden rounded-xl border border-line bg-panel shadow-panel">
      <div className="flex items-center gap-2 border-b border-line px-4 py-2.5">
        <span className={`h-2 w-2 rounded-full ${dot}`} />
        <span className="font-mono text-xs text-muted">{title}</span>
      </div>
      <pre className="overflow-x-auto p-4 font-mono text-[12.5px] leading-relaxed text-ink/90">
        <code>{code}</code>
      </pre>
    </div>
  );
}
