import { useState } from "react";
import { PLANS, LINUX_DOWNLOAD_URL } from "../lib/content";
import { Button, Label, Reveal } from "./ui";
import SignupForm from "./SignupForm";
import { submitLead } from "../lib/supabase";

export default function Pricing() {
  const [openPlan, setOpenPlan] = useState<string | null>(null);

  return (
    <section id="pricing" className="relative border-t border-line bg-void/40 py-20">
      <div className="mx-auto max-w-content px-5">
        <Reveal className="mx-auto max-w-2xl text-center">
          <div className="flex justify-center">
            <Label tone="safe">PRICING</Label>
          </div>
          <h2 className="mt-4 font-display text-4xl font-bold tracking-tight text-ink text-balance">
            Priced per host. Free to start.
          </h2>
          <p className="mt-4 text-lg text-muted">
            Run the full engine on one host for free. Turn on detection, response and fleet control when you
            go to production. Linux available today.
          </p>
        </Reveal>

        <div className="mt-14 grid items-start gap-4 lg:grid-cols-3">
          {PLANS.map((p, i) => (
            <Reveal
              key={p.name}
              delay={i * 90}
              className={`relative flex flex-col rounded-2xl border p-7 ${
                p.featured
                  ? "border-signal/50 bg-panel shadow-glow"
                  : "border-line bg-panel/70"
              }`}
            >
              {p.featured && (
                <span className="absolute -top-3 left-7 rounded-full bg-signal px-3 py-1 font-mono text-[10px] font-bold tracking-wider text-void">
                  MOST POPULAR
                </span>
              )}
              <h3 className="font-display text-xl font-bold text-ink">{p.name}</h3>
              <div className="mt-3 flex items-baseline gap-1.5">
                <span className="tick-mono text-4xl font-bold text-ink">{p.price}</span>
                <span className="text-sm text-muted">/ {p.cadence}</span>
              </div>
              <p className="mt-3 text-sm leading-relaxed text-muted">{p.blurb}</p>

              <ul className="mt-6 flex-1 space-y-2.5">
                {p.perks.map((perk) => (
                  <li key={perk} className="flex items-start gap-2.5 text-sm text-ink/90">
                    <span className="mt-0.5 text-safe" aria-hidden="true">
                      ✓
                    </span>
                    {perk}
                  </li>
                ))}
              </ul>

              <div className="mt-7">
                {p.name === "Community" ? (
                  <Button href={LINUX_DOWNLOAD_URL} variant="ghost" className="w-full">
                    {p.cta}
                  </Button>
                ) : openPlan === p.name ? (
                  <SignupForm
                    compact
                    tone={p.featured ? "signal" : "safe"}
                    cta="Send"
                    placeholder="work email"
                    doneMsg="Got it — we'll reach out shortly."
                    onSubmit={(email) => submitLead({ email, plan: p.name })}
                  />
                ) : (
                  <Button
                    variant={p.featured ? "primary" : "ghost"}
                    onClick={() => setOpenPlan(p.name)}
                    className="w-full"
                  >
                    {p.cta}
                  </Button>
                )}
              </div>
            </Reveal>
          ))}
        </div>

        <p className="mt-8 text-center font-mono text-xs text-muted">
          Prices are illustrative for this preview · no card is collected here — plan interest is emailed to
          our team.
        </p>
      </div>
    </section>
  );
}
