import { Button, Reveal, ShieldMark } from "./ui";
import SignupForm from "./SignupForm";
import { submitLead } from "../lib/supabase";
import { LINUX_DOWNLOAD_URL } from "../lib/content";

export default function Footer() {
  return (
    <>
      {/* Final CTA band */}
      <section className="relative mx-auto max-w-content px-5 py-20">
        <Reveal className="relative overflow-hidden rounded-3xl border border-signal/30 bg-panel p-10 text-center shadow-glow md:p-14">
          <div className="grid-backdrop pointer-events-none absolute inset-0 opacity-60" />
          <div className="relative">
            <h2 className="mx-auto max-w-2xl font-display text-3xl font-bold tracking-tight text-ink text-balance sm:text-4xl">
              Stop trusting ports. Start trusting identities.
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-lg text-muted">
              Deploy Unified Firewall on your Linux hosts today, or get the monthly briefing on releases and
              threat research.
            </p>
            <div className="mx-auto mt-8 flex max-w-md flex-col items-center gap-4">
              <Button href={LINUX_DOWNLOAD_URL} download className="px-7">
                Download for Linux — free
              </Button>
              <div className="w-full">
                <SignupForm
                  cta="Keep me posted"
                  placeholder="you@company.com"
                  doneMsg="Subscribed — watch your inbox."
                  onSubmit={(email) => submitLead({ email, plan: "newsletter" })}
                />
              </div>
            </div>
          </div>
        </Reveal>
      </section>

      <footer className="border-t border-line">
        <div className="mx-auto flex max-w-content flex-col gap-6 px-5 py-10 sm:flex-row sm:items-center sm:justify-between">
          <div className="flex items-center gap-2.5">
            <ShieldMark className="h-6 w-6" />
            <span className="font-display font-bold text-ink">
              Unified<span className="text-signal">Firewall</span>
            </span>
          </div>
          <nav className="flex flex-wrap gap-x-6 gap-y-2 font-mono text-xs text-muted">
            <a className="hover:text-ink" href="#features">Features</a>
            <a className="hover:text-ink" href="#how">How it works</a>
            <a className="hover:text-ink" href="#pricing">Pricing</a>
            <a className="hover:text-ink" href="https://github.com/fahad90fa/Firewall" target="_blank" rel="noreferrer">
              GitHub ↗
            </a>
          </nav>
          <p className="font-mono text-xs text-muted/70">
            © {new Date().getFullYear()} Unified Firewall · Apache-2.0 core
          </p>
        </div>
      </footer>
    </>
  );
}
