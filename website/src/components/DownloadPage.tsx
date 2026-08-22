import { useEffect, useRef, useState, type ReactNode } from "react";
import { Button, Label, ShieldMark } from "./ui";
import { LINUX_DEB, LINUX_DOWNLOAD_URL } from "../lib/content";

/**
 * The dedicated download page (route `#download`). It plays a short download
 * animation, auto-starts the .deb download, and lays out the setup steps.
 *
 * The auto-start uses a programmatic <a download> click. If a browser declines
 * it (some require a direct user gesture), the prominent "Download again" button
 * — a real click — always works, and the page says so.
 */
export default function DownloadPage() {
  const [started, setStarted] = useState(false);
  const [barFull, setBarFull] = useState(false);
  const anchorRef = useRef<HTMLAnchorElement | null>(null);

  // The download and the "started" state are driven by setTimeout, not
  // requestAnimationFrame, so they fire even if the tab is backgrounded (rAF is
  // paused there). The bar is a CSS width transition — purely cosmetic.
  useEffect(() => {
    window.scrollTo(0, 0);
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const delay = reduce ? 60 : 1500;
    const t1 = window.setTimeout(() => setBarFull(true), 40);
    const t2 = window.setTimeout(() => {
      anchorRef.current?.click();
      setStarted(true);
      setBarFull(true);
    }, delay);
    return () => {
      window.clearTimeout(t1);
      window.clearTimeout(t2);
    };
  }, []);

  return (
    <div className="mx-auto max-w-content px-5 pb-24 pt-28">
      {/* hidden real download target */}
      <a ref={anchorRef} href={LINUX_DOWNLOAD_URL} download={LINUX_DEB.file} className="sr-only" aria-hidden="true">
        download
      </a>

      {/* --- animated status card --- */}
      <div className="relative overflow-hidden rounded-3xl border border-line bg-panel p-8 text-center shadow-panel md:p-12">
        <div className="grid-backdrop pointer-events-none absolute inset-0 opacity-50" />
        <div className="relative mx-auto max-w-xl">
          <div className="flex justify-center">
            <Label tone={started ? "safe" : "signal"}>{started ? "DOWNLOAD STARTED" : "PREPARING DOWNLOAD"}</Label>
          </div>

          <div className="mx-auto mt-7 flex h-28 w-28 items-center justify-center">
            <DownloadAnimation started={started} />
          </div>

          <h1 className="mt-6 font-display text-3xl font-bold tracking-tight text-ink text-balance sm:text-4xl">
            {started ? "Your download is on its way" : "Fetching Unified Firewall…"}
          </h1>
          <p className="mx-auto mt-3 max-w-md text-[15px] leading-relaxed text-muted">
            {started ? (
              <>
                If nothing happened, use the button below to grab{" "}
                <span className="font-mono text-ink">{LINUX_DEB.file}</span> again.
              </>
            ) : (
              <>Packaging the Linux build ({LINUX_DEB.size}) for {LINUX_DEB.arch}…</>
            )}
          </p>

          {/* progress bar (cosmetic CSS transition) */}
          <div className="mx-auto mt-6 h-1.5 w-full max-w-sm overflow-hidden rounded-full bg-line">
            <div
              className="h-full rounded-full bg-gradient-to-r from-signal to-safe transition-[width] duration-[1500ms] ease-out"
              style={{ width: barFull ? "100%" : "6%" }}
            />
          </div>

          <div className="mt-7 flex flex-wrap items-center justify-center gap-3">
            <Button href={LINUX_DOWNLOAD_URL} download className="bg-safe text-void">
              <DownArrow /> {started ? "Download again" : "Download now"}
            </Button>
            <Button href="#top" variant="ghost" onClick={() => window.scrollTo(0, 0)}>
              ← Back to site
            </Button>
          </div>

          <dl className="mx-auto mt-8 grid max-w-md grid-cols-3 gap-px overflow-hidden rounded-xl border border-line bg-line/60 text-left">
            <Meta k="Version" v={`v${LINUX_DEB.version}`} />
            <Meta k="Arch" v={LINUX_DEB.arch} />
            <Meta k="Size" v={LINUX_DEB.size} />
          </dl>
          <p className="mx-auto mt-3 max-w-md break-all font-mono text-[10px] text-muted/60">
            sha256 {LINUX_DEB.sha256}
          </p>
        </div>
      </div>

      {/* --- requirements --- */}
      <div className="mt-10">
        <Label>BEFORE YOU START</Label>
        <ul className="mt-4 flex flex-wrap gap-2.5 text-[13px]">
          {[
            "Debian · Ubuntu · Parrot · Kali",
            "x86-64 (amd64)",
            "root / sudo",
            "nftables (installed automatically)",
          ].map((r) => (
            <li key={r} className="rounded-full border border-line bg-panel px-3.5 py-1.5 font-mono text-muted">
              {r}
            </li>
          ))}
        </ul>
      </div>

      {/* --- setup steps --- */}
      <div className="mt-12">
        <Label tone="safe">SET IT UP</Label>
        <h2 className="mt-4 font-display text-3xl font-bold tracking-tight text-ink text-balance">
          Four commands from download to running.
        </h2>
        <ol className="mt-8 space-y-4">
          <Step
            n="01"
            title="Install the package"
            body="Run this from the folder you downloaded into. apt pulls nftables if it isn't already present."
            cmd={`sudo apt install ./${LINUX_DEB.file}`}
          />
          <Step
            n="02"
            title="(Optional) verify the download"
            body="Confirm the file matches the checksum shown above before you install."
            cmd={`sha256sum ${LINUX_DEB.file}`}
          />
          <Step
            n="03"
            title="Open the live console"
            body="It installs in monitor mode — observing and logging, never blocking — and starts on boot. The console is loopback-only."
            cmd={`firewall            # or open http://127.0.0.1:8787`}
          />
          <Step
            n="04"
            title="Enforce when you're ready"
            body="Start with default-allow (denies only never-legitimate protocols). Once you've catalogued egress, graduate to deny-by-default."
            cmd={`sudo firewall apply base/default_allow`}
          />
        </ol>
      </div>

      {/* --- extras --- */}
      <div className="mt-10 grid gap-4 sm:grid-cols-2">
        <InfoCard title="Go to deny-by-default" tone="signal">
          <p className="text-[14px] leading-relaxed text-muted">
            After your allow rules are in place, switch the whole packet filter to deny-by-default:
          </p>
          <Command cmd="sudo firewall apply base/default_deny" />
          <p className="mt-2 text-[13px] text-muted/80">
            Whatever you <span className="text-ink">apply</span> is what reloads automatically on the next boot.
          </p>
        </InfoCard>
        <InfoCard title="Uninstall" tone="threat">
          <p className="text-[14px] leading-relaxed text-muted">
            Stops the services, removes the binaries, and drops the nftables table:
          </p>
          <Command cmd="sudo apt remove unified-firewall" />
          <p className="mt-2 text-[13px] text-muted/80">
            Add <span className="font-mono text-ink">--purge</span> to also remove <span className="font-mono text-ink">/etc/unified-firewall</span>.
          </p>
        </InfoCard>
      </div>

      <p className="mt-10 text-center font-mono text-xs text-muted/70">
        On first install the daemon runs in monitor mode. Nothing here can take you off the network until you
        deliberately enforce a policy.
      </p>
    </div>
  );
}

function Meta({ k, v }: { k: string; v: string }) {
  return (
    <div className="bg-panel px-4 py-3">
      <dt className="font-mono text-[10px] tracking-[0.18em] text-muted">{k.toUpperCase()}</dt>
      <dd className="mt-0.5 font-display text-sm font-bold text-ink">{v}</dd>
    </div>
  );
}

function Step({ n, title, body, cmd }: { n: string; title: string; body: string; cmd: string }) {
  return (
    <li className="flex flex-col gap-3 rounded-xl border border-line bg-panel p-5 sm:flex-row sm:gap-5">
      <div className="tick-mono shrink-0 pt-0.5 text-2xl font-bold text-signal/40">{n}</div>
      <div className="min-w-0 flex-1">
        <h3 className="font-display text-lg font-semibold text-ink">{title}</h3>
        <p className="mt-1 text-[14px] leading-relaxed text-muted">{body}</p>
        <Command cmd={cmd} />
      </div>
    </li>
  );
}

function InfoCard({ title, tone, children }: { title: string; tone: "signal" | "threat"; children: ReactNode }) {
  const dot = tone === "threat" ? "bg-threat" : "bg-signal";
  return (
    <div className="rounded-xl border border-line bg-panel p-5">
      <div className="flex items-center gap-2">
        <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
        <h3 className="font-display text-base font-semibold text-ink">{title}</h3>
      </div>
      <div className="mt-3">{children}</div>
    </div>
  );
}

/** A copyable command line. Clipboard with a legacy fallback for non-secure contexts. */
function Command({ cmd }: { cmd: string }) {
  const [copied, setCopied] = useState(false);
  async function copy() {
    try {
      await navigator.clipboard.writeText(cmd);
    } catch {
      const ta = document.createElement("textarea");
      ta.value = cmd;
      ta.style.position = "fixed";
      ta.style.opacity = "0";
      document.body.appendChild(ta);
      ta.select();
      try {
        document.execCommand("copy");
      } catch {
        /* give up silently */
      }
      ta.remove();
    }
    setCopied(true);
    window.setTimeout(() => setCopied(false), 1400);
  }
  return (
    <div className="mt-3 flex items-center gap-2 rounded-lg border border-line bg-void/70 px-3 py-2.5">
      <span className="select-none text-safe" aria-hidden="true">$</span>
      <code className="min-w-0 flex-1 overflow-x-auto whitespace-nowrap font-mono text-[12.5px] text-ink/90">
        {cmd}
      </code>
      <button
        onClick={copy}
        className="shrink-0 rounded-md border border-line px-2 py-1 font-mono text-[11px] text-muted transition-colors hover:border-signal/60 hover:text-signal"
        aria-label={`Copy: ${cmd}`}
      >
        {copied ? "copied ✓" : "copy"}
      </button>
    </div>
  );
}

function DownArrow() {
  return (
    <svg viewBox="0 0 24 24" className="h-4 w-4" fill="none" stroke="currentColor" strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
      <path d="M12 3v12m0 0l-4-4m4 4l4-4M4 21h16" />
    </svg>
  );
}

/** A shield with a downward arrow; the arrow bounces while preparing, settles to a check when started. */
function DownloadAnimation({ started }: { started: boolean }) {
  return (
    <div className="relative flex h-full w-full items-center justify-center">
      <span
        className={`absolute inset-0 rounded-full border ${started ? "border-safe/40" : "border-signal/30"}`}
        style={started ? undefined : { animation: "dlpulse 1.8s ease-out infinite" }}
      />
      {started ? (
        <ShieldMark className="h-14 w-14" />
      ) : (
        <svg viewBox="0 0 48 48" className="h-14 w-14 text-signal" fill="none" stroke="currentColor" strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" aria-hidden="true">
          <path d="M24 6v24" style={{ animation: "dlarrow 1.2s ease-in-out infinite" }} />
          <path d="M14 22l10 10 10-10" style={{ animation: "dlarrow 1.2s ease-in-out infinite" }} />
          <path d="M10 40h28" className="text-line" stroke="currentColor" />
        </svg>
      )}
    </div>
  );
}
