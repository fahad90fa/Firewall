import { useEffect, useState } from "react";
import { Button, ShieldMark } from "./ui";
import { LINUX_DOWNLOAD_URL } from "../lib/content";

const LINKS = [
  { href: "#features", label: "Features" },
  { href: "#how", label: "How it works" },
  { href: "#platforms", label: "Platforms" },
  { href: "#pricing", label: "Pricing" },
];

export default function Nav() {
  const [scrolled, setScrolled] = useState(false);
  useEffect(() => {
    const onScroll = () => setScrolled(window.scrollY > 12);
    onScroll();
    window.addEventListener("scroll", onScroll, { passive: true });
    return () => window.removeEventListener("scroll", onScroll);
  }, []);

  return (
    <header
      className={`fixed inset-x-0 top-0 z-50 transition-colors duration-300 ${
        scrolled ? "border-b border-line bg-void/85 backdrop-blur-md" : "border-b border-transparent"
      }`}
    >
      <nav className="mx-auto flex max-w-content items-center justify-between px-5 py-3.5">
        <a href="#top" className="flex items-center gap-2.5">
          <ShieldMark />
          <span className="font-display text-lg font-bold tracking-wide text-ink">
            Unified<span className="text-signal">Firewall</span>
          </span>
        </a>

        <div className="hidden items-center gap-8 md:flex">
          {LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              className="font-mono text-xs tracking-[0.14em] text-muted transition-colors hover:text-ink"
            >
              {l.label}
            </a>
          ))}
        </div>

        <div className="flex items-center gap-3">
          <a
            href="https://github.com/fahad90fa/Firewall"
            target="_blank"
            rel="noreferrer"
            className="hidden font-mono text-xs tracking-[0.14em] text-muted transition-colors hover:text-ink sm:inline"
          >
            GitHub ↗
          </a>
          <Button href={LINUX_DOWNLOAD_URL} className="px-4 py-2.5 text-xs">
            Get for Linux
          </Button>
        </div>
      </nav>
    </header>
  );
}
