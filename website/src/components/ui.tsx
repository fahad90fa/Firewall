import { useEffect, useRef, type ReactNode } from "react";

/**
 * Scroll-reveal wrapper. Content is visible by default (see index.css); the
 * observer only *adds* the animated entrance, so nothing is ever stranded
 * invisible if scripting is off. Honors prefers-reduced-motion via CSS.
 */
export function Reveal({
  children,
  className = "",
  delay = 0,
  as: Tag = "div",
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
  as?: "div" | "section" | "li" | "article";
}) {
  const ref = useRef<HTMLElement | null>(null);

  useEffect(() => {
    const el = ref.current;
    if (!el || typeof IntersectionObserver === "undefined") {
      el?.classList.add("is-in");
      return;
    }
    const io = new IntersectionObserver(
      (entries) => {
        for (const e of entries) {
          if (e.isIntersecting) {
            (e.target as HTMLElement).classList.add("is-in");
            io.unobserve(e.target);
          }
        }
      },
      { threshold: 0.16, rootMargin: "0px 0px -8% 0px" },
    );
    io.observe(el);
    return () => io.disconnect();
  }, []);

  return (
    <Tag
      ref={ref as never}
      data-reveal=""
      className={className}
      style={delay ? { transitionDelay: `${delay}ms` } : undefined}
    >
      {children}
    </Tag>
  );
}

/** A HUD eyebrow — a small uppercase console label with a leading marker. */
export function Label({ children, tone = "signal" }: { children: ReactNode; tone?: "signal" | "safe" | "threat" }) {
  const color = tone === "safe" ? "text-safe" : tone === "threat" ? "text-threat" : "text-signal";
  return (
    <span className={`inline-flex items-center gap-2 font-mono text-xs tracking-[0.28em] ${color}`}>
      <span className={`h-1.5 w-1.5 rounded-full ${tone === "safe" ? "bg-safe" : tone === "threat" ? "bg-threat" : "bg-signal"} animate-blip`} />
      {children}
    </span>
  );
}

export function Button({
  children,
  href,
  onClick,
  variant = "primary",
  type = "button",
  className = "",
  disabled,
  download,
}: {
  children: ReactNode;
  href?: string;
  onClick?: () => void;
  variant?: "primary" | "ghost";
  type?: "button" | "submit";
  className?: string;
  disabled?: boolean;
  download?: boolean;
}) {
  const base =
    "inline-flex items-center justify-center gap-2 rounded-lg px-5 py-3 font-display text-sm font-semibold tracking-wide transition-all duration-200 disabled:opacity-50 disabled:pointer-events-none";
  const styles =
    variant === "primary"
      ? "bg-signal text-void hover:shadow-glow hover:-translate-y-0.5"
      : "border border-line text-ink hover:border-signal/60 hover:text-signal";
  const cls = `${base} ${styles} ${className}`;
  if (href) {
    const external = href.startsWith("http");
    return (
      <a
        className={cls}
        href={href}
        download={download}
        target={external ? "_blank" : undefined}
        rel={external ? "noreferrer" : undefined}
      >
        {children}
      </a>
    );
  }
  return (
    <button className={cls} onClick={onClick} type={type} disabled={disabled}>
      {children}
    </button>
  );
}

export function ShieldMark({ className = "h-7 w-7" }: { className?: string }) {
  return (
    <svg viewBox="0 0 32 32" className={className} aria-hidden="true">
      <path d="M16 3l11 3.6v8.2c0 7.3-4.8 12.2-11 14.6C9.8 30 5 25.1 5 17.8V6.6z" fill="none" stroke="#38bdf8" strokeWidth="2" />
      <path d="M10.5 16.4l3.6 3.6L22 12" fill="none" stroke="#34d399" strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}
