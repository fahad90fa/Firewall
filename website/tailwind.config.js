/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{ts,tsx}"],
  theme: {
    extend: {
      colors: {
        void: "#070b14",
        panel: "#0d1826",
        raised: "#12233a",
        line: "#1c2b3f",
        ink: "#e6edf6",
        muted: "#8fa3bd",
        signal: "#38bdf8",
        safe: "#34d399",
        threat: "#fb7185",
        warn: "#fbbf24",
      },
      fontFamily: {
        display: ['"Chakra Petch"', "ui-sans-serif", "system-ui", "sans-serif"],
        sans: ["Manrope", "ui-sans-serif", "system-ui", "sans-serif"],
        mono: ['"JetBrains Mono"', "ui-monospace", "SFMono-Regular", "monospace"],
      },
      maxWidth: { content: "1180px" },
      boxShadow: {
        glow: "0 0 0 1px rgba(56,189,248,0.25), 0 8px 40px -12px rgba(56,189,248,0.35)",
        panel: "0 1px 0 rgba(255,255,255,0.03) inset, 0 20px 50px -30px rgba(0,0,0,0.8)",
      },
      keyframes: {
        sheen: { "0%": { transform: "translateX(-120%)" }, "100%": { transform: "translateX(220%)" } },
        blip: { "0%,100%": { opacity: "0.35" }, "50%": { opacity: "1" } },
        rise: { from: { opacity: "0", transform: "translateY(14px)" }, to: { opacity: "1", transform: "translateY(0)" } },
        caret: { "0%,100%": { opacity: "1" }, "50%": { opacity: "0" } },
        scan: { from: { backgroundPosition: "0 0" }, to: { backgroundPosition: "0 -1000px" } },
      },
      animation: {
        sheen: "sheen 6s linear infinite",
        blip: "blip 2.2s ease-in-out infinite",
        caret: "caret 1s step-end infinite",
      },
    },
  },
  plugins: [],
};
