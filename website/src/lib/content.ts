export type Feature = {
  tag: string;
  title: string;
  body: string;
  tone: "signal" | "safe" | "threat";
};

export const FEATURES: Feature[] = [
  {
    tag: "IDENTITY",
    title: "Filters by who, not where",
    body: "A rule names an application by its code signature — Authenticode subject, Apple Team ID, or Linux path + content hash. “Allow 443 outbound” permits every exfil tool ever written; “allow 443 from our signed binary” does not.",
    tone: "signal",
  },
  {
    tag: "KERNEL",
    title: "Verdicts reached in ring 0",
    body: "The daemon never decides a packet. Every verdict is enforced in the kernel — eBPF + netfilter on Linux — so a compromised user-space process cannot talk its way past the filter.",
    tone: "signal",
  },
  {
    tag: "EQUIVALENCE",
    title: "One policy, three kernels, verified",
    body: "One file compiles to a WFP callout, an eBPF/netfilter table and a Network Extension. The build runs all three against 2,000+ scenarios and fails if they disagree — cross-platform drift becomes a red build, not a production incident.",
    tone: "signal",
  },
  {
    tag: "IPS",
    title: "Inbound intrusion prevention",
    body: "A Suricata-subset engine plus in-kernel DPI signatures catch the wire-unambiguous exploitation primitives — Log4Shell, traversal, SQLi shapes — the moment they cross the boundary.",
    tone: "threat",
  },
  {
    tag: "EGRESS",
    title: "Beaconing & exfil detection",
    body: "Command-and-control gives itself away by its rhythm. The engine flags regular-interval callbacks and the first time a signed app reaches a never-before-seen destination — the shape of exfiltration, invisible to signatures.",
    tone: "threat",
  },
  {
    tag: "SOAR",
    title: "Adaptive auto-response",
    body: "Opt-in playbooks classify the live denial stream and contain matching sources at the kernel with escalating, auto-expiring blocks — audited, public-IP-only, off until you arm it.",
    tone: "threat",
  },
  {
    tag: "FLEET",
    title: "Signed rollout that can't outage you",
    body: "HMAC-signed policy bundles widen through gated canary waves (1% → 10% → 50% → 100%), advancing only on a wave’s health and aborting within the cohort on any regression. A bad policy reaches the canary, never the fleet.",
    tone: "safe",
  },
  {
    tag: "ACCESS",
    title: "RBAC + mutual TLS console",
    body: "Three roles gate every action. Operators authenticate by client certificate — verified against your CA, mapped to a role by fingerprint — or a bearer token over a tunnel. No plaintext, ever.",
    tone: "safe",
  },
  {
    tag: "SUPPLY CHAIN",
    title: "Zero dependencies by default",
    body: "cargo build pulls nothing — the whole engine is hand-written so no transitive dependency lands in the trusted computing base. Reproducible offline builds, a signed SBOM, and continuous differential fuzzing back it.",
    tone: "safe",
  },
];

export type Step = { n: string; label: string; title: string; body: string };

export const STEPS: Step[] = [
  {
    n: "01",
    label: "AUTHOR",
    title: "Write one policy",
    body: "A single readable YAML file describes what each signed application may reach. No per-OS rule sets to keep in sync.",
  },
  {
    n: "02",
    label: "COMPILE",
    title: "Three kernels, one verdict",
    body: "The compiler emits Windows, Linux and macOS artifacts and proves them equivalent across thousands of scenarios before anything ships.",
  },
  {
    n: "03",
    label: "ENFORCE",
    title: "Decide in the kernel",
    body: "Policy loads into the kernel and filters every packet in ring 0 — with a fail-safe watchdog that keeps the host reachable if the data path ever faults.",
  },
  {
    n: "04",
    label: "WATCH",
    title: "See every decision",
    body: "A live console shows each enforced rule, every blocked packet with the reason it was stopped, attack classification, and the fleet at a glance.",
  },
];

export type Plan = {
  name: string;
  price: string;
  cadence: string;
  blurb: string;
  featured?: boolean;
  cta: string;
  perks: string[];
};

export const PLANS: Plan[] = [
  {
    name: "Community",
    price: "$0",
    cadence: "self-hosted",
    blurb: "The full engine for a single host. For homelabs, researchers, and evaluation.",
    cta: "Get it for Linux",
    perks: [
      "1 host",
      "Kernel-level enforcement",
      "Identity + packet policy",
      "Live operations console",
      "Community support",
    ],
  },
  {
    name: "Pro",
    price: "$12",
    cadence: "per host / month",
    blurb: "Detection, response and fleet rollout for teams running Linux in production.",
    featured: true,
    cta: "Start 30-day trial",
    perks: [
      "Everything in Community",
      "IDS/IPS + beaconing detection",
      "Adaptive auto-response (SOAR)",
      "Signed staged-rollout fleet control",
      "RBAC + mTLS console, SIEM export",
      "Priority support",
    ],
  },
  {
    name: "Enterprise",
    price: "Custom",
    cadence: "annual",
    blurb: "For regulated fleets that need scale, assurance, and a name to call.",
    cta: "Talk to us",
    perks: [
      "Everything in Pro",
      "Unlimited hosts, multi-tenant",
      "Signed distribution + air-gapped install",
      "SSO, audit export, compliance mapping",
      "SLA, onboarding & a named engineer",
    ],
  },
];

/** Illustrative live-feed lines — the kind of events the engine attributes. */
export const FEED_LINES: { verb: string; detail: string; verdict: "BLOCKED" | "DROPPED" | "ALLOWED" | "CONTAINED" }[] = [
  { verb: "SSH brute-force", detail: "45.148.10.62 → :22 · 214 attempts/min", verdict: "BLOCKED" },
  { verb: "Log4Shell probe", detail: "GET /?x=${jndi:ldap://…} → :443", verdict: "BLOCKED" },
  { verb: "Port scan", detail: "198.51.100.9 → 1000 ports in 4s", verdict: "DROPPED" },
  { verb: "Signed browser", detail: "chrome → cdn.example.com:443", verdict: "ALLOWED" },
  { verb: "SMB lateral move", detail: "10.0.4.7 → :445 (egress)", verdict: "DROPPED" },
  { verb: "C2 beacon", detail: "app → 203.0.113.44 every 60.0s ±0.3", verdict: "CONTAINED" },
  { verb: "RDP break-in", detail: "185.220.101.5 → :3389", verdict: "BLOCKED" },
  { verb: "Unsigned egress", detail: "/tmp/.x9 → 91.219.236.18:8080", verdict: "CONTAINED" },
  { verb: "DNS exfil pattern", detail: "long-label bursts → :53", verdict: "DROPPED" },
  { verb: "Signed updater", detail: "apt → deb.debian.org:443", verdict: "ALLOWED" },
];

/** The Linux package, hosted on the site itself (served from /public). */
export const LINUX_DEB = {
  version: "0.1.0",
  arch: "amd64",
  file: "unified-firewall_0.1.0_amd64.deb",
  size: "1.3 MB",
  sha256: "5005b250f84429a6a6f63a558115203d3541de6d419414967d81823fb5948887",
};

export const LINUX_DOWNLOAD_URL =
  (import.meta.env.VITE_LINUX_DOWNLOAD_URL as string | undefined) ?? `/downloads/${LINUX_DEB.file}`;

/** One-liner install command shown on the Linux card. */
export const LINUX_INSTALL_CMD = `sudo apt install ./${LINUX_DEB.file}`;
