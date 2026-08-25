<!--
  External-audit outreach packet for Unified Firewall.
  Companion to docs/security/audit-brief.md: the brief is what an auditor reviews;
  this is how you commission that audit — scope/RFP, a real firm shortlist, a
  ready-to-send email, a readiness checklist, and the engagement model.
  Firm details reflect publicly reported work, NOT live quotes — confirm directly.
-->

# Unified Firewall — External Security Audit Outreach Packet

## 1. TL;DR

**The single highest-value lever: an independent, source-level audit of the ring-0 C parsing path + the `nftables` emission correctness.** These are the two places where a defect is catastrophic rather than cosmetic — attacker-controlled bytes parsed in kernel space (memory-safety → remote kernel DoS/RCE), and the policy→ruleset compiler that is *the layer enforcing today* (a miscompile is a silent allow/deny inversion). Everything else (daemon IPC, licensing) is a local or economic boundary; these two are the remote and correctness cores.

**What it buys you:**
- An outside verdict on the two questions your own tooling cannot fully answer: (a) can any authored policy compile into an allow/deny inversion in `inet ufw`; (b) is there any hostile-packet-reachable memory-safety defect in the C decoders/reassembly/DPI automaton that fuzzing + the differential gate miss.
- Independent confirmation that your differential-equivalence gate and fuzz harness *actually constrain* the shipped C (i.e., cannot pass vacuously) — the credibility keystone for an OSS security product with no prior review.
- A publishable report that materially raises trust for adopters, and a path to CVE assignment for anything found before disclosure.

**3 concrete next actions:**
1. **Apply to OSTIF's "Get an Audit" intake** (contactus@ostif.org) — the grant-funded route can make your out-of-pocket ~$0 and OSTIF selects a matched specialist firm. Do this first; it runs in parallel with everything else.
2. **Send the cold-outreach email (Section 4) to 3 firms** whose track record is *specifically* kernel C + Rust: X41 D-Sec, Trail of Bits, and NCC Group. Ask for a fixed-scope proposal against the Priority-1 scope only, with Priorities 2-3 as options.
3. **Freeze a review commit and finish the readiness checklist (Section 5)** so whichever firm engages spends its hours on findings, not setup — the single biggest cost lever you control.

---

## 2. Firm shortlist

All firms below are real, well-known, and independently verifiable. Confidence reflects **fit for this specific ring-0-C + nftables + Rust scope**, not the firm's general reputation.

| Firm | Specialty | Why it fits | How to engage | Confidence |
|---|---|---|---|---|
| **X41 D-Sec** | Boutique German firm; manual source audits of security-critical C/C++ (BIND 9, c-ares, Git, GnuPG) and Rust (RustVMM). On-site/air-gapped option. | Best-in-class match for a compact out-of-tree kernel module + protocol parsers. Direct Rust-crate audit history (RustVMM via OSTIF) and low-level C parser depth. | x41-dsec.de contact form / info@x41-dsec.de. Frequently engaged via OSTIF for OSS. | High |
| **Trail of Bits** | Systems/low-level C and Rust assurance; heavy fuzzing + program-analysis focus; Linux kernel and netfilter-adjacent work; public Rust/Testing Handbook. | Strongest all-rounder for kernel C *and* the Rust daemon/CLI. Reasons about fail-closed invariants, packet parsing, ring-0 attack surface at the design level. | trailofbits.com contact/quote form. Standard scoped SOW; OSS work often OpenSSF-funded. | High |
| **NCC Group** | Large assurance firm; Exploit Development Group with multiple Linux kernel LPE 0-days (CVE-2022-0185/-0995/-32250); formal Code Review + Cryptography Services practices. | Adversarial kernel-exploitation depth to stress-test a ring-0 module, plus scale to cover network + crypto (Ed25519/mTLS) in one engagement. | nccgroup.com — Technical Assurance › Code Review; regional sales. Formal RFP/SOW. | High |
| **Quarkslab** | French R&D firm; binary/kernel-module analysis (LIEF, QBDI). Audited the Falco **kernel module** in a runtime-security context. | Has demonstrably audited a Linux kernel module close to a packet-inspection firewall; reverse-engineering-grade scrutiny of a ring-0 parser. | quarkslab.com contact form / contact@quarkslab.com. EU-based, publishes write-ups. | High |
| **Radically Open Security** | Netherlands not-for-profit; OSS/privacy/network infra focus. Rust audits (Rauthy, NGI Zero) and VPN/network-daemon pentests (Mullvad WireGuard/OpenVPN). | Strong fit for a network-security Rust daemon, *especially* if grant-funded — direct Rust network-daemon and firewall-adjacent experience; publishes openly. | radicallyopensecurity.com. Reachable via EU NGI Zero / NLnet channels if the project qualifies. | High |
| **Atredis Partners** | US/Canada; embedded, firmware, network-stack reverse engineering and research-led pentesting. Ran the OSTIF-managed review of the Linux kernel's own vuln reporting/remediation process. | Best when firewall/parser code targets an appliance/embedded platform; deep network-stack research pedigree. Kernel-process precedent. | atredis.com contact; sample deliverables on request. | Medium-High |
| **Cure53** | Berlin; manual white-box source audits of network/VPN, browser, crypto software (NordVPN, Nym). Public report archive. | Solid for network-facing app/VPN logic and crypto handling; more application/VPN-leaning than pure kernel-parser internals — confirm ring-0 depth in scoping. | cure53.de / mail@cure53.de; github.com/cure53/Publications. | Medium |
| **Ada Logics** | UK; continuous fuzzing + OSS-Fuzz harness engineering (Cilium, cert-manager, Istio). SLSA/provenance work. | Highest value as a **fuzzing complement** to a manual audit — durable coverage-guided harnesses for the C parsers. Portfolio skews Go/userspace; confirm ring-0/kernel-module fuzzing scope explicitly. | adalogics.com. Often commissioned via OSTIF/CNCF; also direct. | Medium |

**Considered but not shortlisted for this scope:** Include Security, Doyensec, 7ASecurity (all real, capable appsec firms, but less kernel-parser-specialized — reasonable as breadth options, weaker on the Priority-1 ring-0 target). Code Intelligence (JVM/Java fuzzing focus) and ForAllSecure/Mayhem (fuzzing *product* vendor, not an OSS source-audit shop) are real but off-scope for a kernel-C + Rust manual audit. OSTIF and Chainguard are covered in Section 6 — OSTIF as an audit *manager*, Chainguard as a supply-chain/SLSA specialist rather than a code-audit firm.

> **Honesty note:** Firm specialties, contacts, and precedents above are drawn from the research inputs and reflect publicly reported work; they are **not** live quotes. Offerings, team availability, kernel-module scope, and pricing change — **you must confirm current capability and cost directly with each firm.** Do not treat any figure here as a proposal.

---

## 3. Scope of work (RFP)

### External Security Audit — RFP / Statement of Work
**Unified Firewall (host agent + licensing backend)**

**Project summary.** Unified Firewall is a Linux host firewall that enforces L3/L4 policy today via one compiled `nftables` table (`inet ufw`), with optional identity-aware/DPI enforcement through an opt-in DKMS kernel module (`ufw.ko`) and a user-space detection daemon (`ufwd`). No third-party security review has ever been performed; this engagement is that review. The codebase ships an honest, evidence-linked audit brief (`docs/security/audit-brief.md`) that this RFP builds on.

#### IN-SCOPE (ranked)

**1 — nftables emission correctness + ring-0 C hostile-byte parsers (highest value)**
- *Policy → ruleset emission:* the packet compiler (`ufw-policy-lang`, `cli/` packet compiler; tests in `cli/tests/`). Central question: can an authored policy compile to an `inet ufw` ruleset that **allows what it names as denied, or denies what it names as allowed**? Confirm the stated invariant — untranslatable rules are dropped, never silently weakened — and that `nft -c` validation before commit cannot be bypassed. This layer enforces today, so a miscompile is a silent policy bypass (threat-model Asset 2, attack-surface #3/#4).
- *Ring-0 hostile-byte parsers:* the packet decoders, stream reassembly, and DPI automaton in `kernel/linux/src/` and `kernel/linux/inc/`, plus the memory-safe Rust reference `kernel/linux/rust/ufw_kcore`. This is the only place attacker-controlled bytes are parsed in ring 0 (adversary A1, attack-surface #1) — memory-safety bugs here are remote kernel DoS/RCE. Assess the C directly and validate that the `differential` equivalence gate (`UFW_DIFF_REQUIRE=1`) and the fuzz harness (`.github/workflows/fuzz.yml`) actually constrain what the shipped C does. The module is off by default; scope covers the built/loaded (`mode=enforce`) configuration.

**2 — Daemon IPC / request-path + loopback console's one mutating action**
- Daemon REST and request handling (`daemon/`, `ufwd` on `:9600`): fleet-plane messages are HMAC-authenticated with `fleet_secret` (≥32 chars); verify auth, request-path subprocess bounding, fault isolation, and pre-apply policy-integrity checks (adversary A3, attack-surface #6; daemon↔module netlink #7).
- Web console (`cli/src/bin/ufw-nft/dashboard/`, `:8787`): binds loopback, read-only **except** the single `Contain` action, which mutates nftables and is gated on the request arriving over loopback and audited. Verify the loopback gate and audit trail, and the optional mTLS + RBAC path (`--features tls`, client-cert→role mapping) (adversary A2, attack-surface #5). Local privilege boundary.

**3 — Licensing client trust + Ed25519 / hardware binding**
- Client trust decision and node-lock (`cli/src/bin/ufw-nft/license.rs`): Ed25519 verification, hardware binding, machine id sent as salted SHA-256 (raw id never leaves), store root-only `0600` (attack-surface #11, adversary A4). Confirm the deterrent cannot be trivially forged into "enforcement-on," and — the durable control — that recurring paid value is **server-gated**, not merely a client boolean.
- Backend edge functions (`website/supabase/functions/`): `activate`/`validate` (public, key-value auth, node-lock, audited) and `admin` (JWT + `admin_users` allowlist; license tables RLS deny-all to anon/authenticated) (attack-surface #9/#10, adversary A6).
- Confirm secrets are absent from the client/`.deb`/repo: `LICENSE_SIGNING_SECRET` / `LICENSE_ED25519_PKCS8` and the Supabase service-role key are server-side only; the client ships only the Ed25519 **public** key and Supabase **anon** key.

#### OUT-OF-SCOPE
- Defeating an attacker who already holds **root on the protected host** (explicit non-goal).
- **Unbreakable** license enforcement — client-side licensing is a deterrent, not DRM (adversary A4).
- A **real-world detection-efficacy figure** on an independent labeled pcap corpus. Published detection numbers are correctness/regression figures against corpora built to the detectors' own models; re-measuring novel-attack efficacy is not asked here.
- Protecting the console against an attacker already inside the loopback trust zone **without** the mTLS build.
- Upstream `nftables`/netfilter and the eBPF verifier themselves (kernel's own).

#### Deliverables expected
1. A findings report ranked by severity, each finding with affected path(s), a reproducer where feasible, and remediation guidance.
2. A specific verdict on the two Priority-1 questions: (a) can any policy miscompile into an allow/deny inversion in the `inet ufw` emission; (b) any memory-safety defect in the ring-0 C decoders/reassembly/DPI automaton reachable from hostile packets.
3. An assessment of whether the `differential` equivalence gate and fuzz harness meaningfully bound the shipped C's behavior (i.e., the gate cannot pass vacuously).
4. Confirmation that the named secrets are absent from client/`.deb`/repo and that paid value is server-gated.
5. A short retest note after we ship fixes for confirmed high-severity issues.

#### Proposed timeline (indicative — firms may re-phase)
- **Week 0:** kickoff, access, environment build (default offline build; one `--features tls` build pulls pinned `rustls`/`ring`).
- **Weeks 1-3:** Priority 1 (emission + ring-0).
- **Week 4:** Priority 2 (daemon IPC / console).
- **Week 5:** Priority 3 (licensing client + backend).
- **Week 6:** draft report + review; retest window after fixes.

#### How to respond
Email **security@unifiedfirewall.dev** with: firm/team and relevant kernel-security and Rust/C review experience; proposed methodology and phasing against the three ranked scope items; team size, rate/fixed-bid, and earliest start; and any access or environment needs. We can provide source, build instructions, and reproduction commands (`cargo test --workspace`, the detection-efficacy and `--features tls` builds, `scripts/soak.sh`).

**Full audit brief:** `docs/security/audit-brief.md` (review order, every claim with its evidence and honest scope). Supporting: `SECURITY.md`, `docs/security/threat-model.md`, `docs/security/attack-surface.md`. Start there.

---

## 4. Outreach email

**Full cold-outreach email:**

```
Subject: Requesting a scoped security audit — open-source kernel-level firewall

Hi [Name],

I maintain [Project Name], an open-source, kernel-level firewall: a Rust
daemon/CLI that compiles high-level policy into nftables rules, paired with
an out-of-tree C kernel module for enforcement. It's ~20-30k LOC, already
fuzzed and differential-tested against a reference model, but has not yet had
an external security review.

I'm reaching out to see whether [Firm Name] would take on a fixed-scope audit.
The area I most want expert eyes on is the ring-0 attack surface: the
out-of-tree C kernel module (memory safety, privilege boundaries, syscall/ioctl
handling, concurrency) and the nftables rule-emission path (correctness and
injection/bypass risk where policy is translated into kernel rules). The Rust
daemon/CLI is secondary and can be included or deferred depending on budget.

- Repository: [repo link]
- Audit brief (scope, threat model, architecture, prior testing): [brief link]

Could you let me know if this is a fit, and if so send a fixed-scope proposal
with a rough cost and timeline? Happy to trim or stage the scope to match a
budget.

I'm available for a call any time over the next two weeks — [days/time zone]
work well, or send a link and I'll book a slot. Thanks for considering it.

Best,
[Your name]
[Project] maintainer
[email] · [GitHub handle]
```

**Short intro variant (LinkedIn / warm intro):**

```
I maintain [Project Name], an open-source kernel-level firewall (Rust
daemon/CLI plus an out-of-tree C kernel module emitting nftables rules,
~20-30k LOC) that's fuzzed and differential-tested but not yet externally
audited. I'm looking for a firm to do a fixed-scope security review, with the
priority being the ring-0 C module and the nftables emission path. Would
[Firm Name] be open to a quick call about a scoped proposal and rough timeline?
```

> Fill the `[bracketed]` fields before sending. If you route through OSTIF, you can lead the email with "We're applying for an OSTIF-managed audit and would like to be considered as the assigned firm" instead of asking for a direct commercial bid.

---

## 5. Readiness checklist

**Target:** Unified Firewall (Rust daemon/CLI + C Linux kernel module + nftables enforcement)
**Purpose:** Everything a maintainer verifies and hands over *before* the auditor starts, so the engagement spends its hours on findings, not setup. Every box must be tickable to *true* before kickoff. Ship it filled-in alongside `docs/security/audit-brief.md`.

### 0. One-page orientation (hand over first)
- [ ] `docs/security/audit-brief.md` current and is the single entry point.
- [ ] `SECURITY.md` "What this software actually enforces" table accurate to the shipped build (nftables `inet ufw` enforces today; C `ufw.ko` is opt-in and *not* claimed memory-safe).
- [ ] `ARCHITECTURE.md` reflects current component/data-flow layout.
- [ ] Named point-of-contact and private channel for live findings agreed.
- [ ] Rules of engagement written: is the DKMS kernel module in or out of scope? Licensing/backend in scope?

### 1. Repository + branch access
- [ ] Auditor granted read access (and to `website/supabase/functions/` if licensing in scope).
- [ ] Exact review commit pinned by tag or full SHA, not a moving branch.
- [ ] Branch map handed over (`main` = default target; plus in-flight `claude/…` and `review/session-baseline` branches); state which is authoritative and whether any must merge first.
- [ ] `Cargo.lock` committed and matches the reviewed commit.
- [ ] No secrets in history confirmed: signing secret / Ed25519 PKCS8 / Supabase service-role key are server-side only; client ships only the Ed25519 **public** key + Supabase **anon** key.

### 2. Reproducible build + run
- [ ] Toolchain versions pinned (Rust, `clang`/sanitizer runtime, kernel headers, `nft`).
- [ ] Default offline build reproduces from clean checkout: `cargo build --workspace`; and `cargo build -p ufw-cli --features tls` (only networked step — pinned `rustls`/`ring`).
- [ ] Kernel module builds via `kernel/linux/Kbuild`/`Makefile` on the stated kernel; DKMS path documented.
- [ ] Ready-to-run env: `tests/docker/docker-compose.yml` + `tests/docker/Dockerfile.linux` come up clean.
- [ ] Live run is one documented command: `scripts/live-run.sh` (+ `DEPLOYMENT.md`).
- [ ] Compiled ruleset dumpable (`nft list table inet ufw`) with a sample policy→ruleset walkthrough.
- [ ] `docs/development/setup.md` and `testing.md` current.

### 3. Threat model + attack-surface docs
- [ ] `threat-model.md` (assets, boundaries, adversaries A1-A6, non-goals, fail-safe posture) current.
- [ ] `attack-surface.md` (every listening socket, privileged path, trusted file, ranked) matches code.
- [ ] `formal_semantics.md` + `policy_language_spec.md` provided.
- [ ] Trust boundaries named explicitly: unprivileged→daemon IPC; daemon→kernel/nftables; client→licensing backend; network→ring-0 parsers.
- [ ] Fail-safe posture documented: behavior on daemon crash, bad policy, module unload.

### 4. Existing evidence (so the auditor extends, not re-creates)
- [ ] **CI gate** — `.github/workflows/ci.yml` (tests, `clippy -D warnings`, fmt, `--features tls`, SBOM) green on the reviewed commit.
- [ ] **Fuzzing** — `.github/workflows/fuzz.yml`: targets `linux-decoders`, `windows-decoders`, `reassembly`, `automaton` (`fuzz/`); seed + evolved corpora present; hand over local-run + crash-artifact instructions.
- [ ] **C↔Rust differential gate** — `cargo test -p ufw-kcore --test differential`; confirm non-vacuous (`UFW_DIFF_REQUIRE=1`, full corpus + mutation count); state Rust `no_std`/no-`unsafe` core is reference, C is what ships.
- [ ] **Policy-compiler equivalence** — `policy-lang/tests/{equivalence_proof_tests.rs,compiler_equivalence_tests.rs}`; `tests/scenarios/cross_platform_equivalence.rs`.
- [ ] **Detection efficacy harness** — `daemon/tests/{waf_efficacy.rs,detection_efficacy.rs}`; hand over figures *with honest scope* (corpus-bound, not novel-attack).
- [ ] **SBOM** — `scripts/gen-sbom.sh` (CycloneDX 1.5 from `Cargo.lock`); `docs/SUPPLY-CHAIN.md`.
- [ ] **SLSA / provenance** — `.github/workflows/release.yml` build-provenance attestation + signed apt repo; provide a signed artifact + verification command.
- [ ] **Soak** — `scripts/soak.sh` + `soak-results-latest.md`; state honestly the published run is smoke-scale.

### 5. Ranked "look here first" (day-one pointers, mirrors the audit brief)
- [ ] **1 — nftables emission / policy compiler:** `policy-lang/`, `cli/` compiler, `cli/tests/`. The layer that actually enforces; miscompile = silent bypass.
- [ ] **2 — Ring-0 parsers:** `kernel/linux/src/{classify.c,dpi_engine.c,stream_reassembly.c,netfilter_hooks.c}`, `kernel/linux/inc/{dpi_automaton.h,stream.h}`, Rust reimpl `kernel/linux/rust/ufw_kcore`.
- [ ] **3 — Daemon request-path/IPC + console's one mutating action:** `daemon/src/ipc/`, `daemon/src/management_api/{rest.rs,grpc.rs}`, `policy_loader.rs`/`policy_store.rs`, `cli/src/bin/ufw-nft/dashboard/`.
- [ ] **4 — Detection/logging state machines:** `daemon/src/logging/{portscan,beacon,bruteforce,dns_exfil,anomaly,correlation}.rs`, `daemon/src/signatures.rs`.
- [ ] **5 — Licensing client trust:** `cli/src/bin/ufw-nft/license.rs`; backend `website/supabase/functions/`.

### 6. Questions the report must settle (yes/no with evidence)
- [ ] **Policy soundness:** can a policy compile to a ruleset that permits what it denies (or vice versa) — incl. ordering, shadowing, default bases, fragment merges?
- [ ] **Compiler-gate integrity:** do the equivalence/differential gates constrain behavior, or can they pass vacuously / miss covered paths?
- [ ] **Ring-0 memory safety:** any attacker-reachable defect in the C decoders/reassembly/automaton that fuzzing + the differential gate miss? Where does C diverge from the Rust reference?
- [ ] **C↔Rust divergence:** inputs where shipped C and Rust reference disagree but the corpus never reaches them?
- [ ] **Privilege boundary:** can an unprivileged local process drive daemon IPC / mgmt API / console "contain" to alter nftables or escalate?
- [ ] **Fail-open vs fail-safe:** on crash/malformed policy/module unload, does enforcement fail *closed*? Any unfiltered window?
- [ ] **Licensing bypass:** can node-lock/Ed25519/hardware binding be forged into "enforcement-on," and is any recurring value NOT server-gated?
- [ ] **Detection honesty:** do WAF/anomaly numbers hold on an *independent* corpus; are stated scopes accurate?
- [ ] **Supply chain:** does the SBOM match the build, and does the SLSA/signature chain verify end-to-end from artifact to source commit?
- [ ] **Secret hygiene:** no signing secret / service-role key in client bundle, `.deb`, or git history.

### 7. Logistics
- [ ] Test corpora + any independent pcap corpus available (or absence flagged as a known gap).
- [ ] Expected-fail / known-issue list handed over.
- [ ] Severity scale + report format agreed up front.
- [ ] Re-test / fix-verification pass scheduled as part of the engagement.

---

## 6. Engagement model & what to expect

> **All durations, effort figures, and dollar amounts below are estimates calibrated to comparable published engagements — not quotes.** Firms do not publish per-project prices; effort scales with `unsafe`/FFI density, syscall/ioctl surface, and concurrency more than raw LOC. Confirm every number with the firm.

**Shape of the engagement (for a ~20-30k LOC kernel-plus-Rust codebase):**
- **Duration:** commonly **2-4 calendar weeks** of active review.
- **Team:** **1-3 reviewers**, often 2 — kernel/Rust work pulls memory-safety, `unsafe`-block, and FFI specialists.
- **Effort:** roughly **20-60 person-days**. Anchors from real OSTIF-managed work: RSTUF ≈ 22 person-days; RustVMM (11 crates) was a multi-week manual X41 review. A meaningful attack surface here skews toward the higher end.
- **Modality:** predominantly **manual source review guided by a threat model**, supplemented with fuzzing (new/tuned harnesses) and static/dynamic analysis. For kernel code the syscall/ioctl/netlink boundary and user↔kernel copy paths are the usual focus.

**Standard deliverables:**
- **Severity-rated findings report** (commonly CVSS v3.1 + critical/high/medium/low), each with impact, affected location, reproducer where feasible, and remediation — typically plus a list of non-security hardening notes.
- **Threat model / management summary** describing actors, attack surface, and scope.
- **Fix-verification / re-test pass** after you patch (standard, not optional — e.g., all 7 Cortex findings were re-verified before the report finalized).
- **Public report** in the grant-funded model, published after a coordinated-disclosure embargo so criticals get patched and CVEs assigned first. A purely private audit can stay confidential, but publication is the norm for funded OSS.

**Cost ranges (estimates / industry anchors — NOT quotes):**
- **Top-tier specialist rate:** reported around **~$25k per engineer-week** (a Trail of Bits figure), with whole engagements often **~$80k-$200k+** for larger/higher-complexity scopes.
- **A focused 2-4 week / 1-3 reviewer audit of a 20-30k LOC codebase** plausibly lands **~$30k-$120k** depending on firm, `unsafe`/FFI density, and depth — **wide on purpose.**
- **Broad security-audit market context (not kernel-specific):** ~$5k to $150k+ by scope.
- **Via a grant manager (OSTIF-style): your out-of-pocket is frequently $0** (funder pays), and OSTIF reports **~30% off** firms' standalone proposals.

**The grant-funded OSS route (OSTIF / OpenSSF / Sovereign Tech Fund) — recommended to pursue first:**
- **How it works.** A funder (OpenSSF's Alpha-Omega, AWS, the German/EU Sovereign Tech Agency, OTF, etc.) puts up the money; a manager — most commonly **OSTIF** — runs the engagement end-to-end: onboarding, scoping, a competitive bid among vetted firms, team selection matched to discipline, threat modeling with maintainers, managing the audit, and coordinating fix verification + publication. The maintainer typically pays nothing directly.
- **Direct precedent for this exact class.** OSTIF managed the **RustVMM** audit (11 Rust crates, reviewed by X41, AWS-funded), **RSTUF** (~22 person-days, X41 + OpenSSF), and a review of the **Linux kernel's own vulnerability reporting/remediation process** (with Atredis) — a kernel+Rust codebase is squarely in-profile.
- **Sovereign Tech Fund/Agency.** Its Resilience program funds FOSS security audits (has funded OSTIF-managed audits of zlib, cURL, LLVM, Rails). Note the main Fund track generally expects work **exceeding €50,000** — a program floor, not the price of one small audit — so the OSTIF intake is the more natural on-ramp for a single audit.
- **How to enter.** OSTIF's **"Get an Audit"** intake (contactus@ostif.org) or LFX crowdfunding; OpenSSF's Securing Critical Projects WG and Alpha-Omega are the funding on-ramps. Practical gating factors: being a recognized/critical dependency and demonstrable maintainer buy-in — which OSTIF repeatedly cites as the single biggest determinant of a smooth, cost-effective audit.

**Adjacent specialists (if you later want the supply-chain half done separately):** **Chainguard** for SLSA/build-provenance assessment, **Ada Logics** for standing up durable continuous fuzzing. Both are real and reputable but are complements to — not substitutes for — the Priority-1 kernel-C + emission audit.

**Cost-control levers you own:** a buildable/documented checkout, a tight named-commit scope, your own threat-model input, existing fuzz/CI harnesses, a responsive point of contact, and committed availability to fix. Every one of these converts directly into fewer reviewer-hours billed — which is what Section 5 is for.

---

> **Honest bottom line on uncertainty:** The firm names, precedents, and contact routes here are real and verifiable, but capabilities and availability drift — confirm directly. Every duration and dollar figure is an estimate anchored to comparable public engagements, not a quote; the only way to get a real number is a scoping call. And no audit removes your own two hardest obligations: pinning a clean review commit, and being available to fix what's found.
