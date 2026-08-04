# Application identity

Filtering by *who* rather than by *where*. This is the layer that distinguishes
this system from a port-based firewall, and the one with the most platform
asymmetry to hide.

## The problem with paths

`/usr/bin/curl` is not an identity. It is a location, and a location is
satisfied by whatever an attacker can write there. Identity has to be something
that cannot be forged without the signing key.

So an application is named by its **signature**, and the path — where used at
all — is one conjunct among several.

## The unified structure

Three platforms, three different sets of available facts, one structure:

```rust
struct AppIdentity {
    pid: u32,
    start_time_us: u64,        // with pid, the cache key
    path: String,
    sha256: Option<[u8; 32]>,
    signature_type: SignatureType,
    signature_valid: bool,     // separate from "present"
    signer: Option<String>,    // Authenticode subject
    team_id: Option<String>,   // Apple Developer Team ID
    bundle_id: Option<String>,
    trust: TrustLevel,
    user: Option<String>,
    platform_meta: BTreeMap<String, String>,  // SELinux, AppArmor, DR
}
```

`signature_valid` is deliberately separate from `signature_type`. "There is a
signature" and "the signature verifies" are different facts, and a binary that
was signed and then modified is a different security posture from one that was
never signed.

`platform_meta` is where facts with no cross-platform equivalent go — SELinux
context, AppArmor profile, designated requirement. They reach the log and the
CLI; they cannot be matched on, because a rule that matched on them would mean
something on one platform and nothing on the other two.

## Per-platform resolution

**Windows.** Open the process, read the image path, `WinVerifyTrust` the
Authenticode chain, extract the subject CN, check revocation against the system
stores.

**Linux.** `/proc/<pid>/exe` for the path, SHA-256 of the ELF image, `/proc/<pid>/stat`
field 22 plus `btime` for the start time, `/proc/<pid>/attr/current` for the LSM
label. Linux has no universal binary signing scheme, so identity is the content
hash plus, where present, an LSM label. A path ending in `" (deleted)"` — the
binary was replaced while running — yields a path marked unconfirmed and **no
trust**.

**macOS.** `SecCodeCopyGuestWithAttributes` from the audit token,
`SecCodeCopySigningInformation` for the Team ID, bundle id and certificate chain,
`SecStaticCodeCheckValidity` for validity. A bundle id that disagrees with the
enclosing bundle's is reported, not silently preferred.

## Trust levels

Ordered, and comparable with `>=`:

```
untrusted < unknown < known < trusted < system
```

The two that matter:

- **`unknown`** — unsigned but readable. Nothing was claimed and nothing failed.
  A rule can still match it by path or hash, or accept it with `trust: [unknown]`.
- **`untrusted`** — a signature is present and does **not** verify, or the
  process could not be inspected at all.

`untrusted` is strictly worse than `unknown`. This is the distinction operators
get backwards most often, which is why `ufwctl identity resolve` prints an
explanation when it reports either.

`AppIdentity::unresolved()` is `Untrusted`, not `Unknown`: a process we could not
inspect at all is the worst case, not a middling one.

## The trust database

Maps signer identities to levels, consulted in order of specificity:

1. Exact SHA-256 — the most specific claim available
2. Team ID (macOS)
3. Signer subject (Windows Authenticode)

Platform anchors are seeded automatically: `Microsoft Windows`, `Apple Inc.`,
and the platform-binary flag. Configured anchors override rather than duplicate.

## Caching, and the key

Every cache in this system keys on a **pair**, never a bare pid:

| Where | Key |
| --- | --- |
| Daemon | `(pid, start_time_us)` |
| Linux module | `(uid, socket cookie)` |
| Windows driver | `(pid, flow id)` |
| macOS extension | audit token (carries pid *and* a unique id) |

Pids are reused, and a reused pid is the difference between "the browser may
reach the internet" and "whatever inherited the browser's pid may reach the
internet". Keying on a pair makes a stale entry **miss** — resolved correctly a
moment later — rather than answer wrongly.

Entries expire (300s by default) so a redeployed binary stops matching its old
hash within a maintenance window.

## Resolution never blocks a packet

This is the constraint that shapes every implementation.

Reading a path, hashing a file and checking a signature are all blocking
operations. Classification runs in softirq context on Linux, at `DISPATCH_LEVEL`
on Windows, and under a hard deadline on macOS. None of the three can wait.

So the kernel never resolves. It reads a cache, and on a miss it asks the daemon
asynchronously and classifies the current packet without identity.

**The honest cost:** the first flow from a never-before-seen process is decided
without knowing the process. Under a default-deny policy that means denied, which
is the safe direction. Under default-allow it means permitted — one more reason
default-allow is a rollout phase rather than a destination.

## The fail-closed asymmetry

The single most important property in the identity layer:

> An absent identity matches **nothing** — including a negated predicate.

If it matched a negated predicate, then

```yaml
application:
  trust: [untrusted, unknown]
```

used as a deny would be satisfied by any process the resolver could not inspect.
Since resolution is asynchronous on every platform, that set is exactly the one
an attacker can arrange to be in: new processes.

The same asymmetry appears in the compiler, which rejects an `application:`
clause on a portless protocol (`LAYER_MISMATCH`) rather than letting it compile
into a rule that can never match.

## Fingerprints: disjunction across platforms, conjunction within one

```yaml
applications:
  browser:
    platforms:
      windows:
        path: "C:\\...\\browser.exe"
        signer: "Contoso Ltd"        # path AND signer
      linux:
        paths: [/usr/lib/contoso-browser/browser]
```

A binary matches if it satisfies **any one** fingerprint, and satisfies a
fingerprint only by meeting **all** of its criteria.

Flattening this — unioning the criteria and intersecting across kinds — makes the
Linux binary fail the Windows signer requirement, so the application becomes
unmatchable on Linux while every rule still reads correctly. It was a real bug in
this codebase, found by a realistic fixture rather than by review.

## What the log carries

Every decision records the resolved identity: path, hash, signer, trust, and
whether the signature validated. When resolution failed, it records *that*,
distinctly from "resolved as untrusted" — because "we could not tell" and "we
checked and it is bad" call for different responses.
