# Deploying on macOS

## The approval problem, stated first

On an unmanaged Mac, activating a System Extension shows a system prompt that the
user can decline. There is no API to suppress it and no way around it.

A host firewall a user can decline is not much of a control. **Production
deployments need an MDM profile pre-approving the team identifier.** Everything
below assumes that; the unmanaged path is documented because it is how you will
develop and test.

## Building

Needs Xcode on macOS. There is no cross-compilation path: signing and entitlement
validation happen at build time against the local keychain.

```sh
make generate POLICY=policies/base/default_deny.yaml
make -C kernel/macos
```

`make generate` is **required** here, unlike on the other two platforms. The
extension compiles its policy in, because it starts enforcing before the daemon
connects — otherwise the window between activation and the daemon's first push
would be a window with no firewall, and it is exactly the window a machine
reboots into.

## Signing and notarisation

```sh
IDENTITY="Developer ID Application: Example (ABCDE12345)" \
TEAM_ID=ABCDE12345 \
  build/macos/signing.sh

APPLE_ID=you@example.com TEAM_ID=ABCDE12345 APP_PASSWORD=xxxx-xxxx-xxxx-xxxx \
  build/macos/notarize.sh
```

Three things the scripts enforce, each because getting them wrong produces a
silent failure:

- **Inside-out signing.** The extension is signed, then embedded, then the app is
  signed over it. Signing the app first produces a bundle whose seal breaks when
  the extension is embedded, and the failure surfaces at activation as "the
  extension is damaged".
- **No `--deep`.** It re-signs nested code with the *app's* entitlements, which
  strips the extension's NetworkExtension entitlement and produces a bundle that
  activates and then does nothing.
- **Stapling.** Notarisation puts a ticket on Apple's servers; stapling attaches
  it to the bundle. Without it, installing needs a route to Apple — which is
  exactly what the restricted networks this firewall is most useful in do not
  have.

`signing.sh` also refuses to proceed while `IPCBridge.swift` still carries the
placeholder Team ID. The extension checks its XPC peer's Team ID before accepting
a policy, and a placeholder there produces a build that activates cleanly and
refuses every connection from the daemon.

## Installing

```sh
sudo cp -R kernel/macos/build/.../UnifiedFirewall.app /Applications/
open /Applications/UnifiedFirewall.app --args --activate
```

macOS will not activate an extension from anywhere other than `/Applications`.

**Unmanaged:** approve it in System Settings → Privacy & Security. The pane shows
a "blocked" notice for a few minutes after activation; that is the normal state,
not a failure.

**Managed:** ship a `SystemExtensionPolicy` payload with
`AllowedTeamIdentifiers = [ABCDE12345]` and a `WebContentFilter` payload naming
the provider bundle. The extension then activates without a prompt.

```sh
make -C kernel/macos status
```

`status` exists because "not running" is four different problems — not installed,
awaiting approval, approved but disabled, activated but crashing — with four
different fixes, and from the outside they look identical.

## Verifying

```sh
systemextensionctl list                  # activation state
log stream --predicate 'subsystem == "com.unifiedfirewall.extension"'
ufwctl status
```

## What is different here

**It is not in the kernel.** The extension is a sandboxed userland process the
system consults, under a deadline. Miss it and the system applies its own default
— permissively, silently, with no error. Everything on the verdict path is
therefore non-blocking, and identity comes from a cache or not at all.

The consequence you can observe: the first flow from a never-before-seen process
is decided without identity. Under default-deny that means denied, which is safe.
Under default-allow it means permitted.

**Reassembly is capped at 32 KiB** by the sandbox — and that cap is the shared
budget on all three platforms. Linux and Windows adopted it rather than choosing
their own, because a larger budget elsewhere would mean a signature that fires
there and silently does not here.

**No remediation UI.** A blocked flow is blocked. Offering the user a "proceed
anyway" button would put the policy decision in the hands of whoever is at the
machine, which is the opposite of what a centrally managed host firewall is for.

## When something is wrong

**"Extension will damage your computer."** Not notarised, or notarised without
stapling on a machine that cannot reach Apple.

**Activated but no callbacks.** Almost always `NEProviderClasses` in
`Info.plist` naming a class that does not exist. The extension activates, appears
healthy in `systemextensionctl list`, and never receives a single flow.

**The daemon cannot reach the extension.** Team ID mismatch, or the two bundles
carry different app groups. `log stream` on the extension's subsystem shows the
refusal.

**Emergency.** `ufwctl debug mode emergency-allow --yes`, or
`systemextensionctl uninstall - com.unifiedfirewall.extension` to remove it
entirely.
