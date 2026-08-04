# UnifiedFirewall.xcodeproj

The Xcode project file is generated rather than committed.

`project.pbxproj` is a machine-written format with unstable object identifiers:
two developers adding a file produce conflicting hunks that git cannot merge and
that a human cannot read well enough to resolve by hand. Committing it turns
every file addition into a merge conflict and every conflict into a coin flip.

So the project is generated from `project.yml` by XcodeGen:

```sh
brew install xcodegen
xcodegen generate      # in this directory's parent
```

`make` in the parent directory does this automatically if the project is
missing.

## What the project has to contain

If you are reconstructing it by hand, these are the parts that are not obvious
and that produce silent failures when wrong:

- **Three targets.** `UnifiedFirewall` (the containing app), `UFWSystemExtension`
  (the `.systemextension` bundle), and the Network Extension inside it. The app
  embeds the system extension in `Contents/Library/SystemExtensions`; anywhere
  else and `OSSystemExtensionManager` reports that it cannot find it.

- **Entitlements.** The extension needs `com.apple.developer.networking.networkextension`
  with the `content-filter-provider` value, and `com.apple.developer.system-extension.install`
  on the containing app. Missing either produces an activation failure whose
  message does not name the missing entitlement.

- **App group.** Both targets need the same `com.apple.security.application-groups`
  entry, or the XPC connection between the daemon and the extension is refused
  with an error that looks like the service does not exist.

- **Hardened runtime, on both targets.** Required for notarisation. Turning it
  off to make a local build work is how a build that cannot be shipped gets
  merged.

- **The generated policy.** `build/generated/macos/UFWPolicy.generated.swift`
  must be in the extension target's sources. Unlike the two kernel modules, the
  extension compiles its policy in — it starts enforcing before the daemon
  connects, so it needs a rule table at build time.
