//
//  IdentityResolver.swift
//  Unified Firewall — which application owns this flow.
//
//  # Why resolution does not happen on the verdict path
//
//  `SecCodeCopySigningInformation` reads the binary, walks a certificate
//  chain, and may hit the disk and the trust settings database. On a cold cache
//  that is tens of milliseconds. `handleNewFlow` has a deadline measured in a
//  small number of milliseconds, and blowing it means the system decides the
//  flow without us — silently, and on the permissive side.
//
//  So the verdict path only ever *reads* this cache. A miss returns nil and
//  schedules the resolution off the critical path; the answer benefits the next
//  flow from the same process, which for anything that talks to the network
//  more than once is nearly all of them.
//
//  The cost is real and worth stating plainly: the first flow of a
//  never-before-seen process is decided without identity. Every application
//  predicate fails for it, so under a default-deny policy it is denied — the
//  safe direction, and why this is tolerable. Under a default-allow policy it
//  is permitted, which is one more reason default-allow is a rollout phase
//  rather than a destination.
//
//  # The cache key
//
//  The audit token, not the pid. An audit token carries the pid *and* the
//  process's unique identifier, so a reused pid produces a different token and
//  therefore a cache miss — resolved correctly a moment later — instead of a
//  confident wrong answer. Keying on the bare pid would mean whatever
//  inherited the browser's pid inherits the browser's network access.
//

import Foundation
import Security
import os.log

final class UFWIdentityResolver {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "identity")

    /// Entries expire so a redeployed binary stops matching its old hash within
    /// a maintenance window, and so a long-lived process does not carry a
    /// signature verdict made against a trust store that has since changed.
    private static let ttl: TimeInterval = 300

    /// Bounded: an unbounded cache keyed on something an attacker can create at
    /// will (a new process) is a memory exhaustion primitive. Generous for any
    /// real host, and eviction costs only a re-resolution.
    private static let capacity = 4096

    private struct Entry {
        let identity: UFWIdentity
        let resolvedAt: Date
    }

    private let lock = NSLock()
    private var entries: [Data: Entry] = [:]
    private var inFlight: Set<Data> = []
    private let resolveQueue = DispatchQueue(label: "com.unifiedfirewall.identity",
                                             qos: .utility)

    /// Trust anchors, pushed by the daemon. Kept here rather than compiled in
    /// so that "which publishers do we trust" is policy — with the exception of
    /// the platform anchor below, which is not negotiable by configuration.
    private var trustedTeamIDs: Set<String> = []

    func setTrustedTeamIDs(_ ids: Set<String>) {
        lock.lock()
        trustedTeamIDs = ids
        lock.unlock()
    }

    /// Look up an identity. Never blocks, never resolves.
    func identity(for auditToken: Data?) -> UFWIdentity? {
        guard let auditToken else { return nil }

        lock.lock()
        if let entry = entries[auditToken],
           Date().timeIntervalSince(entry.resolvedAt) < Self.ttl {
            lock.unlock()
            return entry.identity
        }
        let alreadyResolving = inFlight.contains(auditToken)
        if !alreadyResolving {
            inFlight.insert(auditToken)
        }
        lock.unlock()

        if !alreadyResolving {
            resolveQueue.async { [weak self] in
                self?.resolve(auditToken)
            }
        }
        return nil
    }

    func flush() {
        lock.lock()
        entries.removeAll()
        lock.unlock()
    }

    // MARK: Resolution

    private func resolve(_ auditToken: Data) {
        defer {
            lock.lock()
            inFlight.remove(auditToken)
            lock.unlock()
        }

        let attributes = [kSecGuestAttributeAudit: auditToken] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let code else {
            // The process is gone, or the token is not one we can resolve.
            // Nothing is cached: a negative entry would pin an "untrusted"
            // verdict for the whole TTL, and the honest state is "we do not
            // know", which a cache miss already expresses.
            return
        }

        var staticCode: SecStaticCode?
        guard SecCodeCopyStaticCode(code, [], &staticCode) == errSecSuccess,
              let staticCode else {
            return
        }

        let binaryPath = path(of: staticCode)

        // Signing information and requirement information in one pass; asking
        // separately would walk the same signature twice.
        let flags = SecCSFlags(rawValue: kSecCSSigningInformation | kSecCSRequirementInformation)
        var info: CFDictionary?
        guard SecCodeCopySigningInformation(staticCode, flags, &info) == errSecSuccess,
              let dictionary = info as? [String: Any] else {
            store(auditToken, unsigned(auditToken, path: binaryPath))
            return
        }

        // Validity is a separate question from "is a signature present". A
        // signature that is present and does not verify is strictly worse than
        // none: it means something was signed and then modified.
        let signatureValid = (SecStaticCodeCheckValidity(staticCode, [], nil) == errSecSuccess)

        let teamID = dictionary[kSecCodeInfoTeamIdentifier as String] as? String
        let bundleID = dictionary[kSecCodeInfoIdentifier as String] as? String
        let cdHash = (dictionary[kSecCodeInfoUnique as String] as? Data)
            .map { $0.map { String(format: "%02x", $0) }.joined() }
        let signer = signerName(from: dictionary)

        lock.lock()
        let isTrustedTeam = teamID.map { trustedTeamIDs.contains($0) } ?? false
        lock.unlock()

        let trust: UFWTrust
        if !signatureValid {
            // Signed and broken. This is the distinction operators most often
            // get wrong, which is why `ufwctl identity resolve` spells it out.
            trust = .untrusted
        } else if binaryPath.hasPrefix("/System/") || binaryPath.hasPrefix("/usr/libexec/") {
            // Inside the sealed system volume. A stronger statement than any
            // Team ID, and the one trust level policy cannot grant by
            // configuration.
            trust = .system
        } else if isTrustedTeam {
            trust = .trusted
        } else if teamID != nil {
            trust = .known
        } else {
            trust = .unknown
        }

        store(auditToken, UFWIdentity(
            processID: processID(from: auditToken),
            path: binaryPath,
            sha256: cdHash,
            teamID: teamID,
            bundleID: bundleID,
            signer: signer,
            trust: trust,
            signatureValid: signatureValid
        ))
    }

    /// Unsigned but readable: `unknown`, not `untrusted`. Nothing was claimed
    /// and nothing failed. A rule can still match it by path or hash, or accept
    /// it with `trust: [unknown]`.
    private func unsigned(_ token: Data, path: String) -> UFWIdentity {
        UFWIdentity(processID: processID(from: token), path: path, sha256: nil,
                    teamID: nil, bundleID: nil, signer: nil,
                    trust: .unknown, signatureValid: false)
    }

    private func store(_ token: Data, _ identity: UFWIdentity) {
        lock.lock()
        entries[token] = Entry(identity: identity, resolvedAt: Date())
        if entries.count > Self.capacity {
            let cutoff = Date().addingTimeInterval(-Self.ttl)
            entries = entries.filter { $0.value.resolvedAt > cutoff }
            if entries.count > Self.capacity {
                entries.removeAll()
            }
        }
        lock.unlock()
    }

    private func path(of staticCode: SecStaticCode) -> String {
        var url: CFURL?
        guard SecCodeCopyPath(staticCode, [], &url) == errSecSuccess,
              let path = (url as URL?)?.path else {
            return ""
        }
        return path
    }

    private func signerName(from info: [String: Any]) -> String? {
        guard let chain = info[kSecCodeInfoCertificates as String] as? [SecCertificate],
              let leaf = chain.first else {
            return nil
        }
        var common: CFString?
        guard SecCertificateCopyCommonName(leaf, &common) == errSecSuccess else {
            return nil
        }
        return common as String?
    }

    private func processID(from auditToken: Data) -> pid_t {
        guard auditToken.count >= MemoryLayout<audit_token_t>.size else { return 0 }
        return auditToken.withUnsafeBytes { raw -> pid_t in
            audit_token_to_pid(raw.load(as: audit_token_t.self))
        }
    }
}
