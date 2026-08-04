//
//  RuleEngine.swift
//  Unified Firewall — the decision, macOS.
//
//  This is the macOS third of the equivalence claim. Everything here must
//  agree with `CompiledPolicy::evaluate` in shared/src/policy_types.rs, with
//  kernel/linux/src/classify.c and with kernel/windows/src/classify.c, for
//  every input. The compiler's equivalence verifier checks that claim at build
//  time against a scenario corpus derived from the policy itself.
//
//  The structure is deliberately the same as the two C classifiers: stages in
//  a fixed order, rules within a stage in a fixed order, first terminal action
//  wins. Reading the three side by side should be boring. Anywhere it is
//  interesting is a place to look when the verifier disagrees.
//
//  # What macOS makes harder
//
//  Two things, and both shape this file.
//
//  A Network Extension is not in the kernel. It is a userland process the
//  system consults, with a deadline: if `handleNewFlow` does not answer in
//  time the system applies its own default and the flow proceeds without our
//  opinion. So the decision has to be *fast* and, more importantly, it has to
//  be **bounded** — there is no path here that can wait on anything. Identity
//  comes from the audit token synchronously or it does not come at all.
//
//  And the sandbox caps reassembly memory. That is why the shared 32 KiB
//  budget exists on all three platforms: it is macOS's constraint, adopted
//  everywhere so that a signature which fires on Linux fires here too.
//

import Foundation

// MARK: - Policy vocabulary
//
// These types are the Swift half of the ABI. `UFWPolicy.generated.swift`
// constructs them directly, so a change here is a change to what the compiler
// must emit — the same relationship `policy_structs.h` has on Linux.

enum UFWAction: UInt8, Codable {
    case allow = 0
    case deny = 1
    case alert = 2
    case `continue` = 3
    /// A provisional permit. The flow proceeds, but evaluation does not stop,
    /// so a later stage can still deny. This is how "allow this flow, but kill
    /// it if the payload trips a signature" is expressed, and it is what the
    /// compiler silently lowers a perimeter-crossing `allow` into.
    case allowInspect = 4
}

/// Evaluation stages, in the order they run.
///
/// Not the numeric order of the defense layers: identity is stage 2 and DPI is
/// stage 3, because the process behind a flow is known before its payload has
/// been seen. An identity rule that would deny the flow should not first pay
/// for buffering and a signature scan.
enum UFWStage: UInt8, Codable, CaseIterable, Comparable {
    case perimeter = 0
    case packet = 1
    case identity = 2
    case appDPI = 3
    case stream = 4

    static func < (lhs: UFWStage, rhs: UFWStage) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

enum UFWDirection: UInt8, Codable {
    case any = 0
    case inbound = 1
    case outbound = 2
}

/// Which NEFilter callback carries this rule.
///
/// `.flow` rules are decided in `handleNewFlow`, where the audit token gives
/// us the process. `.packet` rules are decided in `handleNewPacket`, which
/// sees ICMP and everything else without a flow — and carries no process
/// context at all.
enum UFWProvider: UInt8, Codable {
    case flow = 0
    case packet = 1
}

enum UFWProtocolScope: UInt8, Codable {
    case all = 0
    case connectionOriented = 1
    case connectionless = 2
}

enum UFWTrust: UInt8, Codable, Comparable {
    case untrusted = 0
    case unknown = 1
    case known = 2
    case trusted = 3
    case system = 4

    static func < (lhs: UFWTrust, rhs: UFWTrust) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

enum UFWZone: UInt8, Codable {
    case local = 0
    case `internal` = 1
    case perimeter = 2
    case external = 3
}

enum UFWL7: UInt8, Codable {
    case unknown = 0
    case http = 1
    case tls = 2
    case dns = 3
    case ssh = 4
    case smtp = 5
    case quic = 6
}

struct UFWPortRange: Codable, Equatable {
    let lo: UInt16
    let hi: UInt16

    init(_ lo: UInt16, _ hi: UInt16) {
        self.lo = lo
        self.hi = hi
    }

    func contains(_ port: UInt16) -> Bool {
        port >= lo && port <= hi
    }
}

/// One platform's way of naming a binary.
///
/// Conjunctive within a fingerprint, disjunctive across them. A macOS
/// fingerprint naming both a Team ID and a bundle id means "this bundle, from
/// that team". A rule holding a macOS fingerprint and a Linux one means
/// "either" — which is what lets one logical application be described for three
/// platforms without a Linux binary being required to carry a Team ID.
struct UFWFingerprint: Codable, Equatable {
    let paths: [String]
    let sha256: [String]
    let signers: [String]
    let teamIDs: [String]
    let bundleIDs: [String]

    init(paths: [String] = [], sha256: [String] = [], signers: [String] = [],
         teamIDs: [String] = [], bundleIDs: [String] = []) {
        self.paths = paths
        self.sha256 = sha256
        self.signers = signers
        self.teamIDs = teamIDs
        self.bundleIDs = bundleIDs
    }

    var isEmpty: Bool {
        paths.isEmpty && sha256.isEmpty && signers.isEmpty
            && teamIDs.isEmpty && bundleIDs.isEmpty
    }
}

struct UFWAppMatch: Codable, Equatable {
    let fingerprints: [UFWFingerprint]
    let trust: [UFWTrust]
    let requireValidSignature: Bool
    let negate: Bool

    init(fingerprints: [UFWFingerprint] = [], trust: [UFWTrust] = [],
         requireValidSignature: Bool = false, negate: Bool = false) {
        self.fingerprints = fingerprints
        self.trust = trust
        self.requireValidSignature = requireValidSignature
        self.negate = negate
    }
}

struct UFWDPIMatch: Codable, Equatable {
    let signatures: [UInt32]
    let protocols: [UFWL7]
    /// The verdict when the predicate holds. Separate from the rule's own
    /// action so `action: allow` + `on_match: deny` expresses "permit unless
    /// the payload trips".
    let onMatch: UFWAction

    init(signatures: [UInt32] = [], protocols: [UFWL7] = [],
         onMatch: UFWAction = .deny) {
        self.signatures = signatures
        self.protocols = protocols
        self.onMatch = onMatch
    }
}

/// One compiled rule, exactly as `UFWPolicy.generated.swift` constructs it.
struct UFWRule {
    let id: UInt32
    let name: String
    let stage: UFWStage
    let priority: UInt32
    let provider: UFWProvider
    let protocolScope: UFWProtocolScope
    let action: UFWAction
    let direction: UFWDirection
    /// IANA protocol number, or 255 for "any".
    let ipProtocol: UInt8
    let sourceCIDRs: [String]
    let sourcePorts: [UFWPortRange]
    let destCIDRs: [String]
    let destPorts: [UFWPortRange]
    let sourceZones: [UFWZone]
    let destZones: [UFWZone]
    let application: UFWAppMatch?
    let dpi: UFWDPIMatch?
    let shouldLog: Bool

    init(id: UInt32, name: String, stage: UFWStage, priority: UInt32,
         provider: UFWProvider, protocolScope: UFWProtocolScope,
         action: UFWAction, direction: UFWDirection, ipProtocol: UInt8,
         sourceCIDRs: [String], sourcePorts: [UFWPortRange],
         destCIDRs: [String], destPorts: [UFWPortRange],
         sourceZones: [UFWZone], destZones: [UFWZone],
         application: UFWAppMatch?, dpi: UFWDPIMatch?, shouldLog: Bool) {
        self.id = id
        self.name = name
        self.stage = stage
        self.priority = priority
        self.provider = provider
        self.protocolScope = protocolScope
        self.action = action
        self.direction = direction
        self.ipProtocol = ipProtocol
        self.sourceCIDRs = sourceCIDRs
        self.sourcePorts = sourcePorts
        self.destCIDRs = destCIDRs
        self.destPorts = destPorts
        self.sourceZones = sourceZones
        self.destZones = destZones
        self.application = application
        self.dpi = dpi
        self.shouldLog = shouldLog
    }

    /// A rule with a DPI clause contributes the clause's `onMatch`, which is
    /// what makes `action: allow` + `on_match: deny` mean "permit unless the
    /// payload trips".
    var effectiveAction: UFWAction {
        dpi?.onMatch ?? action
    }
}

// MARK: - Flow facts

/// Everything the extension knows about one flow or packet.
///
/// `identity` and `dpi` are optionals rather than defaulted values because
/// absent facts must never read as wildcards. An unresolved identity does not
/// match an application predicate — and does not match a *negated* one either.
/// If it did, "deny anything that is not our signed binary" would be satisfied
/// by any process the extension could not inspect, which on a deadline is a
/// set an attacker can arrange to be in simply by being new.
struct UFWFlowFacts {
    var isIPv6: Bool = false
    var ipProtocol: UInt8 = 0
    var direction: UFWDirection = .any
    var sourceAddress: UFWAddress = .zeroV4
    var destAddress: UFWAddress = .zeroV4
    var sourcePort: UInt16 = 0
    var destPort: UInt16 = 0
    var sourceZone: UFWZone = .external
    var destZone: UFWZone = .external

    var identity: UFWIdentity?
    var dpi: UFWDPIResult?

    /// Minutes since Monday 00:00 local time, when a schedule needs it.
    var minuteOfWeek: UInt16?
}

struct UFWIdentity {
    let processID: pid_t
    let path: String
    let sha256: String?
    let teamID: String?
    let bundleID: String?
    let signer: String?
    let trust: UFWTrust
    let signatureValid: Bool
}

struct UFWDPIResult {
    let l7: UFWL7
    let matchedSignatures: [UInt32]
    /// The scan hit the reassembly budget, so a miss is not evidence of
    /// absence. A rule that denies on a signature treats a truncated miss as a
    /// non-match; a rule that alerts reports the truncation, because "we did
    /// not finish looking" is itself the finding.
    let truncated: Bool
}

struct UFWDecision {
    let action: UFWAction
    let stage: UFWStage
    let ruleID: UInt32
    let ruleName: String
    let shouldLog: Bool

    var isAllowed: Bool {
        action == .allow || action == .allowInspect || action == .alert
            || action == .continue
    }
}

/// Synthetic rule ids, matching the other two platforms so a log line means
/// the same thing wherever it was produced.
enum UFWSyntheticRule {
    static let policyDefault: UInt32 = 0xFFFF_FFFF
    static let noPolicy: UInt32 = 0xFFFF_FFFE
    static let failClosed: UInt32 = 0xFFFF_FFFD
}

// MARK: - Addresses

/// An IPv4 or IPv6 address, stored as bytes in network order.
///
/// Not `IPv4Address`/`IPv6Address` from Network.framework: those compare and
/// canonicalise according to their own rules, and this file's whole purpose is
/// to match two C implementations byte for byte. A v4-mapped v6 address must
/// not satisfy a v4 CIDR here just because Network.framework thinks the two are
/// the same address — that ambiguity is exactly the kind that becomes a bypass.
struct UFWAddress: Equatable {
    let bytes: [UInt8]   // 4 or 16
    let isV6: Bool

    static let zeroV4 = UFWAddress(bytes: [0, 0, 0, 0], isV6: false)

    init(bytes: [UInt8], isV6: Bool) {
        self.bytes = bytes
        self.isV6 = isV6
    }

    /// Parse a dotted-quad or colon-hex literal. Returns nil rather than a
    /// zero address on failure: a malformed address that silently became
    /// 0.0.0.0 would match a `0.0.0.0/0` rule.
    init?(string: String) {
        if string.contains(":") {
            guard let parsed = UFWAddress.parseIPv6(string) else { return nil }
            self.bytes = parsed
            self.isV6 = true
        } else {
            let parts = string.split(separator: ".")
            guard parts.count == 4 else { return nil }
            var out = [UInt8]()
            for part in parts {
                guard let value = UInt8(part) else { return nil }
                out.append(value)
            }
            self.bytes = out
            self.isV6 = false
        }
    }

    /// Parse a colon-hex literal, including the `::` compression form.
    ///
    /// Hand-written rather than via `inet_pton` because this must produce the
    /// same bytes as the two C implementations for every input the compiler can
    /// emit, including the ones `inet_pton` accepts with platform-specific
    /// leniency. A parser that is stricter than the address it will be compared
    /// against is safe; one that is more lenient is a place where macOS matches
    /// a CIDR the other two do not.
    private static func parseIPv6(_ s: String) -> [UInt8]? {
        // At most one `::`, splitting the literal into a head and a tail.
        let halves = s.components(separatedBy: "::")
        guard halves.count <= 2 else { return nil }

        func groups(_ text: String) -> [UInt16]? {
            if text.isEmpty { return [] }
            var out = [UInt16]()
            for piece in text.split(separator: ":", omittingEmptySubsequences: false) {
                guard !piece.isEmpty, piece.count <= 4,
                      let value = UInt16(piece, radix: 16) else { return nil }
                out.append(value)
            }
            return out
        }

        guard let head = groups(halves[0]) else { return nil }
        let tail: [UInt16]
        if halves.count == 2 {
            guard let parsed = groups(halves[1]) else { return nil }
            tail = parsed
        } else {
            tail = []
        }

        let stated = head.count + tail.count
        guard stated <= 8 else { return nil }
        // Without a `::` every group must be written out; with one, the gap
        // must cover at least one group.
        guard halves.count == 2 ? stated < 8 : stated == 8 else { return nil }

        var all = head
        all.append(contentsOf: [UInt16](repeating: 0, count: 8 - stated))
        all.append(contentsOf: tail)

        var out = [UInt8]()
        out.reserveCapacity(16)
        for group in all {
            out.append(UInt8(group >> 8))
            out.append(UInt8(group & 0xFF))
        }
        return out
    }
}

/// A parsed CIDR. Parsing happens once, when the policy is installed, rather
/// than per flow: on a deadline, re-parsing a string for every rule of every
/// flow is the difference between answering and being defaulted.
struct UFWCIDR {
    let address: UFWAddress
    let prefixLength: Int

    init?(_ text: String) {
        let parts = text.split(separator: "/")
        guard let addressText = parts.first,
              let address = UFWAddress(string: String(addressText)) else {
            return nil
        }
        let maxPrefix = address.isV6 ? 128 : 32
        if parts.count == 2 {
            guard let prefix = Int(parts[1]), prefix >= 0, prefix <= maxPrefix else {
                return nil
            }
            self.prefixLength = prefix
        } else {
            self.prefixLength = maxPrefix
        }
        self.address = address
    }

    func contains(_ other: UFWAddress) -> Bool {
        // A v4 rule never matches a v6 address and vice versa. See the note on
        // UFWAddress for why this is strict rather than accommodating.
        guard address.isV6 == other.isV6 else { return false }

        let fullBytes = prefixLength / 8
        let restBits = prefixLength % 8

        if fullBytes > 0 {
            guard address.bytes.count >= fullBytes, other.bytes.count >= fullBytes else {
                return false
            }
            for i in 0..<fullBytes where address.bytes[i] != other.bytes[i] {
                return false
            }
        }
        if restBits > 0 {
            guard address.bytes.count > fullBytes, other.bytes.count > fullBytes else {
                return false
            }
            let mask = UInt8(0xFF << (8 - restBits))
            if (address.bytes[fullBytes] & mask) != (other.bytes[fullBytes] & mask) {
                return false
            }
        }
        return true
    }
}

// MARK: - The engine

/// The installed policy, with everything pre-parsed.
final class UFWRuleEngine {
    /// Rules grouped by stage. Grouping happens once at install so evaluating
    /// a stage is a bounded walk rather than a filtered pass over everything.
    private let stages: [[PreparedRule]]
    private let defaultAction: UFWAction
    private let internalNetworks: [UFWCIDR]
    private let perimeterNetworks: [UFWCIDR]

    let revision: UInt64
    let rulesetSHA256: String
    let ruleCount: Int

    /// A rule with its CIDR strings already parsed.
    private struct PreparedRule {
        let rule: UFWRule
        let sourceCIDRs: [UFWCIDR]
        let destCIDRs: [UFWCIDR]
    }

    init(rules: [UFWRule],
         defaultAction: UFWAction,
         internalNetworks: [String],
         perimeterNetworks: [String],
         revision: UInt64 = 0,
         rulesetSHA256: String = "") {
        self.defaultAction = defaultAction
        self.revision = revision
        self.rulesetSHA256 = rulesetSHA256
        self.ruleCount = rules.count
        self.internalNetworks = internalNetworks.compactMap(UFWCIDR.init)
        self.perimeterNetworks = perimeterNetworks.compactMap(UFWCIDR.init)

        var buckets = [[PreparedRule]](repeating: [], count: UFWStage.allCases.count)
        // The compiler emits rules already sorted by (stage, priority, id), so
        // preserving the incoming order within a stage preserves the reference
        // evaluation order exactly. Re-sorting here would be a second place
        // for the tie-break rule to live, and a second place to get it wrong.
        for rule in rules {
            let prepared = PreparedRule(
                rule: rule,
                sourceCIDRs: rule.sourceCIDRs.compactMap(UFWCIDR.init),
                destCIDRs: rule.destCIDRs.compactMap(UFWCIDR.init)
            )
            buckets[Int(rule.stage.rawValue)].append(prepared)
        }
        self.stages = buckets
    }

    /// Build from the compiled-in policy. Used when the extension starts
    /// before the daemon has pushed anything, so there is never a window in
    /// which the extension is running with no rules at all.
    static func fromGeneratedPolicy() -> UFWRuleEngine {
        UFWRuleEngine(
            rules: UFWGeneratedPolicy.rules,
            defaultAction: UFWGeneratedPolicy.defaultAction,
            internalNetworks: UFWGeneratedPolicy.internalNetworks,
            perimeterNetworks: UFWGeneratedPolicy.perimeterNetworks,
            revision: UFWGeneratedPolicy.revision,
            rulesetSHA256: UFWGeneratedPolicy.rulesetSHA256
        )
    }

    // MARK: Zone classification

    func zone(of address: UFWAddress) -> UFWZone {
        if !address.isV6 {
            if address.bytes.first == 127 { return .local }
        } else if address.bytes == [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1] {
            return .local
        }
        // Perimeter before internal: the two overlap (a DMZ range is usually
        // inside RFC1918) and the more specific classification is the one the
        // operator meant.
        for cidr in perimeterNetworks where cidr.contains(address) { return .perimeter }
        for cidr in internalNetworks where cidr.contains(address) { return .internal }
        return .external
    }

    // MARK: Evaluation

    /// Evaluate the policy against one flow.
    ///
    /// `scope` restricts which rules are considered. It is not an optimisation:
    /// it is what keeps `handleNewFlow` and `handleNewPacket` from both
    /// deciding the same traffic. A TCP connection is decided once, in the flow
    /// callback where identity is available; the packet callback sees the same
    /// bytes afterwards and must not reach a second, possibly different,
    /// verdict.
    func evaluate(_ facts: UFWFlowFacts,
                  scope: UFWProtocolScope = .all) -> UFWDecision {
        var provisional: (UInt32, String)?

        for stage in UFWStage.allCases {
            guard stageApplies(stage, protocol: facts.ipProtocol) else { continue }

            for prepared in stages[Int(stage.rawValue)] {
                let rule = prepared.rule
                guard scopeApplies(rule.protocolScope, asking: scope) else { continue }
                guard matches(prepared, facts) else { continue }

                switch rule.effectiveAction {
                case .allow:
                    return UFWDecision(action: .allow, stage: stage, ruleID: rule.id,
                                       ruleName: rule.name, shouldLog: rule.shouldLog)
                case .deny:
                    return UFWDecision(action: .deny, stage: stage, ruleID: rule.id,
                                       ruleName: rule.name, shouldLog: rule.shouldLog)
                case .allowInspect:
                    // A provisional permit: remember it and keep going, because
                    // a later stage may still deny. Only the first is recorded,
                    // so the log names the rule that granted the permit rather
                    // than the last one that would have.
                    if provisional == nil {
                        provisional = (rule.id, rule.name)
                    }
                case .alert:
                    // Not a verdict. The caller emits the alert; evaluation
                    // continues so a later rule can still decide the flow.
                    alerts.append(UFWDecision(action: .alert, stage: stage,
                                              ruleID: rule.id, ruleName: rule.name,
                                              shouldLog: true))
                case .continue:
                    break
                }
            }
        }

        if let (id, name) = provisional {
            return UFWDecision(action: .allowInspect, stage: .packet, ruleID: id,
                               ruleName: name, shouldLog: true)
        }
        return UFWDecision(action: defaultAction, stage: .packet,
                           ruleID: UFWSyntheticRule.policyDefault,
                           ruleName: "policy-default", shouldLog: true)
    }

    /// Alerts raised by the most recent `evaluate`. Read and cleared by the
    /// caller; not thread-safe on its own, which is why the providers serialise
    /// evaluation onto their own queue.
    private(set) var alerts: [UFWDecision] = []

    func drainAlerts() -> [UFWDecision] {
        defer { alerts.removeAll(keepingCapacity: true) }
        return alerts
    }

    // MARK: Predicates

    /// Whether a stage runs at all for this protocol.
    ///
    /// Identity, app-dpi and stream all need a flow with an owning process and
    /// a payload. ICMP arrives through `handleNewPacket`, which has neither.
    /// Gating on the *stage* rather than on the individual predicates matters
    /// for a rule that sits at one of those stages without an app or DPI clause
    /// — a terminal `layer: stream` deny, say. Without this the three platforms
    /// would agree on the verdict for an ICMP packet while disagreeing about
    /// which rule produced it, which breaks cross-platform log correlation and
    /// which a verdict-only comparison would never surface.
    private func stageApplies(_ stage: UFWStage, protocol proto: UInt8) -> Bool {
        switch stage {
        case .perimeter, .packet:
            return true
        case .identity, .appDPI, .stream:
            return proto == 6 || proto == 17 || proto == 255
        }
    }

    private func scopeApplies(_ ruleScope: UFWProtocolScope,
                              asking: UFWProtocolScope) -> Bool {
        if asking == .all || ruleScope == .all { return true }
        return ruleScope == asking
    }

    private func matches(_ prepared: PreparedRule, _ facts: UFWFlowFacts) -> Bool {
        let rule = prepared.rule

        if rule.direction != .any && rule.direction != facts.direction { return false }
        if rule.ipProtocol != 255 && rule.ipProtocol != facts.ipProtocol { return false }

        guard addressMatches(cidrs: prepared.sourceCIDRs, zones: rule.sourceZones,
                             address: facts.sourceAddress, zone: facts.sourceZone) else {
            return false
        }
        guard addressMatches(cidrs: prepared.destCIDRs, zones: rule.destZones,
                             address: facts.destAddress, zone: facts.destZone) else {
            return false
        }
        guard portMatches(rule.sourcePorts, facts.sourcePort, facts.ipProtocol) else {
            return false
        }
        guard portMatches(rule.destPorts, facts.destPort, facts.ipProtocol) else {
            return false
        }
        if let app = rule.application, !appMatches(app, facts.identity) { return false }
        if let dpi = rule.dpi, !dpiMatches(dpi, facts.dpi) { return false }

        return true
    }

    private func addressMatches(cidrs: [UFWCIDR], zones: [UFWZone],
                                address: UFWAddress, zone: UFWZone) -> Bool {
        if cidrs.isEmpty && zones.isEmpty { return true }
        for cidr in cidrs where cidr.contains(address) { return true }
        return zones.contains(zone)
    }

    private func portMatches(_ ranges: [UFWPortRange], _ port: UInt16,
                             _ proto: UInt8) -> Bool {
        if ranges.isEmpty { return true }
        // A port constraint on a protocol with no ports never matches, not even
        // negated. "Port is not 53" is not vacuously true for ICMP — it is
        // unanswerable, and an unanswerable predicate must not permit.
        // Identical to both C classifiers; one of the places the three
        // implementations most easily drift.
        guard proto == 6 || proto == 17 || proto == 255 else { return false }
        for range in ranges where range.contains(port) { return true }
        return false
    }

    private func appMatches(_ match: UFWAppMatch, _ identity: UFWIdentity?) -> Bool {
        // The fail-closed asymmetry. See UFWFlowFacts for why an absent
        // identity fails even a negated predicate.
        guard let identity else { return false }

        if !match.trust.isEmpty && !match.trust.contains(identity.trust) {
            return false
        }
        if match.requireValidSignature && !identity.signatureValid {
            return false
        }

        var hit: Bool
        if match.fingerprints.isEmpty {
            hit = true
        } else {
            hit = match.fingerprints.contains { fingerprintMatches($0, identity) }
        }
        return match.negate ? !hit : hit
    }

    private func fingerprintMatches(_ fp: UFWFingerprint,
                                    _ identity: UFWIdentity) -> Bool {
        // Conjunctive within a fingerprint: one naming both a Team ID and a
        // bundle id means "this bundle, from that team", not "either".
        if !fp.paths.isEmpty {
            guard fp.paths.contains(where: { UFWGlob.match($0, identity.path) }) else {
                return false
            }
        }
        if !fp.sha256.isEmpty {
            guard let hash = identity.sha256,
                  fp.sha256.contains(where: { $0.caseInsensitiveCompare(hash) == .orderedSame })
            else { return false }
        }
        if !fp.teamIDs.isEmpty {
            guard let team = identity.teamID, fp.teamIDs.contains(team) else {
                return false
            }
        }
        if !fp.bundleIDs.isEmpty {
            guard let bundle = identity.bundleID, fp.bundleIDs.contains(bundle) else {
                return false
            }
        }
        if !fp.signers.isEmpty {
            guard let signer = identity.signer, fp.signers.contains(signer) else {
                return false
            }
        }
        return true
    }

    private func dpiMatches(_ match: UFWDPIMatch, _ result: UFWDPIResult?) -> Bool {
        guard let result else { return false }
        if !match.protocols.isEmpty && !match.protocols.contains(result.l7) {
            return false
        }
        if match.signatures.isEmpty { return true }
        return match.signatures.contains { result.matchedSignatures.contains($0) }
    }
}

// MARK: - Glob matching

enum UFWGlob {
    /// Iterative glob with one backtrack point.
    ///
    /// The recursive form is exponential on patterns like `*a*a*a*b`, and a
    /// process path is attacker-influenced: a process can be named anything.
    /// On a deadline that matters more here than in the kernel implementations
    /// — a pathological pattern does not crash the extension, it makes it miss
    /// its verdict window, and a missed window means the system decides without
    /// us.
    ///
    /// macOS paths are case-sensitive, so unlike the Windows implementation
    /// this compares exactly.
    static func match(_ pattern: String, _ path: String) -> Bool {
        let p = Array(pattern.utf8)
        let s = Array(path.utf8)
        var pi = 0, si = 0
        var star = -1, starS = 0

        while si < s.count {
            if pi < p.count && (p[pi] == UInt8(ascii: "?") || p[pi] == s[si]) {
                pi += 1
                si += 1
            } else if pi < p.count && p[pi] == UInt8(ascii: "*") {
                star = pi
                starS = si
                pi += 1
            } else if star >= 0 {
                pi = star + 1
                starS += 1
                si = starS
            } else {
                return false
            }
        }
        while pi < p.count && p[pi] == UInt8(ascii: "*") { pi += 1 }
        return pi == p.count
    }
}
