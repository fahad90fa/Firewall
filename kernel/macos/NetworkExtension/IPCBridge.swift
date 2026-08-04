//
//  IPCBridge.swift
//  Unified Firewall — the daemon channel.
//
//  # Two channels, and which one carries what
//
//  The daemon speaks the framed binary protocol in `shared/src/protocol.rs`
//  over a UNIX socket in the app-group container — the same framing,
//  multiplexing and bounds checking it uses on Linux and Windows. One protocol
//  implementation, one set of tests, one place for a framing bug to hide. That
//  is `UFWControlSocket`, at the bottom of this file, and it is the channel
//  that actually carries policy in a deployment.
//
//  XPC remains for clients that cannot open a socket in the container — a
//  management tool running outside the group. It carries the same operations
//  through `UFWExtensionProtocol`.
//
//  An earlier version of this file said a socket was unavailable inside the
//  sandbox. That is true of an app-sandboxed `.appex`; it is not true of a
//  System Extension holding `com.apple.security.application-groups`, which is
//  what `build/macos/extension.entitlements` declares. The daemon's macOS
//  transport was written against the socket and this side was not, so the two
//  halves never met.
//
//  # Verifying the peer, on either channel
//
//  This channel carries the rule table. Anything that can push a policy here
//  decides what the machine may talk to, so "who is on the other end" is the
//  security boundary rather than a nicety.
//
//  XPC gives the peer's audit token directly. A UNIX socket gives it too, via
//  `LOCAL_PEERTOKEN` — which is why the socket does not weaken the check. Both
//  paths end at the same Team ID requirement. The peer's *pid* would not do:
//  pids are reused, and the window between accepting a connection and checking
//  its owner is exactly the window an attacker would want.
//
//  # Back-pressure stops here
//
//  Log events are queued and dropped oldest-first when the queue is full. A
//  daemon that has stopped reading — because its SIEM collector stopped
//  reading — must not be able to slow down a verdict. Losing log lines is bad;
//  missing the verdict deadline is worse, because the system then decides the
//  flow permissively and nobody finds out.
//

import CryptoKit
import Foundation
import Security
import os.log

/// `SOL_LOCAL` and `LOCAL_PEERTOKEN` from `<sys/un.h>`, which Swift's Darwin
/// overlay does not re-export. The values are ABI and have not changed since
/// they were introduced; naming them here beats a pid-based check, which is
/// the only alternative and is defeated by pid reuse.
private let ufwSolLocal: Int32 = 0
private let ufwLocalPeerToken: Int32 = 0x006

/// What the extension exposes to the daemon.
@objc protocol UFWExtensionProtocol {
    func installPolicy(_ payload: Data, withReply reply: @escaping (Bool, String?) -> Void)
    func installSignatures(_ payload: Data, withReply reply: @escaping (Bool, String?) -> Void)
    func setEnforcementMode(_ mode: UInt8, withReply reply: @escaping (Bool) -> Void)
    func statistics(withReply reply: @escaping (Data?) -> Void)
}

/// What the daemon exposes to the extension.
@objc protocol UFWDaemonProtocol {
    func reportEvent(_ payload: Data)
    func requestPolicy(withReply reply: @escaping (Data?) -> Void)
    func requestSignatures(withReply reply: @escaping (Data?) -> Void)
}

/// Counters the daemon can ask the extension for.
///
/// Deliberately small, and served from a snapshot rather than from the live
/// rule engine: the extension is on the verdict path, and a statistics call
/// must not contend with a classification.
struct UFWExtensionStatistics: Codable {
    let policyRevision: UInt64
    let ruleCount: Int
    let signatureCount: Int
    let logEventsDropped: UInt64
}

final class UFWIPCBridge: NSObject {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "ipc")

    static let machServiceName = "com.unifiedfirewall.daemon"

    /// The daemon's Team ID. A connection whose peer does not present this is
    /// refused: see the file header for why this is the boundary rather than a
    /// nicety. Replaced at build time by build/macos/signing.sh with the
    /// signing identity actually used.
    static let expectedTeamID = "ABCDE12345"

    var onPolicy: ((UFWRuleEngine) -> Void)?
    var onSignatures: ((UFWSignatureSet) -> Void)?
    /// Set by the provider. Returns what is installed, from a snapshot it
    /// updates on install rather than from the engine the classifier owns.
    var statisticsSource: (() -> (revision: UInt64, rules: Int, signatures: Int))?

    private var connection: NSXPCConnection?
    private let queue = DispatchQueue(label: "com.unifiedfirewall.ipc")

    /// Bounded and lossy. When full the oldest event is discarded: during an
    /// incident the interesting events are the ones happening now, and a
    /// newest-first policy would preferentially drop exactly those while
    /// retaining a backlog from before anything happened.
    private static let queueDepth = 2048
    private var pending: [Data] = []
    private var dropped: UInt64 = 0

    /// The revision the last accepted policy carried, so `installPolicy` can
    /// tell "applied" from "rejected" without duplicating the decode.
    private(set) var installedRevision: UInt64 = 0

    /// Read by the statistics call. Not a precise count under concurrency and
    /// does not need to be: it answers "is this host losing log lines", and a
    /// lock on the report path to make it exact would cost the verdict.
    var droppedEventCount: UInt64 { dropped }

    // MARK: Connection

    func connect() {
        queue.async { [weak self] in
            guard let self else { return }

            let connection = NSXPCConnection(machServiceName: Self.machServiceName,
                                             options: [.privileged])
            connection.remoteObjectInterface = NSXPCInterface(with: UFWDaemonProtocol.self)
            // The daemon pushes policy and signatures; without an exported
            // object those calls reach nothing and fail silently on its side,
            // which reads as "the extension accepted it".
            connection.exportedInterface = NSXPCInterface(with: UFWExtensionProtocol.self)
            connection.exportedObject = self
            connection.invalidationHandler = { [weak self] in
                self?.log.notice("daemon connection invalidated")
                self?.connection = nil
            }
            connection.interruptionHandler = { [weak self] in
                // Interrupted, not invalidated: the daemon restarted. The
                // extension keeps enforcing the policy it already has — a
                // daemon restart must not open a filtering gap.
                self?.log.notice("daemon connection interrupted; keeping the installed policy")
            }
            connection.resume()
            self.connection = connection

            self.requestPolicy()
        }
    }

    func disconnect() {
        queue.async { [weak self] in
            self?.connection?.invalidate()
            self?.connection = nil
        }
    }

    /// Ask the daemon for the current policy. Called on connect and on
    /// reconnect, so a daemon restart re-synchronises rather than leaving the
    /// extension on whatever it last received.
    private func requestPolicy() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ [weak self] error in
            self?.log.error("requesting policy: \(error.localizedDescription, privacy: .public)")
        }) as? UFWDaemonProtocol else { return }

        proxy.requestPolicy { [weak self] payload in
            guard let self, let payload else { return }
            self.applyPolicy(payload)
        }
        // Signatures are pulled alongside, not pushed afterwards. A daemon
        // restart would otherwise leave the extension enforcing the policy it
        // re-fetched against whatever signature set it happened to be holding.
        proxy.requestSignatures { [weak self] payload in
            guard let self, let payload else { return }
            self.applySignatures(payload)
        }
    }

    // MARK: Inbound

    /// Decode a policy payload and hand it to the provider.
    ///
    /// A malformed payload is rejected wholesale rather than partially applied.
    /// Half a rule table is a policy nobody wrote, and the window it is live
    /// for is the window an attacker would want.
    ///
    /// The encoding is `CompiledPolicy::encode_into` in
    /// `shared/src/policy_types.rs` — the same bytes the Linux module and the
    /// Windows driver receive. It is not JSON: the payload has to be decodable
    /// by two C modules that have no JSON parser and are not getting one, and
    /// a second format for macOS alone would be a second thing to keep in step.
    func applyPolicy(_ payload: Data) {
        guard let engine = UFWPolicyWire.decode(payload) else {
            log.error("rejecting malformed policy (\(payload.count, privacy: .public) bytes)")
            return
        }
        installedRevision = engine.revision
        onPolicy?(engine)
    }

    /// Decode a signature payload and hand it to the provider.
    ///
    /// Rejected wholesale on any error, for the same reason a policy is: half
    /// a signature set is a set nobody wrote, and while it is live the
    /// extension reports clean scans for signatures it silently dropped.
    ///
    /// The encoding is the one `ufw_daemon::signatures::SignatureSet::encode`
    /// produces and both kernel modules decode — flat and little-endian
    /// rather than JSON, because the same bytes have to be read by two C
    /// decoders that have no JSON parser and are not getting one.
    func applySignatures(_ payload: Data) {
        guard let set = UFWSignatureSet.decode(payload) else {
            log.error("rejecting malformed signature payload (\(payload.count, privacy: .public) bytes)")
            return
        }
        onSignatures?(set)
    }

    // MARK: Outbound

    func report(_ decision: UFWDecision, facts: UFWFlowFacts) {
        let event = UFWLogEvent(
            timestampMicros: UInt64(Date().timeIntervalSince1970 * 1_000_000),
            ruleID: decision.ruleID,
            ruleName: decision.ruleName,
            action: decision.action,
            stage: decision.stage,
            ipProtocol: facts.ipProtocol,
            direction: facts.direction,
            sourceAddress: facts.sourceAddress.description,
            destAddress: facts.destAddress.description,
            sourcePort: facts.sourcePort,
            destPort: facts.destPort,
            sourceZone: facts.sourceZone,
            destZone: facts.destZone,
            processID: facts.identity?.processID ?? 0,
            path: facts.identity?.path,
            trust: facts.identity?.trust,
            l7: facts.dpi?.l7,
            matchedSignatures: facts.dpi?.matchedSignatures ?? [],
            dpiTruncated: facts.dpi?.truncated ?? false)

        guard let payload = try? JSONEncoder().encode(event) else { return }
        // The XPC queue below carries the JSON form for management clients.
        // The daemon reads the binary form off the control socket; see
        // `UFWLogEventWire`, and `UFWFilterDataProvider` for where the two are
        // driven from.

        queue.async { [weak self] in
            guard let self else { return }
            if self.pending.count >= Self.queueDepth {
                self.pending.removeFirst()
                self.dropped += 1
            }
            self.pending.append(payload)
            self.drain()
        }
    }

    private func drain() {
        guard let proxy = connection?.remoteObjectProxyWithErrorHandler({ _ in })
            as? UFWDaemonProtocol else {
            // Nobody listening. Events stay queued up to the bound, so a brief
            // daemon restart does not lose the events that happened during it.
            return
        }
        while !pending.isEmpty {
            proxy.reportEvent(pending.removeFirst())
        }
    }
}

// MARK: - Wire types

/// One log event. Field names match the unified log schema in
/// `shared/src/log_types.rs`, so a macOS event and a Linux event correlate on
/// rule id without a translation step in the aggregator.
struct UFWLogEvent: Codable {
    let timestampMicros: UInt64
    let ruleID: UInt32
    let ruleName: String
    let action: UFWAction
    let stage: UFWStage
    let ipProtocol: UInt8
    let direction: UFWDirection
    let sourceAddress: String
    let destAddress: String
    let sourcePort: UInt16
    let destPort: UInt16
    let sourceZone: UFWZone
    let destZone: UFWZone
    let processID: pid_t
    let path: String?
    let trust: UFWTrust?
    let l7: UFWL7?
    let matchedSignatures: [UInt32]
    let dpiTruncated: Bool
}

extension UFWAddress: CustomStringConvertible {
    var description: String {
        if isV6 {
            var groups: [String] = []
            var i = 0
            while i + 1 < bytes.count {
                groups.append(String(format: "%x", Int(bytes[i]) << 8 | Int(bytes[i + 1])))
                i += 2
            }
            return groups.joined(separator: ":")
        }
        return bytes.map(String.init).joined(separator: ".")
    }
}

// MARK: - What the daemon can call

/// The push half of the connection.
///
/// The extension also *pulls* policy and signatures when it connects, which is
/// what covers a daemon restart. These exist for the other direction: an
/// operator edits a policy, the daemon recompiles, and the new rules should
/// reach the extension without waiting for a reconnect that may never come.
///
/// Every method replies. An XPC method with a reply block that is never
/// invoked leaves the caller waiting until its own timeout, and the daemon
/// would report that as "the extension did not answer" rather than as the
/// specific thing that went wrong.
extension UFWIPCBridge: UFWExtensionProtocol {
    func installPolicy(_ payload: Data, withReply reply: @escaping (Bool, String?) -> Void) {
        let before = installedRevision
        applyPolicy(payload)
        if installedRevision != before {
            reply(true, nil)
        } else {
            reply(false, "the policy payload was rejected; see the extension log")
        }
    }

    func installSignatures(_ payload: Data, withReply reply: @escaping (Bool, String?) -> Void) {
        guard let set = UFWSignatureSet.decode(payload) else {
            reply(false, "the signature payload was malformed and was rejected wholesale")
            return
        }
        onSignatures?(set)
        reply(true, nil)
    }

    func setEnforcementMode(_ mode: UInt8, withReply reply: @escaping (Bool) -> Void) {
        guard let mode = UFWEnforcement(rawValue: mode) else {
            log.error("refusing unknown enforcement mode \(mode, privacy: .public)")
            reply(false)
            return
        }
        UFWEnforcement.current = mode
        // Recorded at notice or higher because emergency-allow means this host
        // has stopped filtering, and that must be visible in the unified log
        // even if the daemon's own sinks are unreachable.
        if mode == .emergencyAllow {
            log.critical("enforcement is OFF: every flow will be permitted")
        } else {
            log.notice("enforcement mode is now \(mode.rawValue, privacy: .public)")
        }
        reply(true)
    }

    func statistics(withReply reply: @escaping (Data?) -> Void) {
        guard let source = statisticsSource else {
            reply(nil)
            return
        }
        let snapshot = source()
        let stats = UFWExtensionStatistics(policyRevision: snapshot.revision,
                                           ruleCount: snapshot.rules,
                                           signatureCount: snapshot.signatures,
                                           logEventsDropped: droppedEventCount)
        reply(try? JSONEncoder().encode(stats))
    }
}

// MARK: - Policy wire decoding

/// The binary policy the daemon ships, decoded into a rule engine.
///
/// Mirrors `CompiledPolicy::encode_into` and `CompiledRule::encode` in
/// `shared/src/policy_types.rs`, field for field and in order. Every
/// discriminant it depends on is pinned by `shared/tests/macos_wire_contract.rs`,
/// which names the function below that has to change when one moves — there is
/// no Swift compiler in this workspace's CI, so that test is the only thing
/// standing between a renumbered enum and macOS quietly filtering a different
/// policy.
enum UFWPolicyWire {
    /// Refuse a payload claiming a wire version we do not implement, rather
    /// than decoding it as if the layout were unchanged.
    static let supportedWireVersion: UInt16 = 1

    static func decode(_ payload: Data) -> UFWRuleEngine? {
        var r = UFWWireReader(bytes: [UInt8](payload))
        guard let engine = decodePolicy(&r) else { return nil }
        return engine
    }

    static func decodePolicy(_ r: inout UFWWireReader) -> UFWRuleEngine? {
        guard let wireVersion = r.u16(), wireVersion == supportedWireVersion,
              let revision = r.u64(),
              let name = string(&r),
              let defaultRaw = r.u8(),
              let defaultAction = UFWAction(rawValue: defaultRaw),
              let profile = decodeNetworkProfile(&r),
              let count = r.u32(), count <= 65_536
        else { return nil }
        _ = name

        var rules: [UFWRule] = []
        rules.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let wire = decodeRule(&r) else { return nil }
            // One wire rule can become two installed rules: a
            // protocol-agnostic rule is carried by the flow provider for TCP
            // and UDP and by the packet provider for everything else. See
            // `placements(for:)`.
            for (provider, scope) in placements(for: wire) {
                rules.append(wire.installed(provider: provider, scope: scope))
            }
        }

        guard let hash = r.raw(32) else { return nil }

        return UFWRuleEngine(rules: rules,
                             defaultAction: defaultAction,
                             internalNetworks: profile.internal,
                             perimeterNetworks: profile.perimeter,
                             revision: revision,
                             rulesetSHA256: hex(hash))
    }

    // MARK: Rules

    /// A rule as it arrives, before placement splits it.
    struct WireRule {
        let id: UInt32
        let name: String
        let priority: UInt16
        let layer: UInt8
        let stage: UFWStage
        let direction: UFWDirection
        let action: UFWAction
        let ipProtocol: UInt8
        let isProtocolAny: Bool
        let sourceCIDRs: [String]
        let sourceZones: [UFWZone]
        let sourcePorts: [UFWPortRange]
        let destCIDRs: [String]
        let destZones: [UFWZone]
        let destPorts: [UFWPortRange]
        let application: UFWAppMatch?
        let dpi: UFWDPIMatch?
        let shouldLog: Bool

        func installed(provider: UFWProvider, scope: UFWProtocolScope) -> UFWRule {
            UFWRule(id: id, name: name, stage: stage, priority: UInt32(priority),
                    provider: provider, protocolScope: scope,
                    action: action, direction: direction, ipProtocol: ipProtocol,
                    sourceCIDRs: sourceCIDRs, sourcePorts: sourcePorts,
                    destCIDRs: destCIDRs, destPorts: destPorts,
                    sourceZones: sourceZones, destZones: destZones,
                    application: application, dpi: dpi, shouldLog: shouldLog)
        }
    }

    static func decodeRule(_ r: inout UFWWireReader) -> WireRule? {
        guard let id = r.u32(), let name = string(&r), let priority = r.u16(),
              let layerRaw = r.u8(), let stage = stage(fromWireLayer: layerRaw),
              let directionRaw = r.u8(), let direction = direction(fromWire: directionRaw),
              let actionRaw = r.u8(), let action = UFWAction(rawValue: actionRaw),
              let protocolRaw = r.u16()
        else { return nil }

        guard let source = decodeAddressMatch(&r),
              let sourcePorts = decodePortMatch(&r),
              let dest = decodeAddressMatch(&r),
              let destPorts = decodePortMatch(&r),
              let hasApp = r.u8()
        else { return nil }

        var application: UFWAppMatch?
        if hasApp != 0 {
            guard let app = decodeAppMatch(&r) else { return nil }
            application = app
        }

        guard let hasDPI = r.u8() else { return nil }
        var dpi: UFWDPIMatch?
        if hasDPI != 0 {
            guard let d = decodeDPIMatch(&r) else { return nil }
            dpi = d
        }

        // Interface names. The extension has no reliable interface for a
        // NEFilterFlow, so the list is read to keep the cursor aligned and
        // then dropped; a rule scoped to an interface simply does not narrow
        // here. `interface-match` is not in the advertised capabilities for
        // exactly this reason.
        guard stringList(&r) != nil else { return nil }

        guard let hasSchedule = r.u8() else { return nil }
        if hasSchedule != 0 {
            // days (u8), start minute (u16), end minute (u16).
            guard r.u8() != nil, r.u16() != nil, r.u16() != nil else { return nil }
        }

        guard let flags = r.u16(), stringList(&r) != nil else { return nil }

        return WireRule(
            id: id,
            name: name,
            priority: priority,
            layer: layerRaw,
            stage: stage,
            direction: direction,
            action: action,
            ipProtocol: protocolRaw == 0xFFFF ? 0 : UInt8(truncatingIfNeeded: protocolRaw),
            isProtocolAny: protocolRaw == 0xFFFF,
            sourceCIDRs: source.cidrs,
            sourceZones: source.zones,
            sourcePorts: sourcePorts,
            destCIDRs: dest.cidrs,
            destZones: dest.zones,
            destPorts: destPorts,
            application: application,
            dpi: dpi,
            shouldLog: flags & 0x0001 != 0)
    }

    // MARK: Placement

    /// Where a rule is installed, mirroring `CompiledRule::macos_placements`
    /// in `shared/src/policy_types.rs`.
    ///
    /// `shared/tests/macos_wire_contract.rs` enumerates every (layer,
    /// protocol, has-identity) combination and fails naming this function if
    /// the Rust side moves.
    ///
    /// The empty result is real and deliberate: an identity-scoped rule on a
    /// connectionless protocol has nowhere to go. The flow provider never sees
    /// ICMP, and the packet provider has no `sourceAppAuditToken` to match on,
    /// so installing it anywhere would be a rule that silently never fires.
    /// The compiler reports that as a note at build time.
    static func placements(for rule: WireRule) -> [(UFWProvider, UFWProtocolScope)] {
        let isFlowProtocol = rule.ipProtocol == 6 || rule.ipProtocol == 17
        let agnostic = rule.isProtocolAny

        // Payload inspection only exists for flows, whatever the protocol says.
        if rule.stage == .appDPI || rule.stage == .stream {
            return [(.flow, .connectionOriented)]
        }

        var out: [(UFWProvider, UFWProtocolScope)] = []
        if agnostic || isFlowProtocol {
            out.append((.flow, .connectionOriented))
        }
        if (agnostic || !isFlowProtocol) && rule.application == nil {
            out.append((.packet, .connectionless))
        }
        return out
    }

    // MARK: Enum mappings

    /// `Layer` is numbered by defense layer; `UFWStage` by evaluation order.
    /// Identity is L4 but evaluates third, so this is not a cast.
    static func stage(fromWireLayer raw: UInt8) -> UFWStage? {
        switch raw {
        case 1: return .perimeter
        case 2: return .packet
        case 3: return .appDPI
        case 4: return .identity
        case 5: return .stream
        default: return nil
        }
    }

    /// `Direction` is `Inbound=0, Outbound=1, Any=2`; `UFWDirection` is
    /// `any=0, inbound=1, outbound=2`. Also not a cast.
    static func direction(fromWire raw: UInt8) -> UFWDirection? {
        switch raw {
        case 0: return .inbound
        case 1: return .outbound
        case 2: return .any
        default: return nil
        }
    }

    // MARK: Sub-structures

    struct AddressMatch {
        let cidrs: [String]
        let zones: [UFWZone]
        let negate: Bool
    }

    static func decodeAddressMatch(_ r: inout UFWWireReader) -> AddressMatch? {
        guard let cidrCount = r.u16(), cidrCount <= 4096 else { return nil }
        var cidrs: [String] = []
        cidrs.reserveCapacity(Int(cidrCount))
        for _ in 0..<cidrCount {
            guard let cidr = decodeCIDR(&r) else { return nil }
            cidrs.append(cidr)
        }
        guard let zoneCount = r.u8() else { return nil }
        var zones: [UFWZone] = []
        for _ in 0..<zoneCount {
            guard let raw = r.u8(), let zone = UFWZone(rawValue: raw) else { return nil }
            zones.append(zone)
        }
        guard let negate = r.u8() else { return nil }
        // Negated address sets are carried but not applied here: the rule
        // engine's CIDR matching has no negation, and silently ignoring the
        // flag would invert the rule. Refusing the policy is the fail-closed
        // direction — the compiler does not emit one today, and if it starts,
        // this is where it must be implemented rather than where it is missed.
        if negate != 0 { return nil }
        return AddressMatch(cidrs: cidrs, zones: zones, negate: false)
    }

    /// `u8` family (4 or 6), the octets, then a `u8` prefix length.
    static func decodeCIDR(_ r: inout UFWWireReader) -> String? {
        guard let family = r.u8() else { return nil }
        switch family {
        case 4:
            guard let o = r.raw(4), let prefix = r.u8() else { return nil }
            return "\(o[0]).\(o[1]).\(o[2]).\(o[3])/\(prefix)"
        case 6:
            guard let o = r.raw(16), let prefix = r.u8() else { return nil }
            var groups: [String] = []
            for i in stride(from: 0, to: 16, by: 2) {
                groups.append(String(format: "%x", (UInt16(o[i]) << 8) | UInt16(o[i + 1])))
            }
            return groups.joined(separator: ":") + "/\(prefix)"
        default:
            return nil
        }
    }

    static func decodePortMatch(_ r: inout UFWWireReader) -> [UFWPortRange]? {
        guard let count = r.u16(), count <= 4096 else { return nil }
        var ranges: [UFWPortRange] = []
        ranges.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let lo = r.u16(), let hi = r.u16() else { return nil }
            ranges.append(UFWPortRange(lo, hi))
        }
        guard let negate = r.u8() else { return nil }
        // Same reasoning as an address set: a negated port set that were
        // dropped would widen the rule.
        if negate != 0 { return nil }
        return ranges
    }

    static func decodeAppMatch(_ r: inout UFWWireReader) -> UFWAppMatch? {
        guard let count = r.u16(), count <= 256 else { return nil }
        var fingerprints: [UFWFingerprint] = []
        for _ in 0..<count {
            guard let fingerprint = decodeFingerprint(&r) else { return nil }
            fingerprints.append(fingerprint)
        }
        guard let trustBits = r.u8(), let requireValid = r.u8(), let negate = r.u8()
        else { return nil }

        // The trust set is a bitmask over UFWTrust's raw values.
        var trust: [UFWTrust] = []
        for level in [UFWTrust.untrusted, .unknown, .known, .trusted, .system]
        where trustBits & (1 << level.rawValue) != 0 {
            trust.append(level)
        }

        return UFWAppMatch(fingerprints: fingerprints,
                           trust: trust,
                           requireValidSignature: requireValid != 0,
                           negate: negate != 0)
    }

    static func decodeFingerprint(_ r: inout UFWWireReader) -> UFWFingerprint? {
        guard let pathCount = r.u16(), pathCount <= 256 else { return nil }
        var paths: [String] = []
        for _ in 0..<pathCount {
            // Each path is a pattern plus a case-insensitivity flag. The
            // engine's matcher folds case on the platforms that need it, so
            // the flag is read and dropped rather than silently changing
            // whether a pattern matches.
            guard let pattern = string(&r), r.u8() != nil else { return nil }
            paths.append(pattern)
        }
        guard let hashCount = r.u16(), hashCount <= 256 else { return nil }
        var hashes: [String] = []
        for _ in 0..<hashCount {
            guard let digest = r.raw(32) else { return nil }
            hashes.append(hex(digest))
        }
        guard let signers = stringList(&r), let teamIDs = stringList(&r),
              let bundleIDs = stringList(&r) else { return nil }
        return UFWFingerprint(paths: paths, sha256: hashes, signers: signers,
                              teamIDs: teamIDs, bundleIDs: bundleIDs)
    }

    static func decodeDPIMatch(_ r: inout UFWWireReader) -> UFWDPIMatch? {
        guard let signatureCount = r.u16(), signatureCount <= 4096 else { return nil }
        var signatures: [UInt32] = []
        for _ in 0..<signatureCount {
            guard let id = r.u32() else { return nil }
            signatures.append(id)
        }
        guard let protocolCount = r.u8() else { return nil }
        var protocols: [UFWL7] = []
        for _ in 0..<protocolCount {
            guard let raw = r.u8(), let l7 = UFWL7(rawValue: raw) else { return nil }
            protocols.append(l7)
        }
        guard let onMatchRaw = r.u8(), let onMatch = UFWAction(rawValue: onMatchRaw)
        else { return nil }
        return UFWDPIMatch(signatures: signatures, protocols: protocols, onMatch: onMatch)
    }

    struct NetworkProfile {
        let `internal`: [String]
        let perimeter: [String]
    }

    static func decodeNetworkProfile(_ r: inout UFWWireReader) -> NetworkProfile? {
        func cidrList(_ r: inout UFWWireReader) -> [String]? {
            guard let count = r.u16(), count <= 4096 else { return nil }
            var out: [String] = []
            for _ in 0..<count {
                guard let cidr = decodeCIDR(&r) else { return nil }
                out.append(cidr)
            }
            return out
        }
        func ipList(_ r: inout UFWWireReader) -> Bool {
            guard let count = r.u16(), count <= 4096 else { return false }
            for _ in 0..<count {
                guard let family = r.u8() else { return false }
                let width = family == 4 ? 4 : (family == 6 ? 16 : -1)
                guard width > 0, r.raw(width) != nil else { return false }
            }
            return true
        }

        guard let internalNets = cidrList(&r), let perimeterNets = cidrList(&r) else {
            return nil
        }
        // Gateways and DNS servers enrich log events on the daemon side and
        // are not consulted here; read to keep the cursor aligned.
        guard ipList(&r), ipList(&r), r.u8() != nil else { return nil }
        return NetworkProfile(internal: internalNets, perimeter: perimeterNets)
    }

    // MARK: Primitives

    /// `u16` length prefix, then UTF-8.
    static func string(_ r: inout UFWWireReader) -> String? {
        guard let length = r.u16(), let bytes = r.raw(Int(length)) else { return nil }
        return String(decoding: bytes, as: UTF8.self)
    }

    static func stringList(_ r: inout UFWWireReader) -> [String]? {
        guard let count = r.u16(), count <= 4096 else { return nil }
        var out: [String] = []
        out.reserveCapacity(Int(count))
        for _ in 0..<count {
            guard let s = string(&r) else { return nil }
            out.append(s)
        }
        return out
    }

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
}

// MARK: - The control socket

/// The channel the daemon actually uses.
///
/// A UNIX socket in the app-group container carrying the framed binary
/// protocol from `shared/src/protocol.rs` — the same framing the Linux module
/// and the Windows driver receive. `daemon/src/ipc/macos.rs` is the other end.
///
/// # Why the extension listens rather than connects
///
/// The extension is activated by the system and may be running before the
/// daemon starts, after it crashes, and across its restarts. Whoever listens
/// must be the one with the longer life, or every daemon restart would need
/// the extension to notice and reconnect — and the window while it had not
/// noticed is a window in which policy changes go nowhere silently.
///
/// # One connection at a time
///
/// A second connection is accepted and immediately closed rather than served.
/// Two peers pushing rule tables into the same extension is not a
/// configuration anyone wants, and "the last writer wins" is not a property to
/// discover during an incident.
final class UFWControlSocket {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "control")

    /// Must match `ufw_shared::constants::PROTOCOL_MAGIC` and
    /// `PROTOCOL_VERSION`. Pinned by `shared/tests/macos_wire_contract.rs`.
    private static let magic: UInt32 = 0x0157_4655  // b"UFW\x01" little-endian
    private static let protocolVersion: UInt16 = 1
    private static let headerLength = 16

    /// A payload larger than this is refused without reading it. The daemon
    /// never sends one; anything that does is either broken or probing.
    private static let maxPayload = 8 * 1024 * 1024

    /// Message type codes. See `MessageType` in `shared/src/protocol.rs`.
    private enum Kind: UInt16 {
        case hello = 1
        case helloAck = 2
        case policyInstall = 10
        case policyInstallAck = 11
        case policyFlush = 14
        case logEvents = 30
        case statsRequest = 40
        case statsResponse = 41
        case setMode = 50
        case modeAck = 51
        case signatureInstall = 60
        case signatureInstallAck = 61
        case error = 99
    }

    /// What this extension tells the daemon it can do.
    ///
    /// `incrementalUpdate` is deliberately absent. Applying a delta means
    /// re-sorting the rule table by the compiler's evaluation-order key, which
    /// would be a second implementation of that ordering and a place for the
    /// two to disagree about which rule wins. Without the bit the daemon sends
    /// the whole table on every reload — more bytes, no second sort.
    ///
    /// `interfaceMatch` is absent because a `NEFilterFlow` does not reliably
    /// name an interface, and `ebpfFastpath` and `conntrack` because neither
    /// exists here.
    private static let capabilities: UInt32 =
        (1 << 0) |  // ipv6
        (1 << 1) |  // app-identity
        (1 << 2) |  // stream-reassembly
        (1 << 3) |  // dpi
        (1 << 7)    // scheduled-rules

    /// The system-wide container. Must match `DEFAULT_ENDPOINT` in
    /// `daemon/src/ipc/macos.rs`, which is where the daemon looks first.
    ///
    /// A System Extension runs as root, so this is the path that applies. The
    /// daemon also tries the per-user container for an agent-shaped
    /// deployment; the extension does not, because a system extension has no
    /// user session to have a container in.
    static let defaultPath =
        "/Library/Group Containers/group.com.unifiedfirewall/ufw-control.sock"

    private let path: String
    private let teamID: String
    private let queue = DispatchQueue(label: "com.unifiedfirewall.control")

    private var listenFD: Int32 = -1
    private var peerFD: Int32 = -1
    private var running = false

    var onPolicy: ((UFWRuleEngine) -> Void)?
    var onSignatures: ((UFWSignatureSet) -> Void)?
    var onFlush: (() -> Void)?
    var statisticsSource: (() -> (revision: UInt64, rules: Int, signatures: Int))?

    init(path: String, teamID: String) {
        self.path = path
        self.teamID = teamID
    }

    // MARK: Lifecycle

    func start() {
        queue.async { [weak self] in
            guard let self, !self.running else { return }
            guard self.bindAndListen() else { return }
            self.running = true
            self.acceptLoop()
        }
    }

    func stop() {
        queue.async { [weak self] in
            guard let self else { return }
            self.running = false
            if self.peerFD >= 0 { close(self.peerFD); self.peerFD = -1 }
            if self.listenFD >= 0 { close(self.listenFD); self.listenFD = -1 }
            unlink(self.path)
        }
    }

    private func bindAndListen() -> Bool {
        let fd = socket(AF_UNIX, SOCK_STREAM, 0)
        guard fd >= 0 else {
            log.error("control socket: socket() failed, errno \(errno, privacy: .public)")
            return false
        }

        // A socket left behind by a previous run would make bind() fail with
        // EADDRINUSE forever. Removing it is safe: only one extension is
        // activated at a time, so there is no live listener to steal.
        unlink(path)

        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let pathBytes = Array(path.utf8)
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard pathBytes.count < capacity else {
            log.error("control socket: path is longer than sun_path allows")
            close(fd)
            return false
        }
        withUnsafeMutablePointer(to: &addr.sun_path) { raw in
            raw.withMemoryRebound(to: CChar.self, capacity: capacity) { dst in
                for (i, byte) in pathBytes.enumerated() {
                    dst[i] = CChar(bitPattern: byte)
                }
                dst[pathBytes.count] = 0
            }
        }

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let bound = withUnsafePointer(to: &addr) { pointer in
            pointer.withMemoryRebound(to: sockaddr.self, capacity: 1) { generic in
                bind(fd, generic, size)
            }
        }
        guard bound == 0 else {
            log.error("control socket: bind(\(self.path, privacy: .public)) failed, errno \(errno, privacy: .public)")
            close(fd)
            return false
        }

        // Owner-only. The container is already restricted, but a mode that
        // depends on the container's permissions is a mode that changes when
        // somebody adjusts the container.
        chmod(path, 0o600)

        guard listen(fd, 1) == 0 else {
            log.error("control socket: listen() failed, errno \(errno, privacy: .public)")
            close(fd)
            unlink(path)
            return false
        }

        listenFD = fd
        log.notice("control socket listening on \(self.path, privacy: .public)")
        return true
    }

    private func acceptLoop() {
        while running {
            let fd = accept(listenFD, nil, nil)
            guard fd >= 0 else {
                if errno == EINTR { continue }
                if running {
                    log.error("control socket: accept() failed, errno \(errno, privacy: .public)")
                }
                return
            }

            guard verifyPeer(fd) else {
                // Not the daemon. Closing without a reply is deliberate: an
                // error frame would tell whoever is probing what protocol
                // speaks here and how far they got.
                log.error("control socket: refusing a peer that is not the daemon")
                close(fd)
                continue
            }
            if peerFD >= 0 {
                log.notice("control socket: refusing a second connection")
                close(fd)
                continue
            }

            peerFD = fd
            log.notice("control socket: daemon connected")
            serve(fd)
            close(fd)
            peerFD = -1
            log.notice("control socket: daemon disconnected")
        }
    }

    // MARK: Peer verification

    /// Verify the peer's code signature before accepting anything from it.
    ///
    /// By audit token, not by pid. A pid identifies a process only until it
    /// exits, and the gap between accepting a connection and asking who owns
    /// it is exactly the gap a pid-reuse attack needs. The audit token names
    /// the process that opened this socket and stays valid.
    private func verifyPeer(_ fd: Int32) -> Bool {
        var token = audit_token_t()
        var length = socklen_t(MemoryLayout<audit_token_t>.size)
        let ok = withUnsafeMutablePointer(to: &token) { pointer in
            getsockopt(fd, ufwSolLocal, ufwLocalPeerToken, pointer, &length)
        }
        guard ok == 0, length == socklen_t(MemoryLayout<audit_token_t>.size) else {
            log.error("control socket: no peer audit token, errno \(errno, privacy: .public)")
            return false
        }

        let tokenData = withUnsafeBytes(of: token) { Data($0) }
        let attributes = [kSecGuestAttributeAudit: tokenData] as CFDictionary
        var code: SecCode?
        guard SecCodeCopyGuestWithAttributes(nil, attributes, [], &code) == errSecSuccess,
              let peer = code else {
            log.error("control socket: peer has no code signature")
            return false
        }

        // Anchored at Apple's root and signed by our team. Anchoring matters:
        // without it a self-signed binary can claim any OU it likes.
        let requirementText =
            "anchor apple generic and certificate leaf[subject.OU] = \"\(teamID)\""
        var requirement: SecRequirement?
        guard SecRequirementCreateWithString(requirementText as CFString, [], &requirement)
                == errSecSuccess,
              let req = requirement else {
            return false
        }
        let status = SecCodeCheckValidity(peer, [], req)
        if status != errSecSuccess {
            log.error("control socket: peer failed the Team ID requirement (\(status, privacy: .public))")
            return false
        }
        return true
    }

    // MARK: Framing

    private func serve(_ fd: Int32) {
        while running {
            guard let (kind, seq, payload) = readFrame(fd) else { return }
            guard let reply = dispatch(kind: kind, payload: payload) else { continue }
            guard send(fd, kind: reply.0, seq: seq, payload: reply.1) else { return }
        }
    }

    /// Read one frame, or nil when the peer went away or sent something that
    /// is not this protocol.
    private func readFrame(_ fd: Int32) -> (UInt16, UInt32, [UInt8])? {
        guard let header = readExactly(fd, Self.headerLength) else { return nil }
        var r = UFWWireReader(bytes: header)
        guard let magic = r.u32(), magic == Self.magic else {
            log.error("control socket: bad magic; closing")
            return nil
        }
        guard let version = r.u16(), version == Self.protocolVersion else {
            log.error("control socket: unsupported protocol version; closing")
            return nil
        }
        guard let kind = r.u16(), let seq = r.u32(), let length = r.u32() else { return nil }
        guard length <= UInt32(Self.maxPayload) else {
            log.error("control socket: payload of \(length, privacy: .public) bytes refused")
            return nil
        }
        if length == 0 { return (kind, seq, []) }
        guard let payload = readExactly(fd, Int(length)) else { return nil }
        return (kind, seq, payload)
    }

    /// `read(2)` returns what it has, not what was asked for. Looping is not
    /// an optimisation here: a policy payload is larger than a socket buffer,
    /// so a single read is guaranteed to be short.
    private func readExactly(_ fd: Int32, _ count: Int) -> [UInt8]? {
        var buffer = [UInt8](repeating: 0, count: count)
        var filled = 0
        while filled < count {
            let n = buffer.withUnsafeMutableBytes { raw -> Int in
                read(fd, raw.baseAddress!.advanced(by: filled), count - filled)
            }
            if n > 0 { filled += n; continue }
            if n == 0 { return nil }          // peer closed
            if errno == EINTR { continue }
            return nil
        }
        return buffer
    }

    private func send(_ fd: Int32, kind: Kind, seq: UInt32, payload: [UInt8]) -> Bool {
        var frame = UFWWireWriter()
        frame.u32(Self.magic)
        frame.u16(Self.protocolVersion)
        frame.u16(kind.rawValue)
        frame.u32(seq)
        frame.u32(UInt32(payload.count))
        frame.raw(payload)
        return writeAll(fd, frame.bytes)
    }

    private func writeAll(_ fd: Int32, _ bytes: [UInt8]) -> Bool {
        var sent = 0
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                write(fd, raw.baseAddress!.advanced(by: sent), bytes.count - sent)
            }
            if n > 0 { sent += n; continue }
            if n < 0 && errno == EINTR { continue }
            return false
        }
        return true
    }

    // MARK: Dispatch

    /// Returns the reply to send, or nil for a message that needs none.
    private func dispatch(kind: UInt16, payload: [UInt8]) -> (Kind, [UInt8])? {
        guard let kind = Kind(rawValue: kind) else {
            // An unknown type is not fatal to the connection: a newer daemon
            // may know messages this extension does not, and closing would
            // turn a forward-compatible addition into an outage.
            return (.error, errorPayload(code: 1, detail: "unsupported message type"))
        }

        switch kind {
        case .hello:
            var w = UFWWireWriter()
            w.string(UFWControlSocket.moduleVersion)
            w.u32(UFWControlSocket.abiRevision)
            w.u32(Self.capabilities)
            w.u64(statisticsSource?().revision ?? 0)
            w.string("macos")
            return (.helloAck, w.bytes)

        case .policyInstall:
            guard let engine = UFWPolicyWire.decode(Data(payload)) else {
                return (.error, errorPayload(code: 2, detail: "malformed policy payload"))
            }
            onPolicy?(engine)
            return (.policyInstallAck, installAck(engine: engine))

        case .policyFlush:
            // Every rule removed leaves the default action, which for a
            // default-deny policy means the host stops talking. That is the
            // operator's call to make and the extension's job to carry out.
            onFlush?()
            var w = UFWWireWriter()
            w.u64(0)
            w.u32(0)
            w.u32(0)
            w.raw([UInt8](repeating: 0, count: 32))
            w.u16(0)
            return (.policyInstallAck, w.bytes)

        case .signatureInstall:
            var r = UFWWireReader(bytes: payload)
            guard let length = r.u32(), let bytes = r.raw(Int(length)),
                  let set = UFWSignatureSet.decode(Data(bytes)) else {
                return (.error, errorPayload(code: 3, detail: "malformed signature payload"))
            }
            onSignatures?(set)
            var w = UFWWireWriter()
            w.u32(UInt32(set.signatures.count))
            w.u32(UInt32(set.automaton?.patterns.count ?? 0))
            // The daemon compares this against its own digest of what it
            // sent. Without it a decoder that stopped halfway would report
            // success, and the operator would believe traffic was being
            // inspected against signatures this side never loaded.
            w.raw(Array(SHA256.hash(data: Data(bytes))))
            return (.signatureInstallAck, w.bytes)

        case .setMode:
            var r = UFWWireReader(bytes: payload)
            guard let raw = r.u8(), let mode = UFWEnforcement(rawValue: raw) else {
                return (.error, errorPayload(code: 4, detail: "unknown enforcement mode"))
            }
            UFWEnforcement.current = mode
            if mode == .emergencyAllow {
                log.critical("enforcement is OFF: every flow will be permitted")
            } else {
                log.notice("enforcement mode is now \(mode.rawValue, privacy: .public)")
            }
            var w = UFWWireWriter()
            w.u8(raw)
            return (.modeAck, w.bytes)

        case .statsRequest:
            let snapshot = statisticsSource?() ?? (revision: 0, rules: 0, signatures: 0)
            var w = UFWWireWriter()
            // Sixteen counters in the order KernelStats declares them. The
            // extension keeps few of them; the rest are zero rather than
            // invented, because a fabricated counter is worse than an absent
            // one for whoever is trying to understand a host.
            for _ in 0..<16 { w.u64(0) }
            w.u32(0)  // no per-rule hit counters
            _ = snapshot
            return (.statsResponse, w.bytes)

        default:
            return (.error, errorPayload(code: 5, detail: "message not accepted by the extension"))
        }
    }

    private func installAck(engine: UFWRuleEngine) -> [UInt8] {
        var w = UFWWireWriter()
        w.u64(engine.revision)
        w.u32(UInt32(engine.ruleCount))
        w.u32(0)
        w.raw(UFWControlSocket.bytes(fromHex: engine.rulesetSHA256, count: 32))
        w.u16(0)  // no warnings
        return w.bytes
    }

    private func errorPayload(code: UInt32, detail: String) -> [UInt8] {
        var w = UFWWireWriter()
        w.u32(code)
        w.string(detail)
        return w.bytes
    }

    static func bytes(fromHex hex: String, count: Int) -> [UInt8] {
        var out = [UInt8](repeating: 0, count: count)
        let characters = Array(hex.utf8)
        guard characters.count >= count * 2 else { return out }
        for i in 0..<count {
            let hi = value(ofHexDigit: characters[i * 2])
            let lo = value(ofHexDigit: characters[i * 2 + 1])
            guard let hi, let lo else { return out }
            out[i] = (hi << 4) | lo
        }
        return out
    }

    private static func value(ofHexDigit c: UInt8) -> UInt8? {
        switch c {
        case 0x30...0x39: return c - 0x30
        case 0x61...0x66: return c - 0x61 + 10
        case 0x41...0x46: return c - 0x41 + 10
        default: return nil
        }
    }

    /// Reported in the handshake. The daemon refuses a module whose ABI
    /// revision differs from its own, so this must track
    /// `ufw_shared::constants::ABI_REVISION`.
    static let abiRevision: UInt32 = 2
    static let moduleVersion = "0.1.0"

    // MARK: Outbound

    /// Push a batch of log events. Unsolicited, so it carries sequence zero —
    /// the daemon's multiplexer routes by type for these rather than matching
    /// a pending request.
    func report(events: [[UInt8]]) {
        queue.async { [weak self] in
            guard let self, self.peerFD >= 0 else { return }
            var w = UFWWireWriter()
            w.u32(UInt32(events.count))
            for event in events { w.raw(event) }
            _ = self.send(self.peerFD, kind: .logEvents, seq: 0, payload: w.bytes)
        }
    }
}

// MARK: - Little-endian writer

/// The mirror of `UFWWireReader`. Little-endian throughout, like everything
/// else on this wire.
struct UFWWireWriter {
    private(set) var bytes: [UInt8] = []

    mutating func u8(_ v: UInt8) { bytes.append(v) }

    mutating func u16(_ v: UInt16) {
        bytes.append(UInt8(v & 0xFF))
        bytes.append(UInt8((v >> 8) & 0xFF))
    }

    mutating func u32(_ v: UInt32) {
        for shift in stride(from: 0, to: 32, by: 8) {
            bytes.append(UInt8((v >> UInt32(shift)) & 0xFF))
        }
    }

    mutating func u64(_ v: UInt64) {
        for shift in stride(from: 0, to: 64, by: 8) {
            bytes.append(UInt8((v >> UInt64(shift)) & 0xFF))
        }
    }

    mutating func raw(_ v: [UInt8]) { bytes.append(contentsOf: v) }

    /// `u16` length prefix, then UTF-8.
    mutating func string(_ v: String) {
        let utf8 = Array(v.utf8)
        u16(UInt16(min(utf8.count, Int(UInt16.max))))
        raw(Array(utf8.prefix(Int(UInt16.max))))
    }
}

// MARK: - Log event encoding

/// One log event in the wire form `LogEvent::encode` produces in
/// `shared/src/log_types.rs`.
///
/// The same schema the other two platforms emit, so a macOS event and a Linux
/// event correlate on rule id in the aggregator without a translation step —
/// which is the whole point of Flow 7 in the architecture, and would be lost
/// if this side invented its own shape.
enum UFWLogEventWire {
    /// `ufw_shared::constants::LOG_SCHEMA_VERSION`.
    static let schemaVersion: UInt16 = 1

    /// `EventKind` in `shared/src/log_types.rs`.
    enum Kind: UInt8 {
        case flowDecision = 0
        case alert = 1
        case dpiMatch = 2
        case identityResolved = 3
        case policyChange = 4
        case systemFault = 5
    }

    /// `Severity` in the same file.
    enum Severity: UInt8 {
        case debug = 0, info = 1, notice = 2, warning = 3, error = 4, critical = 5
    }

    static func encode(hostID: String,
                       sequence: UInt64,
                       timestampMicros: UInt64,
                       policyRevision: UInt64,
                       decision: UFWDecision,
                       facts: UFWFlowFacts,
                       latencyNanos: UInt64) -> [UInt8] {
        var w = UFWWireWriter()
        w.u16(schemaVersion)
        w.u64(timestampMicros)
        w.string(hostID)
        w.u64(sequence)

        // An alert-action rule reports as an alert; a DPI hit that decided the
        // flow reports as a DPI match. Both are still flow decisions, and the
        // kind is what lets a SIEM triage without re-deriving it.
        let kind: Kind
        if facts.dpi?.matchedSignatures.isEmpty == false {
            kind = .dpiMatch
        } else if decision.action == .alert {
            kind = .alert
        } else {
            kind = .flowDecision
        }
        w.u8(kind.rawValue)
        w.u8(decision.action == .deny ? Severity.warning.rawValue : Severity.info.rawValue)

        w.u64(policyRevision)
        w.u32(decision.ruleID)
        w.string(decision.ruleName)
        w.u8(wireLayer(for: decision.stage))
        // `Decision` on the wire is allow=0 / deny=1. A provisional permit is
        // reported as an allow: it is what happened to the flow, and the stage
        // that could still deny it will report separately if it does.
        w.u8(decision.action == .deny ? 1 : 0)
        w.u8(wireDirection(for: facts.direction))

        // Five-tuple: protocol as u16, then each address as a family byte and
        // its octets, with the port after it.
        w.u16(facts.ipProtocol == 0 ? 0xFFFF : UInt16(facts.ipProtocol))
        writeAddress(&w, facts.sourceAddress)
        w.u16(facts.sourcePort)
        writeAddress(&w, facts.destAddress)
        w.u16(facts.destPort)

        w.u8(facts.destZone.rawValue)
        w.u8(facts.destZone == .external || facts.destZone == .perimeter ? 1 : 0)

        if let identity = facts.identity {
            w.u8(1)
            w.u32(UInt32(bitPattern: Int32(identity.processID)))
            w.string(identity.path)
            writeOptionalString(&w, identity.sha256)
            writeOptionalString(&w, identity.signer)
            w.u8(1)
            w.u8(identity.trust.rawValue)
        } else {
            // Absent, not defaulted. An unresolved identity reported as
            // "untrusted, path empty" would read downstream as a fact rather
            // than as a gap.
            w.u8(0)
        }

        if let dpi = facts.dpi, let first = dpi.matchedSignatures.first {
            w.u8(1)
            w.u32(first)
            w.string("")            // the extension carries ids, not names
            w.u8(dpi.l7.rawValue)
            w.u64(0)                // stream offset is not tracked per match
            w.string("")            // no excerpt: it would carry payload bytes
        } else {
            w.u8(0)
        }

        w.u64(latencyNanos)
        writeOptionalString(&w, nil)
        w.u16(dpiTruncated(facts) ? 1 : 0)
        if dpiTruncated(facts) {
            w.string("dpi-truncated")
        }
        return w.bytes
    }

    private static func dpiTruncated(_ facts: UFWFlowFacts) -> Bool {
        facts.dpi?.truncated ?? false
    }

    /// The inverse of `UFWPolicyWire.stage(fromWireLayer:)`.
    static func wireLayer(for stage: UFWStage) -> UInt8 {
        switch stage {
        case .perimeter: return 1
        case .packet: return 2
        case .identity: return 4
        case .appDPI: return 3
        case .stream: return 5
        }
    }

    /// The inverse of `UFWPolicyWire.direction(fromWire:)`.
    static func wireDirection(for direction: UFWDirection) -> UInt8 {
        switch direction {
        case .inbound: return 0
        case .outbound: return 1
        case .any: return 2
        }
    }

    private static func writeAddress(_ w: inout UFWWireWriter, _ address: UFWAddress) {
        w.u8(address.isV6 ? 6 : 4)
        w.raw(address.bytes)
    }

    private static func writeOptionalString(_ w: inout UFWWireWriter, _ value: String?) {
        if let value {
            w.u8(1)
            w.string(value)
        } else {
            w.u8(0)
        }
    }
}
