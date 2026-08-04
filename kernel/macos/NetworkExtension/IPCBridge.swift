//
//  IPCBridge.swift
//  Unified Firewall — the XPC channel to the daemon.
//
//  # Why XPC and not a socket
//
//  A Network Extension's sandbox does not grant arbitrary filesystem or
//  network access, so a UNIX socket in a shared directory is not available the
//  way it is on Linux. XPC is the sanctioned channel, and it brings something
//  a socket would not: the peer's code signature. `NSXPCConnection` exposes the
//  audit token of whoever connected, which lets this side verify that the
//  daemon really is the daemon before accepting a policy from it.
//
//  That check is not decoration. This channel carries the rule table. Anything
//  that can push a policy here can decide what the machine may talk to, so
//  "who is on the other end" is the security boundary, and a Team ID check is
//  the only thing standing in front of it.
//
//  # Back-pressure stops here
//
//  Log events are queued and dropped oldest-first when the queue is full. A
//  daemon that has stopped reading — because its SIEM collector stopped
//  reading — must not be able to slow down a verdict. Losing log lines is bad;
//  missing the verdict deadline is worse, because the system then decides the
//  flow permissively and nobody finds out.
//

import Foundation
import os.log

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
    func applyPolicy(_ payload: Data) {
        do {
            let document = try JSONDecoder().decode(UFWPolicyDocument.self, from: payload)
            let engine = UFWRuleEngine(
                rules: document.rules.map { $0.toRule() },
                defaultAction: document.defaultAction,
                internalNetworks: document.internalNetworks,
                perimeterNetworks: document.perimeterNetworks,
                revision: document.revision,
                rulesetSHA256: document.rulesetSHA256)
            installedRevision = document.revision
            onPolicy?(engine)
        } catch {
            log.error("rejecting malformed policy: \(error.localizedDescription, privacy: .public)")
        }
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

/// The policy as the daemon sends it. Deliberately the same shape as
/// `macos/ufw-policy.json`, which the compiler emits — so the file a build
/// bakes in and the payload a daemon pushes are the same format, and only one
/// of them can be wrong.
struct UFWPolicyDocument: Codable {
    let revision: UInt64
    let rulesetSHA256: String
    let defaultAction: UFWAction
    let internalNetworks: [String]
    let perimeterNetworks: [String]
    let rules: [WireRule]

    struct WireRule: Codable {
        let id: UInt32
        let name: String
        let stage: UFWStage
        let priority: UInt32
        let provider: UFWProvider
        let protocolScope: UFWProtocolScope
        let action: UFWAction
        let direction: UFWDirection
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

        func toRule() -> UFWRule {
            UFWRule(id: id, name: name, stage: stage, priority: priority,
                    provider: provider, protocolScope: protocolScope,
                    action: action, direction: direction, ipProtocol: ipProtocol,
                    sourceCIDRs: sourceCIDRs, sourcePorts: sourcePorts,
                    destCIDRs: destCIDRs, destPorts: destPorts,
                    sourceZones: sourceZones, destZones: destZones,
                    application: application, dpi: dpi, shouldLog: shouldLog)
        }
    }
}

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
