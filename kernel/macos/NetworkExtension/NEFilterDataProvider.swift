//
//  NEFilterDataProvider.swift
//  Unified Firewall — the macOS enforcement point.
//
//  A Network Extension is not a kernel module. It is a userland process the
//  system asks for an opinion, under a deadline. Everything about this file is
//  shaped by that one fact.
//
//  # The deadline
//
//  `handleNewFlow` must return a verdict promptly. If it does not, the system
//  applies its own default and the flow proceeds without our decision — a
//  silent failure, on the permissive side, with no error anywhere. So there is
//  no path in this file that waits on anything: not on the daemon, not on a
//  lock held by a slow writer, not on disk. Facts that are not already
//  available are simply absent, and absent facts do not match.
//
//  That is the same rule the Linux module and the Windows driver follow, for a
//  different reason. There the constraint is softirq and DISPATCH_LEVEL; here
//  it is a timeout. The consequence is identical, which is why all three can
//  share a decision procedure.
//
//  # Why the verdicts are not `.allow()`
//
//  `NEFilterNewFlowVerdict.allow()` ends the extension's involvement in the
//  flow — no further callbacks, no inspection. That is right for a rule that
//  reached a terminal permit, and wrong for `allow-inspect`, which means
//  "proceed, but I still want to see the bytes". The latter returns
//  `filterDataVerdict`, which keeps the flow under observation so a signature
//  can still condemn it. Collapsing the two would silently disable every
//  stream-stage rule.
//

import Foundation
import NetworkExtension
import os.log

final class UFWFilterDataProvider: NEFilterDataProvider {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "filter")

    /// Evaluation is serialised onto one queue.
    ///
    /// Not for correctness of the rule table — that is immutable once
    /// published — but because the engine accumulates alerts during a single
    /// evaluation, and because a single queue makes the latency budget
    /// something that can be reasoned about. Concurrent evaluation would trade
    /// a predictable serial cost for an unpredictable parallel one, and the
    /// deadline cares about the tail, not the mean.
    private let queue = DispatchQueue(label: "com.unifiedfirewall.classify")

    private var engine: UFWRuleEngine = .fromGeneratedPolicy()
    private let identity = UFWIdentityResolver()
    private let streams = UFWStreamHandler()
    private let packets = UFWPacketHandler()
    private var bridge: UFWIPCBridge?
    private var control: UFWControlSocket?
    private let installed = UFWInstalledSnapshot()

    /// Monotonic per-event counter. The daemon orders events by it when two
    /// share a microsecond, which on a machine deciding thousands of flows a
    /// second is often.
    private var eventSequence: UInt64 = 0

    /// Resolved once. `ProcessInfo.hostName` can go to the resolver, and the
    /// verdict path is not somewhere to discover that.
    private let hostID = ProcessInfo.processInfo.hostName

    // MARK: Lifecycle

    override func startFilter(completionHandler: @escaping (Error?) -> Void) {
        log.info("starting: compiled-in policy revision \(self.engine.revision, privacy: .public), \(self.engine.ruleCount, privacy: .public) rules")

        // The extension starts with the policy that was compiled into it, so
        // there is never a window in which it is running and enforcing nothing.
        // The daemon replaces it moments later; until then the built-in table
        // is what applies, and it is the same table the build shipped.
        let bridge = UFWIPCBridge()
        bridge.onPolicy = { [weak self] engine in
            guard let self else { return }
            self.queue.async {
                self.engine = engine
                self.installed.setPolicy(revision: engine.revision, rules: engine.ruleCount)
                self.log.info("installed policy revision \(engine.revision, privacy: .public) (\(engine.ruleCount, privacy: .public) rules)")
            }
        }
        bridge.onSignatures = { [weak self] set in
            self?.queue.async {
                self?.streams.installSignatures(set)
                self?.installed.setSignatures(set.signatures.count)
            }
        }
        // Served from a snapshot rather than from `engine`, which the
        // classifier owns on `queue`. A statistics request must not contend
        // with a verdict that has a deadline.
        bridge.statisticsSource = { [weak self] in
            self?.installed.snapshot() ?? (revision: 0, rules: 0, signatures: 0)
        }
        bridge.connect()
        self.bridge = bridge

        // The channel the daemon actually uses. XPC above is for clients that
        // cannot open a socket in the group container; this is what carries
        // policy in a deployment, and `daemon/src/ipc/macos.rs` is the other
        // end of it.
        let control = UFWControlSocket(path: UFWControlSocket.defaultPath,
                                       teamID: UFWIPCBridge.expectedTeamID)
        control.onPolicy = { [weak self] engine in
            guard let self else { return }
            self.queue.async {
                self.engine = engine
                self.installed.setPolicy(revision: engine.revision, rules: engine.ruleCount)
                self.log.info("installed policy revision \(engine.revision, privacy: .public) (\(engine.ruleCount, privacy: .public) rules) over the control socket")
            }
        }
        control.onSignatures = { [weak self] set in
            self?.queue.async {
                self?.streams.installSignatures(set)
                self?.installed.setSignatures(set.signatures.count)
            }
        }
        control.onFlush = { [weak self] in
            guard let self else { return }
            self.queue.async {
                // An empty table, not the built-in one. Re-installing the
                // compiled-in policy would make a flush mean "revert to the
                // build", which is not what the operator asked for.
                self.engine = UFWRuleEngine(rules: [], defaultAction: .deny,
                                            internalNetworks: [], perimeterNetworks: [])
                self.installed.setPolicy(revision: 0, rules: 0)
                self.log.notice("policy flushed; the default action now decides every flow")
            }
        }
        control.statisticsSource = { [weak self] in
            self?.installed.snapshot() ?? (revision: 0, rules: 0, signatures: 0)
        }
        control.start()
        self.control = control

        completionHandler(nil)
    }

    override func stopFilter(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        log.info("stopping: reason \(reason.rawValue, privacy: .public)")
        bridge?.disconnect()
        control?.stop()
        streams.flushAll()
        completionHandler()
    }

    // MARK: Flows

    override func handleNewFlow(_ flow: NEFilterFlow) -> NEFilterNewFlowVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else {
            // Not a socket flow — a browser flow, or something the system
            // added after this was written. Deciding it with rules written for
            // sockets would be guessing, so it is passed to the system rather
            // than judged on facts we do not have.
            return .allow()
        }

        var facts = UFWFlowFacts()
        facts.direction = (socketFlow.direction == .inbound) ? .inbound : .outbound
        facts.ipProtocol = UInt8(socketFlow.socketProtocol == IPPROTO_UDP ? 17 : 6)

        if let remote = socketFlow.remoteEndpoint as? NWHostEndpoint,
           let address = UFWAddress(string: remote.hostname) {
            let port = UInt16(remote.port) ?? 0
            if facts.direction == .inbound {
                facts.sourceAddress = address
                facts.sourcePort = port
            } else {
                facts.destAddress = address
                facts.destPort = port
            }
            facts.isIPv6 = address.isV6
        }
        if let local = socketFlow.localEndpoint as? NWHostEndpoint,
           let address = UFWAddress(string: local.hostname) {
            let port = UInt16(local.port) ?? 0
            if facts.direction == .inbound {
                facts.destAddress = address
                facts.destPort = port
            } else {
                facts.sourceAddress = address
                facts.sourcePort = port
            }
        }

        // Synchronous, from a cache the resolver fills off this queue. A miss
        // leaves `identity` nil, which fails every application predicate
        // including negated ones — the fail-closed asymmetry. See
        // IdentityResolver.swift for why resolution cannot happen here.
        facts.identity = identity.identity(for: flow.sourceAppAuditToken)

        return queue.sync {
            facts.sourceZone = engine.zone(of: facts.sourceAddress)
            facts.destZone = engine.zone(of: facts.destAddress)

            let decision = engine.evaluate(facts, scope: .connectionOriented)
            for alert in engine.drainAlerts() {
                emit(alert, facts: facts)
            }
            if decision.shouldLog {
                emit(decision, facts: facts)
            }

            switch UFWEnforcement.current {
            case .emergencyAllow:
                return .allow()
            case .monitor:
                // Computed, logged, not enforced. How a deployment builds the
                // inventory a default-deny policy needs without an outage.
                return .allow()
            case .enforce:
                break
            }

            switch decision.action {
            case .deny:
                return .drop()
            case .allowInspect, .alert, .continue:
                // Provisional: proceed, but keep the flow under observation so
                // a stream-stage rule can still condemn it.
                return NEFilterNewFlowVerdict.filterDataVerdict(
                    withFilterInbound: true, peekInboundBytes: Int(UFWGeneratedPolicy.reassemblyBudgetBytes),
                    filterOutbound: true, peekOutboundBytes: Int(UFWGeneratedPolicy.reassemblyBudgetBytes))
            case .allow:
                return .allow()
            }
        }
    }

    // MARK: Stream data

    override func handleInboundData(from flow: NEFilterFlow,
                                    readBytesStartOffset offset: Int,
                                    readBytes: Data) -> NEFilterDataVerdict {
        inspect(flow: flow, data: readBytes, inbound: true)
    }

    override func handleOutboundData(from flow: NEFilterFlow,
                                     readBytesStartOffset offset: Int,
                                     readBytes: Data) -> NEFilterDataVerdict {
        inspect(flow: flow, data: readBytes, inbound: false)
    }

    private func inspect(flow: NEFilterFlow, data: Data, inbound: Bool) -> NEFilterDataVerdict {
        guard let socketFlow = flow as? NEFilterSocketFlow else { return .allow() }

        return queue.sync {
            var facts = UFWFlowFacts()
            facts.direction = inbound ? .inbound : .outbound
            facts.ipProtocol = UInt8(socketFlow.socketProtocol == IPPROTO_UDP ? 17 : 6)
            facts.identity = identity.identity(for: flow.sourceAppAuditToken)
            facts.dpi = streams.observe(flow: flow, data: data, inbound: inbound)

            if let remote = socketFlow.remoteEndpoint as? NWHostEndpoint,
               let address = UFWAddress(string: remote.hostname) {
                facts.destAddress = address
                facts.destPort = UInt16(remote.port) ?? 0
                facts.destZone = engine.zone(of: address)
            }

            let decision = engine.evaluate(facts, scope: .connectionOriented)
            for alert in engine.drainAlerts() {
                emit(alert, facts: facts)
            }
            if decision.shouldLog {
                emit(decision, facts: facts)
            }

            if decision.action == .deny && UFWEnforcement.current == .enforce {
                // Drop the flow, not just this chunk. A signature that fires
                // mid-stream condemns the conversation; letting the rest
                // through because the offending bytes already passed would be
                // detection theatre.
                streams.release(flow: flow)
                return .drop()
            }

            // Keep looking. A signature can match bytes that have not arrived.
            return .allow()
        }
    }

    // MARK: Packets

    override func handleNewPacket(_ packet: NEFilterPacket) -> NEFilterPacketVerdict {
        packets.handle(packet, engine: engine, queue: queue, bridge: bridge)
    }

    override func handleRemediation(for flow: NEFilterFlow) -> NEFilterRemediationVerdict {
        // No remediation UI. A blocked flow is blocked; offering the user a
        // "proceed anyway" button would put the policy decision in the hands of
        // whoever is sitting at the machine, which is the opposite of what a
        // centrally managed host firewall is for.
        .drop()
    }
}

/// Enforcement mode, set by the daemon over XPC.
enum UFWEnforcement: UInt8 {
    case enforce = 0
    case monitor = 1
    case emergencyAllow = 2

    private static let lock = NSLock()
    private static var value: UFWEnforcement = .enforce

    static var current: UFWEnforcement {
        get { lock.lock(); defer { lock.unlock() }; return value }
        set { lock.lock(); value = newValue; lock.unlock() }
    }
}


/// What is currently installed, readable without touching the classifier's
/// queue.
///
/// The rule engine is owned by `queue` and replaced there. A statistics call
/// arriving on an XPC queue cannot read it safely, and dispatching onto
/// `queue` to find out would put an operator's status request behind whatever
/// flows are being decided. This is the small amount of state that answer
/// needs, kept beside the engine and updated when it changes.
final class UFWInstalledSnapshot {
    private let lock = NSLock()
    private var revision: UInt64 = 0
    private var rules = 0
    private var signatures = 0

    func setPolicy(revision: UInt64, rules: Int) {
        lock.lock()
        self.revision = revision
        self.rules = rules
        lock.unlock()
    }

    func setSignatures(_ count: Int) {
        lock.lock()
        signatures = count
        lock.unlock()
    }

    func snapshot() -> (revision: UInt64, rules: Int, signatures: Int) {
        lock.lock()
        defer { lock.unlock() }
        return (revision, rules, signatures)
    }
}


extension UFWFilterDataProvider {
    /// Report one decision on whichever channels are up.
    ///
    /// Both, when both are: the control socket carries the binary event the
    /// daemon's log pipeline reads, and XPC carries the JSON form for a
    /// management client. Neither is allowed to block the verdict — the socket
    /// hands off to its own queue, and the XPC queue drops oldest-first when
    /// it fills. A log line lost is bad; a verdict that misses its deadline is
    /// worse, because the system then decides the flow permissively and nobody
    /// finds out.
    func emit(_ decision: UFWDecision, facts: UFWFlowFacts) {
        bridge?.report(decision, facts: facts)

        guard let control else { return }
        eventSequence &+= 1
        let event = UFWLogEventWire.encode(
            hostID: hostID,
            sequence: eventSequence,
            timestampMicros: UInt64(Date().timeIntervalSince1970 * 1_000_000),
            // From the snapshot rather than from `engine`, which the
            // classifier owns; this runs on the same queue today and should
            // not depend on that staying true.
            policyRevision: installed.snapshot().revision,
            decision: decision,
            facts: facts,
            latencyNanos: 0)
        control.report(events: [event])
    }
}
