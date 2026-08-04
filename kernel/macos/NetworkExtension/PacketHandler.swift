//
//  PacketHandler.swift
//  Unified Firewall — the packet path, and why it is deliberately narrow.
//
//  `handleNewPacket` sees everything, including packets belonging to flows
//  `handleNewFlow` already decided. If both callbacks judged the same traffic
//  they could disagree, and because the flow verdict is taken once at flow
//  setup while packets keep arriving, the packet path would win by being last.
//  A policy would then mean something different from what the flow path
//  computed with identity available.
//
//  So the two partition rather than layer. This handler evaluates only rules
//  scoped to `.connectionless` — the protocols with no flow, principally ICMP —
//  and passes TCP and UDP through untouched, because those were decided in
//  `handleNewFlow` where the process was known.
//
//  This is the same partition the Windows driver draws between ALE and the IP
//  packet layers, for the same reason, and it is why `UFWProtocolScope` exists
//  in the rule table at all.
//
//  # Performance
//
//  Apple's own guidance is that the packet path is markedly slower than the
//  flow path, and that matches what this design wants anyway: almost all
//  traffic is TCP or UDP and returns from the first branch below without
//  touching the rule table.
//

import Foundation
import NetworkExtension
import os.log

final class UFWPacketHandler {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "packet")

    func handle(_ packet: NEFilterPacket,
                engine: UFWRuleEngine,
                queue: DispatchQueue,
                bridge: UFWIPCBridge?) -> NEFilterPacketVerdict {
        guard let facts = parse(packet, engine: engine) else {
            // Unparseable, or not IP. Passing rather than dropping: unlike the
            // kernel implementations, this handler does not see every packet on
            // the machine — the flow path already decided most of them — so a
            // parse failure here is far more likely to be a packet shape this
            // code does not know than an evasion attempt. Dropping would break
            // traffic the flow path already permitted.
            return .allow()
        }

        // Decided at flow setup, with identity. Re-deciding here would be
        // deciding again with less information.
        if facts.ipProtocol == 6 || facts.ipProtocol == 17 {
            return .allow()
        }

        return queue.sync {
            let decision = engine.evaluate(facts, scope: .connectionless)
            for alert in engine.drainAlerts() {
                bridge?.report(alert, facts: facts)
            }
            if decision.shouldLog {
                bridge?.report(decision, facts: facts)
            }

            switch UFWEnforcement.current {
            case .emergencyAllow, .monitor:
                return .allow()
            case .enforce:
                return decision.action == .deny ? .drop() : .allow()
            }
        }
    }

    /// Read the IP header. Only far enough to classify: this is not a protocol
    /// stack, and every byte read past what a rule can test is a byte of parser
    /// that could be wrong.
    private func parse(_ packet: NEFilterPacket,
                       engine: UFWRuleEngine) -> UFWFlowFacts? {
        let data = packet.data
        guard let first = data.first else { return nil }

        var facts = UFWFlowFacts()
        facts.direction = (packet.direction == .inbound) ? .inbound : .outbound

        let version = first >> 4
        if version == 4 {
            guard data.count >= 20 else { return nil }
            let headerLength = Int(first & 0x0F) * 4
            guard headerLength >= 20, data.count >= headerLength else { return nil }

            facts.isIPv6 = false
            facts.ipProtocol = data[9]

            // A non-first fragment carries no transport header, so its ports
            // are unknowable. Rather than classify it with port 0 — which would
            // let an attacker choose which rule applies by fragmenting — it is
            // passed to the system, which reassembles before the flow path sees
            // it.
            let fragmentOffset = (UInt16(data[6]) << 8 | UInt16(data[7])) & 0x1FFF
            if fragmentOffset != 0 { return nil }

            facts.sourceAddress = UFWAddress(bytes: [UInt8](data[12..<16]), isV6: false)
            facts.destAddress = UFWAddress(bytes: [UInt8](data[16..<20]), isV6: false)
        } else if version == 6 {
            guard data.count >= 40 else { return nil }
            facts.isIPv6 = true
            facts.ipProtocol = data[6]
            facts.sourceAddress = UFWAddress(bytes: [UInt8](data[8..<24]), isV6: true)
            facts.destAddress = UFWAddress(bytes: [UInt8](data[24..<40]), isV6: true)
        } else {
            return nil
        }

        facts.sourceZone = engine.zone(of: facts.sourceAddress)
        facts.destZone = engine.zone(of: facts.destAddress)
        return facts
    }
}
