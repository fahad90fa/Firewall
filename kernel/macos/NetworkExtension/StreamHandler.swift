//
//  StreamHandler.swift
//  Unified Firewall — payload accumulation and the signature engine.
//
//  # The budget everything else copies
//
//  32 KiB per flow. This is the constraint that the Linux module and the
//  Windows driver adopted rather than one they imposed on macOS: a Network
//  Extension is sandboxed, and reassembly memory is the resource the sandbox is
//  least generous with.
//
//  Having all three platforms share it is what makes a signature mean the same
//  thing everywhere. A larger Linux budget would produce a signature that fires
//  on Linux and silently does not here — an equivalence failure that depends on
//  stream length rather than on policy, so no policy test would ever surface
//  it. The cheapest fix was to make the tightest platform's limit the shared
//  one, and to say so in all three files.
//
//  # Truncation is a finding, not a gap
//
//  When a flow exceeds the budget the context is marked truncated and stops
//  growing. That marker travels with the scan result, and the distinction it
//  draws is the point:
//
//    - A rule that DENIES on a signature treats a truncated miss as a
//      non-match, because no match was seen. But the log says the scan was
//      truncated, so "nothing fired" stays distinguishable from "we stopped
//      looking".
//    - A rule that ALERTS reports the truncation itself, because "this flow
//      could not be fully inspected" is a finding.
//
//  Blocking on truncation alone would make every long-lived connection fail
//  once it passed the budget, which is not a security control — it is an
//  outage with a security-sounding name.
//

import Foundation
import NetworkExtension
import os.log

/// A signature, decoded from the daemon's wire form. Mirrors
/// `daemon/src/signatures.rs` and the two C decoders.
struct UFWSignature {
    enum Condition {
        case field(id: UInt16, op: UFWCompare, value: UInt64)
        case content(pattern: [UInt8], offset: Int, depth: Int, nocase: Bool)
        /// Entropy in hundredths of a bit per byte. Integer, because the two
        /// kernel implementations have no floating point available and a
        /// threshold that rounds differently per platform is a divergence that
        /// depends on payload content.
        case entropy(id: UInt16, minCentibits: UInt32)
    }

    let id: UInt32
    let l7: UFWL7
    let severity: UInt8
    let conditions: [Condition]
}

enum UFWCompare: UInt8 {
    case equal = 1, notEqual = 2, less = 3, lessEqual = 4, greater = 5, greaterEqual = 6

    func apply(_ lhs: UInt64, _ rhs: UInt64) -> Bool {
        switch self {
        case .equal: return lhs == rhs
        case .notEqual: return lhs != rhs
        case .less: return lhs < rhs
        case .lessEqual: return lhs <= rhs
        case .greater: return lhs > rhs
        case .greaterEqual: return lhs >= rhs
        }
    }
}

final class UFWStreamHandler {
    private let log = Logger(subsystem: "com.unifiedfirewall.extension", category: "stream")

    /// Must equal `ufw_shared::constants::STREAM_REASSEMBLY_MAX_BYTES_MACOS`,
    /// `UFW_STREAM_MAX_BYTES` in both kernel implementations, and the default
    /// `depth` the signature loader applies. See the file header.
    static let budgetBytes = 32 * 1024

    /// Contexts are bounded too: a host churning short-lived connections would
    /// otherwise accumulate dead buffers until the idle sweep caught up.
    private static let maxContexts = 1024
    private static let idleTimeout: TimeInterval = 30

    private final class Context {
        var data = Data()
        var truncated = false
        var l7: UFWL7 = .unknown
        var lastSeen = Date()
    }

    /// Keyed on the flow's identifier and direction. A request and its response
    /// are two byte sequences with different content; merging them would
    /// produce bytes that never appeared on the wire, which is a source of both
    /// false positives and — worse — false negatives where a pattern spans the
    /// boundary.
    private var contexts: [String: Context] = [:]
    private var signatures: [UFWSignature] = []
    private let lock = NSLock()

    func installSignatures(_ set: [UFWSignature]) {
        lock.lock()
        signatures = set
        lock.unlock()
        log.info("installed \(set.count, privacy: .public) signatures")
    }

    func flushAll() {
        lock.lock()
        contexts.removeAll()
        lock.unlock()
    }

    func release(flow: NEFilterFlow) {
        lock.lock()
        contexts.removeValue(forKey: key(flow, inbound: true))
        contexts.removeValue(forKey: key(flow, inbound: false))
        lock.unlock()
    }

    private func key(_ flow: NEFilterFlow, inbound: Bool) -> String {
        "\(flow.identifier.uuidString)#\(inbound ? "in" : "out")"
    }

    /// Accumulate and rescan.
    func observe(flow: NEFilterFlow, data: Data, inbound: Bool) -> UFWDPIResult {
        let contextKey = key(flow, inbound: inbound)

        lock.lock()
        defer { lock.unlock() }

        let context: Context
        if let existing = contexts[contextKey] {
            context = existing
        } else {
            reclaimIfNeeded()
            if contexts.count >= Self.maxContexts {
                // No room. The flow is not inspected, and saying so is what
                // distinguishes it from a clean scan that found nothing.
                return UFWDPIResult(l7: .unknown, matchedSignatures: [], truncated: true)
            }
            context = Context()
            contexts[contextKey] = context
        }

        context.lastSeen = Date()

        let space = Self.budgetBytes - context.data.count
        if space <= 0 {
            context.truncated = true
        } else if data.count > space {
            context.data.append(data.prefix(space))
            context.truncated = true
        } else {
            context.data.append(data)
        }

        if context.l7 == .unknown && !context.data.isEmpty {
            context.l7 = UFWProtocolIdentifier.identify(context.data)
        }

        let matched = scan(context.data, l7: context.l7)
        return UFWDPIResult(l7: context.l7, matchedSignatures: matched,
                            truncated: context.truncated)
    }

    /// Drop idle contexts. Called on allocation rather than on a timer: a timer
    /// would need its own queue and would fire on a machine doing nothing,
    /// whereas the only moment the count actually matters is when it is about
    /// to grow.
    private func reclaimIfNeeded() {
        guard contexts.count >= Self.maxContexts else { return }
        let cutoff = Date().addingTimeInterval(-Self.idleTimeout)
        contexts = contexts.filter { $0.value.lastSeen > cutoff }
    }

    // MARK: Signature evaluation

    private func scan(_ data: Data, l7: UFWL7) -> [UInt32] {
        guard !signatures.isEmpty, !data.isEmpty else { return [] }

        let bytes = [UInt8](data)
        let decoded = UFWProtocolDecoder.decode(bytes, l7: l7)
        var hits: [UInt32] = []

        for signature in signatures {
            // An `unknown`-scoped signature runs against everything, which is
            // how a content match on a protocol the decoders do not know still
            // works.
            if signature.l7 != .unknown && signature.l7 != l7 { continue }

            let all = signature.conditions.allSatisfy { condition in
                holds(condition, decoded: decoded, bytes: bytes)
            }
            if all {
                hits.append(signature.id)
                if hits.count >= 16 { break }
            }
        }
        return hits
    }

    private func holds(_ condition: UFWSignature.Condition,
                       decoded: [UInt16: UInt32], bytes: [UInt8]) -> Bool {
        switch condition {
        case let .field(id, op, value):
            if id == UFWField.payloadLength {
                return op.apply(UInt64(bytes.count), value)
            }
            // The decoder did not produce this field — either the payload was
            // malformed or the field belongs to another protocol. Absent is not
            // zero: an absent field fails its condition, which fails the
            // signature. The fail-closed direction.
            guard let actual = decoded[id] else { return false }
            return op.apply(UInt64(actual), value)

        case let .content(pattern, offset, depth, nocase):
            return UFWContentSearch.contains(bytes, pattern: pattern, offset: offset,
                                             depth: depth, nocase: nocase)

        case let .entropy(_, minCentibits):
            return UFWEntropy.centibits(bytes) >= minCentibits
        }
    }
}

// MARK: - Content search

enum UFWContentSearch {
    /// Bounded naive search, matching both kernel implementations.
    ///
    /// The window is at most 32 KiB and patterns at most 64 bytes, so the worst
    /// case is bounded and reached only by a pattern of repeated bytes a
    /// signature author would have to write deliberately. A skip-table
    /// algorithm needs state built per scan or cached per signature, and cached
    /// state is state an attacker influences the use of. This loop has none.
    static func contains(_ haystack: [UInt8], pattern: [UInt8], offset: Int,
                         depth: Int, nocase: Bool) -> Bool {
        guard !pattern.isEmpty, offset < haystack.count else { return false }

        let end = depth > 0 ? min(offset + depth, haystack.count) : haystack.count
        guard end >= offset + pattern.count else { return false }

        var i = offset
        while i + pattern.count <= end {
            var matched = true
            for j in 0..<pattern.count {
                var a = haystack[i + j]
                var b = pattern[j]
                if nocase {
                    if a >= 65 && a <= 90 { a += 32 }
                    if b >= 65 && b <= 90 { b += 32 }
                }
                if a != b { matched = false; break }
            }
            if matched { return true }
            i += 1
        }
        return false
    }
}

// MARK: - Entropy

enum UFWEntropy {
    /// Integer log2 in hundredths of a bit, bit-for-bit identical to the two
    /// kernel implementations. An entropy threshold that rounds differently per
    /// platform is an equivalence failure that depends on payload content,
    /// which no policy test could ever surface.
    static func ilog2Centi(_ v: UInt32) -> UInt32 {
        guard v > 0 else { return 0 }
        let whole = UInt32(31 - v.leadingZeroBitCount)
        let remainder = v - (1 << whole)
        let frac = (remainder &* 100) / (1 << whole)
        return whole &* 100 &+ frac
    }

    /// Shannon entropy via H = log2(n) - (1/n) * sum(c_i * log2(c_i)), which
    /// avoids per-symbol probabilities and therefore avoids division until the
    /// very end.
    static func centibits(_ data: [UInt8]) -> UInt32 {
        guard !data.isEmpty else { return 0 }

        var counts = [UInt32](repeating: 0, count: 256)
        for byte in data { counts[Int(byte)] += 1 }

        var weighted: UInt64 = 0
        for count in counts where count > 0 {
            weighted += UInt64(count) * UInt64(ilog2Centi(count))
        }

        let total = ilog2Centi(UInt32(data.count))
        let mean = UInt32(weighted / UInt64(data.count))
        return total > mean ? total - mean : 0
    }
}

// MARK: - Protocol identification and decoding

enum UFWField {
    static let dnsMaxLabelLength: UInt16 = 1
    static let dnsNameLength: UInt16 = 2
    static let dnsLabelCount: UInt16 = 3
    static let dnsQueryType: UInt16 = 4
    static let dnsAnswerCount: UInt16 = 5
    static let httpMethod: UInt16 = 20
    static let httpURILength: UInt16 = 21
    static let httpHeaderCount: UInt16 = 22
    static let httpBodyLength: UInt16 = 23
    static let httpHostLength: UInt16 = 24
    static let tlsVersion: UInt16 = 40
    static let tlsSNILength: UInt16 = 41
    static let tlsCipherCount: UInt16 = 42
    static let tlsExtensionCount: UInt16 = 43
    static let tlsHandshakeType: UInt16 = 44
    static let sshProtocolVersion: UInt16 = 60
    static let sshBannerLength: UInt16 = 61
    static let payloadLength: UInt16 = 100
    static let payloadPrintableRatio: UInt16 = 101
}

enum UFWProtocolIdentifier {
    static func identify(_ data: Data) -> UFWL7 {
        let bytes = [UInt8](data.prefix(16))
        if bytes.count >= 3 && bytes[0] == 0x16 && bytes[1] == 0x03 { return .tls }
        if bytes.count >= 4 && bytes[0...3] == [0x53, 0x53, 0x48, 0x2D] { return .ssh }
        if UFWProtocolDecoder.httpMethodID(bytes) != 0 { return .http }
        if bytes.count >= 4 && bytes[0...3] == [0x48, 0x54, 0x54, 0x50] { return .http }
        // DNS has no distinctive prefix. The flow path does not carry a port
        // here, so an unrecognised payload stays unknown rather than being
        // guessed at — a signature scoped to `protocols: [dns]` that does not
        // fire is a documented limitation; one that fires on the wrong protocol
        // is a false positive nobody can explain.
        return .unknown
    }
}

enum UFWProtocolDecoder {
    static func decode(_ bytes: [UInt8], l7: UFWL7) -> [UInt16: UInt32] {
        var out: [UInt16: UInt32] = [UFWField.payloadLength: UInt32(bytes.count)]
        switch l7 {
        case .dns: decodeDNS(bytes, into: &out)
        case .http: decodeHTTP(bytes, into: &out)
        case .tls: decodeTLS(bytes, into: &out)
        case .ssh: decodeSSH(bytes, into: &out)
        default: break
        }
        return out
    }

    static func httpMethodID(_ b: [UInt8]) -> UInt32 {
        func starts(_ s: String) -> Bool {
            let p = [UInt8](s.utf8)
            return b.count >= p.count && Array(b[0..<p.count]) == p
        }
        if starts("GET ") { return 1 }
        if starts("POST ") { return 2 }
        if starts("PUT ") { return 3 }
        if starts("DELETE ") { return 4 }
        if starts("HEAD ") { return 5 }
        if starts("OPTIONS ") { return 6 }
        if starts("PATCH ") { return 7 }
        if starts("CONNECT ") { return 8 }
        if starts("TRACE ") { return 9 }
        return 0
    }

    private static func decodeDNS(_ b: [UInt8], into out: inout [UInt16: UInt32]) {
        guard b.count >= 12 else { return }
        out[UFWField.dnsAnswerCount] = UInt32(b[6]) << 8 | UInt32(b[7])

        var pos = 12
        var nameLength: UInt32 = 0
        var maxLabel: UInt32 = 0
        var labels: UInt32 = 0

        while pos < b.count {
            let labelLength = b[pos]
            if labelLength == 0 { break }
            // Compression pointers are not followed. A pointer in a question is
            // malformed, and following them needs a visited set to survive a
            // crafted loop. Bailing out leaves the fields absent, and an absent
            // field fails its condition — the safe direction.
            if labelLength & 0xC0 == 0xC0 { return }
            if labelLength > 63 || pos + 1 + Int(labelLength) > b.count { return }

            maxLabel = max(maxLabel, UInt32(labelLength))
            nameLength += UInt32(labelLength) + 1
            labels += 1
            pos += 1 + Int(labelLength)

            if nameLength > 255 || labels > 128 { return }
        }

        out[UFWField.dnsMaxLabelLength] = maxLabel
        out[UFWField.dnsNameLength] = nameLength
        out[UFWField.dnsLabelCount] = labels

        if pos + 3 <= b.count {
            out[UFWField.dnsQueryType] = UInt32(b[pos + 1]) << 8 | UInt32(b[pos + 2])
        }
    }

    private static func decodeHTTP(_ b: [UInt8], into out: inout [UInt16: UInt32]) {
        out[UFWField.httpMethod] = httpMethodID(b)

        var uriStart = 0
        for i in 0..<min(b.count, 64) where b[i] == 0x20 {
            uriStart = i + 1
            break
        }
        var uriLength: UInt32 = 0
        if uriStart > 0 {
            var i = uriStart
            while i < b.count, b[i] != 0x20, b[i] != 0x0D, b[i] != 0x0A {
                uriLength += 1
                i += 1
            }
        }
        out[UFWField.httpURILength] = uriLength

        var headers: UInt32 = 0
        var bodyStart = 0
        var i = 0
        while i + 1 < b.count {
            if b[i] == 0x0A {
                headers += 1
                if b[i + 1] == 0x0D || b[i + 1] == 0x0A {
                    bodyStart = i + 2
                    break
                }
            }
            i += 1
        }
        // The request line is not a header.
        out[UFWField.httpHeaderCount] = headers > 0 ? headers - 1 : 0
        out[UFWField.httpBodyLength] =
            (bodyStart > 0 && bodyStart < b.count) ? UInt32(b.count - bodyStart) : 0

        if bodyStart < b.count {
            var printable: UInt32 = 0
            for j in bodyStart..<b.count {
                let c = b[j]
                if (c >= 0x20 && c < 0x7F) || c == 0x0A || c == 0x0D || c == 0x09 {
                    printable += 1
                }
            }
            out[UFWField.payloadPrintableRatio] =
                printable * 100 / UInt32(b.count - bodyStart)
        }
    }

    private static func decodeTLS(_ b: [UInt8], into out: inout [UInt16: UInt32]) {
        guard b.count >= 6 else { return }
        out[UFWField.tlsVersion] = UInt32(b[1]) << 8 | UInt32(b[2])
        out[UFWField.tlsHandshakeType] = UInt32(b[5])

        guard b[0] == 0x16, b[5] == 0x01 else { return }

        var pos = 5 + 4 + 2 + 32
        guard pos < b.count else { return }

        // The ClientHello's own version is more informative than the record
        // layer's, which is often pinned low for compatibility.
        if b.count > 10 {
            out[UFWField.tlsVersion] = UInt32(b[9]) << 8 | UInt32(b[10])
        }

        let sessionLength = Int(b[pos])
        pos += 1 + sessionLength
        guard pos + 2 <= b.count else { return }

        let cipherLength = Int(b[pos]) << 8 | Int(b[pos + 1])
        out[UFWField.tlsCipherCount] = UInt32(cipherLength / 2)
        pos += 2 + cipherLength
        guard pos < b.count else { return }

        let compressionLength = Int(b[pos])
        pos += 1 + compressionLength
        guard pos + 2 <= b.count else { return }

        let extensionsTotal = Int(b[pos]) << 8 | Int(b[pos + 1])
        pos += 2
        let extensionsEnd = min(pos + extensionsTotal, b.count)

        out[UFWField.tlsSNILength] = 0
        var extensions: UInt32 = 0

        while pos + 4 <= extensionsEnd {
            let type = Int(b[pos]) << 8 | Int(b[pos + 1])
            let length = Int(b[pos + 2]) << 8 | Int(b[pos + 3])
            extensions += 1
            pos += 4
            guard pos + length <= extensionsEnd else { break }
            if type == 0 && length >= 5 {
                out[UFWField.tlsSNILength] = UInt32(b[pos + 3]) << 8 | UInt32(b[pos + 4])
            }
            pos += length
        }
        out[UFWField.tlsExtensionCount] = extensions
    }

    private static func decodeSSH(_ b: [UInt8], into out: inout [UInt16: UInt32]) {
        guard b.count >= 8, Array(b[0..<4]) == [0x53, 0x53, 0x48, 0x2D] else { return }

        if b[4] >= 0x30, b[4] <= 0x39, b[6] >= 0x30, b[6] <= 0x39 {
            out[UFWField.sshProtocolVersion] =
                UInt32(b[4] - 0x30) * 10 + UInt32(b[6] - 0x30)
        }

        var bannerLength: UInt32 = 0
        for i in 0..<min(b.count, 255) {
            if b[i] == 0x0D || b[i] == 0x0A { break }
            bannerLength += 1
        }
        out[UFWField.sshBannerLength] = bannerLength
    }
}
