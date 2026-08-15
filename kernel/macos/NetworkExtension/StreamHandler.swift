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
        /// `patternId` indexes the shipped automaton's pattern table, or is
        /// `UFWAutomaton.noPattern` when the set arrived without one. The
        /// pattern bytes are kept either way: the automaton's fallback arm
        /// needs them, and so does every match when there is no automaton.
        case content(pattern: [UInt8], offset: Int, depth: Int, nocase: Bool,
                     patternId: UInt32)
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
    private var automaton: UFWAutomaton?
    private let lock = NSLock()

    func installSignatures(_ set: UFWSignatureSet) {
        lock.lock()
        signatures = set.signatures
        automaton = set.automaton
        lock.unlock()

        // No automaton means either nothing to search for, or a pattern set
        // past the shipped table limits. Both mean a search per signature:
        // slower, and the same verdicts.
        let patterns = set.automaton?.patterns.count ?? 0
        log.info("installed \(set.signatures.count, privacy: .public) signatures, \(patterns, privacy: .public) shared content patterns")
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

        // One pass over the payload for every content pattern in the set,
        // before any signature is considered. The loop below then costs a
        // table lookup per content condition instead of a search over the
        // window. Same verdicts either way — see UFWAutomaton.
        let patternHits = automaton?.scan(bytes)

        for signature in signatures {
            // An `unknown`-scoped signature runs against everything, which is
            // how a content match on a protocol the decoders do not know still
            // works.
            if signature.l7 != .unknown && signature.l7 != l7 { continue }

            let all = signature.conditions.allSatisfy { condition in
                holds(condition, decoded: decoded, bytes: bytes, patternHits: patternHits)
            }
            if all {
                hits.append(signature.id)
                if hits.count >= 16 { break }
            }
        }
        return hits
    }

    private func holds(_ condition: UFWSignature.Condition,
                       decoded: [UInt16: UInt32], bytes: [UInt8],
                       patternHits: [UFWAutomaton.Hit]?) -> Bool {
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

        case let .content(pattern, offset, depth, nocase, patternId):
            if let hits = patternHits, patternId != UFWAutomaton.noPattern,
               Int(patternId) < hits.count {
                return UFWContentSearch.matches(bytes, pattern: pattern, offset: offset,
                                                depth: depth, nocase: nocase,
                                                hit: hits[Int(patternId)])
            }
            return UFWContentSearch.contains(bytes, pattern: pattern, offset: offset,
                                             depth: depth, nocase: nocase)

        case let .entropy(_, minCentibits):
            return UFWEntropy.centibits(bytes) >= minCentibits
        }
    }
}

// MARK: - Multi-pattern search

/// The multi-pattern automaton, decoded from the table the daemon shipped.
///
/// Mirrors `daemon/src/automaton.rs`, `kernel/linux/inc/dpi_automaton.h` and
/// `kernel/windows/inc/dpi_automaton.h`. There is no construction here on
/// purpose: building an Aho-Corasick automaton is the subtle part — failure
/// links, output-set merging, the root self-loop — and doing it in three
/// places is three chances to disagree about what a stream contains. The
/// daemon builds it once; this walks it.
struct UFWAutomaton {
    struct Pattern {
        let bytes: [UInt8]
        let nocase: Bool
    }

    struct State {
        let fail: Int
        let transStart: Int
        let transCount: Int
        let outStart: Int
        let outCount: Int
    }

    struct Transition {
        let byte: UInt8
        let next: Int
    }

    struct Trie {
        /// Whether input bytes are ASCII-folded before traversal. Patterns in
        /// a folded trie are stored folded, so case-insensitivity costs one
        /// comparison per byte rather than a second pass per pattern.
        let fold: Bool
        let stateBase: Int
        let stateCount: Int
        let transBase: Int
        let outBase: Int
    }

    /// What one pattern did in one scan. `count` saturates at 2: zero, one at
    /// a known offset, or "more than one, ask the slow path". Storing every
    /// offset would make the result table as long as attacker-chosen input.
    struct Hit {
        var firstStart: UInt32 = 0
        var count: UInt8 = 0
    }

    /// Must equal the ceilings in the two C headers and in the Rust builder.
    static let maxPatterns = 512
    static let maxStates = 16384
    static let maxOutputs = 8192
    static let maxPatternBytes = 64

    /// A content condition whose pattern has no automaton entry.
    static let noPattern: UInt32 = 0xFFFF_FFFF

    let patterns: [Pattern]
    let states: [State]
    let transitions: [Transition]
    let outputs: [UInt16]
    let tries: [Trie]

    /// ASCII case folding, and only ASCII — matching the naive search, which
    /// folds `A...Z` and nothing else. Anything more correct here would be a
    /// divergence dressed as an improvement.
    static func fold(_ b: UInt8) -> UInt8 {
        (b >= 65 && b <= 90) ? b &+ 32 : b
    }

    /// Binary search rather than a scan: the root of a trie over printable
    /// patterns can have dozens of children, and this runs once per input
    /// byte per trie. Returns nil for "no transition".
    private func transition(_ trie: Trie, _ state: Int, _ byte: UInt8) -> Int? {
        let st = states[trie.stateBase + state]
        var lo = 0
        var hi = st.transCount
        while lo < hi {
            let mid = lo + (hi - lo) / 2
            let tr = transitions[trie.transBase + st.transStart + mid]
            if tr.byte == byte { return tr.next }
            if tr.byte < byte { lo = mid + 1 } else { hi = mid }
        }
        return nil
    }

    /// Follow one input byte, falling back along failure links until a
    /// transition exists or the root is reached. Amortised O(1) per byte on a
    /// well-formed table: a fallback strictly decreases depth, and depth rises
    /// by at most one per byte. The `state == 0` exit is what stops the root
    /// trapping on a byte no pattern starts with.
    ///
    /// The walk is additionally capped at `stateCount` hops. Depth-decreasing
    /// is a property of the table, which is decoded from bytes the daemon is not
    /// trusted to be correct about; the loader bounds-checks every index but not
    /// that a fail link points to a shallower state, so a malformed one could
    /// form a cycle that never reaches the root. A valid chain never approaches
    /// the cap; a cyclic one can no longer loop forever. (Kept identical to the
    /// Linux and Windows traversals.)
    private func step(_ trie: Trie, _ state: Int, _ byte: UInt8) -> Int {
        var current = state
        var hops = trie.stateCount
        while true {
            if let next = transition(trie, current, byte) { return next }
            if current == 0 || hops == 0 { return 0 }
            hops -= 1
            current = states[trie.stateBase + current].fail
        }
    }

    /// One pass over `data` for every pattern in the table.
    func scan(_ data: [UInt8]) -> [Hit] {
        var hits = [Hit](repeating: Hit(), count: patterns.count)
        guard !data.isEmpty else { return hits }

        for trie in tries {
            var state = 0
            for i in 0..<data.count {
                let byte = trie.fold ? Self.fold(data[i]) : data[i]
                state = step(trie, state, byte)
                let st = states[trie.stateBase + state]
                guard st.outCount > 0 else { continue }
                for k in 0..<st.outCount {
                    let pid = Int(outputs[trie.outBase + st.outStart + k])
                    let plen = patterns[pid].bytes.count
                    // `i` indexes the last byte of the match. Matches arrive
                    // in increasing end offset and a pattern has a fixed
                    // length, so the first one recorded is the earliest.
                    let start = UInt32(i + 1 - plen)
                    if hits[pid].count == 0 {
                        hits[pid].firstStart = start
                        hits[pid].count = 1
                    } else if hits[pid].count == 1 {
                        hits[pid].count = 2
                    }
                }
            }
        }
        return hits
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

    /// Decide one content condition from a scan result.
    ///
    /// Exactly equivalent to `contains` over the same arguments. The four
    /// arms, cheapest first:
    ///
    ///   1. absent from the whole buffer   => absent from any window in it
    ///   2. first occurrence in the window => match
    ///   3. exactly one occurrence, outside the window => no match
    ///   4. several occurrences, none of them the first => search this one
    ///
    /// Arm 1 is the common case for a signature set and is why the shared
    /// pass pays for itself. Arm 4 is reached only by a pattern that repeats
    /// within one stream and is scoped to a window excluding its first hit.
    static func matches(_ haystack: [UInt8], pattern: [UInt8], offset: Int,
                        depth: Int, nocase: Bool, hit: UFWAutomaton.Hit) -> Bool {
        guard hit.count > 0 else { return false }
        guard !pattern.isEmpty, offset < haystack.count else { return false }

        let end = depth > 0 ? min(offset + depth, haystack.count) : haystack.count
        guard end >= offset + pattern.count else { return false }

        let first = Int(hit.firstStart)
        if first >= offset && first + pattern.count <= end { return true }
        if hit.count == 1 { return false }
        return contains(haystack, pattern: pattern, offset: offset, depth: depth,
                        nocase: nocase)
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

// MARK: - Signature wire decoding

/// Everything one `SignatureInstall` carries: the signatures, and the
/// multi-pattern table they share.
struct UFWSignatureSet {
    let signatures: [UFWSignature]
    let automaton: UFWAutomaton?

    static let empty = UFWSignatureSet(signatures: [], automaton: nil)
}

/// Little-endian reader over the daemon's flat encoding.
///
/// Every read is bounds-checked. The payload arrives over XPC from a peer
/// whose Team ID was verified, which makes it the daemon — not which makes it
/// correct, and a decoder is not the place to discover the difference.
struct UFWWireReader {
    let bytes: [UInt8]
    var position = 0

    var remaining: Int { bytes.count - position }

    mutating func u8() -> UInt8? {
        guard remaining >= 1 else { return nil }
        defer { position += 1 }
        return bytes[position]
    }

    mutating func u16() -> UInt16? {
        guard remaining >= 2 else { return nil }
        defer { position += 2 }
        return UInt16(bytes[position]) | (UInt16(bytes[position + 1]) << 8)
    }

    mutating func u32() -> UInt32? {
        guard remaining >= 4 else { return nil }
        defer { position += 4 }
        return UInt32(bytes[position])
            | (UInt32(bytes[position + 1]) << 8)
            | (UInt32(bytes[position + 2]) << 16)
            | (UInt32(bytes[position + 3]) << 24)
    }

    mutating func u64() -> UInt64? {
        guard let lo = u32(), let hi = u32() else { return nil }
        return UInt64(lo) | (UInt64(hi) << 32)
    }

    mutating func raw(_ count: Int) -> [UInt8]? {
        guard count >= 0, remaining >= count else { return nil }
        defer { position += count }
        return Array(bytes[position..<(position + count)])
    }
}

extension UFWSignatureSet {
    /// Decode one signature payload, or return nil.
    ///
    /// Nil rather than a partial set on purpose. Half a signature set is a
    /// set nobody wrote, and the window it is live for is one in which the
    /// extension reports clean scans for signatures it silently dropped —
    /// which is the failure mode the whole subsystem exists to avoid.
    static func decode(_ data: Data) -> UFWSignatureSet? {
        var r = UFWWireReader(bytes: [UInt8](data))

        guard let count = r.u32(), count <= 1024 else { return nil }
        var signatures: [UFWSignature] = []
        signatures.reserveCapacity(Int(count))

        for _ in 0..<count {
            guard let id = r.u32(), let l7Raw = r.u8(), let severity = r.u8(),
                  let conditionCount = r.u16(), conditionCount <= 8 else { return nil }

            var conditions: [UFWSignature.Condition] = []
            conditions.reserveCapacity(Int(conditionCount))

            for _ in 0..<conditionCount {
                guard let kind = r.u8() else { return nil }
                switch kind {
                case 1:
                    guard let field = r.u16(), let opRaw = r.u8(),
                          let op = UFWCompare(rawValue: opRaw), let value = r.u64()
                    else { return nil }
                    conditions.append(.field(id: field, op: op, value: value))
                case 2:
                    guard let offset = r.u32(), let depth = r.u32(),
                          let nocase = r.u8(), let patternId = r.u32(),
                          let length = r.u32(),
                          length <= UInt32(UFWAutomaton.maxPatternBytes),
                          let pattern = r.raw(Int(length)) else { return nil }
                    conditions.append(.content(pattern: pattern, offset: Int(offset),
                                               depth: Int(depth), nocase: nocase != 0,
                                               patternId: patternId))
                case 3:
                    // The encoding reuses the offset slot for min_centibits on
                    // this kind, matching both C decoders.
                    guard let field = r.u16(), let minCentibits = r.u32() else { return nil }
                    conditions.append(.entropy(id: field, minCentibits: minCentibits))
                default:
                    return nil
                }
            }

            signatures.append(UFWSignature(id: id,
                                           l7: UFWL7(rawValue: l7Raw) ?? .unknown,
                                           severity: severity,
                                           conditions: conditions))
        }

        guard let hasAutomaton = r.u8() else { return nil }
        if hasAutomaton == 0 {
            return UFWSignatureSet(signatures: signatures, automaton: nil)
        }
        guard let automaton = decodeAutomaton(&r) else { return nil }
        return UFWSignatureSet(signatures: signatures, automaton: automaton)
    }

    /// Decode the shipped table, validating every index so the traversal
    /// needs no checks at all.
    private static func decodeAutomaton(_ r: inout UFWWireReader) -> UFWAutomaton? {
        guard let patternCount = r.u32(), patternCount > 0,
              patternCount <= UInt32(UFWAutomaton.maxPatterns) else { return nil }

        var patterns: [UFWAutomaton.Pattern] = []
        patterns.reserveCapacity(Int(patternCount))
        for _ in 0..<patternCount {
            guard let nocase = r.u8(), let length = r.u32(), length > 0,
                  length <= UInt32(UFWAutomaton.maxPatternBytes),
                  let bytes = r.raw(Int(length)) else { return nil }
            patterns.append(UFWAutomaton.Pattern(bytes: bytes, nocase: nocase != 0))
        }

        guard let trieCount = r.u8(), trieCount > 0, trieCount <= 2 else { return nil }

        var states: [UFWAutomaton.State] = []
        var transitions: [UFWAutomaton.Transition] = []
        var outputs: [UInt16] = []
        var tries: [UFWAutomaton.Trie] = []

        for _ in 0..<trieCount {
            guard let fold = r.u8(), let stateCount = r.u32(), stateCount > 0,
                  let transCount = r.u32(), let outCount = r.u32() else { return nil }
            guard states.count + Int(stateCount) <= UFWAutomaton.maxStates,
                  transitions.count + Int(transCount) <= UFWAutomaton.maxStates,
                  outputs.count + Int(outCount) <= UFWAutomaton.maxOutputs
            else { return nil }

            let stateBase = states.count
            let transBase = transitions.count
            let outBase = outputs.count

            for _ in 0..<stateCount {
                guard let fail = r.u32(), let transStart = r.u32(),
                      let stateTransCount = r.u16(), let outStart = r.u32(),
                      let stateOutCount = r.u16() else { return nil }
                guard fail < stateCount,
                      transStart <= transCount,
                      UInt32(stateTransCount) <= transCount - transStart,
                      outStart <= outCount,
                      UInt32(stateOutCount) <= outCount - outStart else { return nil }
                states.append(UFWAutomaton.State(fail: Int(fail),
                                                 transStart: Int(transStart),
                                                 transCount: Int(stateTransCount),
                                                 outStart: Int(outStart),
                                                 outCount: Int(stateOutCount)))
            }

            for _ in 0..<transCount {
                guard let byte = r.u8(), let next = r.u32(), next < stateCount
                else { return nil }
                transitions.append(UFWAutomaton.Transition(byte: byte, next: Int(next)))
            }

            // Each state's transitions must be sorted by byte, because the
            // traversal binary-searches them. An unsorted slice would not
            // fail — it would silently miss matches, which is an extension
            // reporting a clean scan of a stream it mis-walked.
            for index in stateBase..<states.count {
                let st = states[index]
                guard st.transCount > 1 else { continue }
                for k in 1..<st.transCount {
                    let prev = transitions[transBase + st.transStart + k - 1]
                    let cur = transitions[transBase + st.transStart + k]
                    if prev.byte >= cur.byte { return nil }
                }
            }

            for _ in 0..<outCount {
                guard let pid = r.u16(), UInt32(pid) < patternCount else { return nil }
                outputs.append(pid)
            }

            tries.append(UFWAutomaton.Trie(fold: fold != 0,
                                           stateBase: stateBase,
                                           stateCount: Int(stateCount),
                                           transBase: transBase,
                                           outBase: outBase))
        }

        return UFWAutomaton(patterns: patterns, states: states,
                            transitions: transitions, outputs: outputs, tries: tries)
    }
}
