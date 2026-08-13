/*
 * Unified Firewall — stream reassembly placement arithmetic.
 *
 * # Why this is a header
 *
 * `ufw_stream_observe()` in `src/stream_reassembly.c` runs in softirq context
 * under a spinlock and is unreachable without a kernel — it speaks `sk_buff`,
 * `kvzalloc`, `spin_lock_irqsave`. But the part that actually touches
 * attacker-influenced offsets and lengths — deciding where a segment's bytes
 * land in the per-flow buffer and copying them there — is pure arithmetic over
 * a byte array. That is the memory-safety surface: a wrong bound here is an
 * out-of-bounds `memcpy` in ring 0.
 *
 * So it lives here, free of every kernel API, for the same reason
 * `dpi_decoders.h` does: a hosted compiler can then reach it, and
 * `fuzz/reassembly.c` compiles it under AddressSanitizer and
 * UndefinedBehaviorSanitizer and replays crafted segment sequences through the
 * exact code the module runs — not a copy of it that can drift. A reassembler
 * that is only ever exercised on a live kernel is a reassembler nobody has
 * fuzzed.
 *
 * The state machine that calls these — flow keying, context allocation and
 * reclaim, locking, the TCP/UDP header parse — stays in the .c, because none of
 * that is where a byte gets written past the end of a buffer.
 */

#ifndef UFW_STREAM_PLACE_H
#define UFW_STREAM_PLACE_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
/* Guarded so a hosted translation unit that also pulls in dpi_decoders.h (which
 * defines the same aliases) does not redefine them. */
#ifndef UFW_HOSTED_FIXED_INTS
#define UFW_HOSTED_FIXED_INTS
typedef uint8_t  __u8;
typedef uint32_t __u32;
#endif
#endif

/*
 * Place `len` bytes at `offset` in a reassembly buffer of capacity `cap` that
 * currently holds `*buf_len` bytes. Returns the number of *new* bytes accepted,
 * which is also added to `*buf_len`. Overlaps with data already present are
 * discarded and set `*truncated`; see the file header of stream_reassembly.c
 * for why an overlap is dropped rather than applied.
 *
 * `*trunc_events` is incremented once per truncation event so the caller can
 * mirror it into its statistics counter — the kernel increments
 * `reassembly_truncated`; the fuzzer ignores it. This keeps the counter
 * semantics identical to the pre-extraction code, which bumped the counter at
 * each of these three points rather than once per call.
 *
 * Pure: no allocation, no locking, no kernel call. The only precondition is
 * that `[data, data+len)` is readable and `[buf, buf+cap)` is writable.
 */
static inline __u32 ufw_stream_place(__u8 *buf, __u32 *buf_len, __u8 *truncated,
				     __u32 cap, __u32 offset,
				     const __u8 *data, __u32 len,
				     __u32 *trunc_events)
{
	__u32 blen = *buf_len;
	__u32 space;

	if (offset < blen) {
		/* Retransmission or overlap. If it lies entirely within what has
		 * already been accepted it is a plain retransmission and carries
		 * no new information. If it extends past, the overlapping prefix
		 * is a rewrite attempt.
		 *
		 * Written as `len <= blen - offset` rather than
		 * `offset + len <= blen`: offset < blen holds in this branch, so
		 * (blen - offset) cannot underflow, and the comparison never
		 * forms offset+len. The sum would wrap a u32 for any caller that
		 * handed in an unclamped sequence offset, silently turning
		 * injected bytes into a "retransmission" that is dropped — an
		 * evasion. This keeps placement sound on its own, not only under
		 * the caller's current clamping. */
		if (len <= blen - offset)
			return 0;

		*truncated = 1;
		(*trunc_events)++;
		len -= (blen - offset);
		data += (blen - offset);
		offset = blen;
	}

	if (offset > blen) {
		/* A gap. The bytes before it have not arrived, so appending here
		 * would produce a byte sequence that never appeared on the wire —
		 * the exact false-positive-and-false-negative problem that
		 * per-packet matching has. Hold the buffer at its current length
		 * and mark it truncated; if the missing segment arrives later it
		 * will be placed normally. */
		*truncated = 1;
		(*trunc_events)++;
		return 0;
	}

	space = cap - blen;
	if (len > space) {
		len = space;
		*truncated = 1;
		(*trunc_events)++;
	}
	if (!len)
		return 0;

	memcpy(buf + blen, data, len);
	*buf_len = blen + len;
	return len;
}

/*
 * Map a raw TCP sequence number to a buffer offset relative to the first
 * sequence seen on the flow, so out-of-order segments are placed rather than
 * appended. `*base_seq`/`*seq_valid` hold that first sequence across calls.
 *
 * A segment landing entirely past the budget (`offset > cap`) has nothing to
 * place: `*truncated` is set, `*len_io` is zeroed, and the returned offset is
 * the current buffer length (a no-op append point).
 *
 * The subtraction wraps a u32 on purpose — TCP sequence numbers wrap, and the
 * distance from the base is what indexes the buffer. Pure arithmetic; no read
 * of `data`, so unlike ufw_stream_place() it has no memory-safety surface of
 * its own, but it feeds the offset that one indexes with, which is why it is
 * fuzzed through the same harness.
 */
static inline __u32 ufw_stream_seq_offset(__u32 raw_seq, __u32 *base_seq,
					  __u8 *seq_valid, __u8 *truncated,
					  __u32 buf_len, __u32 cap,
					  __u32 *len_io)
{
	__u32 offset;

	if (!*seq_valid) {
		*base_seq = raw_seq;
		*seq_valid = 1;
	}
	offset = raw_seq - *base_seq;
	if (offset > cap) {
		*truncated = 1;
		offset = buf_len;
		*len_io = 0;
	}
	return offset;
}

#endif /* UFW_STREAM_PLACE_H */
