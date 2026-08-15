/*
 * libFuzzer entry point for the stream reassembler's placement state machine.
 *
 * The decoders (fuzz/decoders.c) each see one buffer. The reassembler is the
 * other shape of ring-0 parsing risk: it holds per-flow state across calls and
 * indexes a fixed buffer with an attacker-influenced offset, so the bug it can
 * hide is an out-of-bounds copy that only appears after a particular *sequence*
 * of segments — an overlap that rewinds the write cursor, a gap, a sequence
 * number that wraps the u32, a segment that straddles the 32 KiB budget. One
 * buffer cannot express that; this harness replays a sequence.
 *
 * It drives the exact code the module runs: ufw_stream_place() and
 * ufw_stream_seq_offset() from kernel/linux/inc/stream_place.h are what
 * ufw_stream_observe() calls once the kernel-only scaffolding (flow keying,
 * allocation, locking, header parse) has run. That scaffolding is not modelled
 * here because it is not where a byte gets written past the end of a buffer.
 *
 *   clang -g -O1 -fsanitize=fuzzer,address,undefined \
 *         -fno-sanitize-recover=all \
 *         -I ../kernel/linux/inc -o fuzz-reassembly reassembly.c
 *   ./fuzz-reassembly corpus-reassembly/ -max_len=65536 -jobs=$(nproc)
 *
 * A crash writes the input to `crash-<sha1>`; feed that file back to the binary
 * to reproduce, and add it to `corpus-reassembly/` once fixed so it stays fixed.
 */

#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "stream_place.h"

/* Equal to UFW_STREAM_MAX_BYTES in stream.h — the per-flow budget, kept as a
 * literal here so the harness needs none of stream.h's kernel-typed includes. */
#define UFW_FUZZ_CAP (32u * 1024u)

/*
 * The fields of struct ufw_stream_ctx that placement actually reads or writes.
 * The real struct adds an hlist node, the flow key, timestamps and the L7 tag;
 * none of those are touched by the arithmetic under test, and leaving them out
 * keeps the harness free of the kernel headers that define them.
 */
struct fuzz_ctx {
	__u32 len;
	__u32 base_seq;
	__u8  seq_valid;
	__u8  truncated;
	__u8  data[UFW_FUZZ_CAP];
};

/* Read a little-endian u32/u16 from a cursor, advancing it. The caller has
 * already checked that enough bytes remain. */
static __u32 take_u32(const uint8_t **p, size_t *rem)
{
	__u32 v;

	memcpy(&v, *p, sizeof(v));
	*p += sizeof(v);
	*rem -= sizeof(v);
	return v;
}

static __u32 take_u16(const uint8_t **p, size_t *rem)
{
	uint16_t v;

	memcpy(&v, *p, sizeof(v));
	*p += sizeof(v);
	*rem -= sizeof(v);
	return v;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
	struct fuzz_ctx ctx;
	const uint8_t *p = data;
	size_t rem = size;

	memset(&ctx, 0, sizeof(ctx));

	/*
	 * Each iteration is one segment, the way ufw_stream_observe() sees one
	 * packet of a flow. The control byte's low bits pick how the offset is
	 * formed, so the fuzzer can learn to mix the three modes within a single
	 * flow — which is exactly how an evasion is built.
	 */
	while (rem >= 1) {
		uint8_t ctl = *p++;
		uint8_t mode = ctl & 0x03u;

		rem--;
		__u32 raw, seglen, place_len, offset, before, trunc_events = 0;
		const __u8 *seg;

		if (mode == 2u) {
			/* A new context, or a UDP datagram: the module resets the
			 * buffer and scans each datagram alone. */
			ctx.len = 0;
			ctx.truncated = 0;
			ctx.seq_valid = 0;
			ctx.base_seq = 0;
			continue;
		}

		if (rem < 4u)
			break;
		raw = take_u32(&p, &rem);

		if (rem < 2u)
			break;
		seglen = take_u16(&p, &rem);
		if (seglen > rem)
			seglen = (__u32)rem;
		seg = p;
		p += seglen;
		rem -= seglen;

		place_len = seglen;
		if (mode == 1u) {
			/* TCP: normalize a raw sequence number into an offset,
			 * exercising base-seq capture and the u32 wraparound. */
			offset = ufw_stream_seq_offset(raw, &ctx.base_seq,
						       &ctx.seq_valid,
						       &ctx.truncated, ctx.len,
						       UFW_FUZZ_CAP, &place_len);
		} else if (mode == 3u) {
			/* In-order append, the common case. */
			offset = ctx.len;
		} else {
			/* A raw offset is the superset of every value the
			 * normalization can produce, so this mode alone drives
			 * place() across its entire offset domain — including the
			 * overlap and gap branches a well-behaved sender never
			 * reaches. */
			offset = raw;
		}

		before = ctx.len;
		if (place_len)
			ufw_stream_place(ctx.data, &ctx.len, &ctx.truncated,
					 UFW_FUZZ_CAP, offset, seg, place_len,
					 &trunc_events);

		/*
		 * Invariants placement must hold for any input. A violation is a
		 * logic bug the sanitizers would not catch on their own (the copy
		 * itself stayed in bounds), so assert them into a visible abort:
		 *   - the buffer never exceeds its capacity;
		 *   - it never shrinks — accepted bytes only ever append.
		 */
		if (ctx.len > UFW_FUZZ_CAP || ctx.len < before)
			__builtin_trap();
	}

	return 0;
}
