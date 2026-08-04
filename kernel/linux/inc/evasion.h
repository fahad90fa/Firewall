/*
 * Unified Firewall — evasion resistance below the reassembler.
 *
 * Stream reassembly already refuses to be fooled by overlapping TCP segments:
 * the first copy of a byte wins and a later rewrite marks the context
 * truncated, so "the firewall was fooled" becomes "the firewall said it could
 * not be sure". See docs/design/stream_reassembly.md.
 *
 * That handles one attack. This file handles the rest of the classic set,
 * which all share a shape: make the firewall and the endpoint see *different
 * bytes* by exploiting that they are different machines at different points on
 * the path.
 *
 *   - **TTL insertion.** Send a segment with a TTL high enough to reach the
 *     firewall and too low to reach the endpoint. The firewall scans it; the
 *     endpoint never sees it. Ptacek and Newsham, 1998, and still effective
 *     against anything that does not look.
 *   - **IP fragment overlap.** The same trick as TCP overlap, one layer down,
 *     and with worse disagreement between stacks: Linux prefers the first
 *     copy, older Windows the last, and BSD varies by offset.
 *   - **RST injection.** A forged RST tears down the firewall's flow state
 *     while the endpoint, which validates the sequence number, ignores it.
 *     Everything after that is unmonitored.
 *   - **PAWS / timestamp games.** A segment with a timestamp older than the
 *     connection's is discarded by the endpoint (RFC 7323) and accepted by a
 *     firewall that does not implement PAWS.
 *
 * # The rule this file follows
 *
 * Where the firewall cannot know what the endpoint will do, it does not guess.
 * It records that the flow contains an ambiguity and lets policy decide, the
 * same way the reassembler marks truncation rather than picking an overlap
 * winner. A firewall that guesses is a firewall that is wrong silently; one
 * that reports is a firewall an analyst can act on.
 *
 * # Why a header
 *
 * Nothing here needs the kernel. That is what lets
 * `daemon/tests/evasion_tests.rs` drive it through the attack sequences under
 * sanitizers, which is the only way anyone finds out whether it works —
 * these paths are, by construction, never taken by ordinary traffic.
 */

#ifndef UFW_EVASION_H
#define UFW_EVASION_H

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/string.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/* Findings, as a bitmask. A flow can trip several, and which ones matters:
 * "low TTL and an overlapping fragment" is a deliberate evasion attempt, while
 * either alone is occasionally a misconfigured network. */
#define UFW_EVADE_NONE            0x0000u
/* A packet whose TTL is far enough below the flow's baseline that it may not
 * reach the endpoint this firewall protects. */
#define UFW_EVADE_TTL_INSERTION   0x0001u
/* Two fragments claiming the same offset range with different bytes. */
#define UFW_EVADE_FRAG_OVERLAP    0x0002u
/* A fragment whose offset+length exceeds the maximum datagram size, or which
 * would overflow the reassembly window. The teardrop shape. */
#define UFW_EVADE_FRAG_OVERSIZE   0x0004u
/* A RST whose sequence number is outside the receive window, which the
 * endpoint will ignore and a naive firewall will act on. */
#define UFW_EVADE_BAD_RST         0x0008u
/* A segment whose TCP timestamp goes backwards; PAWS says the endpoint drops
 * it. RFC 7323 section 5.3. */
#define UFW_EVADE_PAWS_REPLAY     0x0010u
/* A SYN retransmitted with different options or a different initial sequence
 * number — two different connections presented as one. */
#define UFW_EVADE_SYN_MISMATCH    0x0020u

/* How many fragment extents are tracked per datagram before the engine stops
 * trying to be precise and reports oversize. A legitimate datagram fragments
 * into a handful of pieces; hundreds is the attack. */
#define UFW_EVADE_MAX_FRAGMENTS 16

/* How far below the observed baseline a TTL has to fall before it is
 * suspicious.
 *
 * The baseline is the highest TTL seen on the flow, which approximates the
 * sender's initial value minus the hops to here. A packet more than this many
 * hops lower may die before the endpoint. Four is chosen because path length
 * varies by a hop or two under ECMP and route flap, and a threshold that fires
 * on normal variation is a threshold that gets disabled.
 */
#define UFW_EVADE_TTL_SLACK 4

struct ufw_frag_extent {
	__u32 start;
	__u32 end;
	/* A cheap checksum of the bytes, so an overlap that carries *identical*
	 * data — which is a legitimate retransmission — is not reported as an
	 * attack. Cheap on purpose: a collision here causes a false negative on
	 * one fragment, and the alternative is keeping the bytes. */
	__u32 digest;
};

/* Per-flow evasion state.
 *
 * Small and fixed-size, because there is one per tracked flow and a firewall
 * that allocates per flow on the packet path is a firewall with a memory
 * exhaustion bug waiting for the right traffic pattern.
 */
struct ufw_evasion {
	__u16 findings;

	/* TTL */
	__u8  ttl_baseline;
	__u8  ttl_min;

	/* TCP */
	__u32 rcv_next;      /* next sequence we expect */
	__u32 rcv_window;    /* advertised window, scaled */
	__u32 last_tsval;    /* most recent TCP timestamp seen */
	__u32 syn_isn;
	__u8  have_syn;
	__u8  have_tsval;
	__u8  have_window;

	/* IP fragments */
	__u8  frag_count;
	__u32 frag_id;
	struct ufw_frag_extent frags[UFW_EVADE_MAX_FRAGMENTS];
};

static inline void ufw_evasion_init(struct ufw_evasion *e)
{
	memset(e, 0, sizeof(*e));
	e->ttl_min = 255;
}

/* --- TTL ----------------------------------------------------------------- */

/*
 * Record a TTL and report whether it looks like an insertion.
 *
 * The baseline is the *highest* value seen, not the first: a flow whose first
 * packet was itself the attack would otherwise calibrate against the attack.
 * Raising the baseline never reports; only falling below it does.
 */
static inline __u16 ufw_evasion_ttl(struct ufw_evasion *e, __u8 ttl)
{
	if (ttl > e->ttl_baseline)
		e->ttl_baseline = ttl;
	if (ttl < e->ttl_min)
		e->ttl_min = ttl;

	/* A single packet cannot be judged: with no baseline there is nothing
	 * to be below. */
	if (e->ttl_baseline == 0)
		return UFW_EVADE_NONE;

	if ((__u32)e->ttl_baseline - ttl > UFW_EVADE_TTL_SLACK) {
		e->findings |= UFW_EVADE_TTL_INSERTION;
		return UFW_EVADE_TTL_INSERTION;
	}
	return UFW_EVADE_NONE;
}

/* --- IP fragments -------------------------------------------------------- */

/* FNV-1a over the fragment payload. Not a security hash — see the comment on
 * `digest` — just enough to tell a retransmission from a rewrite. */
static inline __u32 ufw_evasion_digest(const __u8 *data, __u32 len)
{
	__u32 h = 2166136261u, i;

	for (i = 0; i < len; i++) {
		h ^= data[i];
		h *= 16777619u;
	}
	return h;
}

/*
 * Record a fragment and report what is wrong with it.
 *
 * `offset` is in bytes (the header's field times 8), `len` the payload length.
 *
 * An overlap carrying identical bytes is a retransmission and is not reported.
 * An overlap carrying *different* bytes is the attack: the firewall and the
 * endpoint will disagree about which copy counts, and no resolution policy is
 * correct for every stack — Linux prefers the first, older Windows the last.
 * So this makes no choice and says so, exactly as the TCP reassembler does.
 */
static inline __u16 ufw_evasion_fragment(struct ufw_evasion *e, __u32 id,
					 __u32 offset, const __u8 *data,
					 __u32 len)
{
	__u32 start = offset, end, digest;
	__u8 i;

	/* A new datagram resets the extent list. Fragments from two datagrams
	 * cannot overlap each other, and keeping both would make the bound
	 * meaningless. */
	if (!e->frag_count || e->frag_id != id) {
		e->frag_id = id;
		e->frag_count = 0;
	}

	/* 65535 is the ceiling the IP header's own length field can express.
	 * A fragment claiming to end past it cannot be reassembled by anything
	 * and is the teardrop shape. */
	if (len > 65535u || start > 65535u || start + len > 65535u) {
		e->findings |= UFW_EVADE_FRAG_OVERSIZE;
		return UFW_EVADE_FRAG_OVERSIZE;
	}
	end = start + len;

	if (e->frag_count >= UFW_EVADE_MAX_FRAGMENTS) {
		/* More pieces than any legitimate datagram needs. Refusing to
		 * track further is not the same as accepting them: the flow
		 * carries the finding from here on. */
		e->findings |= UFW_EVADE_FRAG_OVERSIZE;
		return UFW_EVADE_FRAG_OVERSIZE;
	}

	digest = ufw_evasion_digest(data, len);
	for (i = 0; i < e->frag_count; i++) {
		const struct ufw_frag_extent *f = &e->frags[i];

		if (start >= f->end || end <= f->start)
			continue;   /* disjoint */

		if (start == f->start && end == f->end && digest == f->digest)
			return UFW_EVADE_NONE;   /* retransmission */

		e->findings |= UFW_EVADE_FRAG_OVERLAP;
		return UFW_EVADE_FRAG_OVERLAP;
	}

	e->frags[e->frag_count].start = start;
	e->frags[e->frag_count].end = end;
	e->frags[e->frag_count].digest = digest;
	e->frag_count++;
	return UFW_EVADE_NONE;
}

/* --- TCP ----------------------------------------------------------------- */

/* Sequence comparison that survives wraparound. `a` is after `b` when their
 * signed difference is positive — the standard trick, and the reason every
 * sequence variable here is unsigned and every comparison goes through this. */
static inline int ufw_seq_after(__u32 a, __u32 b)
{
	return (int32_t)(a - b) > 0;
}

static inline void ufw_evasion_syn(struct ufw_evasion *e, __u32 isn)
{
	if (!e->have_syn) {
		e->have_syn = 1;
		e->syn_isn = isn;
		e->rcv_next = isn + 1;
		return;
	}
	/* A retransmitted SYN carries the same ISN. A different one is either
	 * a new connection reusing the tuple — in which case the state this
	 * flow accumulated is about a different connection — or an injection.
	 * Neither is something to fold silently into the existing state. */
	if (e->syn_isn != isn)
		e->findings |= UFW_EVADE_SYN_MISMATCH;
}

static inline void ufw_evasion_window(struct ufw_evasion *e, __u32 next,
				      __u32 window)
{
	e->rcv_next = next;
	e->rcv_window = window;
	e->have_window = 1;
}

/*
 * Validate a RST.
 *
 * RFC 5961: a receiver accepts a RST only when its sequence number falls in
 * the receive window, and modern stacks implement that. A firewall that tears
 * down flow state on any RST can therefore be blinded by a forged one — the
 * endpoint ignores it and keeps talking, while the firewall has stopped
 * watching. Everything after that point is unmonitored, which is a better
 * outcome for the attacker than being blocked.
 *
 * Returns nonzero when the RST should be *ignored* for state purposes.
 */
static inline __u16 ufw_evasion_rst(struct ufw_evasion *e, __u32 seq)
{
	__u32 end;

	if (!e->have_window)
		return UFW_EVADE_NONE;   /* nothing to validate against yet */

	end = e->rcv_next + e->rcv_window;
	/* In window when it is at or after rcv_next and before the window end,
	 * with wraparound handled by the signed comparison. */
	if (!ufw_seq_after(e->rcv_next, seq) && ufw_seq_after(end, seq))
		return UFW_EVADE_NONE;

	e->findings |= UFW_EVADE_BAD_RST;
	return UFW_EVADE_BAD_RST;
}

/*
 * PAWS: Protection Against Wrapped Sequences, RFC 7323 section 5.3.
 *
 * A segment whose timestamp is older than the most recent one is discarded by
 * the endpoint. A firewall that inspects it anyway is inspecting bytes the
 * endpoint will never process — which is the same class of mistake as TTL
 * insertion, arriving through a different door.
 *
 * Returns nonzero when the segment should not be inspected.
 */
static inline __u16 ufw_evasion_timestamp(struct ufw_evasion *e, __u32 tsval)
{
	if (!e->have_tsval) {
		e->have_tsval = 1;
		e->last_tsval = tsval;
		return UFW_EVADE_NONE;
	}
	if (ufw_seq_after(e->last_tsval, tsval)) {
		e->findings |= UFW_EVADE_PAWS_REPLAY;
		return UFW_EVADE_PAWS_REPLAY;
	}
	e->last_tsval = tsval;
	return UFW_EVADE_NONE;
}

/* Everything this flow has tripped. Carried into the log event, so a flow that
 * was permitted but looked wrong is visible rather than indistinguishable from
 * one that looked fine. */
static inline __u16 ufw_evasion_findings(const struct ufw_evasion *e)
{
	return e->findings;
}

#endif /* UFW_EVASION_H */
