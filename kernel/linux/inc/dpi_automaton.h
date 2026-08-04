/*
 * Unified Firewall — multi-pattern search, the kernel half.
 *
 * The daemon builds one Aho-Corasick automaton over every `content:` pattern
 * in the signature set and ships the finished table (see
 * `daemon/src/automaton.rs`). This header decodes that table and walks it.
 *
 * There is no construction here on purpose. Building the automaton is the
 * subtle part — failure links, output-set merging, the root self-loop — and
 * doing it three times, twice in C and once in Swift, is three chances to
 * disagree about which patterns a stream contains. What is left is a loop
 * short enough to read against its Windows and Swift counterparts and see
 * that it is the same loop.
 *
 * # Why this is a header and not a .c
 *
 * Nothing in here needs the kernel: no allocation, no locking, no sleeping,
 * no kernel API at all. Keeping it free of those is what lets
 * `policy-lang/tests/dpi_automaton_tests.rs` compile this exact code with a
 * hosted compiler and run it against the Rust reference on a corpus. A
 * traversal that is only ever exercised on a live kernel is a traversal
 * nobody checks.
 *
 * # What a scan produces
 *
 * Per pattern: the offset of the first occurrence in the scanned buffer, and
 * whether there was more than one. Not every offset — that would be a table
 * whose size an attacker chooses. `ufw_ac_content_matches` turns those two
 * facts into a verdict for a condition's window, falling back to the bounded
 * naive search in the one case the two facts cannot decide.
 */

#ifndef UFW_DPI_AUTOMATON_H
#define UFW_DPI_AUTOMATON_H

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

/* These mirror daemon/src/automaton.rs. A table that exceeds them is refused
 * at decode rather than truncated: a truncated automaton reports a clean scan
 * for patterns it never looked at, which is the one failure mode a signature
 * engine must not have. */
#define UFW_AC_MAX_PATTERNS 512
#define UFW_AC_MAX_STATES   16384
#define UFW_AC_MAX_OUTPUTS  8192
#define UFW_AC_MAX_PATTERN  64
#define UFW_AC_MAX_TRIES    2

/* A content condition whose pattern has no automaton entry — either the set
 * shipped without an automaton, or this condition was added after one was
 * built. Both mean "search for this one the slow way". */
#define UFW_AC_NO_PATTERN 0xFFFFFFFFu

struct ufw_ac_pattern {
	__u32 len;
	__u8  nocase;
	__u8  bytes[UFW_AC_MAX_PATTERN];
};

struct ufw_ac_state {
	__u32 fail;
	__u32 trans_start;	/* index within this trie's transition slice */
	__u32 out_start;	/* index within this trie's output slice */
	__u16 trans_count;
	__u16 out_count;
};

struct ufw_ac_transition {
	__u32 next;
	__u8  byte;
};

struct ufw_ac_trie {
	__u8  fold;		/* ASCII-fold input bytes before traversing */
	__u32 state_base;
	__u32 state_count;
	__u32 trans_base;
	__u32 trans_count;
	__u32 out_base;
	__u32 out_count;
};

/*
 * The decoded table. The four arrays are caller-owned: `ufw_ac_sizes` reports
 * how large each must be, the caller allocates them however its platform
 * allocates, and `ufw_ac_load` fills them. That split is what keeps this
 * header free of any allocator.
 */
struct ufw_ac {
	__u32 pattern_count;
	__u8  trie_count;
	struct ufw_ac_trie tries[UFW_AC_MAX_TRIES];
	struct ufw_ac_pattern    *patterns;
	struct ufw_ac_state      *states;
	struct ufw_ac_transition *transitions;
	__u16                    *outputs;
};

/* What one pattern did in one scan. `count` saturates at 2: zero, one at a
 * known offset, or "more than one, ask the slow path". */
struct ufw_ac_hit {
	__u32 first_start;
	__u8  count;
};

/* Array sizes a table needs, reported before anything is allocated. */
struct ufw_ac_sizes {
	__u32 patterns;
	__u32 states;
	__u32 transitions;
	__u32 outputs;
};

/* --- little-endian cursor ------------------------------------------------ */

struct ufw_ac_cursor {
	const __u8 *data;
	size_t len;
	size_t pos;
};

static inline int ufw_ac_take(struct ufw_ac_cursor *c, void *out, size_t n)
{
	if (n > c->len || c->pos > c->len - n)
		return 0;
	memcpy(out, c->data + c->pos, n);
	c->pos += n;
	return 1;
}

static inline int ufw_ac_u8(struct ufw_ac_cursor *c, __u8 *v)
{
	return ufw_ac_take(c, v, 1);
}

static inline int ufw_ac_u16(struct ufw_ac_cursor *c, __u16 *v)
{
	__u8 b[2];

	if (!ufw_ac_take(c, b, 2))
		return 0;
	*v = (__u16)((__u16)b[0] | ((__u16)b[1] << 8));
	return 1;
}

static inline int ufw_ac_u32(struct ufw_ac_cursor *c, __u32 *v)
{
	__u8 b[4];

	if (!ufw_ac_take(c, b, 4))
		return 0;
	*v = (__u32)b[0] | ((__u32)b[1] << 8) | ((__u32)b[2] << 16) |
	     ((__u32)b[3] << 24);
	return 1;
}

/* --- decoding ------------------------------------------------------------ */

/*
 * Read the counts without consuming the payload, so the caller can size its
 * allocation. `cursor` is left where it started; `ufw_ac_load` re-reads from
 * the same position.
 *
 * Returns 0 on a malformed or oversized table.
 */
static inline int ufw_ac_sizes_of(const struct ufw_ac_cursor *cursor,
				  struct ufw_ac_sizes *out)
{
	struct ufw_ac_cursor c = *cursor;
	__u32 pattern_count, i;
	__u8 trie_count, t;

	memset(out, 0, sizeof(*out));

	if (!ufw_ac_u32(&c, &pattern_count))
		return 0;
	if (pattern_count == 0 || pattern_count > UFW_AC_MAX_PATTERNS)
		return 0;
	out->patterns = pattern_count;

	for (i = 0; i < pattern_count; i++) {
		__u32 len;
		__u8 nocase;

		if (!ufw_ac_u8(&c, &nocase) || !ufw_ac_u32(&c, &len))
			return 0;
		if (len == 0 || len > UFW_AC_MAX_PATTERN)
			return 0;
		c.pos += len;
		if (c.pos > c.len)
			return 0;
	}

	if (!ufw_ac_u8(&c, &trie_count))
		return 0;
	if (trie_count == 0 || trie_count > UFW_AC_MAX_TRIES)
		return 0;

	for (t = 0; t < trie_count; t++) {
		__u32 states, transitions, outputs;
		__u8 fold;

		if (!ufw_ac_u8(&c, &fold) || !ufw_ac_u32(&c, &states) ||
		    !ufw_ac_u32(&c, &transitions) || !ufw_ac_u32(&c, &outputs))
			return 0;
		if (states == 0)
			return 0;
		out->states += states;
		out->transitions += transitions;
		out->outputs += outputs;
		if (out->states > UFW_AC_MAX_STATES ||
		    out->transitions > UFW_AC_MAX_STATES ||
		    out->outputs > UFW_AC_MAX_OUTPUTS)
			return 0;
		/* 16 bytes per state (u32 fail, u32 trans_start, u16
		 * trans_count, u32 out_start, u16 out_count), 5 per transition,
		 * 2 per output. Skipped rather than read, because this pass
		 * only needs the shape. */
		c.pos += (size_t)states * 16u + (size_t)transitions * 5u +
			 (size_t)outputs * 2u;
		if (c.pos > c.len)
			return 0;
	}
	return 1;
}

/*
 * Fill `ac` from the payload. Every index in the table is bounds-checked here
 * so that the traversal below needs no checks at all: the table arrives over
 * netlink from a process trusted to be the daemon but not trusted to be
 * correct, and a scan is not the place to discover it was not.
 *
 * Returns 0 on a malformed table, leaving `ac` unusable.
 */
static inline int ufw_ac_load(struct ufw_ac_cursor *c, struct ufw_ac *ac)
{
	__u32 i, state_base = 0, trans_base = 0, out_base = 0;
	__u8 t;

	if (!ufw_ac_u32(c, &ac->pattern_count))
		return 0;
	if (ac->pattern_count == 0 || ac->pattern_count > UFW_AC_MAX_PATTERNS)
		return 0;

	for (i = 0; i < ac->pattern_count; i++) {
		struct ufw_ac_pattern *p = &ac->patterns[i];

		if (!ufw_ac_u8(c, &p->nocase) || !ufw_ac_u32(c, &p->len))
			return 0;
		if (p->len == 0 || p->len > UFW_AC_MAX_PATTERN)
			return 0;
		if (!ufw_ac_take(c, p->bytes, p->len))
			return 0;
	}

	if (!ufw_ac_u8(c, &ac->trie_count))
		return 0;
	if (ac->trie_count == 0 || ac->trie_count > UFW_AC_MAX_TRIES)
		return 0;

	for (t = 0; t < ac->trie_count; t++) {
		struct ufw_ac_trie *trie = &ac->tries[t];
		__u32 s, k;

		if (!ufw_ac_u8(c, &trie->fold) ||
		    !ufw_ac_u32(c, &trie->state_count) ||
		    !ufw_ac_u32(c, &trie->trans_count) ||
		    !ufw_ac_u32(c, &trie->out_count))
			return 0;
		if (trie->state_count == 0)
			return 0;
		trie->state_base = state_base;
		trie->trans_base = trans_base;
		trie->out_base = out_base;

		for (s = 0; s < trie->state_count; s++) {
			struct ufw_ac_state *st = &ac->states[state_base + s];

			if (!ufw_ac_u32(c, &st->fail) ||
			    !ufw_ac_u32(c, &st->trans_start) ||
			    !ufw_ac_u16(c, &st->trans_count) ||
			    !ufw_ac_u32(c, &st->out_start) ||
			    !ufw_ac_u16(c, &st->out_count))
				return 0;
			if (st->fail >= trie->state_count)
				return 0;
			if (st->trans_start > trie->trans_count ||
			    (__u32)st->trans_count >
				    trie->trans_count - st->trans_start)
				return 0;
			if (st->out_start > trie->out_count ||
			    (__u32)st->out_count >
				    trie->out_count - st->out_start)
				return 0;
		}

		for (k = 0; k < trie->trans_count; k++) {
			struct ufw_ac_transition *tr =
				&ac->transitions[trans_base + k];

			if (!ufw_ac_u8(c, &tr->byte) || !ufw_ac_u32(c, &tr->next))
				return 0;
			if (tr->next >= trie->state_count)
				return 0;
		}

		/* Each state's transitions must be sorted by byte, because the
		 * traversal binary-searches them. An unsorted slice would not
		 * fail — it would silently miss matches, which is a firewall
		 * reporting a clean scan of a stream it mis-walked. */
		for (s = 0; s < trie->state_count; s++) {
			const struct ufw_ac_state *st =
				&ac->states[state_base + s];

			for (k = 1; k < (__u32)st->trans_count; k++) {
				const struct ufw_ac_transition *prev =
					&ac->transitions[trans_base +
							 st->trans_start + k - 1];
				const struct ufw_ac_transition *cur =
					&ac->transitions[trans_base +
							 st->trans_start + k];

				if (prev->byte >= cur->byte)
					return 0;
			}
		}

		for (k = 0; k < trie->out_count; k++) {
			__u16 pid;

			if (!ufw_ac_u16(c, &pid))
				return 0;
			if ((__u32)pid >= ac->pattern_count)
				return 0;
			ac->outputs[out_base + k] = pid;
		}

		state_base += trie->state_count;
		trans_base += trie->trans_count;
		out_base += trie->out_count;
	}
	return 1;
}

/* --- traversal ----------------------------------------------------------- */

static inline __u8 ufw_ac_fold(__u8 b)
{
	return (b >= 'A' && b <= 'Z') ? (__u8)(b + 32) : b;
}

/* Binary search rather than a scan: the root of a trie over printable
 * patterns can have dozens of children, and this runs once per input byte per
 * trie. Returns the next state, or `state_count` for "no transition". */
static inline __u32 ufw_ac_transition_of(const struct ufw_ac *ac,
					 const struct ufw_ac_trie *trie,
					 __u32 state, __u8 byte)
{
	const struct ufw_ac_state *st = &ac->states[trie->state_base + state];
	__u32 lo = 0, hi = (__u32)st->trans_count;

	while (lo < hi) {
		__u32 mid = lo + (hi - lo) / 2;
		const struct ufw_ac_transition *tr =
			&ac->transitions[trie->trans_base + st->trans_start + mid];

		if (tr->byte == byte)
			return tr->next;
		if (tr->byte < byte)
			lo = mid + 1;
		else
			hi = mid;
	}
	return trie->state_count;
}

/*
 * Follow one input byte, falling back along failure links until a transition
 * exists or the root is reached.
 *
 * Amortised O(1) per byte: each fallback strictly decreases depth and depth
 * rises by at most one per byte. The `state == 0` exit is what stops the root
 * from trapping on a byte no pattern starts with.
 */
static inline __u32 ufw_ac_step(const struct ufw_ac *ac,
				const struct ufw_ac_trie *trie, __u32 state,
				__u8 byte)
{
	for (;;) {
		__u32 next = ufw_ac_transition_of(ac, trie, state, byte);

		if (next != trie->state_count)
			return next;
		if (state == 0)
			return 0;
		state = ac->states[trie->state_base + state].fail;
	}
}

/*
 * One pass over `data` for every pattern in the table.
 *
 * `hits` must have `ac->pattern_count` entries and is zeroed here rather than
 * by the caller, so a caller who reuses a per-CPU scratch buffer cannot leak
 * the previous flow's matches into this one.
 */
static inline void ufw_ac_scan(const struct ufw_ac *ac, const __u8 *data,
			       __u32 len, struct ufw_ac_hit *hits)
{
	__u8 t;
	__u32 i;

	memset(hits, 0, (size_t)ac->pattern_count * sizeof(hits[0]));
	if (!data || len == 0)
		return;

	for (t = 0; t < ac->trie_count; t++) {
		const struct ufw_ac_trie *trie = &ac->tries[t];
		__u32 state = 0;

		for (i = 0; i < len; i++) {
			const struct ufw_ac_state *st;
			__u8 byte = trie->fold ? ufw_ac_fold(data[i]) : data[i];
			__u32 k;

			state = ufw_ac_step(ac, trie, state, byte);
			st = &ac->states[trie->state_base + state];
			for (k = 0; k < (__u32)st->out_count; k++) {
				__u16 pid = ac->outputs[trie->out_base +
							st->out_start + k];
				__u32 plen = ac->patterns[pid].len;
				struct ufw_ac_hit *hit = &hits[pid];
				__u32 start;

				/* `i` indexes the last byte of the match. */
				start = i + 1u - plen;
				/* Matches arrive in increasing end offset and a
				 * pattern has a fixed length, so the first one
				 * recorded is the earliest. */
				if (hit->count == 0) {
					hit->first_start = start;
					hit->count = 1;
				} else if (hit->count == 1) {
					hit->count = 2;
				}
			}
		}
	}
}

/* --- deciding a condition ------------------------------------------------ */

/*
 * The bounded search this whole file exists to avoid running per signature.
 * Kept because the last arm of `ufw_ac_content_matches` needs it, and because
 * a set that shipped without an automaton runs nothing else.
 *
 * `depth == 0` means "to the end of the buffer", not "an empty window".
 */
static inline int ufw_ac_naive_contains(const __u8 *pattern, __u32 pattern_len,
					__u8 nocase, const __u8 *data,
					__u32 len, __u32 offset, __u32 depth)
{
	__u32 start, end, i, j;

	if (pattern_len == 0 || pattern_len > UFW_AC_MAX_PATTERN)
		return 0;
	start = offset;
	if (start >= len)
		return 0;
	end = depth ? start + depth : len;
	if (end > len || end < start)
		end = len;
	if (end < start + pattern_len)
		return 0;

	for (i = start; i + pattern_len <= end; i++) {
		for (j = 0; j < pattern_len; j++) {
			__u8 a = data[i + j];
			__u8 b = pattern[j];

			if (nocase) {
				a = ufw_ac_fold(a);
				b = ufw_ac_fold(b);
			}
			if (a != b)
				break;
		}
		if (j == pattern_len)
			return 1;
	}
	return 0;
}

/*
 * Decide one content condition from a scan result.
 *
 * Exactly equivalent to `ufw_ac_naive_contains` over the same arguments. The
 * four arms, in the order they are cheap:
 *
 *   1. absent from the whole buffer  ⇒ absent from any window inside it
 *   2. first occurrence in the window ⇒ match
 *   3. exactly one occurrence, outside the window ⇒ no match
 *   4. several occurrences, none of them the first ⇒ search this one pattern
 *
 * Arm 1 is the common case for a signature set and is why the shared pass
 * pays for itself. Arm 4 is reached only by a pattern that repeats within one
 * stream and is scoped to a window that excludes its first hit.
 */
static inline int ufw_ac_content_matches(const __u8 *pattern, __u32 pattern_len,
					 __u8 nocase, __u32 offset, __u32 depth,
					 struct ufw_ac_hit hit, const __u8 *data,
					 __u32 len)
{
	__u32 end;

	if (hit.count == 0)
		return 0;
	if (pattern_len == 0 || offset >= len)
		return 0;
	end = depth ? offset + depth : len;
	if (end > len || end < offset)
		end = len;
	if (end < offset + pattern_len)
		return 0;
	if (hit.first_start >= offset && hit.first_start + pattern_len <= end)
		return 1;
	if (hit.count == 1)
		return 0;
	return ufw_ac_naive_contains(pattern, pattern_len, nocase, data, len,
				     offset, depth);
}

#endif /* UFW_DPI_AUTOMATON_H */
