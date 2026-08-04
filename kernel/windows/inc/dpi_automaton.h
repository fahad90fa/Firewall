/*
 * Unified Firewall — multi-pattern search, Windows.
 *
 * The same table walk as kernel/linux/inc/dpi_automaton.h, in the same order,
 * with the same arithmetic. Where the two differ they differ in type names
 * and nothing else, because the equivalence claim depends on that being true
 * and `daemon/tests/dpi_automaton_tests.rs` compiles both and compares them
 * against the Rust reference on the same corpus.
 *
 * The daemon builds one Aho-Corasick automaton over every `content:` pattern
 * in the signature set (see `daemon/src/automaton.rs`) and ships the finished
 * table. There is no construction here: building is the subtle part, and
 * doing it three times is three chances to disagree about what a stream
 * contains.
 *
 * Nothing here needs the kernel — no allocation, no locking, no WDK call —
 * which is what lets the same code run under a hosted compiler in a test.
 */

#pragma once

#if defined(UFW_ABI_CHECK)
/* Checking this header on a machine with no Windows SDK. See ipc_ioctl.h for
 * why that mode exists. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#ifndef TRUE
#define TRUE  1
#define FALSE 0
typedef int BOOLEAN;
#endif
#ifndef RtlZeroMemory
#define RtlZeroMemory(d, l) memset((d), 0, (l))
#define RtlCopyMemory(d, s, l) memcpy((d), (s), (l))
#endif
#elif defined(UFW_KERNEL_MODE)
#include <ntddk.h>
#else
#include <windows.h>
#endif

/* Mirrors daemon/src/automaton.rs and the Linux header. A table exceeding
 * these is refused at decode rather than truncated: a truncated automaton
 * reports a clean scan for patterns it never looked at. */
#define UFW_AC_MAX_PATTERNS 512
#define UFW_AC_MAX_STATES   16384
#define UFW_AC_MAX_OUTPUTS  8192
#define UFW_AC_MAX_PATTERN  64
#define UFW_AC_MAX_TRIES    2

/* A content condition whose pattern has no automaton entry: search it the
 * slow way. */
#define UFW_AC_NO_PATTERN 0xFFFFFFFFu

typedef struct _UFW_AC_PATTERN {
	UINT32 len;
	UINT8  nocase;
	UINT8  bytes[UFW_AC_MAX_PATTERN];
} UFW_AC_PATTERN;

typedef struct _UFW_AC_STATE {
	UINT32 fail;
	UINT32 transStart;	/* index within this trie's transition slice */
	UINT32 outStart;	/* index within this trie's output slice */
	UINT16 transCount;
	UINT16 outCount;
} UFW_AC_STATE;

typedef struct _UFW_AC_TRANSITION {
	UINT32 next;
	UINT8  byte;
} UFW_AC_TRANSITION;

typedef struct _UFW_AC_TRIE {
	UINT8  fold;		/* ASCII-fold input bytes before traversing */
	UINT32 stateBase;
	UINT32 stateCount;
	UINT32 transBase;
	UINT32 transCount;
	UINT32 outBase;
	UINT32 outCount;
} UFW_AC_TRIE;

/*
 * The decoded table. The four arrays are caller-owned: UfwAcSizesOf reports
 * how large each must be, the caller allocates from whichever pool it uses,
 * and UfwAcLoad fills them. That split keeps this header free of any
 * allocator.
 */
typedef struct _UFW_AC {
	UINT32 patternCount;
	UINT8  trieCount;
	UFW_AC_TRIE tries[UFW_AC_MAX_TRIES];
	UFW_AC_PATTERN    *patterns;
	UFW_AC_STATE      *states;
	UFW_AC_TRANSITION *transitions;
	UINT16            *outputs;
} UFW_AC;

/* What one pattern did in one scan. `count` saturates at 2: zero, one at a
 * known offset, or "more than one, ask the slow path". */
typedef struct _UFW_AC_HIT {
	UINT32 firstStart;
	UINT8  count;
} UFW_AC_HIT;

typedef struct _UFW_AC_SIZES {
	UINT32 patterns;
	UINT32 states;
	UINT32 transitions;
	UINT32 outputs;
} UFW_AC_SIZES;

/* --- little-endian cursor ------------------------------------------------- */

typedef struct _UFW_AC_CURSOR {
	const UINT8 *data;
	size_t length;
	size_t position;
} UFW_AC_CURSOR;

static __inline BOOLEAN UfwAcTake(UFW_AC_CURSOR *c, void *out, size_t n)
{
	if (n > c->length || c->position > c->length - n)
		return FALSE;
	RtlCopyMemory(out, c->data + c->position, n);
	c->position += n;
	return TRUE;
}

static __inline BOOLEAN UfwAcU8(UFW_AC_CURSOR *c, UINT8 *v)
{
	return UfwAcTake(c, v, 1);
}

static __inline BOOLEAN UfwAcU16(UFW_AC_CURSOR *c, UINT16 *v)
{
	UINT8 b[2];

	if (!UfwAcTake(c, b, 2))
		return FALSE;
	*v = (UINT16)((UINT16)b[0] | ((UINT16)b[1] << 8));
	return TRUE;
}

static __inline BOOLEAN UfwAcU32(UFW_AC_CURSOR *c, UINT32 *v)
{
	UINT8 b[4];

	if (!UfwAcTake(c, b, 4))
		return FALSE;
	*v = (UINT32)b[0] | ((UINT32)b[1] << 8) | ((UINT32)b[2] << 16) |
	     ((UINT32)b[3] << 24);
	return TRUE;
}

/* --- decoding -------------------------------------------------------------- */

/*
 * Read the counts without consuming the payload, so the caller can size its
 * allocation. The cursor is left where it started.
 */
static __inline BOOLEAN UfwAcSizesOf(const UFW_AC_CURSOR *cursor,
				     UFW_AC_SIZES *out)
{
	UFW_AC_CURSOR c = *cursor;
	UINT32 patternCount, i;
	UINT8 trieCount, t;

	RtlZeroMemory(out, sizeof(*out));

	if (!UfwAcU32(&c, &patternCount))
		return FALSE;
	if (patternCount == 0 || patternCount > UFW_AC_MAX_PATTERNS)
		return FALSE;
	out->patterns = patternCount;

	for (i = 0; i < patternCount; i++) {
		UINT32 len;
		UINT8 nocase;

		if (!UfwAcU8(&c, &nocase) || !UfwAcU32(&c, &len))
			return FALSE;
		if (len == 0 || len > UFW_AC_MAX_PATTERN)
			return FALSE;
		c.position += len;
		if (c.position > c.length)
			return FALSE;
	}

	if (!UfwAcU8(&c, &trieCount))
		return FALSE;
	if (trieCount == 0 || trieCount > UFW_AC_MAX_TRIES)
		return FALSE;

	for (t = 0; t < trieCount; t++) {
		UINT32 states, transitions, outputs;
		UINT8 fold;

		if (!UfwAcU8(&c, &fold) || !UfwAcU32(&c, &states) ||
		    !UfwAcU32(&c, &transitions) || !UfwAcU32(&c, &outputs))
			return FALSE;
		if (states == 0)
			return FALSE;
		out->states += states;
		out->transitions += transitions;
		out->outputs += outputs;
		if (out->states > UFW_AC_MAX_STATES ||
		    out->transitions > UFW_AC_MAX_STATES ||
		    out->outputs > UFW_AC_MAX_OUTPUTS)
			return FALSE;
		/* 16 bytes per state (UINT32 fail, UINT32 transStart, UINT16
		 * transCount, UINT32 outStart, UINT16 outCount), 5 per
		 * transition, 2 per output. */
		c.position += (size_t)states * 16u + (size_t)transitions * 5u +
			      (size_t)outputs * 2u;
		if (c.position > c.length)
			return FALSE;
	}
	return TRUE;
}

/*
 * Fill `ac` from the payload. Every index is bounds-checked here so the
 * traversal below needs no checks at all: the table arrives over IOCTL from a
 * process trusted to be the daemon but not trusted to be correct, and a scan
 * is not the place to discover it was not.
 */
static __inline BOOLEAN UfwAcLoad(UFW_AC_CURSOR *c, UFW_AC *ac)
{
	UINT32 i, stateBase = 0, transBase = 0, outBase = 0;
	UINT8 t;

	if (!UfwAcU32(c, &ac->patternCount))
		return FALSE;
	if (ac->patternCount == 0 || ac->patternCount > UFW_AC_MAX_PATTERNS)
		return FALSE;

	for (i = 0; i < ac->patternCount; i++) {
		UFW_AC_PATTERN *p = &ac->patterns[i];

		if (!UfwAcU8(c, &p->nocase) || !UfwAcU32(c, &p->len))
			return FALSE;
		if (p->len == 0 || p->len > UFW_AC_MAX_PATTERN)
			return FALSE;
		if (!UfwAcTake(c, p->bytes, p->len))
			return FALSE;
	}

	if (!UfwAcU8(c, &ac->trieCount))
		return FALSE;
	if (ac->trieCount == 0 || ac->trieCount > UFW_AC_MAX_TRIES)
		return FALSE;

	for (t = 0; t < ac->trieCount; t++) {
		UFW_AC_TRIE *trie = &ac->tries[t];
		UINT32 s, k;

		if (!UfwAcU8(c, &trie->fold) ||
		    !UfwAcU32(c, &trie->stateCount) ||
		    !UfwAcU32(c, &trie->transCount) ||
		    !UfwAcU32(c, &trie->outCount))
			return FALSE;
		if (trie->stateCount == 0)
			return FALSE;
		trie->stateBase = stateBase;
		trie->transBase = transBase;
		trie->outBase = outBase;

		for (s = 0; s < trie->stateCount; s++) {
			UFW_AC_STATE *st = &ac->states[stateBase + s];

			if (!UfwAcU32(c, &st->fail) ||
			    !UfwAcU32(c, &st->transStart) ||
			    !UfwAcU16(c, &st->transCount) ||
			    !UfwAcU32(c, &st->outStart) ||
			    !UfwAcU16(c, &st->outCount))
				return FALSE;
			if (st->fail >= trie->stateCount)
				return FALSE;
			if (st->transStart > trie->transCount ||
			    (UINT32)st->transCount >
				    trie->transCount - st->transStart)
				return FALSE;
			if (st->outStart > trie->outCount ||
			    (UINT32)st->outCount > trie->outCount - st->outStart)
				return FALSE;
		}

		for (k = 0; k < trie->transCount; k++) {
			UFW_AC_TRANSITION *tr = &ac->transitions[transBase + k];

			if (!UfwAcU8(c, &tr->byte) || !UfwAcU32(c, &tr->next))
				return FALSE;
			if (tr->next >= trie->stateCount)
				return FALSE;
		}

		/* Each state's transitions must be sorted by byte, because the
		 * traversal binary-searches them. An unsorted slice would not
		 * fail — it would silently miss matches. */
		for (s = 0; s < trie->stateCount; s++) {
			const UFW_AC_STATE *st = &ac->states[stateBase + s];

			for (k = 1; k < (UINT32)st->transCount; k++) {
				const UFW_AC_TRANSITION *prev =
					&ac->transitions[transBase +
							 st->transStart + k - 1];
				const UFW_AC_TRANSITION *cur =
					&ac->transitions[transBase +
							 st->transStart + k];

				if (prev->byte >= cur->byte)
					return FALSE;
			}
		}

		for (k = 0; k < trie->outCount; k++) {
			UINT16 pid;

			if (!UfwAcU16(c, &pid))
				return FALSE;
			if ((UINT32)pid >= ac->patternCount)
				return FALSE;
			ac->outputs[outBase + k] = pid;
		}

		stateBase += trie->stateCount;
		transBase += trie->transCount;
		outBase += trie->outCount;
	}
	return TRUE;
}

/* --- traversal ------------------------------------------------------------- */

static __inline UINT8 UfwAcFold(UINT8 b)
{
	return (b >= 'A' && b <= 'Z') ? (UINT8)(b + 32) : b;
}

/* Binary search rather than a scan: the root of a trie over printable
 * patterns can have dozens of children, and this runs once per input byte per
 * trie. Returns stateCount for "no transition". */
static __inline UINT32 UfwAcTransitionOf(const UFW_AC *ac,
					 const UFW_AC_TRIE *trie, UINT32 state,
					 UINT8 byte)
{
	const UFW_AC_STATE *st = &ac->states[trie->stateBase + state];
	UINT32 lo = 0, hi = (UINT32)st->transCount;

	while (lo < hi) {
		UINT32 mid = lo + (hi - lo) / 2;
		const UFW_AC_TRANSITION *tr =
			&ac->transitions[trie->transBase + st->transStart + mid];

		if (tr->byte == byte)
			return tr->next;
		if (tr->byte < byte)
			lo = mid + 1;
		else
			hi = mid;
	}
	return trie->stateCount;
}

/*
 * Follow one input byte, falling back along failure links until a transition
 * exists or the root is reached. Amortised O(1) per byte. The `state == 0`
 * exit stops the root trapping on a byte no pattern starts with.
 */
static __inline UINT32 UfwAcStep(const UFW_AC *ac, const UFW_AC_TRIE *trie,
				 UINT32 state, UINT8 byte)
{
	for (;;) {
		UINT32 next = UfwAcTransitionOf(ac, trie, state, byte);

		if (next != trie->stateCount)
			return next;
		if (state == 0)
			return 0;
		state = ac->states[trie->stateBase + state].fail;
	}
}

/*
 * One pass over `data` for every pattern in the table.
 *
 * `hits` must have ac->patternCount entries and is zeroed here rather than by
 * the caller, so a caller reusing a per-processor scratch buffer cannot leak
 * the previous flow's matches into this one.
 */
static __inline void UfwAcScan(const UFW_AC *ac, const UINT8 *data, UINT32 len,
			       UFW_AC_HIT *hits)
{
	UINT8 t;
	UINT32 i;

	RtlZeroMemory(hits, (size_t)ac->patternCount * sizeof(hits[0]));
	if (!data || len == 0)
		return;

	for (t = 0; t < ac->trieCount; t++) {
		const UFW_AC_TRIE *trie = &ac->tries[t];
		UINT32 state = 0;

		for (i = 0; i < len; i++) {
			const UFW_AC_STATE *st;
			UINT8 byte = trie->fold ? UfwAcFold(data[i]) : data[i];
			UINT32 k;

			state = UfwAcStep(ac, trie, state, byte);
			st = &ac->states[trie->stateBase + state];
			for (k = 0; k < (UINT32)st->outCount; k++) {
				UINT16 pid = ac->outputs[trie->outBase +
							 st->outStart + k];
				UINT32 plen = ac->patterns[pid].len;
				UFW_AC_HIT *hit = &hits[pid];
				UINT32 start;

				/* `i` indexes the last byte of the match. */
				start = i + 1u - plen;
				/* Matches arrive in increasing end offset and a
				 * pattern has a fixed length, so the first one
				 * recorded is the earliest. */
				if (hit->count == 0) {
					hit->firstStart = start;
					hit->count = 1;
				} else if (hit->count == 1) {
					hit->count = 2;
				}
			}
		}
	}
}

/* --- deciding a condition -------------------------------------------------- */

/*
 * The bounded search this file exists to avoid running per signature. Kept
 * because the last arm of UfwAcContentMatches needs it, and because a set
 * that shipped without an automaton runs nothing else.
 *
 * `depth == 0` means "to the end of the buffer", not "an empty window".
 */
static __inline BOOLEAN UfwAcNaiveContains(const UINT8 *pattern,
					   UINT32 patternLen, UINT8 nocase,
					   const UINT8 *data, UINT32 len,
					   UINT32 offset, UINT32 depth)
{
	UINT32 start, end, i, j;

	if (patternLen == 0 || patternLen > UFW_AC_MAX_PATTERN)
		return FALSE;
	start = offset;
	if (start >= len)
		return FALSE;
	end = depth ? start + depth : len;
	if (end > len || end < start)
		end = len;
	if (end < start + patternLen)
		return FALSE;

	for (i = start; i + patternLen <= end; i++) {
		for (j = 0; j < patternLen; j++) {
			UINT8 a = data[i + j];
			UINT8 b = pattern[j];

			if (nocase) {
				a = UfwAcFold(a);
				b = UfwAcFold(b);
			}
			if (a != b)
				break;
		}
		if (j == patternLen)
			return TRUE;
	}
	return FALSE;
}

/*
 * Decide one content condition from a scan result. Exactly equivalent to
 * UfwAcNaiveContains over the same arguments; the four arms, cheapest first:
 *
 *   1. absent from the whole buffer   => absent from any window inside it
 *   2. first occurrence in the window => match
 *   3. exactly one occurrence, outside the window => no match
 *   4. several occurrences, none of them the first => search this one pattern
 */
static __inline BOOLEAN UfwAcContentMatches(const UINT8 *pattern,
					    UINT32 patternLen, UINT8 nocase,
					    UINT32 offset, UINT32 depth,
					    UFW_AC_HIT hit, const UINT8 *data,
					    UINT32 len)
{
	UINT32 end;

	if (hit.count == 0)
		return FALSE;
	if (patternLen == 0 || offset >= len)
		return FALSE;
	end = depth ? offset + depth : len;
	if (end > len || end < offset)
		end = len;
	if (end < offset + patternLen)
		return FALSE;
	if (hit.firstStart >= offset && hit.firstStart + patternLen <= end)
		return TRUE;
	if (hit.count == 1)
		return FALSE;
	return UfwAcNaiveContains(pattern, patternLen, nocase, data, len, offset,
				  depth);
}
