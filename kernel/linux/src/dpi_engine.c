// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — signature evaluation.
 *
 * This is the kernel half of `daemon/src/signatures.rs`. The daemon parses
 * the YAML, validates it, refuses signatures that could never match, and
 * ships a flat binary encoding; this file decodes that and runs it.
 *
 * # Why the language is this small
 *
 * Three condition kinds — a field comparison, a bounded byte search, and an
 * entropy threshold — combined only by conjunction. No alternation, no
 * grouping, no regular expressions.
 *
 * The reason is that this code runs in softirq context on bytes an adversary
 * chose. A signature language with backtracking hands them a way to make the
 * kernel spend unbounded time on a packet they crafted, which is a denial of
 * service that arrives looking like ordinary traffic. Every construct here
 * runs in time linear in the scanned window, and the window is bounded by the
 * reassembly budget. The worst case is therefore a constant, and it is a
 * constant an operator can compute: signatures × 32 KiB.
 *
 * The second reason is equivalence. This evaluator exists three times — here,
 * in the Windows driver, and in Swift inside a sandboxed macOS extension. A
 * construct is not free once; it is paid for three times and is a place the
 * three can disagree.
 *
 * # Floating point
 *
 * There is none, and there cannot be: kernel code may not use the FPU without
 * explicit save/restore, and the macOS extension would round differently
 * anyway. Entropy is therefore computed and compared in hundredths of a bit,
 * with an integer log2 approximation shared by all three implementations.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/percpu.h>
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#include "../inc/module.h"
#include "../inc/dpi_automaton.h"
#include "../inc/dpi_decoders.h"

/* Condition kinds, matching daemon/src/signatures.rs. */
#define UFW_COND_FIELD   1
#define UFW_COND_CONTENT 2
#define UFW_COND_ENTROPY 3

/* Comparison operators. */
#define UFW_CMP_EQ 1
#define UFW_CMP_NE 2
#define UFW_CMP_LT 3
#define UFW_CMP_LE 4
#define UFW_CMP_GT 5
#define UFW_CMP_GE 6


#define UFW_MAX_CONDITIONS 8
#define UFW_MAX_PATTERN 64
#define UFW_MAX_LOADED_SIGNATURES 1024

#if UFW_MAX_PATTERN != UFW_AC_MAX_PATTERN
#error "the condition pattern ceiling and the automaton's have drifted apart"
#endif

struct ufw_condition {
	__u8  kind;
	__u8  op;
	__u16 field;
	__u32 offset;
	__u32 depth;
	__u8  nocase;
	__u8  pattern_len;
	__u8  pattern[UFW_MAX_PATTERN];
	/* Index into the shipped automaton's pattern table, or
	 * UFW_AC_NO_PATTERN when the set arrived without one. The pattern
	 * bytes above are kept either way: the automaton's fallback arm needs
	 * them, and so does every match when there is no automaton. */
	__u32 pattern_id;
	__u64 value;
};

struct ufw_signature {
	__u32 id;
	__u8  l7;
	__u8  severity;
	__u8  condition_count;
	struct ufw_condition conditions[UFW_MAX_CONDITIONS];
};

struct ufw_signature_set {
	__u32 count;
	/* Whether `ac` below was populated. A set can legitimately arrive
	 * without an automaton — no content conditions at all, or a pattern
	 * set past the shipped table limits — and then every content
	 * condition takes the bounded search it always took. */
	__u8  has_automaton;
	struct ufw_ac ac;
	struct ufw_signature signatures[];
};

static struct ufw_signature_set __rcu *ufw_signatures;
static DEFINE_SPINLOCK(ufw_signature_lock);

/*
 * Scan results, one entry per pattern, reused across scans.
 *
 * Per-CPU rather than on the stack: 512 entries is 4 KiB, and a kernel stack
 * is 16. Per-CPU rather than per-set, because two CPUs scan two flows against
 * the same signature set at the same time.
 *
 * `ufw_ac_scan` zeroes the entries it will use before writing any, so the
 * previous flow's matches cannot leak into this one.
 */
static DEFINE_PER_CPU(struct ufw_ac_hit, ufw_ac_scratch[UFW_AC_MAX_PATTERNS]);

/* --- condition evaluation ------------------------------------------------ */

static bool compare(__u8 op, __u64 left, __u64 right)
{
	switch (op) {
	case UFW_CMP_EQ: return left == right;
	case UFW_CMP_NE: return left != right;
	case UFW_CMP_LT: return left < right;
	case UFW_CMP_LE: return left <= right;
	case UFW_CMP_GT: return left > right;
	case UFW_CMP_GE: return left >= right;
	default:         return false;
	}
}

/*
 * Content matching.
 *
 * The search itself lives in inc/dpi_automaton.h, in two forms: a shared
 * Aho-Corasick pass that finds every pattern in the set at once, and the
 * bounded naive search it replaces. This function only chooses between them.
 *
 * The naive search is still here, and is still the definition. It is what
 * runs when a set ships without an automaton — no content conditions, or a
 * pattern set past the shipped table limits — and it is the fallback for the
 * one case a scan result cannot decide. Keeping it means the fast path has
 * something to be equivalent *to*, which is what
 * `daemon/tests/dpi_automaton_tests.rs` checks on every build.
 */
static bool content_match(const struct ufw_condition *c,
			  const struct ufw_signature_set *set,
			  const struct ufw_ac_hit *hits, const __u8 *data,
			  __u32 len)
{
	if (hits && c->pattern_id != UFW_AC_NO_PATTERN &&
	    c->pattern_id < set->ac.pattern_count)
		return ufw_ac_content_matches(c->pattern, c->pattern_len,
					      c->nocase, c->offset, c->depth,
					      hits[c->pattern_id], data, len) != 0;

	return ufw_ac_naive_contains(c->pattern, c->pattern_len, c->nocase,
				     data, len, c->offset, c->depth) != 0;
}

static bool condition_holds(const struct ufw_condition *c,
			    const struct ufw_decoded *decoded,
			    const struct ufw_signature_set *set,
			    const struct ufw_ac_hit *hits, const __u8 *data,
			    __u32 len)
{
	switch (c->kind) {
	case UFW_COND_FIELD:
		if (c->field == UFW_FIELD_PAYLOAD_LEN)
			return compare(c->op, len, c->value);
		if (c->field >= 128 || !decoded->present[c->field])
			/* The decoder did not produce this field, either
			 * because the payload was malformed or because it is
			 * another protocol's. Absent is not zero: an absent
			 * field fails its condition. */
			return false;
		return compare(c->op, decoded->values[c->field], c->value);

	case UFW_COND_CONTENT:
		return content_match(c, set, hits, data, len);

	case UFW_COND_ENTROPY:
		return entropy_centibits(data, len) >= (__u32)c->value;

	default:
		return false;
	}
}

int ufw_dpi_scan(__u8 l7, const __u8 *data, size_t len,
		 __u32 *matched, __u8 max_matches, __u8 *truncated)
{
	const struct ufw_signature_set *set;
	struct ufw_ac_hit *pattern_hits = NULL;
	struct ufw_decoded decoded;
	__u32 i;
	int hits = 0;

	if (!data || !len || !matched || !max_matches)
		return 0;

	memset(&decoded, 0, sizeof(decoded));
	decoded_set(&decoded, UFW_FIELD_PAYLOAD_LEN, (__u32)len);

	switch (l7) {
	case UFW_L7_DNS:  decode_dns(&decoded, data, (__u32)len); break;
	case UFW_L7_HTTP: decode_http(&decoded, data, (__u32)len); break;
	case UFW_L7_TLS:  decode_tls(&decoded, data, (__u32)len); break;
	case UFW_L7_SSH:  decode_ssh(&decoded, data, (__u32)len); break;
	default: break;
	}

	rcu_read_lock();
	set = rcu_dereference(ufw_signatures);
	if (!set) {
		rcu_read_unlock();
		return 0;
	}

	/*
	 * One pass over the payload for every content pattern in the set,
	 * before any signature is considered. This is the whole point of the
	 * automaton: the loop below then costs a table lookup per content
	 * condition instead of a search over the window.
	 *
	 * get_cpu_ptr disables preemption for the duration, which bounds how
	 * long the scratch is held to the length of this scan — and the scan
	 * is bounded by the reassembly budget.
	 */
	if (set->has_automaton) {
		pattern_hits = get_cpu_ptr(ufw_ac_scratch);
		ufw_ac_scan(&set->ac, data, (__u32)len, pattern_hits);
	}

	for (i = 0; i < set->count && hits < max_matches; i++) {
		const struct ufw_signature *sig = &set->signatures[i];
		bool all = true;
		__u8 c;

		/* A signature scoped to a protocol only runs against that
		 * protocol. UFW_L7_UNKNOWN signatures run against everything,
		 * which is how a content match on a protocol the decoders do
		 * not know still works. */
		if (sig->l7 != UFW_L7_UNKNOWN && sig->l7 != l7)
			continue;

		for (c = 0; c < sig->condition_count && c < UFW_MAX_CONDITIONS; c++) {
			if (!condition_holds(&sig->conditions[c], &decoded, set,
					     pattern_hits, data, (__u32)len)) {
				all = false;
				break;
			}
		}
		if (all)
			matched[hits++] = sig->id;
	}

	if (pattern_hits)
		put_cpu_ptr(ufw_ac_scratch);
	rcu_read_unlock();

	/* A truncated stream that produced no match is not evidence of
	 * absence, and the caller needs to be able to tell the two apart. */
	if (truncated && *truncated && hits == 0)
		*truncated = 1;

	return hits;
}

/* --- installation --------------------------------------------------------- */

/* A little decoder over the daemon's little-endian encoding. Bounds are
 * checked on every read: this buffer arrives over netlink from a process
 * that is trusted to be the daemon but not trusted to be correct. */
struct cursor {
	const __u8 *data;
	size_t len;
	size_t pos;
};

static bool take(struct cursor *c, void *out, size_t n)
{
	if (c->pos + n > c->len)
		return false;
	memcpy(out, c->data + c->pos, n);
	c->pos += n;
	return true;
}

static bool take_u8(struct cursor *c, __u8 *v)  { return take(c, v, 1); }
static bool take_u16(struct cursor *c, __u16 *v) { return take(c, v, 2); }
static bool take_u32(struct cursor *c, __u32 *v) { return take(c, v, 4); }
static bool take_u64(struct cursor *c, __u64 *v) { return take(c, v, 8); }

/* Frees a set and whatever automaton arrays it owns. kvfree tolerates NULL,
 * so this is also the cleanup path for a half-built set. */
static void signature_set_free(struct ufw_signature_set *set)
{
	if (!set)
		return;
	kvfree(set->ac.patterns);
	kvfree(set->ac.states);
	kvfree(set->ac.transitions);
	kvfree(set->ac.outputs);
	kvfree(set);
}

int ufw_dpi_install(const __u8 *encoded, size_t len)
{
	struct cursor cur = { .data = encoded, .len = len, .pos = 0 };
	struct ufw_signature_set *set, *old;
	unsigned long flags;
	__u32 count, i;
	__u8 has_automaton;

	if (!take_u32(&cur, &count))
		return -EINVAL;
	if (count > UFW_MAX_LOADED_SIGNATURES)
		return -E2BIG;

	set = kvzalloc(struct_size(set, signatures, count), GFP_KERNEL);
	if (!set)
		return -ENOMEM;
	set->count = count;

	for (i = 0; i < count; i++) {
		struct ufw_signature *sig = &set->signatures[i];
		__u16 condition_count;
		__u16 c;

		if (!take_u32(&cur, &sig->id) || !take_u8(&cur, &sig->l7) ||
		    !take_u8(&cur, &sig->severity) ||
		    !take_u16(&cur, &condition_count))
			goto malformed;

		if (condition_count > UFW_MAX_CONDITIONS)
			goto malformed;
		sig->condition_count = (__u8)condition_count;

		for (c = 0; c < condition_count; c++) {
			struct ufw_condition *cond = &sig->conditions[c];
			__u32 pattern_len;

			if (!take_u8(&cur, &cond->kind))
				goto malformed;

			switch (cond->kind) {
			case UFW_COND_FIELD:
				if (!take_u16(&cur, &cond->field) ||
				    !take_u8(&cur, &cond->op) ||
				    !take_u64(&cur, &cond->value))
					goto malformed;
				break;
			case UFW_COND_CONTENT:
				if (!take_u32(&cur, &cond->offset) ||
				    !take_u32(&cur, &cond->depth) ||
				    !take_u8(&cur, &cond->nocase) ||
				    !take_u32(&cur, &cond->pattern_id) ||
				    !take_u32(&cur, &pattern_len))
					goto malformed;
				if (pattern_len > UFW_MAX_PATTERN)
					goto malformed;
				cond->pattern_len = (__u8)pattern_len;
				if (!take(&cur, cond->pattern, pattern_len))
					goto malformed;
				break;
			case UFW_COND_ENTROPY:
				if (!take_u16(&cur, &cond->field) ||
				    !take_u32(&cur, &cond->offset))
					goto malformed;
				/* `offset` carries min_centibits for this
				 * kind; the encoding reuses the slot. */
				cond->value = cond->offset;
				cond->offset = 0;
				break;
			default:
				goto malformed;
			}
		}
	}

	/*
	 * The automaton section, if the daemon shipped one. It is absent when
	 * no signature has a content condition, and when the pattern set
	 * exceeds the table limits — in which case every content condition
	 * carries UFW_AC_NO_PATTERN and takes the bounded search. That is a
	 * performance cliff and never a behavioural one, which is the right
	 * way round: a table that silently stopped covering some patterns
	 * would report a clean scan of a stream it never searched.
	 */
	if (!take_u8(&cur, &has_automaton))
		goto malformed;
	if (has_automaton) {
		struct ufw_ac_cursor ac_cur = {
			.data = cur.data, .len = cur.len, .pos = cur.pos
		};
		struct ufw_ac_sizes sizes;

		if (!ufw_ac_sizes_of(&ac_cur, &sizes))
			goto malformed;

		set->ac.patterns = kvcalloc(sizes.patterns,
					    sizeof(*set->ac.patterns), GFP_KERNEL);
		set->ac.states = kvcalloc(sizes.states,
					  sizeof(*set->ac.states), GFP_KERNEL);
		set->ac.transitions = kvcalloc(sizes.transitions,
					       sizeof(*set->ac.transitions),
					       GFP_KERNEL);
		set->ac.outputs = kvcalloc(sizes.outputs,
					   sizeof(*set->ac.outputs), GFP_KERNEL);
		if (!set->ac.patterns || !set->ac.states ||
		    !set->ac.transitions || !set->ac.outputs) {
			signature_set_free(set);
			return -ENOMEM;
		}

		if (!ufw_ac_load(&ac_cur, &set->ac))
			goto malformed;
		set->has_automaton = 1;
		cur.pos = ac_cur.pos;
	}

	spin_lock_irqsave(&ufw_signature_lock, flags);
	old = rcu_dereference_protected(ufw_signatures,
					lockdep_is_held(&ufw_signature_lock));
	rcu_assign_pointer(ufw_signatures, set);
	spin_unlock_irqrestore(&ufw_signature_lock, flags);

	if (old) {
		synchronize_rcu();
		signature_set_free(old);
	}
	return 0;

malformed:
	signature_set_free(set);
	return -EINVAL;
}

int ufw_dpi_init(void)
{
	RCU_INIT_POINTER(ufw_signatures, NULL);
	return 0;
}

void ufw_dpi_exit(void)
{
	struct ufw_signature_set *old;
	unsigned long flags;

	spin_lock_irqsave(&ufw_signature_lock, flags);
	old = rcu_dereference_protected(ufw_signatures,
					lockdep_is_held(&ufw_signature_lock));
	rcu_assign_pointer(ufw_signatures, NULL);
	spin_unlock_irqrestore(&ufw_signature_lock, flags);

	if (old) {
		synchronize_rcu();
		signature_set_free(old);
	}
}
