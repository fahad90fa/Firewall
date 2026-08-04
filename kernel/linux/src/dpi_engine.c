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
#include <linux/rcupdate.h>
#include <linux/spinlock.h>

#include "../inc/module.h"

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

/* Field ids, matching the Field enum in the daemon. Only the ones this
 * module's decoders can produce are handled; an unknown id makes its
 * condition fail, which makes the signature fail, which is the fail-closed
 * direction: an unrecognised field must never be treated as satisfied. */
#define UFW_FIELD_DNS_MAX_LABEL_LEN 1
#define UFW_FIELD_DNS_NAME_LEN      2
#define UFW_FIELD_DNS_LABEL_COUNT   3
#define UFW_FIELD_DNS_QUERY_TYPE    4
#define UFW_FIELD_DNS_ANSWER_COUNT  5
#define UFW_FIELD_HTTP_METHOD       20
#define UFW_FIELD_HTTP_URI_LEN      21
#define UFW_FIELD_HTTP_HEADER_COUNT 22
#define UFW_FIELD_HTTP_BODY_LEN     23
#define UFW_FIELD_HTTP_HOST_LEN     24
#define UFW_FIELD_TLS_VERSION       40
#define UFW_FIELD_TLS_SNI_LEN       41
#define UFW_FIELD_TLS_CIPHER_COUNT  42
#define UFW_FIELD_TLS_EXT_COUNT     43
#define UFW_FIELD_TLS_HANDSHAKE     44
#define UFW_FIELD_SSH_PROTO_VERSION 60
#define UFW_FIELD_SSH_BANNER_LEN    61
#define UFW_FIELD_PAYLOAD_LEN       100
#define UFW_FIELD_PAYLOAD_PRINTABLE 101

#define UFW_MAX_CONDITIONS 8
#define UFW_MAX_PATTERN 64
#define UFW_MAX_LOADED_SIGNATURES 1024

struct ufw_condition {
	__u8  kind;
	__u8  op;
	__u16 field;
	__u32 offset;
	__u32 depth;
	__u8  nocase;
	__u8  pattern_len;
	__u8  pattern[UFW_MAX_PATTERN];
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
	struct ufw_signature signatures[];
};

static struct ufw_signature_set __rcu *ufw_signatures;
static DEFINE_SPINLOCK(ufw_signature_lock);

/* --- decoded protocol facts --------------------------------------------- */

/*
 * What the decoders extract.
 *
 * Signatures test these named values rather than offsets into the payload,
 * and that is a security decision rather than an ergonomic one. An offset
 * into a protocol is only meaningful if the signature author's mental model
 * of the framing matches the decoder's, and every place those two models can
 * disagree is a place an attacker can put bytes that the firewall reads as
 * one field and the endpoint reads as another.
 */
struct ufw_decoded {
	__u32 values[128];
	__u8  present[128];
};

static void decoded_set(struct ufw_decoded *d, __u16 field, __u32 value)
{
	if (field < 128) {
		d->values[field] = value;
		d->present[field] = 1;
	}
}

/* --- DNS ---------------------------------------------------------------- */

static void decode_dns(struct ufw_decoded *d, const __u8 *data, __u32 len)
{
	__u32 pos = 12, name_len = 0, max_label = 0, labels = 0;

	if (len < 12)
		return;

	decoded_set(d, UFW_FIELD_DNS_ANSWER_COUNT,
		    ((__u32)data[6] << 8) | data[7]);

	/*
	 * Walk the QNAME label chain. Compression pointers are not followed:
	 * a pointer in a *question* is malformed, and following pointers in
	 * kernel context needs a visited set to avoid a crafted loop. Bailing
	 * out leaves the fields absent, and an absent field fails its
	 * condition, which fails the signature — the safe direction.
	 */
	while (pos < len) {
		__u8 label_len = data[pos];

		if (label_len == 0)
			break;
		if ((label_len & 0xC0) == 0xC0)
			return;
		if (label_len > 63 || pos + 1 + label_len > len)
			return;

		if (label_len > max_label)
			max_label = label_len;
		name_len += label_len + 1;
		labels++;
		pos += 1 + label_len;

		/* A name cannot exceed 255 bytes; more than that is either
		 * malformed or a loop the length check above missed. */
		if (name_len > 255 || labels > 128)
			return;
	}

	decoded_set(d, UFW_FIELD_DNS_MAX_LABEL_LEN, max_label);
	decoded_set(d, UFW_FIELD_DNS_NAME_LEN, name_len);
	decoded_set(d, UFW_FIELD_DNS_LABEL_COUNT, labels);

	if (pos + 3 <= len) {
		decoded_set(d, UFW_FIELD_DNS_QUERY_TYPE,
			    ((__u32)data[pos + 1] << 8) | data[pos + 2]);
	}
}

/* --- HTTP --------------------------------------------------------------- */

static __u32 http_method_id(const __u8 *data, __u32 len)
{
	if (len >= 4 && !memcmp(data, "GET ", 4))
		return 1;
	if (len >= 5 && !memcmp(data, "POST ", 5))
		return 2;
	if (len >= 4 && !memcmp(data, "PUT ", 4))
		return 3;
	if (len >= 7 && !memcmp(data, "DELETE ", 7))
		return 4;
	if (len >= 5 && !memcmp(data, "HEAD ", 5))
		return 5;
	if (len >= 8 && !memcmp(data, "OPTIONS ", 8))
		return 6;
	if (len >= 6 && !memcmp(data, "PATCH ", 6))
		return 7;
	if (len >= 8 && !memcmp(data, "CONNECT ", 8))
		return 8;
	if (len >= 6 && !memcmp(data, "TRACE ", 6))
		return 9;
	return 0;
}

static void decode_http(struct ufw_decoded *d, const __u8 *data, __u32 len)
{
	__u32 i, uri_start = 0, uri_len = 0, headers = 0, body_start = 0;
	__u32 printable = 0;

	decoded_set(d, UFW_FIELD_HTTP_METHOD, http_method_id(data, len));

	for (i = 0; i < len && i < 64; i++) {
		if (data[i] == ' ') {
			uri_start = i + 1;
			break;
		}
	}
	if (uri_start) {
		for (i = uri_start; i < len; i++) {
			if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n')
				break;
			uri_len++;
		}
	}
	decoded_set(d, UFW_FIELD_HTTP_URI_LEN, uri_len);

	/* Count header lines and find the blank line that ends them. */
	for (i = 0; i + 1 < len; i++) {
		if (data[i] == '\n') {
			headers++;
			if (data[i + 1] == '\r' || data[i + 1] == '\n') {
				body_start = i + 2;
				break;
			}
		}
	}
	/* The request line is not a header. */
	decoded_set(d, UFW_FIELD_HTTP_HEADER_COUNT, headers ? headers - 1 : 0);
	decoded_set(d, UFW_FIELD_HTTP_BODY_LEN,
		    body_start && body_start < len ? len - body_start : 0);

	for (i = body_start; i < len; i++) {
		if ((data[i] >= 0x20 && data[i] < 0x7F) || data[i] == '\n' ||
		    data[i] == '\r' || data[i] == '\t')
			printable++;
	}
	if (body_start < len) {
		decoded_set(d, UFW_FIELD_PAYLOAD_PRINTABLE,
			    (printable * 100u) / (len - body_start));
	}
}

/* --- TLS ---------------------------------------------------------------- */

static void decode_tls(struct ufw_decoded *d, const __u8 *data, __u32 len)
{
	__u32 pos, session_len, cipher_len, comp_len, ext_total, ext_end;
	__u32 extensions = 0;

	if (len < 6)
		return;

	/* Record layer: type(1) version(2) length(2), then the handshake. */
	decoded_set(d, UFW_FIELD_TLS_VERSION,
		    ((__u32)data[1] << 8) | data[2]);
	decoded_set(d, UFW_FIELD_TLS_HANDSHAKE, data[5]);

	if (data[0] != 0x16 || data[5] != 0x01)
		return; /* Not a ClientHello; the fields below do not exist. */

	/* handshake header(4) + client version(2) + random(32) */
	pos = 5 + 4 + 2 + 32;
	if (pos >= len)
		return;

	/* The ClientHello's own version is more informative than the record
	 * layer's, which is often pinned low for compatibility. */
	decoded_set(d, UFW_FIELD_TLS_VERSION,
		    ((__u32)data[9] << 8) | data[10]);

	session_len = data[pos];
	pos += 1 + session_len;
	if (pos + 2 > len)
		return;

	cipher_len = ((__u32)data[pos] << 8) | data[pos + 1];
	decoded_set(d, UFW_FIELD_TLS_CIPHER_COUNT, cipher_len / 2);
	pos += 2 + cipher_len;
	if (pos >= len)
		return;

	comp_len = data[pos];
	pos += 1 + comp_len;
	if (pos + 2 > len)
		return;

	ext_total = ((__u32)data[pos] << 8) | data[pos + 1];
	pos += 2;
	ext_end = pos + ext_total;
	if (ext_end > len)
		ext_end = len;

	decoded_set(d, UFW_FIELD_TLS_SNI_LEN, 0);

	while (pos + 4 <= ext_end) {
		__u32 ext_type = ((__u32)data[pos] << 8) | data[pos + 1];
		__u32 ext_len = ((__u32)data[pos + 2] << 8) | data[pos + 3];

		extensions++;
		pos += 4;
		if (pos + ext_len > ext_end)
			break;

		/* server_name (0): list length(2) type(1) name length(2). */
		if (ext_type == 0 && ext_len >= 5) {
			decoded_set(d, UFW_FIELD_TLS_SNI_LEN,
				    ((__u32)data[pos + 3] << 8) | data[pos + 4]);
		}
		pos += ext_len;
	}
	decoded_set(d, UFW_FIELD_TLS_EXT_COUNT, extensions);
}

/* --- SSH ---------------------------------------------------------------- */

static void decode_ssh(struct ufw_decoded *d, const __u8 *data, __u32 len)
{
	__u32 i, banner_len = 0;

	/* "SSH-2.0-..." — the major and minor are ASCII digits. */
	if (len < 8 || memcmp(data, "SSH-", 4) != 0)
		return;

	if (data[4] >= '0' && data[4] <= '9' && data[6] >= '0' && data[6] <= '9') {
		decoded_set(d, UFW_FIELD_SSH_PROTO_VERSION,
			    (__u32)(data[4] - '0') * 10u + (data[6] - '0'));
	}

	for (i = 0; i < len && i < 255; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
		banner_len++;
	}
	decoded_set(d, UFW_FIELD_SSH_BANNER_LEN, banner_len);
}

/* --- protocol identification --------------------------------------------- */

__u8 ufw_dpi_identify(const __u8 *data, size_t len, __u16 dst_port)
{
	if (len >= 3 && data[0] == 0x16 && data[1] == 0x03)
		return UFW_L7_TLS;
	if (len >= 4 && !memcmp(data, "SSH-", 4))
		return UFW_L7_SSH;
	if (http_method_id(data, (__u32)len))
		return UFW_L7_HTTP;
	if (len >= 4 && !memcmp(data, "HTTP", 4))
		return UFW_L7_HTTP;

	/*
	 * DNS has no distinctive prefix, so it falls back to the port. That
	 * is weaker than the others and deliberately last: a signature scoped
	 * to `protocols: [dns]` on a non-standard port will not fire, which
	 * is a documented limitation rather than a guess that could be wrong
	 * in the permissive direction.
	 */
	if (dst_port == 53 || dst_port == 5353)
		return UFW_L7_DNS;
	if (dst_port == 25 || dst_port == 465 || dst_port == 587)
		return UFW_L7_SMTP;

	return UFW_L7_UNKNOWN;
}

/* --- entropy ------------------------------------------------------------- */

/*
 * Shannon entropy in hundredths of a bit per byte.
 *
 * Integer arithmetic throughout: no FPU in kernel context, and the Windows
 * driver and the Swift extension must produce bit-identical results or the
 * same stream matches a signature on one platform and not another.
 *
 * The identity used is H = log2(n) - (1/n) * sum(c_i * log2(c_i)), which
 * avoids computing per-symbol probabilities. log2 is the integer
 * approximation below, and all three implementations use exactly this one.
 */
static __u32 ilog2_centi(__u32 v)
{
	__u32 whole, frac, remainder;

	if (v == 0)
		return 0;

	whole = fls(v) - 1;
	/* Linear interpolation within the octave. Accurate to a few
	 * hundredths, which is well inside the precision a threshold like
	 * "4.2 bits" expresses. */
	remainder = v - (1u << whole);
	frac = (remainder * 100u) / (1u << whole);
	return whole * 100u + frac;
}

static __u32 entropy_centibits(const __u8 *data, __u32 len)
{
	__u32 counts[256];
	__u64 weighted = 0;
	__u32 i;

	if (len == 0)
		return 0;

	memset(counts, 0, sizeof(counts));
	for (i = 0; i < len; i++)
		counts[data[i]]++;

	for (i = 0; i < 256; i++) {
		if (counts[i])
			weighted += (__u64)counts[i] * ilog2_centi(counts[i]);
	}

	{
		__u32 total = ilog2_centi(len);
		__u32 mean = (__u32)div_u64(weighted, len);

		return total > mean ? total - mean : 0;
	}
}

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
 * Bounded substring search.
 *
 * Naive rather than Boyer-Moore, and that is a considered choice: the window
 * is at most 32 KiB and patterns are at most 64 bytes, so the worst case is
 * two million byte comparisons — measurable but bounded, and reached only by
 * a pattern of repeated bytes that a signature author would have to write
 * deliberately. A skip-table algorithm would need the table built per scan or
 * cached per signature, and the cached form is state an attacker influences
 * the use of. The simple loop has no state at all.
 */
static bool content_match(const struct ufw_condition *c, const __u8 *data,
			  __u32 len)
{
	__u32 start, end, i, j;

	if (c->pattern_len == 0 || c->pattern_len > UFW_MAX_PATTERN)
		return false;

	start = c->offset;
	if (start >= len)
		return false;

	end = c->depth ? start + c->depth : len;
	if (end > len)
		end = len;
	if (end < start + c->pattern_len)
		return false;

	for (i = start; i + c->pattern_len <= end; i++) {
		for (j = 0; j < c->pattern_len; j++) {
			__u8 a = data[i + j];
			__u8 b = c->pattern[j];

			if (c->nocase) {
				if (a >= 'A' && a <= 'Z')
					a = (__u8)(a + 32);
				if (b >= 'A' && b <= 'Z')
					b = (__u8)(b + 32);
			}
			if (a != b)
				break;
		}
		if (j == c->pattern_len)
			return true;
	}
	return false;
}

static bool condition_holds(const struct ufw_condition *c,
			    const struct ufw_decoded *decoded,
			    const __u8 *data, __u32 len)
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
		return content_match(c, data, len);

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
			if (!condition_holds(&sig->conditions[c], &decoded,
					     data, (__u32)len)) {
				all = false;
				break;
			}
		}
		if (all)
			matched[hits++] = sig->id;
	}
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

int ufw_dpi_install(const __u8 *encoded, size_t len)
{
	struct cursor cur = { .data = encoded, .len = len, .pos = 0 };
	struct ufw_signature_set *set, *old;
	unsigned long flags;
	__u32 count, i;

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

	spin_lock_irqsave(&ufw_signature_lock, flags);
	old = rcu_dereference_protected(ufw_signatures,
					lockdep_is_held(&ufw_signature_lock));
	rcu_assign_pointer(ufw_signatures, set);
	spin_unlock_irqrestore(&ufw_signature_lock, flags);

	if (old) {
		synchronize_rcu();
		kvfree(old);
	}
	return 0;

malformed:
	kvfree(set);
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
		kvfree(old);
	}
}
