/*
 * Unified Firewall — protocol decoders.
 *
 * The named values a signature can test: `dns.max_label_length`,
 * `tls.sni_length`, `http.header_count`. A signature never names an offset
 * into a payload, and this file is why — an offset is only meaningful if the
 * signature author's model of the framing matches the decoder's, and every
 * place those two models can disagree is a place an attacker can put bytes
 * that the firewall reads as one field and the endpoint reads as another.
 *
 * # Why this is a header
 *
 * These functions parse bytes an adversary chose, in softirq context, in ring
 * 0. That is the highest-risk code in the project, and until this extraction
 * nothing could reach it without a kernel: it lived inside `dpi_engine.c`
 * behind `#include <linux/kernel.h>`.
 *
 * Nothing in here needs the kernel — no allocation, no locking, no kernel
 * call. Keeping it that way is what lets `daemon/tests/dpi_decoder_tests.rs`
 * compile it with a hosted compiler under AddressSanitizer and
 * UndefinedBehaviorSanitizer and throw mutated input at it, and lets the same
 * test compare it against the Windows decoders byte for byte. A parser that is
 * only ever exercised on a live kernel is a parser nobody has fuzzed.
 *
 * # The rules every decoder here follows
 *
 *   1. Bounds are checked before every read, not after.
 *   2. A malformed payload leaves fields *absent*, never zero. An absent field
 *      fails its condition, which fails the signature — the fail-closed
 *      direction. Zero would be a value, and a signature testing `< 10` would
 *      match on garbage.
 *   3. Every loop has a bound that does not depend on the payload's own
 *      length fields, so a crafted length cannot buy unbounded time.
 */

#ifndef UFW_DPI_DECODERS_H
#define UFW_DPI_DECODERS_H

#ifdef __KERNEL__
#include <linux/kernel.h>
#include <linux/string.h>
#include <linux/math64.h>
#else
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t  __u8;
typedef uint16_t __u16;
typedef uint32_t __u32;
typedef uint64_t __u64;

/* `fls` is "find last set", one-based. The kernel has it as an intrinsic; the
 * hosted build needs one, and it must round the same way or the entropy
 * threshold differs between what CI fuzzes and what ships. */
static inline int ufw_hosted_fls(__u32 v)
{
	int n = 0;

	while (v) {
		n++;
		v >>= 1;
	}
	return n;
}
#define fls(v) ufw_hosted_fls(v)
#define div_u64(n, d) ((__u64)(n) / (__u64)(d))
#endif

/* Field ids, matching the `Field` enum in `daemon/src/signatures.rs`. The
 * discriminants are ABI: they are what the kernel-side evaluator switches on,
 * so values are never reused. */
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
/* Encrypted-traffic classification. A DPI engine that can say nothing about a
 * TLS flow can say nothing about most flows, and the payload is not available
 * without the interception this project does not do. What *is* available is
 * how the client asked: which ciphers, which extensions, which ALPN, in which
 * order. That is a fingerprint of the implementation, and implementations are
 * what separate a browser from a beacon on the same port to the same host. */
#define UFW_FIELD_TLS_CIPHER_HASH   45
#define UFW_FIELD_TLS_EXT_HASH      46
#define UFW_FIELD_TLS_ALPN_HASH     47
#define UFW_FIELD_TLS_JA4           48
#define UFW_FIELD_TLS_GREASE_COUNT  49
#define UFW_FIELD_TLS_SUPPORTED_VER 50
#define UFW_FIELD_TLS_ECH           51
#define UFW_FIELD_SSH_PROTO_VERSION 60
#define UFW_FIELD_SSH_BANNER_LEN    61
#define UFW_FIELD_PAYLOAD_LEN       100
#define UFW_FIELD_PAYLOAD_PRINTABLE 101

/* Application protocols the decoders recognise, matching `L7Protocol` in
 * `shared/src/policy_types.rs`. Duplicated from `policy_structs.h` under a
 * guard rather than included from it, so this header stays self-contained and
 * a fuzz harness needs nothing but a C compiler. */
#ifndef UFW_L7_UNKNOWN
#define UFW_L7_UNKNOWN 0
#define UFW_L7_HTTP    1
#define UFW_L7_TLS     2
#define UFW_L7_DNS     3
#define UFW_L7_SSH     4
#define UFW_L7_SMTP    5
#define UFW_L7_QUIC    6
#endif

/* memset under a name the Windows header also has, so the shared test harness
 * needs no per-platform spelling for it. */
static inline void ufw_zero(void *p, size_t n)
{
	memset(p, 0, n);
}


/* --- TLS fingerprinting -------------------------------------------------- */

/*
 * FNV-1a, 32-bit.
 *
 * # Why not MD5, which is what JA3 specifies
 *
 * JA3 hashes its component string with MD5, JA4 with truncated SHA-256.
 * Neither belongs on the packet path: this runs in softirq context on every
 * ClientHello, and a cryptographic digest there is cost bought for no
 * security. The fingerprint is an identifier, not a commitment — nobody
 * relies on it being hard to collide, because an adversary who wants a
 * different fingerprint just sends a different ClientHello.
 *
 * So the *structure* is JA4's and the hash is FNV-1a. The consequence is
 * stated rather than hidden: these are not byte-comparable with published
 * JA3/JA4 tables. The components travel in the log event so a SIEM can compute
 * the canonical form downstream, and `daemon/src/fingerprint.rs` does it for
 * the events this host emits.
 */
static inline __u32 ufw_fnv1a(__u32 h, __u8 b)
{
	h ^= b;
	return h * 16777619u;
}

#define UFW_FNV_OFFSET 2166136261u

/*
 * GREASE (RFC 8701) is random padding a client inserts to keep middleboxes
 * honest. Including it would give one client a different fingerprint on every
 * connection — which is what GREASE is for, and what a fingerprint must not
 * have. Skipped, and counted: the *absence* of GREASE is itself a signal,
 * because a client that sends none is usually not a browser.
 */
static inline int ufw_tls_is_grease(__u32 v)
{
	return (v & 0x0F0F) == 0x0A0A && ((v >> 8) & 0xFF) == (v & 0xFF);
}

/* --- decoded protocol facts --------------------------------------------- */

struct ufw_decoded {
	__u32 values[128];
	__u8  present[128];
};

static inline void decoded_set(struct ufw_decoded *d, __u16 field, __u32 value)
{
	if (field < 128) {
		d->values[field] = value;
		d->present[field] = 1;
	}
}
/* --- DNS ---------------------------------------------------------------- */

static inline void decode_dns(struct ufw_decoded *d, const __u8 *data, __u32 len)
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

static inline __u32 http_method_id(const __u8 *data, __u32 len)
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

static inline void decode_http(struct ufw_decoded *d, const __u8 *data, __u32 len)
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

static inline void decode_tls(struct ufw_decoded *d, const __u8 *data, __u32 len)
{
	__u32 pos, session_len, cipher_len, comp_len, ext_total, ext_end;
	__u32 extensions = 0, grease = 0, cipher_count = 0;
	__u32 cipher_hash = UFW_FNV_OFFSET;
	__u32 ext_hash = UFW_FNV_OFFSET;
	__u32 alpn_hash = UFW_FNV_OFFSET;

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
	{
		__u32 c = pos + 2, cend = pos + 2 + cipher_len;

		if (cend > len)
			cend = len;
		while (c + 1 < cend) {
			__u32 suite = ((__u32)data[c] << 8) | data[c + 1];

			if (!ufw_tls_is_grease(suite)) {
				cipher_count++;
				cipher_hash = ufw_fnv1a(cipher_hash, data[c]);
				cipher_hash = ufw_fnv1a(cipher_hash, data[c + 1]);
			}
			c += 2;
		}
	}
	decoded_set(d, UFW_FIELD_TLS_CIPHER_COUNT, cipher_count);
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
	decoded_set(d, UFW_FIELD_TLS_ECH, 0);

	while (pos + 4 <= ext_end) {
		__u32 ext_type = ((__u32)data[pos] << 8) | data[pos + 1];
		__u32 ext_len = ((__u32)data[pos + 2] << 8) | data[pos + 3];

		if (ufw_tls_is_grease(ext_type)) {
			grease++;
		} else {
			extensions++;
			/* Extension *types* in order, GREASE removed. This is
			 * the half of a JA4 fingerprint that identifies the
			 * library; the cipher list identifies its version. */
			ext_hash = ufw_fnv1a(ext_hash, (__u8)(ext_type >> 8));
			ext_hash = ufw_fnv1a(ext_hash, (__u8)ext_type);
		}
		pos += 4;
		if (pos + ext_len > ext_end)
			break;

		/* server_name (0): list length(2) type(1) name length(2). */
		if (ext_type == 0 && ext_len >= 5) {
			decoded_set(d, UFW_FIELD_TLS_SNI_LEN,
				    ((__u32)data[pos + 3] << 8) | data[pos + 4]);
		}

		/* application_layer_protocol_negotiation (16): list length(2)
		 * then length-prefixed protocol names. `h2` and `http/1.1`
		 * are the pair a browser sends; a lone `http/1.1` from a
		 * modern client is worth noticing. */
		if (ext_type == 16 && ext_len >= 3) {
			__u32 a = pos + 2, alpn_end = pos + ext_len;

			if (alpn_end > ext_end)
				alpn_end = ext_end;
			while (a < alpn_end) {
				__u32 n = data[a], k;

				a++;
				if (a + n > alpn_end)
					break;
				for (k = 0; k < n; k++)
					alpn_hash = ufw_fnv1a(alpn_hash, data[a + k]);
				a += n;
			}
		}

		/* supported_versions (43): the real negotiated version lives
		 * here for TLS 1.3, which pins the legacy field at 1.2. A
		 * signature testing `tls.version` alone would misread every
		 * 1.3 flow as 1.2. */
		if (ext_type == 43 && ext_len >= 3) {
			__u32 v = pos + 1, vend = pos + ext_len, best = 0;

			if (vend > ext_end)
				vend = ext_end;
			while (v + 1 < vend) {
				__u32 ver = ((__u32)data[v] << 8) | data[v + 1];

				if (!ufw_tls_is_grease(ver) && ver > best)
					best = ver;
				v += 2;
			}
			if (best)
				decoded_set(d, UFW_FIELD_TLS_SUPPORTED_VER, best);
		}

		/* encrypted_client_hello (0xFE0D). The SNI is inside it and
		 * this engine cannot read it. Recording that the flow *used*
		 * ECH is the honest alternative to reporting an empty SNI,
		 * which would read as "no server name" rather than "the server
		 * name was hidden from us". */
		if (ext_type == 0xFE0D)
			decoded_set(d, UFW_FIELD_TLS_ECH, 1);

		pos += ext_len;
	}
	decoded_set(d, UFW_FIELD_TLS_EXT_COUNT, extensions);
	decoded_set(d, UFW_FIELD_TLS_GREASE_COUNT, grease);
	decoded_set(d, UFW_FIELD_TLS_CIPHER_HASH, cipher_hash);
	decoded_set(d, UFW_FIELD_TLS_EXT_HASH, ext_hash);
	decoded_set(d, UFW_FIELD_TLS_ALPN_HASH, alpn_hash);

	/* JA4's `a` segment, packed rather than spelled: transport (TCP here),
	 * version, whether SNI was present, cipher count, extension count,
	 * first ALPN byte. One integer a signature can compare, carrying what
	 * the human-readable prefix carries. */
	{
		__u32 version = d->present[UFW_FIELD_TLS_SUPPORTED_VER]
			? d->values[UFW_FIELD_TLS_SUPPORTED_VER]
			: d->values[UFW_FIELD_TLS_VERSION];
		__u32 ja4 = 0;

		ja4 |= (version & 0xFF) << 24;
		ja4 |= (d->values[UFW_FIELD_TLS_SNI_LEN] ? 1u : 0u) << 23;
		ja4 |= (d->values[UFW_FIELD_TLS_ECH] ? 1u : 0u) << 22;
		ja4 |= (cipher_count > 99 ? 99 : cipher_count) << 15;
		ja4 |= (extensions > 99 ? 99 : extensions) << 8;
		ja4 |= (alpn_hash & 0xFF);
		decoded_set(d, UFW_FIELD_TLS_JA4, ja4);
	}
}

/* --- SSH ---------------------------------------------------------------- */

static inline void decode_ssh(struct ufw_decoded *d, const __u8 *data, __u32 len)
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

static inline __u8 ufw_dpi_identify(const __u8 *data, size_t len, __u16 dst_port)
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
static inline __u32 ilog2_centi(__u32 v)
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

static inline __u32 entropy_centibits(const __u8 *data, __u32 len)
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

#endif /* UFW_DPI_DECODERS_H */
