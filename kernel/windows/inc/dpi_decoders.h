/*
 * Unified Firewall — protocol decoders, Windows.
 *
 * The same decoders as kernel/linux/inc/dpi_decoders.h, in the same order,
 * with the same arithmetic. Where the two differ they differ in type names
 * and SAL annotations and nothing else, because the equivalence claim depends
 * on that being true — and `daemon/tests/dpi_decoder_tests.rs` compiles both
 * and compares the fields they extract, over the same mutated corpus.
 *
 * These functions parse bytes an adversary chose, at DISPATCH_LEVEL, in ring
 * 0. That is the highest-risk code in the driver. Keeping it free of every
 * WDK call is what lets a hosted compiler build it under AddressSanitizer and
 * UndefinedBehaviorSanitizer, and a parser that is only ever exercised on a
 * live kernel is a parser nobody has fuzzed.
 *
 * The rules every decoder follows are in the Linux header and apply here
 * unchanged: bounds checked before the read, a malformed payload leaves
 * fields absent rather than zero, and no loop bound comes from the payload's
 * own length fields.
 */

#pragma once

#if defined(UFW_ABI_CHECK)
/* Checking these on a machine with no Windows SDK. See ipc_ioctl.h for why
 * that mode exists. */
#include <stddef.h>
#include <stdint.h>
#include <string.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
#ifndef VOID
#define VOID void
#endif
#ifndef _In_
#define _In_
#define _Inout_
#define _In_reads_bytes_(n)
#endif
#ifndef RtlZeroMemory
#define RtlZeroMemory(d, l) memset((d), 0, (l))
/* Returns the count of leading equal bytes, not a sign like memcmp. The
 * decoders below compare that count against the length, so a memcmp-shaped
 * shim would invert every protocol test. */
static __inline size_t RtlCompareMemory(const void *a, const void *b, size_t n)
{
        const unsigned char *x = (const unsigned char *)a;
        const unsigned char *y = (const unsigned char *)b;
        size_t i = 0;

        while (i < n && x[i] == y[i])
                i++;
        return i;
}
#endif
typedef size_t SIZE_T;
typedef uint32_t ULONG;
/* One-based index of the highest set bit, written into *index, returning
 * whether there was one. The intrinsic's contract, reproduced so the entropy
 * arithmetic here rounds exactly as it does in the driver. */
static __inline unsigned char BitScanReverse(ULONG *index, ULONG v)
{
        ULONG n = 0;

        if (!v)
                return 0;
        while (v >>= 1)
                n++;
        *index = n;
        return 1;
}
#elif defined(UFW_KERNEL_MODE)
#include <ntddk.h>
#else
#include <windows.h>
#endif

/* Field ids, matching the `Field` enum in `daemon/src/signatures.rs`. */
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

#ifndef UFW_L7_UNKNOWN
#define UFW_L7_UNKNOWN 0
#define UFW_L7_HTTP    1
#define UFW_L7_TLS     2
#define UFW_L7_DNS     3
#define UFW_L7_SSH     4
#define UFW_L7_SMTP    5
#define UFW_L7_QUIC    6
#endif

typedef struct _UFW_DECODED {
	UINT32 values[128];
	UINT8  present[128];
} UFW_DECODED;

static __inline VOID UfwDecodedSet(_Inout_ UFW_DECODED *d, _In_ UINT16 field, _In_ UINT32 value)
{
	if (field < 128) {
		d->values[field] = value;
		d->present[field] = 1;
	}
}

/* --- decoders ------------------------------------------------------------- */

static __inline VOID UfwDecodeDns(_Inout_ UFW_DECODED *d,
			 _In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
{
	UINT32 pos = 12, nameLen = 0, maxLabel = 0, labels = 0;

	if (len < 12)
		return;

	UfwDecodedSet(d, UFW_FIELD_DNS_ANSWER_COUNT,
		      ((UINT32)data[6] << 8) | data[7]);

	/* Compression pointers are not followed: a pointer in a question is
	 * malformed, and following them at DISPATCH_LEVEL needs a visited set
	 * to survive a crafted loop. Bailing out leaves the fields absent, and
	 * an absent field fails its condition — the safe direction. */
	while (pos < len) {
		UINT8 labelLen = data[pos];

		if (labelLen == 0)
			break;
		if ((labelLen & 0xC0) == 0xC0)
			return;
		if (labelLen > 63 || pos + 1 + labelLen > len)
			return;

		if (labelLen > maxLabel)
			maxLabel = labelLen;
		nameLen += labelLen + 1u;
		labels++;
		pos += 1u + labelLen;

		if (nameLen > 255 || labels > 128)
			return;
	}

	UfwDecodedSet(d, UFW_FIELD_DNS_MAX_LABEL_LEN, maxLabel);
	UfwDecodedSet(d, UFW_FIELD_DNS_NAME_LEN, nameLen);
	UfwDecodedSet(d, UFW_FIELD_DNS_LABEL_COUNT, labels);

	if (pos + 3 <= len)
		UfwDecodedSet(d, UFW_FIELD_DNS_QUERY_TYPE,
			      ((UINT32)data[pos + 1] << 8) | data[pos + 2]);
}

static __inline UINT32 UfwHttpMethodId(_In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
{
	if (len >= 4 && RtlCompareMemory(data, "GET ", 4) == 4) return 1;
	if (len >= 5 && RtlCompareMemory(data, "POST ", 5) == 5) return 2;
	if (len >= 4 && RtlCompareMemory(data, "PUT ", 4) == 4) return 3;
	if (len >= 7 && RtlCompareMemory(data, "DELETE ", 7) == 7) return 4;
	if (len >= 5 && RtlCompareMemory(data, "HEAD ", 5) == 5) return 5;
	if (len >= 8 && RtlCompareMemory(data, "OPTIONS ", 8) == 8) return 6;
	if (len >= 6 && RtlCompareMemory(data, "PATCH ", 6) == 6) return 7;
	if (len >= 8 && RtlCompareMemory(data, "CONNECT ", 8) == 8) return 8;
	if (len >= 6 && RtlCompareMemory(data, "TRACE ", 6) == 6) return 9;
	return 0;
}

static __inline VOID UfwDecodeHttp(_Inout_ UFW_DECODED *d,
			  _In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
{
	UINT32 i, uriStart = 0, uriLen = 0, headers = 0, bodyStart = 0, printable = 0;

	UfwDecodedSet(d, UFW_FIELD_HTTP_METHOD, UfwHttpMethodId(data, len));

	for (i = 0; i < len && i < 64; i++) {
		if (data[i] == ' ') {
			uriStart = i + 1;
			break;
		}
	}
	if (uriStart) {
		for (i = uriStart; i < len; i++) {
			if (data[i] == ' ' || data[i] == '\r' || data[i] == '\n')
				break;
			uriLen++;
		}
	}
	UfwDecodedSet(d, UFW_FIELD_HTTP_URI_LEN, uriLen);

	for (i = 0; i + 1 < len; i++) {
		if (data[i] == '\n') {
			headers++;
			if (data[i + 1] == '\r' || data[i + 1] == '\n') {
				bodyStart = i + 2;
				break;
			}
		}
	}
	/* The request line is not a header. */
	UfwDecodedSet(d, UFW_FIELD_HTTP_HEADER_COUNT, headers ? headers - 1 : 0);
	UfwDecodedSet(d, UFW_FIELD_HTTP_BODY_LEN,
		      (bodyStart && bodyStart < len) ? len - bodyStart : 0);

	for (i = bodyStart; i < len; i++) {
		if ((data[i] >= 0x20 && data[i] < 0x7F) || data[i] == '\n' ||
		    data[i] == '\r' || data[i] == '\t')
			printable++;
	}
	if (bodyStart < len)
		UfwDecodedSet(d, UFW_FIELD_PAYLOAD_PRINTABLE,
			      (printable * 100u) / (len - bodyStart));
}

static __inline VOID UfwDecodeTls(_Inout_ UFW_DECODED *d,
			 _In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
{
	UINT32 pos, sessionLen, cipherLen, compLen, extTotal, extEnd, extensions = 0;

	if (len < 6)
		return;

	UfwDecodedSet(d, UFW_FIELD_TLS_VERSION, ((UINT32)data[1] << 8) | data[2]);
	UfwDecodedSet(d, UFW_FIELD_TLS_HANDSHAKE, data[5]);

	if (data[0] != 0x16 || data[5] != 0x01)
		return;

	pos = 5 + 4 + 2 + 32;
	if (pos >= len)
		return;

	/* The ClientHello's own version is more informative than the record
	 * layer's, which is often pinned low for compatibility. */
	UfwDecodedSet(d, UFW_FIELD_TLS_VERSION, ((UINT32)data[9] << 8) | data[10]);

	sessionLen = data[pos];
	pos += 1 + sessionLen;
	if (pos + 2 > len)
		return;

	cipherLen = ((UINT32)data[pos] << 8) | data[pos + 1];
	UfwDecodedSet(d, UFW_FIELD_TLS_CIPHER_COUNT, cipherLen / 2);
	pos += 2 + cipherLen;
	if (pos >= len)
		return;

	compLen = data[pos];
	pos += 1 + compLen;
	if (pos + 2 > len)
		return;

	extTotal = ((UINT32)data[pos] << 8) | data[pos + 1];
	pos += 2;
	extEnd = pos + extTotal;
	if (extEnd > len)
		extEnd = len;

	UfwDecodedSet(d, UFW_FIELD_TLS_SNI_LEN, 0);

	while (pos + 4 <= extEnd) {
		UINT32 extType = ((UINT32)data[pos] << 8) | data[pos + 1];
		UINT32 extLen = ((UINT32)data[pos + 2] << 8) | data[pos + 3];

		extensions++;
		pos += 4;
		if (pos + extLen > extEnd)
			break;
		if (extType == 0 && extLen >= 5)
			UfwDecodedSet(d, UFW_FIELD_TLS_SNI_LEN,
				      ((UINT32)data[pos + 3] << 8) | data[pos + 4]);
		pos += extLen;
	}
	UfwDecodedSet(d, UFW_FIELD_TLS_EXT_COUNT, extensions);
}

static __inline VOID UfwDecodeSsh(_Inout_ UFW_DECODED *d,
			 _In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
{
	UINT32 i, bannerLen = 0;

	if (len < 8 || RtlCompareMemory(data, "SSH-", 4) != 4)
		return;

	if (data[4] >= '0' && data[4] <= '9' && data[6] >= '0' && data[6] <= '9')
		UfwDecodedSet(d, UFW_FIELD_SSH_PROTO_VERSION,
			      (UINT32)(data[4] - '0') * 10u + (data[6] - '0'));

	for (i = 0; i < len && i < 255; i++) {
		if (data[i] == '\r' || data[i] == '\n')
			break;
		bannerLen++;
	}
	UfwDecodedSet(d, UFW_FIELD_SSH_BANNER_LEN, bannerLen);
}

static __inline UINT8 UfwDpiIdentify(_In_reads_bytes_(length) const UINT8 *data,
		     _In_ SIZE_T length, _In_ UINT16 dstPort)
{
	if (length >= 3 && data[0] == 0x16 && data[1] == 0x03)
		return UFW_L7_TLS;
	if (length >= 4 && RtlCompareMemory(data, "SSH-", 4) == 4)
		return UFW_L7_SSH;
	if (UfwHttpMethodId(data, (UINT32)length))
		return UFW_L7_HTTP;
	if (length >= 4 && RtlCompareMemory(data, "HTTP", 4) == 4)
		return UFW_L7_HTTP;

	/* DNS has no distinctive prefix, so it falls back to the port. Weaker
	 * than the others and deliberately last: a signature scoped to
	 * `protocols: [dns]` on a non-standard port will not fire, which is a
	 * documented limitation rather than a guess that could be wrong in the
	 * permissive direction. */
	if (dstPort == 53 || dstPort == 5353)
		return UFW_L7_DNS;
	if (dstPort == 25 || dstPort == 465 || dstPort == 587)
		return UFW_L7_SMTP;

	return UFW_L7_UNKNOWN;
}

/* --- entropy --------------------------------------------------------------- */

/*
 * Integer log2, in hundredths of a bit. Bit-for-bit identical to the Linux
 * module's and the Swift extension's: an entropy threshold that rounds
 * differently per platform is an equivalence failure that depends on payload
 * content, which no policy test could ever surface.
 */
static __inline UINT32 UfwILog2Centi(_In_ UINT32 v)
{
	UINT32 whole, frac, remainder;
	ULONG index;

	if (v == 0)
		return 0;

	BitScanReverse(&index, v);
	whole = (UINT32)index;
	remainder = v - (1u << whole);
	frac = (remainder * 100u) / (1u << whole);
	return whole * 100u + frac;
}

static __inline UINT32 UfwEntropyCentibits(_In_reads_bytes_(len) const UINT8 *data,
				  _In_ UINT32 len)
{
	UINT32 counts[256];
	UINT64 weighted = 0;
	UINT32 i, total, mean;

	if (len == 0)
		return 0;

	RtlZeroMemory(counts, sizeof(counts));
	for (i = 0; i < len; i++)
		counts[data[i]]++;

	for (i = 0; i < 256; i++) {
		if (counts[i])
			weighted += (UINT64)counts[i] * UfwILog2Centi(counts[i]);
	}

	total = UfwILog2Centi(len);
	mean = (UINT32)(weighted / len);
	return total > mean ? total - mean : 0;
}
