/*
 * Unified Firewall — signature evaluation, Windows.
 *
 * The same evaluator as kernel/linux/src/dpi_engine.c, in the same order,
 * with the same integer arithmetic. Where the two files differ they differ
 * because the platform forced it — pool allocation, no `fls`, no `div_u64` —
 * and nothing else.
 *
 * That duplication is deliberate and it is the cost of the design. A shared
 * library linked into two kernels and a sandboxed Swift extension is not
 * available; what is available is two files that can be read side by side. So
 * the structure is identical line for line where it can be, because a
 * divergence should look like a divergence.
 *
 * See the Linux file for the reasoning on why the signature language has no
 * alternation, no grouping and no regular expressions, and why entropy is
 * computed in hundredths of a bit with an integer log2. All of it applies
 * here unchanged; the equivalence claim depends on it applying unchanged.
 */

#include "../inc/driver.h"

#define UFW_COND_FIELD   1
#define UFW_COND_CONTENT 2
#define UFW_COND_ENTROPY 3

#define UFW_CMP_EQ 1
#define UFW_CMP_NE 2
#define UFW_CMP_LT 3
#define UFW_CMP_LE 4
#define UFW_CMP_GT 5
#define UFW_CMP_GE 6

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

typedef struct _UFW_CONDITION {
	UINT8  kind;
	UINT8  op;
	UINT16 field;
	UINT32 offset;
	UINT32 depth;
	UINT8  nocase;
	UINT8  patternLength;
	UINT8  pattern[UFW_MAX_PATTERN];
	UINT64 value;
} UFW_CONDITION;

typedef struct _UFW_SIGNATURE {
	UINT32 id;
	UINT8  l7;
	UINT8  severity;
	UINT8  conditionCount;
	UINT8  reserved;
	UFW_CONDITION conditions[UFW_MAX_CONDITIONS];
} UFW_SIGNATURE;

typedef struct _UFW_SIGNATURE_SET {
	UINT32 count;
	UFW_SIGNATURE signatures[1];
} UFW_SIGNATURE_SET;

static UFW_SIGNATURE_SET *g_signatures;
static EX_SPIN_LOCK g_signatureLock;

typedef struct _UFW_DECODED {
	UINT32 values[128];
	UINT8  present[128];
} UFW_DECODED;

static VOID UfwDecodedSet(_Inout_ UFW_DECODED *d, _In_ UINT16 field, _In_ UINT32 value)
{
	if (field < 128) {
		d->values[field] = value;
		d->present[field] = 1;
	}
}

/* --- decoders ------------------------------------------------------------- */

static VOID UfwDecodeDns(_Inout_ UFW_DECODED *d,
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

static UINT32 UfwHttpMethodId(_In_reads_bytes_(len) const UINT8 *data, _In_ UINT32 len)
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

static VOID UfwDecodeHttp(_Inout_ UFW_DECODED *d,
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

static VOID UfwDecodeTls(_Inout_ UFW_DECODED *d,
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

static VOID UfwDecodeSsh(_Inout_ UFW_DECODED *d,
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

UINT8 UfwDpiIdentify(_In_reads_bytes_(length) const UINT8 *data,
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
static UINT32 UfwILog2Centi(_In_ UINT32 v)
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

static UINT32 UfwEntropyCentibits(_In_reads_bytes_(len) const UINT8 *data,
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

/* --- conditions ------------------------------------------------------------- */

static BOOLEAN UfwCompare(_In_ UINT8 op, _In_ UINT64 left, _In_ UINT64 right)
{
	switch (op) {
	case UFW_CMP_EQ: return left == right;
	case UFW_CMP_NE: return left != right;
	case UFW_CMP_LT: return left < right;
	case UFW_CMP_LE: return left <= right;
	case UFW_CMP_GT: return left > right;
	case UFW_CMP_GE: return left >= right;
	default:         return FALSE;
	}
}

/*
 * Naive bounded search, matching the Linux implementation.
 *
 * The window is at most 32 KiB and patterns at most 64 bytes, so the worst
 * case is bounded and reached only by a pattern of repeated bytes a signature
 * author would have to write deliberately. A skip-table algorithm needs state
 * built per scan or cached per signature, and cached state is state an
 * attacker influences the use of. This loop has none.
 */
static BOOLEAN UfwContentMatch(_In_ const UFW_CONDITION *c,
			       _In_reads_bytes_(len) const UINT8 *data,
			       _In_ UINT32 len)
{
	UINT32 start, end, i, j;

	if (c->patternLength == 0 || c->patternLength > UFW_MAX_PATTERN)
		return FALSE;

	start = c->offset;
	if (start >= len)
		return FALSE;

	end = c->depth ? start + c->depth : len;
	if (end > len)
		end = len;
	if (end < start + c->patternLength)
		return FALSE;

	for (i = start; i + c->patternLength <= end; i++) {
		for (j = 0; j < c->patternLength; j++) {
			UINT8 a = data[i + j];
			UINT8 b = c->pattern[j];

			if (c->nocase) {
				if (a >= 'A' && a <= 'Z') a = (UINT8)(a + 32);
				if (b >= 'A' && b <= 'Z') b = (UINT8)(b + 32);
			}
			if (a != b)
				break;
		}
		if (j == c->patternLength)
			return TRUE;
	}
	return FALSE;
}

static BOOLEAN UfwConditionHolds(_In_ const UFW_CONDITION *c,
				 _In_ const UFW_DECODED *decoded,
				 _In_reads_bytes_(len) const UINT8 *data,
				 _In_ UINT32 len)
{
	switch (c->kind) {
	case UFW_COND_FIELD:
		if (c->field == UFW_FIELD_PAYLOAD_LEN)
			return UfwCompare(c->op, len, c->value);
		/* The decoder did not produce this field, either because the
		 * payload was malformed or because it belongs to another
		 * protocol. Absent is not zero: an absent field fails. */
		if (c->field >= 128 || !decoded->present[c->field])
			return FALSE;
		return UfwCompare(c->op, decoded->values[c->field], c->value);

	case UFW_COND_CONTENT:
		return UfwContentMatch(c, data, len);

	case UFW_COND_ENTROPY:
		return UfwEntropyCentibits(data, len) >= (UINT32)c->value;

	default:
		return FALSE;
	}
}

UINT8 UfwDpiScan(_In_ UINT8 l7,
		 _In_reads_bytes_(length) const UINT8 *data, _In_ SIZE_T length,
		 _Out_writes_(maxMatches) UINT32 *matched, _In_ UINT8 maxMatches,
		 _Inout_ UINT8 *truncated)
{
	UFW_SIGNATURE_SET *set;
	UFW_DECODED decoded;
	KIRQL irql;
	UINT32 i;
	UINT8 hits = 0;

	if (!data || !length || !matched || !maxMatches)
		return 0;

	RtlZeroMemory(&decoded, sizeof(decoded));
	UfwDecodedSet(&decoded, UFW_FIELD_PAYLOAD_LEN, (UINT32)length);

	switch (l7) {
	case UFW_L7_DNS:  UfwDecodeDns(&decoded, data, (UINT32)length); break;
	case UFW_L7_HTTP: UfwDecodeHttp(&decoded, data, (UINT32)length); break;
	case UFW_L7_TLS:  UfwDecodeTls(&decoded, data, (UINT32)length); break;
	case UFW_L7_SSH:  UfwDecodeSsh(&decoded, data, (UINT32)length); break;
	default: break;
	}

	irql = ExAcquireSpinLockShared(&g_signatureLock);
	set = g_signatures;
	if (!set) {
		ExReleaseSpinLockShared(&g_signatureLock, irql);
		return 0;
	}

	for (i = 0; i < set->count && hits < maxMatches; i++) {
		const UFW_SIGNATURE *sig = &set->signatures[i];
		BOOLEAN all = TRUE;
		UINT8 c;

		/* An UNKNOWN-scoped signature runs against everything, which
		 * is how a content match on a protocol the decoders do not
		 * know still works. */
		if (sig->l7 != UFW_L7_UNKNOWN && sig->l7 != l7)
			continue;

		for (c = 0; c < sig->conditionCount && c < UFW_MAX_CONDITIONS; c++) {
			if (!UfwConditionHolds(&sig->conditions[c], &decoded,
					       data, (UINT32)length)) {
				all = FALSE;
				break;
			}
		}
		if (all)
			matched[hits++] = sig->id;
	}
	ExReleaseSpinLockShared(&g_signatureLock, irql);

	UNREFERENCED_PARAMETER(truncated);
	return hits;
}

/* --- installation ------------------------------------------------------------- */

typedef struct _UFW_CURSOR {
	const UINT8 *data;
	SIZE_T length;
	SIZE_T position;
} UFW_CURSOR;

static BOOLEAN UfwTake(_Inout_ UFW_CURSOR *c, _Out_writes_bytes_(n) VOID *out,
		       _In_ SIZE_T n)
{
	if (c->position + n > c->length)
		return FALSE;
	RtlCopyMemory(out, c->data + c->position, n);
	c->position += n;
	return TRUE;
}

NTSTATUS UfwDpiInstall(_In_reads_bytes_(length) const UINT8 *encoded,
		       _In_ SIZE_T length)
{
	UFW_CURSOR cur = { encoded, length, 0 };
	UFW_SIGNATURE_SET *set, *old;
	KIRQL irql;
	UINT32 count, i;
	SIZE_T bytes;

	if (!UfwTake(&cur, &count, sizeof(count)))
		return STATUS_INVALID_PARAMETER;
	if (count > UFW_MAX_LOADED_SIGNATURES)
		return STATUS_INVALID_PARAMETER;

	bytes = FIELD_OFFSET(UFW_SIGNATURE_SET, signatures) +
		(SIZE_T)count * sizeof(UFW_SIGNATURE);
	set = (UFW_SIGNATURE_SET *)ExAllocatePool2(POOL_FLAG_NON_PAGED, bytes,
						   UFW_POOL_TAG);
	if (!set)
		return STATUS_INSUFFICIENT_RESOURCES;
	RtlZeroMemory(set, bytes);
	set->count = count;

	for (i = 0; i < count; i++) {
		UFW_SIGNATURE *sig = &set->signatures[i];
		UINT16 conditionCount, c;

		if (!UfwTake(&cur, &sig->id, 4) || !UfwTake(&cur, &sig->l7, 1) ||
		    !UfwTake(&cur, &sig->severity, 1) ||
		    !UfwTake(&cur, &conditionCount, 2))
			goto malformed;

		if (conditionCount > UFW_MAX_CONDITIONS)
			goto malformed;
		sig->conditionCount = (UINT8)conditionCount;

		for (c = 0; c < conditionCount; c++) {
			UFW_CONDITION *cond = &sig->conditions[c];
			UINT32 patternLength;

			if (!UfwTake(&cur, &cond->kind, 1))
				goto malformed;

			switch (cond->kind) {
			case UFW_COND_FIELD:
				if (!UfwTake(&cur, &cond->field, 2) ||
				    !UfwTake(&cur, &cond->op, 1) ||
				    !UfwTake(&cur, &cond->value, 8))
					goto malformed;
				break;
			case UFW_COND_CONTENT:
				if (!UfwTake(&cur, &cond->offset, 4) ||
				    !UfwTake(&cur, &cond->depth, 4) ||
				    !UfwTake(&cur, &cond->nocase, 1) ||
				    !UfwTake(&cur, &patternLength, 4))
					goto malformed;
				if (patternLength > UFW_MAX_PATTERN)
					goto malformed;
				cond->patternLength = (UINT8)patternLength;
				if (!UfwTake(&cur, cond->pattern, patternLength))
					goto malformed;
				break;
			case UFW_COND_ENTROPY:
				if (!UfwTake(&cur, &cond->field, 2) ||
				    !UfwTake(&cur, &cond->offset, 4))
					goto malformed;
				/* The encoding reuses the offset slot for
				 * min_centibits on this kind. */
				cond->value = cond->offset;
				cond->offset = 0;
				break;
			default:
				goto malformed;
			}
		}
	}

	irql = ExAcquireSpinLockExclusive(&g_signatureLock);
	old = g_signatures;
	g_signatures = set;
	ExReleaseSpinLockExclusive(&g_signatureLock, irql);

	/* The exclusive acquire drained every reader of the old set. */
	if (old)
		ExFreePoolWithTag(old, UFW_POOL_TAG);
	return STATUS_SUCCESS;

malformed:
	ExFreePoolWithTag(set, UFW_POOL_TAG);
	return STATUS_INVALID_PARAMETER;
}

NTSTATUS UfwDpiInitialize(VOID)
{
	g_signatures = NULL;
	return STATUS_SUCCESS;
}

VOID UfwDpiShutdown(VOID)
{
	UFW_SIGNATURE_SET *old;
	KIRQL irql;

	irql = ExAcquireSpinLockExclusive(&g_signatureLock);
	old = g_signatures;
	g_signatures = NULL;
	ExReleaseSpinLockExclusive(&g_signatureLock, irql);

	if (old)
		ExFreePoolWithTag(old, UFW_POOL_TAG);
}
