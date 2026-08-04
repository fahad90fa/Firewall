/*
 * Unified Firewall — Windows driver ABI.
 *
 * This header is the Windows half of the contract that
 * `shared/src/policy_types.rs` defines in Rust. The compiler's Windows backend
 * emits `ufw_policy_generated.h` against these declarations, and the daemon
 * ships the same structures over IOCTL, so a disagreement here is a
 * disagreement about what a policy means.
 *
 * It is included by the driver (kernel mode) and by the daemon's Windows IPC
 * layer (user mode), which is why nothing here depends on wdm.h beyond the
 * type names, and why `UFW_KERNEL_MODE` gates the parts that do.
 *
 * Discriminants are ABI. Values are never reused; new ones are appended.
 */

#pragma once

#if defined(UFW_ABI_CHECK)
/*
 * A third mode, for checking this header against the compiler's generated
 * output on a machine with no Windows SDK.
 *
 * The generated `ufw_policy_generated.h` is a designated-initialiser list over
 * the structures below, and nothing else verifies that the Rust emitter and
 * these declarations agree: the Rust side compiles fine with a field C does
 * not have, and the C side only fails on a machine with the WDK — which CI for
 * a Rust workspace has not got. Defining the handful of scalar types the
 * declarations actually use lets that check run anywhere.
 *
 * This mode declares no functions and is never compiled into the driver.
 */
#include <stdint.h>
typedef uint8_t  UINT8;
typedef uint16_t UINT16;
typedef uint32_t UINT32;
typedef uint64_t UINT64;
typedef int32_t  LONG;
/* The driver's strings are UTF-16; <wchar.h> supplies the type without
 * pulling in anything platform-specific. */
#include <wchar.h>
#ifndef FWP_ACTION_BLOCK
#define FWP_ACTION_BLOCK    0x00000001
#define FWP_ACTION_PERMIT   0x00000002
/* WFP's own "I have no opinion, keep looking". The compiler emits it for
 * `alert` and `continue`, which are annotations rather than verdicts. */
#define FWP_ACTION_CONTINUE 0x00000008
#endif
#ifndef IPPROTO_TCP
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#endif
#elif defined(UFW_KERNEL_MODE)
#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>
#else
#include <windows.h>
#include <fwpmu.h>
#endif

#define UFW_ABI_REVISION 1

/* --- device and IOCTL codes --------------------------------------------- */

/*
 * The device path the daemon opens. Must match
 * ufw_shared::constants::WINDOWS_DEVICE_LINK.
 */
#define UFW_DEVICE_NAME    L"\\Device\\UnifiedFirewall"
#define UFW_SYMBOLIC_LINK  L"\\DosDevices\\UnifiedFirewall"

/*
 * FILE_DEVICE_UNKNOWN with FILE_WRITE_ACCESS on the mutating codes.
 *
 * The access flag in a control code is enforced by the I/O manager against
 * the handle the caller opened, which makes "you may read stats but not
 * install a policy" a check the kernel performs rather than one the driver
 * has to remember to perform. The driver still checks the caller's token in
 * DriverEntry's device ACL — belt and braces, because the two mechanisms fail
 * differently.
 */
#define UFW_IOCTL_BASE 0x800

#ifndef UFW_ABI_CHECK

#define UFW_IOCTL_HELLO \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 0, METHOD_BUFFERED, FILE_READ_ACCESS)
#define UFW_IOCTL_INSTALL_POLICY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 1, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define UFW_IOCTL_INSTALL_SIGNATURES \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 2, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define UFW_IOCTL_SET_MODE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 3, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#define UFW_IOCTL_GET_STATS \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 4, METHOD_BUFFERED, FILE_READ_ACCESS)
#define UFW_IOCTL_FLUSH_POLICY \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 5, METHOD_BUFFERED, FILE_WRITE_ACCESS)
/*
 * The pended-read channel. The daemon keeps one of these outstanding at all
 * times; the driver completes it when it has an identity query or a batch of
 * log events to deliver. An inverted call rather than an event plus a second
 * read, because the pair has a race — the driver can signal between the
 * daemon's check and its wait — and inverted calls do not.
 */
#define UFW_IOCTL_AWAIT_EVENT \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 6, METHOD_OUT_DIRECT, FILE_READ_ACCESS)
#define UFW_IOCTL_IDENTITY_RESPONSE \
	CTL_CODE(FILE_DEVICE_UNKNOWN, UFW_IOCTL_BASE + 7, METHOD_BUFFERED, FILE_WRITE_ACCESS)
#endif /* !UFW_ABI_CHECK */

/* --- limits -------------------------------------------------------------- */

#define UFW_MAX_RULES               65536
#define UFW_MAX_RULE_NAME           64
#define UFW_MAX_CIDRS_PER_RULE      16
#define UFW_MAX_PORT_RANGES         8
#define UFW_MAX_FINGERPRINTS        4
#define UFW_MAX_PATHS_PER_FP        4
#define UFW_MAX_PATH_LEN            256
#define UFW_MAX_SIGNERS_PER_FP      2
#define UFW_MAX_SIGNER_LEN          128
#define UFW_MAX_HASHES_PER_FP       2
#define UFW_MAX_SIGNATURES_PER_RULE 16
#define UFW_MAX_L7_PER_RULE         4

/* --- enumerations -------------------------------------------------------- */

/* Matching ufw_shared::policy_types::Action. FWP_ACTION_* values are used
 * where WFP needs them; these are the policy-level actions the driver
 * evaluates before deciding what to tell WFP. */
typedef enum _UFW_ACTION {
	UFW_ACTION_ALLOW         = 0,
	UFW_ACTION_DENY          = 1,
	UFW_ACTION_ALERT         = 2,
	UFW_ACTION_CONTINUE      = 3,
	UFW_ACTION_ALLOW_INSPECT = 4,
} UFW_ACTION;

typedef enum _UFW_STAGE {
	UFW_STAGE_PERIMETER = 0,
	UFW_STAGE_PACKET    = 1,
	UFW_STAGE_IDENTITY  = 2,
	UFW_STAGE_APP_DPI   = 3,
	UFW_STAGE_STREAM    = 4,
	UFW_STAGE_COUNT     = 5,
} UFW_STAGE;

typedef enum _UFW_DIRECTION {
	UFW_DIR_ANY      = 0,
	UFW_DIR_INBOUND  = 1,
	UFW_DIR_OUTBOUND = 2,
} UFW_DIRECTION;

#define UFW_PROTO_ANY 255

/*
 * Which WFP layer family a filter is installed at.
 *
 * This is the crux of the Windows implementation, and the reason it does not
 * simply mirror the Linux one. WFP layers fire in a different relative order
 * per direction:
 *
 *   outbound:  ALE_AUTH_CONNECT  ->  OUTBOUND_IPPACKET
 *   inbound:   INBOUND_IPPACKET  ->  ALE_AUTH_RECV_ACCEPT
 *
 * A policy split naively across both — say, packet rules at the IP layers and
 * identity rules at ALE — would therefore evaluate in one order for outbound
 * traffic and the reverse for inbound. The same policy would mean two
 * different things depending on which way the packet was going.
 *
 * The resolution: every connection-oriented flow is decided at ALE, where
 * both the process and the five-tuple are available, and the IP packet layers
 * carry the same rules scoped to what ALE cannot see — the protocols with no
 * connection state. `protocolScope` on each filter is what expresses that
 * split, and it is why a filter carries a scope at all.
 */
typedef enum _UFW_ENGINE {
	UFW_ENGINE_WFP_ALE    = 0,
	UFW_ENGINE_WFP_PACKET = 1,
	/* Covers the stream layers and the datagram-data layers, which the
	 * compiler places together: both are "inspect a permitted flow's
	 * payload", and both can only ever tighten an ALE decision. */
	UFW_ENGINE_WFP_STREAM = 2,
} UFW_ENGINE;

/* Which protocols a filter applies to, given the layer it sits at. */
typedef enum _UFW_PROTOCOL_SCOPE {
	UFW_SCOPE_ALL                 = 0,
	/* TCP and UDP: everything ALE sees. */
	UFW_SCOPE_CONNECTION_ORIENTED = 1,
	/* Everything else: ICMP, and any protocol without ports. Installed at
	 * the IP packet layers because ALE never fires for it. */
	UFW_SCOPE_CONNECTIONLESS      = 2,
} UFW_PROTOCOL_SCOPE;

typedef enum _UFW_TRUST {
	UFW_TRUST_UNTRUSTED = 0,
	UFW_TRUST_UNKNOWN   = 1,
	UFW_TRUST_KNOWN     = 2,
	UFW_TRUST_TRUSTED   = 3,
	UFW_TRUST_SYSTEM    = 4,
} UFW_TRUST;

typedef enum _UFW_ZONE {
	UFW_ZONE_LOCAL     = 0,
	UFW_ZONE_INTERNAL  = 1,
	UFW_ZONE_PERIMETER = 2,
	UFW_ZONE_EXTERNAL  = 3,
	UFW_ZONE_ANY       = 4,
} UFW_ZONE;

typedef enum _UFW_L7 {
	UFW_L7_UNKNOWN = 0,
	UFW_L7_HTTP    = 1,
	UFW_L7_TLS     = 2,
	UFW_L7_DNS     = 3,
	UFW_L7_SSH     = 4,
	UFW_L7_SMTP    = 5,
	UFW_L7_QUIC    = 6,
} UFW_L7;

typedef enum _UFW_MODE {
	UFW_MODE_ENFORCE         = 0,
	UFW_MODE_MONITOR         = 1,
	UFW_MODE_EMERGENCY_ALLOW = 2,
} UFW_MODE;

/* --- flags --------------------------------------------------------------- */

#define UFW_FLAG_LOG               0x0001
#define UFW_FLAG_STATEFUL          0x0002
#define UFW_FLAG_NEEDS_IDENTITY    0x0004
#define UFW_FLAG_NEEDS_DPI         0x0008
#define UFW_FLAG_EBPF_ELIGIBLE     0x0010  /* meaningless here; kept so the
					    * flag word is identical across
					    * platforms and a log line's flags
					    * field means one thing */
#define UFW_FLAG_NEGATE_SRC        0x0020
#define UFW_FLAG_NEGATE_DST        0x0040
#define UFW_FLAG_NEGATE_APP        0x0080
#define UFW_FLAG_HAS_SCHEDULE      0x0100
#define UFW_FLAG_REQUIRE_VALID_SIG 0x0200

/* --- predicates ---------------------------------------------------------- */

/*
 * A CIDR, with the address in network byte order.
 *
 * The union makes the family/field correspondence explicit: a v4 entry writes
 * `.addr`, a v6 entry writes `.addr6`, and a reader that consults the wrong one
 * for the family is reading padding rather than a plausible-looking address.
 * The compiler's generated header uses exactly these designators.
 */
typedef struct _UFW_CIDR {
	UINT8 family;	/* 4 or 6 */
	UINT8 prefix;
	union {
		UINT8 addr[4];
		UINT8 addr6[16];
	};
} UFW_CIDR;

typedef struct _UFW_PORT_RANGE {
	UINT16 lo;
	UINT16 hi;
} UFW_PORT_RANGE;

/*
 * One platform's way of naming a binary.
 *
 * Conjunctive within a fingerprint, disjunctive across them. A Windows
 * fingerprint that names both a path and a signer means "this image, signed
 * by them"; a rule holding a Windows fingerprint and a Linux one means
 * "either", which is what lets one logical application be described for three
 * platforms without a Linux binary being required to carry an Authenticode
 * signature.
 */
typedef struct _UFW_FINGERPRINT {
	const wchar_t *paths[UFW_MAX_PATHS_PER_FP];
	UINT8 pathCount;
	/* Windows paths are case-insensitive, and this travels with the
	 * fingerprint rather than being decided by the evaluating platform: a
	 * Windows path stays case-insensitive wherever it is read. */
	UINT8 caseInsensitive;
	UINT8 hashCount;
	UINT8 signerCount;
	const UINT8 *hashes[UFW_MAX_HASHES_PER_FP];	/* 32 bytes each */
	const wchar_t *signers[UFW_MAX_SIGNERS_PER_FP];
} UFW_FINGERPRINT;

typedef struct _UFW_APP_MATCH {
	const UFW_FINGERPRINT *fingerprints;
	UINT8 fingerprintCount;
	UINT8 trustMask;
	UINT8 negate;
	UINT8 requireValidSignature;
} UFW_APP_MATCH;

typedef struct _UFW_DPI_MATCH {
	const UINT32 *signatureIds;
	UINT8 signatureCount;
	const UINT8 *l7;
	UINT8 l7Count;
	UINT8 onMatch;
	UINT8 reserved;
} UFW_DPI_MATCH;

typedef struct _UFW_SCHEDULE {
	UINT16 startMinute;
	UINT16 endMinute;
	UINT8  dayMask;	/* bit 0 = Monday */
	UINT8  reserved[3];
} UFW_SCHEDULE;

/* --- the filter ---------------------------------------------------------- */

/*
 * One compiled rule, as the generated header and the IOCTL payload both
 * express it.
 *
 * `weight` is what WFP sorts by within a sublayer, and it is computed as
 * `UINT64_MAX - evaluationOrderKey(rule)` so that WFP's descending order
 * reproduces the reference implementation's ascending one. The order key puts
 * *stage* above priority, because priority orders rules within a stage and
 * does not order the stages — the single most common way to misread this
 * policy language, and the one place where getting it wrong here would make
 * Windows disagree with the other two platforms while every individual rule
 * looked correct.
 */
typedef struct _UFW_FILTER_SPEC {
	UINT32 ruleId;
	const char *name;
	UINT8  stage;
	UINT8  engine;
	UINT64 weight;
	UINT8  action;		/* FWP_ACTION_PERMIT / FWP_ACTION_BLOCK */
	UINT8  direction;
	UINT8  protocol;
	UINT8  protocolScope;

	const UFW_CIDR *srcCidrs;
	UINT8 srcCidrCount;
	const UFW_CIDR *dstCidrs;
	UINT8 dstCidrCount;
	const UFW_PORT_RANGE *srcPorts;
	UINT8 srcPortCount;
	const UFW_PORT_RANGE *dstPorts;
	UINT8 dstPortCount;

	UINT8 srcZoneMask;
	UINT8 dstZoneMask;

	UFW_APP_MATCH app;
	UFW_DPI_MATCH dpi;
	UFW_SCHEDULE  schedule;

	UINT32 flags;
} UFW_FILTER_SPEC;

/* --- IOCTL payloads ------------------------------------------------------ */

typedef struct _UFW_HELLO_REPLY {
	UINT8  abiRevision;
	UINT8  reserved[3];
	UINT32 driverVersion;
	UINT64 installedRevision;
	UINT32 capabilities;
} UFW_HELLO_REPLY;

#define UFW_CAP_IDENTITY  0x0001
#define UFW_CAP_DPI       0x0002
#define UFW_CAP_STREAM    0x0004
#define UFW_CAP_IPV6      0x0008
#define UFW_CAP_SCHEDULE  0x0010

/*
 * The policy install payload.
 *
 * Self-describing lengths on everything, and the driver checks that the
 * declared sizes sum to exactly the buffer it was given. A payload that is
 * longer leaves trailing bytes; shorter leaves rules uninitialised. Both are
 * a parse desynchronisation between the daemon and the driver, and this is
 * the one place to catch it.
 */
typedef struct _UFW_INSTALL_HEADER {
	UINT8  abiRevision;
	UINT8  defaultAction;
	UINT8  reserved[2];
	UINT32 filterCount;
	UINT64 policyRevision;
	UINT8  rulesetHash[32];
	UINT32 payloadBytes;	/* everything after this header */
} UFW_INSTALL_HEADER;

typedef struct _UFW_STATS {
	UINT64 packetsSeen;
	UINT64 packetsAllowed;
	UINT64 packetsDenied;
	UINT64 flowsSeen;
	UINT64 flowsAllowed;
	UINT64 flowsDenied;
	UINT64 identityCacheHits;
	UINT64 identityCacheMisses;
	UINT64 identityQueriesTimedOut;
	UINT64 dpiScans;
	UINT64 dpiHits;
	UINT64 reassemblyContexts;
	UINT64 reassemblyTruncated;
	UINT64 conntrackEntries;
	UINT64 logEventsDropped;
	UINT64 ebpfFastpathDecisions;	/* always zero here; see UFW_FLAG_EBPF_ELIGIBLE */
} UFW_STATS;

/* Event kinds delivered through UFW_IOCTL_AWAIT_EVENT. */
typedef enum _UFW_EVENT_KIND {
	UFW_EVENT_IDENTITY_QUERY = 1,
	UFW_EVENT_LOG_BATCH      = 2,
} UFW_EVENT_KIND;

typedef struct _UFW_EVENT_HEADER {
	UINT32 kind;
	UINT32 payloadBytes;
} UFW_EVENT_HEADER;

typedef struct _UFW_IDENTITY_QUERY {
	UINT64 flowId;
	UINT32 processId;
	UINT32 reserved;
} UFW_IDENTITY_QUERY;

typedef struct _UFW_IDENTITY_RESPONSE {
	UINT64 flowId;
	UINT32 processId;
	UINT8  trust;
	UINT8  signatureValid;
	UINT16 pathChars;
	UINT16 signerChars;
	UINT16 reserved;
	UINT8  sha256[32];
	/* pathChars wide characters, then signerChars wide characters. */
	wchar_t data[1];
} UFW_IDENTITY_RESPONSE;

/* Synthetic rule ids, matching the other platforms. */
#define UFW_RULE_ID_DEFAULT     0xFFFFFFFFu
#define UFW_RULE_ID_NO_POLICY   0xFFFFFFFEu
#define UFW_RULE_ID_FAIL_CLOSED 0xFFFFFFFDu
