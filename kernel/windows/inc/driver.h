/*
 * Unified Firewall — Windows callout driver, internal interfaces.
 *
 * # Shape of the driver
 *
 *   driver.c            DriverEntry, unload, device and IOCTL dispatch
 *   wfp_engine.c        engine session, sublayer, callout and filter setup
 *   classify.c          the decision, shared by every callout
 *   callouts/*.c        one thin file per WFP layer
 *   policy_cache.c      the published filter table
 *   stream_reassembly.c, dpi_engine.c, ipc_handler.c, logging.c
 *
 * # The rule about IRQL
 *
 * Classification runs at DISPATCH_LEVEL. That means no paged memory, no
 * waits, no registry, no file I/O, and no acquiring anything that a
 * PASSIVE_LEVEL thread might hold while doing those things. Every allocation
 * on the classify path is NonPagedPoolNx, and every lock is a spin lock.
 *
 * Where a fact needs PASSIVE_LEVEL work to obtain — an image path, an
 * Authenticode check — the classifier does not obtain it. It uses what is
 * cached and asks the daemon for the rest, asynchronously. This is the same
 * design decision as the Linux module's, made for the same reason and forced
 * by a different mechanism.
 */

#pragma once

#define UFW_KERNEL_MODE
#include "ipc_ioctl.h"

#include <ntddk.h>
#include <fwpsk.h>
#include <fwpmk.h>

#define UFW_POOL_TAG 'wfUR'	/* "RUfw" reversed, as the tag displays */

#define UFW_DRIVER_VERSION 0x00000100u

/* --- global driver state -------------------------------------------------- */

typedef struct _UFW_DRIVER_STATE {
	PDEVICE_OBJECT deviceObject;
	HANDLE engineHandle;
	HANDLE injectionHandleV4;
	HANDLE injectionHandleV6;

	/* Registered callout ids, so unload can deregister exactly what was
	 * registered even if setup failed partway. */
	UINT32 calloutIds[8];
	UINT32 calloutCount;

	/* The filter table, published under a reader-writer spin lock. WFP
	 * calls classify from multiple processors concurrently, so this is
	 * read far more than it is written. */
	struct _UFW_POLICY_TABLE *policy;
	EX_SPIN_LOCK policyLock;

	volatile LONG mode;		/* UFW_MODE */
	volatile LONG daemonAttached;	/* non-zero when the daemon holds a handle */

	UFW_STATS stats;
} UFW_DRIVER_STATE;

extern UFW_DRIVER_STATE g_ufw;

/*
 * Statistics are updated with InterlockedIncrement rather than per-CPU
 * counters.
 *
 * The Linux module uses per-CPU counters to keep the hot path off a shared
 * cache line, and the same argument applies here — but WFP callouts already
 * cost far more than an interlocked add, and KeGetCurrentProcessorNumber-
 * indexed arrays in a driver are a lifetime problem when processors are
 * hot-added. The contention is real and it is not the bottleneck.
 */
#define UFW_COUNT(field) InterlockedIncrement64((volatile LONG64 *)&g_ufw.stats.field)
#define UFW_ADD(field, n) InterlockedAdd64((volatile LONG64 *)&g_ufw.stats.field, (LONG64)(n))

/* --- the published policy ------------------------------------------------- */

typedef struct _UFW_POLICY_TABLE {
	UINT64 revision;
	UINT8  rulesetHash[32];
	UINT32 filterCount;
	UINT8  defaultAction;
	UINT8  abiRevision;
	UINT8  reserved[2];
	/* First filter of each stage; the table is sorted by (stage, weight),
	 * so evaluating a stage is a bounded scan. */
	UINT32 stageStart[UFW_STAGE_COUNT + 1];
	/* The WFP filter ids added for this table, so a replacement can remove
	 * exactly its predecessor's filters rather than everything in the
	 * sublayer — which would also remove filters a concurrent install had
	 * just added. */
	UINT64 *wfpFilterIds;
	UINT32 wfpFilterCount;
	UFW_FILTER_SPEC filters[1];
} UFW_POLICY_TABLE;

NTSTATUS UfwPolicyInstall(_In_ const UFW_INSTALL_HEADER *header,
			  _In_reads_bytes_(payloadBytes) const UINT8 *payload,
			  _In_ SIZE_T payloadBytes);
VOID UfwPolicyFlush(VOID);
UFW_POLICY_TABLE *UfwPolicyAcquire(_Out_ KIRQL *oldIrql);
VOID UfwPolicyRelease(_In_ KIRQL oldIrql);

/* --- classification -------------------------------------------------------- */

/*
 * Everything the driver knows about one flow.
 *
 * `identityValid` and `dpiValid` are separate from the payloads because
 * absent facts must never read as wildcards: an unresolved identity does not
 * match an application predicate, not even a negated one. That asymmetry is
 * what keeps "deny everything not signed by us" from being satisfied by a
 * process the driver could not inspect.
 */
typedef struct _UFW_FLOW_FACTS {
	UINT8  isV6;
	UINT8  protocol;
	UINT8  direction;
	UINT8  srcZone;
	UINT8  dstZone;
	UINT8  identityValid;
	UINT8  dpiValid;
	UINT8  l7;

	UINT8  srcAddr[16];
	UINT8  dstAddr[16];
	UINT16 srcPort;
	UINT16 dstPort;

	UINT64 flowId;
	UINT32 processId;
	UINT8  trust;
	UINT8  signatureValid;
	const wchar_t *imagePath;
	const wchar_t *signer;
	UINT8  sha256[32];

	UINT32 matchedSignatures[UFW_MAX_SIGNATURES_PER_RULE];
	UINT8  matchedCount;
	UINT8  dpiTruncated;

	UINT16 minuteOfWeek;
	UINT8  minuteValid;
	UINT8  reserved;
} UFW_FLOW_FACTS;

typedef struct _UFW_DECISION {
	UINT8  action;		/* FWP_ACTION_PERMIT / FWP_ACTION_BLOCK */
	UINT8  stage;
	UINT8  logged;
	UINT8  reserved;
	UINT32 ruleId;
	const char *ruleName;
} UFW_DECISION;

/*
 * Evaluate the installed policy. Callable at DISPATCH_LEVEL.
 *
 * `scope` restricts which filters are considered, and it is not an
 * optimisation: it is what keeps the ALE layers and the IP packet layers from
 * both deciding the same flow. See UFW_PROTOCOL_SCOPE in ipc_ioctl.h.
 */
VOID UfwClassify(_In_ const UFW_FLOW_FACTS *facts,
		 _In_ UFW_PROTOCOL_SCOPE scope,
		 _Out_ UFW_DECISION *decision);

/* Populate the L3/L4 half of the facts from WFP's classify parameters. The
 * indices differ per layer, so each callout passes its own. */
NTSTATUS UfwFactsFromClassify(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
			      _In_ const FWPS_INCOMING_METADATA_VALUES *metadata,
			      _In_ UINT8 direction,
			      _Out_ UFW_FLOW_FACTS *facts);

UINT8 UfwZoneOf(_In_reads_(16) const UINT8 *addr, _In_ BOOLEAN isV6);

/* --- WFP engine ------------------------------------------------------------ */

NTSTATUS UfwWfpInitialize(_In_ PDEVICE_OBJECT deviceObject);
VOID UfwWfpShutdown(VOID);

/* Add the WFP filters for a freshly installed table, and remove the previous
 * table's. */
NTSTATUS UfwWfpSyncFilters(_Inout_ UFW_POLICY_TABLE *table,
			   _In_opt_ UFW_POLICY_TABLE *previous);

/* --- identity --------------------------------------------------------------- */

NTSTATUS UfwIdentityInitialize(VOID);
VOID UfwIdentityShutdown(VOID);
VOID UfwIdentityFlush(VOID);

/* Fill the identity half of `facts` from cache. Returns TRUE on a hit.
 * Never waits: a miss queues a query for the daemon and returns FALSE. */
BOOLEAN UfwIdentityFill(_In_ UINT32 processId, _Inout_ UFW_FLOW_FACTS *facts);

VOID UfwIdentityDeliver(_In_ const UFW_IDENTITY_RESPONSE *response,
			_In_ SIZE_T responseBytes);

/* --- stream and DPI ---------------------------------------------------------- */

NTSTATUS UfwStreamInitialize(VOID);
VOID UfwStreamShutdown(VOID);
VOID UfwStreamFlush(VOID);

/* Release one flow's reassembly context, on WFP's flow-delete notification. */
VOID UfwStreamRelease(_In_ UINT64 flowId);

/* Feed stream bytes into the flow's context and rescan. */
NTSTATUS UfwStreamObserve(_In_ UINT64 flowId,
			  _In_reads_bytes_(length) const UINT8 *data,
			  _In_ SIZE_T length,
			  _Inout_ UFW_FLOW_FACTS *facts);

NTSTATUS UfwDpiInitialize(VOID);
VOID UfwDpiShutdown(VOID);
NTSTATUS UfwDpiInstall(_In_reads_bytes_(length) const UINT8 *encoded,
		       _In_ SIZE_T length);
UINT8 UfwDpiIdentify(_In_reads_bytes_(length) const UINT8 *data,
		     _In_ SIZE_T length, _In_ UINT16 dstPort);
UINT8 UfwDpiScan(_In_ UINT8 l7,
		 _In_reads_bytes_(length) const UINT8 *data, _In_ SIZE_T length,
		 _Out_writes_(maxMatches) UINT32 *matched, _In_ UINT8 maxMatches,
		 _Inout_ UINT8 *truncated);

/* --- IPC and logging ---------------------------------------------------------- */

NTSTATUS UfwIpcInitialize(_In_ PDEVICE_OBJECT deviceObject);
VOID UfwIpcShutdown(VOID);
NTSTATUS UfwIpcDispatch(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP irp);

/* Queue an event for the daemon's pended read. Never blocks; a full queue
 * drops the oldest and counts it. */
VOID UfwIpcQueueEvent(_In_ UFW_EVENT_KIND kind,
		      _In_reads_bytes_(length) const VOID *payload,
		      _In_ SIZE_T length);
BOOLEAN UfwDaemonAttached(VOID);

NTSTATUS UfwLogInitialize(VOID);
VOID UfwLogShutdown(VOID);
VOID UfwLogDecision(_In_ const UFW_FLOW_FACTS *facts,
		    _In_ const UFW_DECISION *decision);

/* --- helpers ------------------------------------------------------------------ */

BOOLEAN UfwCidrContains(_In_ const UFW_CIDR *cidr,
			_In_reads_(16) const UINT8 *addr, _In_ BOOLEAN isV6);
BOOLEAN UfwPathMatch(_In_z_ const wchar_t *pattern, _In_opt_z_ const wchar_t *path,
		     _In_ BOOLEAN caseInsensitive);
