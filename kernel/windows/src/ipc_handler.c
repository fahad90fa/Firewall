/*
 * Unified Firewall — the daemon channel, and the identity cache it fills.
 *
 * # Inverted calls
 *
 * The daemon keeps a UFW_IOCTL_AWAIT_EVENT IRP pended at all times; the driver
 * completes it when it has something to say. An event object plus a separate
 * read has a race — the driver can signal between the daemon's check and its
 * wait — and an inverted call does not. It also means the driver never has to
 * decide how long to wait for a reader that may not exist.
 *
 * The pended IRP is cancellable, so a daemon that exits or is killed does not
 * leave an IRP the driver can never complete and therefore can never unload
 * past.
 *
 * # Why the driver does not resolve identity itself
 *
 * Reading an image path, hashing a file and checking an Authenticode
 * signature are all PASSIVE_LEVEL work with file I/O. Classification runs at
 * DISPATCH_LEVEL. A driver that tried would either have to queue work and
 * block the classify — deadlocking the network stack against its own
 * filesystem — or reimplement PE parsing and certificate validation in kernel
 * mode, which is a large attack surface running with no memory protection at
 * all.
 *
 * So the daemon does it, and the driver caches the answer. What is lost is
 * that the first flow of a new process is classified without identity. What
 * is gained is that a signature-verification bug is a userland crash rather
 * than a bugcheck.
 *
 * # The cache key
 *
 * (processId, flowId), never a bare pid. Pids are reused, and a reused pid is
 * the difference between "the browser may reach the internet" and "whatever
 * inherited the browser's pid may reach the internet". Keying on the pair
 * makes a stale entry *miss* rather than answer wrongly.
 */

#include "../inc/driver.h"

#define UFW_EVENT_QUEUE_DEPTH 1024
#define UFW_IDENTITY_BUCKETS 256
#define UFW_IDENTITY_MAX_ENTRIES 4096

/* Five minutes: short enough that a redeployed binary stops matching its old
 * hash within a maintenance window, long enough that the daemon is not
 * re-resolving the same browser every few seconds. */
#define UFW_IDENTITY_TTL_100NS (300LL * 10000000LL)

/* --- identity cache -------------------------------------------------------- */

typedef struct _UFW_IDENTITY_ENTRY {
	LIST_ENTRY link;
	UINT32 processId;
	LARGE_INTEGER resolvedAt;
	LARGE_INTEGER lastQuery;
	UINT8  trust;
	UINT8  signatureValid;
	UINT8  valid;
	UINT8  reserved;
	UINT8  sha256[32];
	wchar_t path[UFW_MAX_PATH_LEN];
	wchar_t signer[UFW_MAX_SIGNER_LEN];
} UFW_IDENTITY_ENTRY;

static LIST_ENTRY g_identityBuckets[UFW_IDENTITY_BUCKETS];
static KSPIN_LOCK g_identityLock;
static UINT32 g_identityCount;

/* --- event queue ----------------------------------------------------------- */

typedef struct _UFW_EVENT {
	LIST_ENTRY link;
	UFW_EVENT_HEADER header;
	UINT8 payload[512];
} UFW_EVENT;

static LIST_ENTRY g_eventQueue;
static KSPIN_LOCK g_eventLock;
static UINT32 g_eventCount;
static PIRP g_pendedIrp;

static UINT32 UfwIdentityBucket(_In_ UINT32 processId)
{
	return (processId * 2654435761u) % UFW_IDENTITY_BUCKETS;
}

NTSTATUS UfwIdentityInitialize(VOID)
{
	UINT32 i;

	KeInitializeSpinLock(&g_identityLock);
	for (i = 0; i < UFW_IDENTITY_BUCKETS; i++)
		InitializeListHead(&g_identityBuckets[i]);
	g_identityCount = 0;
	return STATUS_SUCCESS;
}

VOID UfwIdentityFlush(VOID)
{
	KLOCK_QUEUE_HANDLE lock;
	UINT32 i;

	KeAcquireInStackQueuedSpinLock(&g_identityLock, &lock);
	for (i = 0; i < UFW_IDENTITY_BUCKETS; i++) {
		while (!IsListEmpty(&g_identityBuckets[i])) {
			PLIST_ENTRY entry = RemoveHeadList(&g_identityBuckets[i]);

			ExFreePoolWithTag(
				CONTAINING_RECORD(entry, UFW_IDENTITY_ENTRY, link),
				UFW_POOL_TAG);
		}
	}
	g_identityCount = 0;
	KeReleaseInStackQueuedSpinLock(&lock);
}

VOID UfwIdentityShutdown(VOID)
{
	UfwIdentityFlush();
}

/* Caller holds the lock. */
static UFW_IDENTITY_ENTRY *UfwIdentityLookup(_In_ UINT32 processId)
{
	PLIST_ENTRY head = &g_identityBuckets[UfwIdentityBucket(processId)];
	PLIST_ENTRY entry;

	for (entry = head->Flink; entry != head; entry = entry->Flink) {
		UFW_IDENTITY_ENTRY *e =
			CONTAINING_RECORD(entry, UFW_IDENTITY_ENTRY, link);

		if (e->processId == processId)
			return e;
	}
	return NULL;
}

/* Caller holds the lock. Evicts within one bucket rather than maintaining a
 * global LRU, which would mean a list operation on every cache hit — a shared
 * cache line touched by every classification. */
static VOID UfwIdentityEvict(_In_ UINT32 bucket)
{
	PLIST_ENTRY head = &g_identityBuckets[bucket];
	PLIST_ENTRY entry;
	UFW_IDENTITY_ENTRY *oldest = NULL;

	for (entry = head->Flink; entry != head; entry = entry->Flink) {
		UFW_IDENTITY_ENTRY *e =
			CONTAINING_RECORD(entry, UFW_IDENTITY_ENTRY, link);

		if (!oldest || e->resolvedAt.QuadPart < oldest->resolvedAt.QuadPart)
			oldest = e;
	}
	if (oldest) {
		RemoveEntryList(&oldest->link);
		ExFreePoolWithTag(oldest, UFW_POOL_TAG);
		g_identityCount--;
	}
}

BOOLEAN UfwIdentityFill(_In_ UINT32 processId, _Inout_ UFW_FLOW_FACTS *facts)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_IDENTITY_ENTRY *e;
	LARGE_INTEGER now;
	BOOLEAN hit = FALSE;
	BOOLEAN needQuery = FALSE;

	if (!processId)
		return FALSE;

	KeQuerySystemTime(&now);
	KeAcquireInStackQueuedSpinLock(&g_identityLock, &lock);

	e = UfwIdentityLookup(processId);
	if (e && e->valid &&
	    (now.QuadPart - e->resolvedAt.QuadPart) < UFW_IDENTITY_TTL_100NS) {
		facts->identityValid = 1;
		facts->processId = e->processId;
		facts->trust = e->trust;
		facts->signatureValid = e->signatureValid;
		facts->imagePath = e->path;
		facts->signer = e->signer;
		RtlCopyMemory(facts->sha256, e->sha256, 32);
		hit = TRUE;
	} else {
		if (e && e->valid)
			e->valid = 0;
		if (!e) {
			UINT32 bucket = UfwIdentityBucket(processId);

			if (g_identityCount >= UFW_IDENTITY_MAX_ENTRIES)
				UfwIdentityEvict(bucket);

			e = (UFW_IDENTITY_ENTRY *)ExAllocatePool2(
				POOL_FLAG_NON_PAGED, sizeof(*e), UFW_POOL_TAG);
			if (e) {
				RtlZeroMemory(e, sizeof(*e));
				e->processId = processId;
				InsertHeadList(&g_identityBuckets[bucket], &e->link);
				g_identityCount++;
			}
		}
		/* The negative entry exists to hold the rate limit: without it
		 * a process the daemon cannot resolve would generate a query
		 * per flow. */
		if (e && (now.QuadPart - e->lastQuery.QuadPart) > 20000000LL) {
			e->lastQuery = now;
			needQuery = TRUE;
		}
	}
	KeReleaseInStackQueuedSpinLock(&lock);

	if (hit) {
		UFW_COUNT(identityCacheHits);
		return TRUE;
	}

	UFW_COUNT(identityCacheMisses);

	/* With no daemon attached there is nobody to answer, so the query is
	 * not queued — which is what keeps a daemon crash from filling the
	 * event queue with requests and dropping the log events behind them. */
	if (needQuery && UfwDaemonAttached()) {
		UFW_IDENTITY_QUERY query;

		query.flowId = facts->flowId;
		query.processId = processId;
		query.reserved = 0;
		UfwIpcQueueEvent(UFW_EVENT_IDENTITY_QUERY, &query, sizeof(query));
	}
	return FALSE;
}

VOID UfwIdentityDeliver(_In_ const UFW_IDENTITY_RESPONSE *response,
			_In_ SIZE_T responseBytes)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_IDENTITY_ENTRY *e;
	UINT32 bucket;
	SIZE_T needed;

	/* The declared string lengths must fit inside the buffer that arrived.
	 * This is a user-mode buffer; the daemon is trusted to be the daemon,
	 * not trusted to be correct. */
	needed = FIELD_OFFSET(UFW_IDENTITY_RESPONSE, data) +
		 ((SIZE_T)response->pathChars + response->signerChars) * sizeof(wchar_t);
	if (responseBytes < needed)
		return;
	if (response->pathChars >= UFW_MAX_PATH_LEN ||
	    response->signerChars >= UFW_MAX_SIGNER_LEN)
		return;

	bucket = UfwIdentityBucket(response->processId);

	KeAcquireInStackQueuedSpinLock(&g_identityLock, &lock);
	e = UfwIdentityLookup(response->processId);
	if (!e) {
		if (g_identityCount >= UFW_IDENTITY_MAX_ENTRIES)
			UfwIdentityEvict(bucket);
		e = (UFW_IDENTITY_ENTRY *)ExAllocatePool2(
			POOL_FLAG_NON_PAGED, sizeof(*e), UFW_POOL_TAG);
		if (!e) {
			KeReleaseInStackQueuedSpinLock(&lock);
			return;
		}
		RtlZeroMemory(e, sizeof(*e));
		e->processId = response->processId;
		InsertHeadList(&g_identityBuckets[bucket], &e->link);
		g_identityCount++;
	}

	e->trust = response->trust;
	e->signatureValid = response->signatureValid;
	RtlCopyMemory(e->sha256, response->sha256, 32);

	RtlZeroMemory(e->path, sizeof(e->path));
	RtlZeroMemory(e->signer, sizeof(e->signer));
	if (response->pathChars)
		RtlCopyMemory(e->path, response->data,
			      response->pathChars * sizeof(wchar_t));
	if (response->signerChars)
		RtlCopyMemory(e->signer, response->data + response->pathChars,
			      response->signerChars * sizeof(wchar_t));

	KeQuerySystemTime(&e->resolvedAt);
	e->valid = 1;
	KeReleaseInStackQueuedSpinLock(&lock);
}

/* --- the event channel -------------------------------------------------------- */

NTSTATUS UfwIpcInitialize(_In_ PDEVICE_OBJECT deviceObject)
{
	UNREFERENCED_PARAMETER(deviceObject);
	KeInitializeSpinLock(&g_eventLock);
	InitializeListHead(&g_eventQueue);
	g_eventCount = 0;
	g_pendedIrp = NULL;
	return STATUS_SUCCESS;
}

VOID UfwIpcShutdown(VOID)
{
	KLOCK_QUEUE_HANDLE lock;
	PIRP irp;

	KeAcquireInStackQueuedSpinLock(&g_eventLock, &lock);
	irp = g_pendedIrp;
	g_pendedIrp = NULL;
	while (!IsListEmpty(&g_eventQueue)) {
		PLIST_ENTRY entry = RemoveHeadList(&g_eventQueue);

		ExFreePoolWithTag(CONTAINING_RECORD(entry, UFW_EVENT, link),
				  UFW_POOL_TAG);
	}
	g_eventCount = 0;
	KeReleaseInStackQueuedSpinLock(&lock);

	/* A pended IRP the driver never completes is a driver that can never
	 * unload. */
	if (irp) {
		IoSetCancelRoutine(irp, NULL);
		irp->IoStatus.Status = STATUS_CANCELLED;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}
}

static VOID UfwIpcCancelRoutine(_Inout_ PDEVICE_OBJECT deviceObject,
				_Inout_ PIRP irp)
{
	KLOCK_QUEUE_HANDLE lock;

	UNREFERENCED_PARAMETER(deviceObject);
	IoReleaseCancelSpinLock(irp->CancelIrql);

	KeAcquireInStackQueuedSpinLock(&g_eventLock, &lock);
	if (g_pendedIrp == irp)
		g_pendedIrp = NULL;
	KeReleaseInStackQueuedSpinLock(&lock);

	irp->IoStatus.Status = STATUS_CANCELLED;
	irp->IoStatus.Information = 0;
	IoCompleteRequest(irp, IO_NO_INCREMENT);
}

/* Copy one event into a waiting IRP. Caller holds the event lock. */
static BOOLEAN UfwIpcFillIrp(_In_ PIRP irp, _In_ UFW_EVENT *event)
{
	PIO_STACK_LOCATION stack = IoGetCurrentIrpStackLocation(irp);
	ULONG outLength = stack->Parameters.DeviceIoControl.OutputBufferLength;
	SIZE_T needed = sizeof(UFW_EVENT_HEADER) + event->header.payloadBytes;
	PVOID buffer;

	if (outLength < needed)
		return FALSE;

	buffer = MmGetSystemAddressForMdlSafe(irp->MdlAddress,
					      NormalPagePriority | MdlMappingNoExecute);
	if (!buffer)
		return FALSE;

	RtlCopyMemory(buffer, &event->header, sizeof(UFW_EVENT_HEADER));
	RtlCopyMemory((UINT8 *)buffer + sizeof(UFW_EVENT_HEADER),
		      event->payload, event->header.payloadBytes);
	irp->IoStatus.Information = needed;
	return TRUE;
}

VOID UfwIpcQueueEvent(_In_ UFW_EVENT_KIND kind,
		      _In_reads_bytes_(length) const VOID *payload,
		      _In_ SIZE_T length)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_EVENT *event;
	PIRP irp = NULL;

	if (length > sizeof(event->payload))
		return;

	event = (UFW_EVENT *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
					     sizeof(*event), UFW_POOL_TAG);
	if (!event) {
		/* A failed allocation drops the event rather than making the
		 * caller wait. Classification never blocks on the log path. */
		UFW_COUNT(logEventsDropped);
		return;
	}
	event->header.kind = (UINT32)kind;
	event->header.payloadBytes = (UINT32)length;
	RtlCopyMemory(event->payload, payload, length);

	KeAcquireInStackQueuedSpinLock(&g_eventLock, &lock);

	/* If the daemon is already waiting, hand it straight over. */
	if (g_pendedIrp) {
		irp = g_pendedIrp;
		if (UfwIpcFillIrp(irp, event)) {
			g_pendedIrp = NULL;
			IoSetCancelRoutine(irp, NULL);
			ExFreePoolWithTag(event, UFW_POOL_TAG);
			KeReleaseInStackQueuedSpinLock(&lock);
			irp->IoStatus.Status = STATUS_SUCCESS;
			IoCompleteRequest(irp, IO_NO_INCREMENT);
			return;
		}
		irp = NULL;
	}

	/*
	 * Bounded and lossy. When the queue is full the *oldest* event is
	 * discarded: during an incident the interesting events are the ones
	 * happening now, and a newest-first policy would preferentially
	 * discard exactly those while retaining a backlog of routine traffic
	 * from before anything happened. The drop count is reported, so a gap
	 * in the log reads as a gap rather than as an absence of activity.
	 */
	if (g_eventCount >= UFW_EVENT_QUEUE_DEPTH) {
		PLIST_ENTRY oldest = RemoveHeadList(&g_eventQueue);

		ExFreePoolWithTag(CONTAINING_RECORD(oldest, UFW_EVENT, link),
				  UFW_POOL_TAG);
		g_eventCount--;
		UFW_COUNT(logEventsDropped);
	}

	InsertTailList(&g_eventQueue, &event->link);
	g_eventCount++;
	KeReleaseInStackQueuedSpinLock(&lock);
}

NTSTATUS UfwIpcDispatch(_In_ PDEVICE_OBJECT deviceObject, _In_ PIRP irp)
{
	KLOCK_QUEUE_HANDLE lock;
	UFW_EVENT *event = NULL;
	NTSTATUS status;

	UNREFERENCED_PARAMETER(deviceObject);

	KeAcquireInStackQueuedSpinLock(&g_eventLock, &lock);

	if (!IsListEmpty(&g_eventQueue)) {
		PLIST_ENTRY entry = RemoveHeadList(&g_eventQueue);

		event = CONTAINING_RECORD(entry, UFW_EVENT, link);
		g_eventCount--;
	}

	if (event) {
		BOOLEAN ok = UfwIpcFillIrp(irp, event);

		KeReleaseInStackQueuedSpinLock(&lock);
		ExFreePoolWithTag(event, UFW_POOL_TAG);
		status = ok ? STATUS_SUCCESS : STATUS_BUFFER_TOO_SMALL;
		irp->IoStatus.Status = status;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return status;
	}

	/* Only one outstanding await at a time. A second one is a daemon bug,
	 * and completing it immediately with an error is more diagnosable than
	 * silently replacing the first — which would strand it forever. */
	if (g_pendedIrp) {
		KeReleaseInStackQueuedSpinLock(&lock);
		irp->IoStatus.Status = STATUS_DEVICE_BUSY;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
		return STATUS_DEVICE_BUSY;
	}

	IoMarkIrpPending(irp);
	IoSetCancelRoutine(irp, UfwIpcCancelRoutine);
	g_pendedIrp = irp;
	KeReleaseInStackQueuedSpinLock(&lock);
	return STATUS_PENDING;
}
