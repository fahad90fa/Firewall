/*
 * Unified Firewall — the log path, Windows.
 *
 * # The rule
 *
 * A packet never waits for a log event. Not for the daemon, not for the
 * queue, not for an allocation. If an event cannot be produced it is dropped
 * and counted, and the decision proceeds unchanged.
 *
 * The cost is explicit: a SIEM collector that stops reading causes the
 * daemon's socket to fill, which causes it to stop draining the event queue,
 * which causes events to be dropped. Logs are lost. The alternative — letting
 * back-pressure reach the classifier — means a collector outage becomes a
 * network outage on every host that ships to it, which is a far larger
 * incident and one where the firewall is the cause.
 *
 * # What is in an event
 *
 * Everything needed to correlate the same flow across three platforms: the
 * five-tuple, the rule id, the stage, and the identity if there was one. The
 * rule id is hash-derived from the rule's name, so the same policy produces
 * the same id on Windows, Linux and macOS — which is what makes the
 * correlation work at all.
 */

#include "../inc/driver.h"

/* Mirrors the Linux module's wire form so the daemon has one decoder. */
typedef struct _UFW_LOG_EVENT {
	UINT64 timestamp100ns;
	UINT32 ruleId;
	UINT8  verdict;
	UINT8  stage;
	UINT8  protocol;
	UINT8  direction;
	UINT8  isV6;
	UINT8  srcZone;
	UINT8  dstZone;
	UINT8  l7;
	UINT8  srcAddr[16];
	UINT8  dstAddr[16];
	UINT16 srcPort;
	UINT16 dstPort;
	UINT32 processId;
	UINT8  trust;
	UINT8  identityValid;
	UINT8  dpiTruncated;
	UINT8  matchedCount;
	UINT32 matchedSignatures[UFW_MAX_SIGNATURES_PER_RULE];
	char   ruleName[UFW_MAX_RULE_NAME];
} UFW_LOG_EVENT;

NTSTATUS UfwLogInitialize(VOID)
{
	return STATUS_SUCCESS;
}

VOID UfwLogShutdown(VOID)
{
}

VOID UfwLogDecision(_In_ const UFW_FLOW_FACTS *facts,
		    _In_ const UFW_DECISION *decision)
{
	UFW_LOG_EVENT event;
	LARGE_INTEGER now;
	UINT8 i;
	SIZE_T nameLength;

	/* Nobody is listening. Formatting an event to drop it is work the
	 * classify path should not do. */
	if (!UfwDaemonAttached())
		return;

	RtlZeroMemory(&event, sizeof(event));
	KeQuerySystemTime(&now);
	event.timestamp100ns = (UINT64)now.QuadPart;

	event.ruleId = decision->ruleId;
	event.verdict = (decision->action == FWP_ACTION_BLOCK) ? 1 : 0;
	event.stage = decision->stage;
	event.protocol = facts->protocol;
	event.direction = facts->direction;
	event.isV6 = facts->isV6;
	event.srcZone = facts->srcZone;
	event.dstZone = facts->dstZone;
	event.l7 = facts->l7;
	RtlCopyMemory(event.srcAddr, facts->srcAddr, 16);
	RtlCopyMemory(event.dstAddr, facts->dstAddr, 16);
	event.srcPort = facts->srcPort;
	event.dstPort = facts->dstPort;
	event.processId = facts->processId;
	event.trust = facts->trust;
	event.identityValid = facts->identityValid;
	event.dpiTruncated = facts->dpiTruncated;

	event.matchedCount = facts->matchedCount;
	for (i = 0; i < facts->matchedCount && i < UFW_MAX_SIGNATURES_PER_RULE; i++)
		event.matchedSignatures[i] = facts->matchedSignatures[i];

	if (decision->ruleName) {
		/* The name points into the published table, which the caller
		 * still holds a reference to; copying it here is what makes
		 * the event safe to queue past that lifetime. */
		nameLength = strnlen(decision->ruleName, UFW_MAX_RULE_NAME - 1);
		RtlCopyMemory(event.ruleName, decision->ruleName, nameLength);
	}

	/*
	 * The image path is deliberately not copied. It is a pointer into the
	 * identity cache entry, which can be evicted between here and the
	 * daemon reading the event, and the path is recoverable from the
	 * process id on the daemon side where the resolution happened anyway.
	 * Copying 512 bytes per event to duplicate something userland already
	 * has is the wrong trade in the one place that runs per decision.
	 */

	UfwIpcQueueEvent(UFW_EVENT_LOG_BATCH, &event, sizeof(event));
}
