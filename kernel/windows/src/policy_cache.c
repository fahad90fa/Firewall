/*
 * Unified Firewall — the published filter table.
 *
 * A policy arrives as one IOCTL, is validated in full, is built into a
 * complete new table, and only then replaces the published pointer. There is
 * no incremental path that mutates the live table, and there will not be one:
 * an in-place edit has a window in which the table is neither the old policy
 * nor the new one, and a flow classified in that window is decided by a policy
 * nobody wrote.
 *
 * Hot reload is still incremental on the wire — the daemon sends a delta — but
 * the driver expands it against the current table into a whole new table
 * before publishing. The saving is bandwidth, not a shortcut through the swap.
 *
 * # The lock
 *
 * EX_SPIN_LOCK in shared mode for readers. Classification runs on every
 * processor concurrently and installs happen once in a while, so a
 * reader-writer lock is the right shape. It raises to DISPATCH_LEVEL, which
 * classify is already at.
 *
 * The old table is not freed while the install holds the lock: a reader that
 * had already acquired shared access is still walking it. The exclusive
 * acquire drains those readers, and only then is the pointer swapped and the
 * old table released.
 */

#include "../inc/driver.h"
#include "../inc/wfp_helpers.h"

UFW_POLICY_TABLE *UfwPolicyAcquire(_Out_ KIRQL *oldIrql)
{
	*oldIrql = ExAcquireSpinLockShared(&g_ufw.policyLock);
	return g_ufw.policy;
}

VOID UfwPolicyRelease(_In_ KIRQL oldIrql)
{
	ExReleaseSpinLockShared(&g_ufw.policyLock, oldIrql);
}

static VOID UfwPolicyFree(_In_opt_ UFW_POLICY_TABLE *table)
{
	if (!table)
		return;
	if (table->wfpFilterIds)
		ExFreePoolWithTag(table->wfpFilterIds, UFW_POOL_TAG);
	ExFreePoolWithTag(table, UFW_POOL_TAG);
}

/*
 * Build the stage index, and refuse a table that is not sorted.
 *
 * The classifier walks stages using stageStart[] as bounds, which is only
 * correct if filters are grouped by stage in ascending order. The daemon sorts
 * before sending, so an unsorted table means either a bug there or a payload
 * that was tampered with; either way the right answer is to reject the whole
 * install rather than publish a table that evaluates stages out of order.
 */
static NTSTATUS UfwPolicyIndex(_Inout_ UFW_POLICY_TABLE *table)
{
	UINT32 i;
	UINT8 stage = 0;

	for (i = 0; i <= UFW_STAGE_COUNT; i++)
		table->stageStart[i] = table->filterCount;

	table->stageStart[0] = 0;
	for (i = 0; i < table->filterCount; i++) {
		UINT8 s = table->filters[i].stage;

		if (s >= UFW_STAGE_COUNT)
			return STATUS_INVALID_PARAMETER;
		if (s < stage)
			return STATUS_INVALID_PARAMETER;
		while (stage < s) {
			stage++;
			table->stageStart[stage] = i;
		}
	}
	while (stage < UFW_STAGE_COUNT) {
		stage++;
		table->stageStart[stage] = table->filterCount;
	}
	return STATUS_SUCCESS;
}

NTSTATUS UfwPolicyInstall(_In_ const UFW_INSTALL_HEADER *header,
			  _In_reads_bytes_(payloadBytes) const UINT8 *payload,
			  _In_ SIZE_T payloadBytes)
{
	UFW_POLICY_TABLE *table = NULL, *old = NULL;
	SIZE_T tableBytes, expected;
	KIRQL irql;
	NTSTATUS status;

	if (header->filterCount > UFW_MAX_RULES)
		return STATUS_INVALID_PARAMETER;

	expected = (SIZE_T)header->filterCount * sizeof(UFW_FILTER_SPEC);
	if (payloadBytes != expected)
		return STATUS_INVALID_BUFFER_SIZE;

	tableBytes = FIELD_OFFSET(UFW_POLICY_TABLE, filters) + expected;

	/* NonPagedPoolNx: classify runs at DISPATCH_LEVEL, where a page fault
	 * is a bugcheck, and the table must never be executable. */
	table = (UFW_POLICY_TABLE *)ExAllocatePool2(POOL_FLAG_NON_PAGED,
						    tableBytes, UFW_POOL_TAG);
	if (!table)
		return STATUS_INSUFFICIENT_RESOURCES;

	RtlZeroMemory(table, tableBytes);
	table->revision = header->policyRevision;
	table->filterCount = header->filterCount;
	table->defaultAction = header->defaultAction;
	table->abiRevision = header->abiRevision;
	RtlCopyMemory(table->rulesetHash, header->rulesetHash, 32);
	RtlCopyMemory(table->filters, payload, expected);

	status = UfwPolicyIndex(table);
	if (!NT_SUCCESS(status))
		goto fail;

	/*
	 * Room for two WFP filters per rule: a rule with no explicit direction
	 * needs one at each layer, and sizing for the worst case here means
	 * UfwWfpSyncFilters never has to reallocate mid-transaction.
	 */
	table->wfpFilterIds = (UINT64 *)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		(SIZE_T)table->filterCount * 2 * sizeof(UINT64) + sizeof(UINT64),
		UFW_POOL_TAG);
	if (!table->wfpFilterIds) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		goto fail;
	}

	/* Install the WFP filters *before* publishing the table. If this
	 * fails the old policy is still live and still correct, which is the
	 * only acceptable outcome for a failed install. */
	status = UfwWfpSyncFilters(table, g_ufw.policy);
	if (!NT_SUCCESS(status))
		goto fail;

	irql = ExAcquireSpinLockExclusive(&g_ufw.policyLock);
	old = g_ufw.policy;
	g_ufw.policy = table;
	ExReleaseSpinLockExclusive(&g_ufw.policyLock, irql);

	/* The exclusive acquire drained every reader of the old table, so it
	 * is safe to free once the lock is released. */
	UfwPolicyFree(old);

	DbgPrintEx(DPFLTR_IHVNETWORK_ID, DPFLTR_INFO_LEVEL,
		   "ufw: installed policy revision %llu (%u filters)\n",
		   table->revision, table->filterCount);
	return STATUS_SUCCESS;

fail:
	UfwPolicyFree(table);
	return status;
}

VOID UfwPolicyFlush(VOID)
{
	UFW_POLICY_TABLE *old;
	KIRQL irql;

	irql = ExAcquireSpinLockExclusive(&g_ufw.policyLock);
	old = g_ufw.policy;
	g_ufw.policy = NULL;
	ExReleaseSpinLockExclusive(&g_ufw.policyLock, irql);

	if (old) {
		UINT32 i;

		if (g_ufw.engineHandle) {
			for (i = 0; i < old->wfpFilterCount; i++)
				FwpmFilterDeleteById(g_ufw.engineHandle,
						     old->wfpFilterIds[i]);
		}
		UfwPolicyFree(old);
	}
}
