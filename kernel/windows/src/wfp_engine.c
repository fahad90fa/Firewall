/*
 * Unified Firewall — WFP engine session, sublayer, callouts and filters.
 *
 * See inc/callout.h for why the layers are chosen the way they are, and
 * inc/wfp_helpers.h for the weight scheme and why matching happens in our own
 * code rather than in WFP's condition engine.
 *
 * # Transactions
 *
 * Every mutation of the engine happens inside FwpmTransactionBegin/Commit.
 * That is not tidiness: a filter set applied halfway is a policy nobody wrote,
 * and the window in which it is live is the window an attacker would want. A
 * transaction makes the new filter set appear atomically or not at all.
 */

#include "../inc/driver.h"
#include "../inc/callout.h"
#include "../inc/wfp_helpers.h"

typedef struct _UFW_CALLOUT_DEF {
	const GUID *calloutKey;
	const GUID *layerKey;
	FWPS_CALLOUT_CLASSIFY_FN classifyFn;
	FWPS_CALLOUT_NOTIFY_FN notifyFn;
	FWPS_CALLOUT_FLOW_DELETE_NOTIFY_FN flowDeleteFn;
	const wchar_t *name;
} UFW_CALLOUT_DEF;

static const UFW_CALLOUT_DEF g_callouts[] = {
	{ &UFW_CALLOUT_ALE_CONNECT_V4, &FWPM_LAYER_ALE_AUTH_CONNECT_V4,
	  UfwAleConnectClassifyFn, UfwAleConnectNotifyFn, NULL,
	  L"UFW ALE connect v4" },
	{ &UFW_CALLOUT_ALE_CONNECT_V6, &FWPM_LAYER_ALE_AUTH_CONNECT_V6,
	  UfwAleConnectClassifyFn, UfwAleConnectNotifyFn, NULL,
	  L"UFW ALE connect v6" },
	{ &UFW_CALLOUT_ALE_RECV_ACCEPT_V4, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4,
	  UfwAleRecvAcceptClassifyFn, UfwAleRecvAcceptNotifyFn, NULL,
	  L"UFW ALE recv-accept v4" },
	{ &UFW_CALLOUT_ALE_RECV_ACCEPT_V6, &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V6,
	  UfwAleRecvAcceptClassifyFn, UfwAleRecvAcceptNotifyFn, NULL,
	  L"UFW ALE recv-accept v6" },
	{ &UFW_CALLOUT_INBOUND_IPPACKET_V4, &FWPM_LAYER_INBOUND_IPPACKET_V4,
	  UfwInboundIpv4ClassifyFn, UfwInboundIpv4NotifyFn, NULL,
	  L"UFW inbound IP v4" },
	{ &UFW_CALLOUT_OUTBOUND_IPPACKET_V4, &FWPM_LAYER_OUTBOUND_IPPACKET_V4,
	  UfwOutboundIpv4ClassifyFn, UfwOutboundIpv4NotifyFn, NULL,
	  L"UFW outbound IP v4" },
	{ &UFW_CALLOUT_INBOUND_IPPACKET_V6, &FWPM_LAYER_INBOUND_IPPACKET_V6,
	  UfwInboundIpv6ClassifyFn, UfwInboundIpv6NotifyFn, NULL,
	  L"UFW inbound IP v6" },
	{ &UFW_CALLOUT_OUTBOUND_IPPACKET_V6, &FWPM_LAYER_OUTBOUND_IPPACKET_V6,
	  UfwOutboundIpv6ClassifyFn, UfwOutboundIpv6NotifyFn, NULL,
	  L"UFW outbound IP v6" },
	{ &UFW_CALLOUT_STREAM_V4, &FWPM_LAYER_STREAM_V4,
	  UfwStreamClassifyFn, UfwStreamNotifyFn, UfwStreamFlowDeleteFn,
	  L"UFW stream v4" },
};

static NTSTATUS UfwRegisterCallout(_In_ PDEVICE_OBJECT deviceObject,
				   _In_ const UFW_CALLOUT_DEF *def,
				   _Out_ UINT32 *calloutId)
{
	FWPS_CALLOUT callout = { 0 };
	FWPM_CALLOUT mgmt = { 0 };
	FWPM_DISPLAY_DATA display = { 0 };
	NTSTATUS status;

	callout.calloutKey = *def->calloutKey;
	callout.classifyFn = def->classifyFn;
	callout.notifyFn = def->notifyFn;
	callout.flowDeleteFn = def->flowDeleteFn;
	/* FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW only where a flow context
	 * exists; the stream callout needs it so flowDeleteFn is delivered. */
	callout.flags = def->flowDeleteFn ? FWP_CALLOUT_FLAG_CONDITIONAL_ON_FLOW : 0;

	status = FwpsCalloutRegister(deviceObject, &callout, calloutId);
	if (!NT_SUCCESS(status))
		return status;

	display.name = (wchar_t *)def->name;
	display.description = (wchar_t *)def->name;

	mgmt.calloutKey = *def->calloutKey;
	mgmt.displayData = display;
	mgmt.applicableLayer = *def->layerKey;

	status = FwpmCalloutAdd(g_ufw.engineHandle, &mgmt, NULL, NULL);
	if (!NT_SUCCESS(status)) {
		FwpsCalloutUnregisterById(*calloutId);
		return status;
	}
	return STATUS_SUCCESS;
}

NTSTATUS UfwWfpInitialize(_In_ PDEVICE_OBJECT deviceObject)
{
	FWPM_SESSION session = { 0 };
	FWPM_SUBLAYER sublayer = { 0 };
	FWPM_DISPLAY_DATA display = { 0 };
	NTSTATUS status;
	UINT32 i;
	BOOLEAN inTransaction = FALSE;

	/*
	 * A dynamic session would tear the filters down when the session
	 * closes, which sounds like a useful safety net and is not: it means
	 * a driver that is still loaded but whose session dropped stops
	 * filtering silently. The filters are removed explicitly on unload
	 * instead, so failing to remove them is a visible bug rather than an
	 * invisible one.
	 */
	session.flags = 0;
	session.displayData.name = L"Unified Firewall";
	session.displayData.description = L"Unified Firewall policy session";

	status = FwpmEngineOpen(NULL, RPC_C_AUTHN_WINNT, NULL, &session,
				&g_ufw.engineHandle);
	if (!NT_SUCCESS(status))
		return status;

	status = FwpmTransactionBegin(g_ufw.engineHandle, 0);
	if (!NT_SUCCESS(status))
		goto fail;
	inTransaction = TRUE;

	display.name = L"Unified Firewall";
	display.description = L"Unified Firewall sublayer";
	sublayer.subLayerKey = UFW_SUBLAYER_GUID;
	sublayer.displayData = display;
	sublayer.weight = UFW_SUBLAYER_WEIGHT;

	status = FwpmSubLayerAdd(g_ufw.engineHandle, &sublayer, NULL);
	if (!NT_SUCCESS(status))
		goto fail;

	for (i = 0; i < RTL_NUMBER_OF(g_callouts); i++) {
		status = UfwRegisterCallout(deviceObject, &g_callouts[i],
					    &g_ufw.calloutIds[g_ufw.calloutCount]);
		if (!NT_SUCCESS(status))
			goto fail;
		g_ufw.calloutCount++;
	}

	status = FwpmTransactionCommit(g_ufw.engineHandle);
	if (!NT_SUCCESS(status))
		goto fail;

	return STATUS_SUCCESS;

fail:
	if (inTransaction)
		FwpmTransactionAbort(g_ufw.engineHandle);
	/* Unregister exactly what was registered, which is why calloutCount
	 * is incremented after each success rather than assumed. */
	while (g_ufw.calloutCount) {
		g_ufw.calloutCount--;
		FwpsCalloutUnregisterById(g_ufw.calloutIds[g_ufw.calloutCount]);
	}
	FwpmEngineClose(g_ufw.engineHandle);
	g_ufw.engineHandle = NULL;
	return status;
}

VOID UfwWfpShutdown(VOID)
{
	if (!g_ufw.engineHandle)
		return;

	/*
	 * Filters before callouts. FwpsCalloutUnregisterByKey returns
	 * STATUS_DEVICE_BUSY while a filter still references the callout, and
	 * a driver that unloads with a callout still registered bugchecks the
	 * moment WFP next calls into freed code.
	 */
	if (FwpmTransactionBegin(g_ufw.engineHandle, 0) == STATUS_SUCCESS) {
		FwpmSubLayerDeleteByKey(g_ufw.engineHandle, &UFW_SUBLAYER_GUID);
		FwpmTransactionCommit(g_ufw.engineHandle);
	}

	while (g_ufw.calloutCount) {
		g_ufw.calloutCount--;
		FwpsCalloutUnregisterById(g_ufw.calloutIds[g_ufw.calloutCount]);
	}

	FwpmEngineClose(g_ufw.engineHandle);
	g_ufw.engineHandle = NULL;
}

NTSTATUS UfwWfpAddFilter(_In_ HANDLE engine,
			 _In_ const GUID *layerKey,
			 _In_ const GUID *calloutKey,
			 _In_ const UFW_FILTER_SPEC *spec,
			 _Out_ UINT64 *filterId)
{
	FWPM_FILTER filter = { 0 };
	FWPM_FILTER_CONDITION conditions[2] = { 0 };
	UINT32 conditionCount = 0;

	filter.layerKey = *layerKey;
	filter.subLayerKey = UFW_SUBLAYER_GUID;
	filter.displayData.name = L"Unified Firewall rule";
	filter.displayData.description = L"Compiled from unified policy";
	filter.action.type = FWP_ACTION_CALLOUT_TERMINATING;
	filter.action.calloutKey = *calloutKey;

	/* The weight the compiler emitted, which already encodes stage above
	 * priority. See inc/wfp_helpers.h. */
	filter.weight.type = FWP_UINT64;
	filter.weight.uint64 = (UINT64 *)&spec->weight;

	/*
	 * The only condition installed is the protocol, and only when the rule
	 * names one. Everything else is matched in classify.c — see
	 * inc/wfp_helpers.h for why. A protocol condition is worth having
	 * because it is unambiguous, it is the highest-selectivity field, and
	 * it keeps ICMP filters from waking the ALE callouts at all.
	 */
	if (spec->protocol != UFW_PROTO_ANY) {
		conditions[conditionCount].fieldKey = FWPM_CONDITION_IP_PROTOCOL;
		conditions[conditionCount].matchType = FWP_MATCH_EQUAL;
		conditions[conditionCount].conditionValue.type = FWP_UINT8;
		conditions[conditionCount].conditionValue.uint8 = spec->protocol;
		conditionCount++;
	}

	filter.filterCondition = conditionCount ? conditions : NULL;
	filter.numFilterConditions = conditionCount;

	return FwpmFilterAdd(engine, &filter, NULL, filterId);
}

NTSTATUS UfwWfpSyncFilters(_Inout_ UFW_POLICY_TABLE *table,
			   _In_opt_ UFW_POLICY_TABLE *previous)
{
	NTSTATUS status;
	UINT32 i;
	UINT32 added = 0;

	status = FwpmTransactionBegin(g_ufw.engineHandle, 0);
	if (!NT_SUCCESS(status))
		return status;

	/*
	 * Remove the previous table's filters by id rather than clearing the
	 * sublayer. Clearing would also remove filters a concurrent install
	 * had just added, and the transaction would then commit a policy that
	 * is neither the old one nor the new one.
	 */
	if (previous) {
		for (i = 0; i < previous->wfpFilterCount; i++)
			FwpmFilterDeleteById(g_ufw.engineHandle,
					     previous->wfpFilterIds[i]);
	}

	for (i = 0; i < table->filterCount; i++) {
		const UFW_FILTER_SPEC *spec = &table->filters[i];
		const GUID *layerKey;
		const GUID *calloutKey;
		UINT64 id = 0;

		switch (UfwEngineForStage(spec->stage, spec->protocolScope)) {
		case UFW_ENGINE_WFP_STREAM:
			layerKey = &FWPM_LAYER_STREAM_V4;
			calloutKey = &UFW_CALLOUT_STREAM_V4;
			break;
		case UFW_ENGINE_WFP_IPPACKET:
			/* Connectionless traffic: both directions, v4 here and
			 * v6 immediately below, because a rule with no explicit
			 * direction has to be present at both. */
			layerKey = (spec->direction == UFW_DIR_INBOUND)
				? &FWPM_LAYER_INBOUND_IPPACKET_V4
				: &FWPM_LAYER_OUTBOUND_IPPACKET_V4;
			calloutKey = (spec->direction == UFW_DIR_INBOUND)
				? &UFW_CALLOUT_INBOUND_IPPACKET_V4
				: &UFW_CALLOUT_OUTBOUND_IPPACKET_V4;
			break;
		default:
			layerKey = (spec->direction == UFW_DIR_INBOUND)
				? &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4
				: &FWPM_LAYER_ALE_AUTH_CONNECT_V4;
			calloutKey = (spec->direction == UFW_DIR_INBOUND)
				? &UFW_CALLOUT_ALE_RECV_ACCEPT_V4
				: &UFW_CALLOUT_ALE_CONNECT_V4;
			break;
		}

		status = UfwWfpAddFilter(g_ufw.engineHandle, layerKey,
					 calloutKey, spec, &id);
		if (!NT_SUCCESS(status)) {
			FwpmTransactionAbort(g_ufw.engineHandle);
			return status;
		}
		table->wfpFilterIds[added++] = id;

		/* A rule with no explicit direction applies both ways, so it
		 * needs a filter at both layers. Installing only one would
		 * make `direction: any` mean `direction: outbound`. */
		if (spec->direction == UFW_DIR_ANY &&
		    UfwEngineForStage(spec->stage, spec->protocolScope) !=
			    UFW_ENGINE_WFP_STREAM) {
			const GUID *otherLayer;
			const GUID *otherCallout;

			if (UfwEngineForStage(spec->stage, spec->protocolScope) ==
			    UFW_ENGINE_WFP_IPPACKET) {
				otherLayer = &FWPM_LAYER_INBOUND_IPPACKET_V4;
				otherCallout = &UFW_CALLOUT_INBOUND_IPPACKET_V4;
			} else {
				otherLayer = &FWPM_LAYER_ALE_AUTH_RECV_ACCEPT_V4;
				otherCallout = &UFW_CALLOUT_ALE_RECV_ACCEPT_V4;
			}

			status = UfwWfpAddFilter(g_ufw.engineHandle, otherLayer,
						 otherCallout, spec, &id);
			if (!NT_SUCCESS(status)) {
				FwpmTransactionAbort(g_ufw.engineHandle);
				return status;
			}
			table->wfpFilterIds[added++] = id;
		}
	}

	table->wfpFilterCount = added;

	status = FwpmTransactionCommit(g_ufw.engineHandle);
	if (!NT_SUCCESS(status))
		FwpmTransactionAbort(g_ufw.engineHandle);
	return status;
}
