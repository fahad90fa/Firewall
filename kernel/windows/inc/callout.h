/*
 * Unified Firewall — callout registration, and the layer-ordering problem.
 *
 * # The problem
 *
 * WFP layers do not fire in the same relative order in both directions:
 *
 *   outbound:  ALE_AUTH_CONNECT   ->  OUTBOUND_IPPACKET
 *   inbound:   INBOUND_IPPACKET   ->  ALE_AUTH_RECV_ACCEPT
 *
 * Read that twice, because it is the whole reason this driver is shaped the
 * way it is. If the policy were split naively — packet rules at the IP
 * layers, identity rules at ALE — then for outbound traffic identity would be
 * evaluated first and for inbound traffic it would be evaluated second. The
 * same policy would mean two different things depending on which way the
 * packet was travelling, and neither would match Linux or macOS.
 *
 * # The resolution
 *
 * Every connection-oriented flow is decided at ALE, in one place, where both
 * the five-tuple and the owning process are available. The IP packet layers
 * carry the same rule table but evaluate only filters scoped to
 * UFW_SCOPE_CONNECTIONLESS — the protocols ALE never sees, principally ICMP.
 *
 * So the two layer families partition the traffic rather than layering over
 * it. No flow is decided twice, and the order in which the layers fire stops
 * mattering, because for any given packet only one of them will act.
 *
 * The stream layer is separate again: it does not decide, it observes. It
 * feeds reassembled bytes to the DPI engine and terminates a flow that a
 * signature condemns. Its verdict can only ever be "block a flow ALE already
 * permitted", which is what `allow-inspect` means.
 *
 * # Why not just use ALE for everything
 *
 * ALE does not fire for ICMP, and a host firewall that cannot express "drop
 * inbound pings" is missing something operators reasonably expect. The IP
 * packet layers are the only place ICMP is visible.
 */

#pragma once

#include "driver.h"
#include "packet_info.h"

/*
 * The sublayer.
 *
 * A dedicated sublayer with a defined weight, rather than adding filters to
 * an existing one. Filters in different sublayers are all consulted and the
 * highest-weight sublayer's verdict wins, so having our own means an
 * unrelated product's filters cannot silently override a policy decision, and
 * ours cannot silently override theirs — whoever has the higher sublayer
 * weight is a deliberate, visible choice rather than an accident of
 * installation order.
 */
DEFINE_GUID(UFW_SUBLAYER_GUID,
	    0x8f2a5c14, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);

DEFINE_GUID(UFW_CALLOUT_ALE_CONNECT_V4,
	    0x8f2a5c15, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_ALE_CONNECT_V6,
	    0x8f2a5c16, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_ALE_RECV_ACCEPT_V4,
	    0x8f2a5c17, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_ALE_RECV_ACCEPT_V6,
	    0x8f2a5c18, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_INBOUND_IPPACKET_V4,
	    0x8f2a5c19, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_OUTBOUND_IPPACKET_V4,
	    0x8f2a5c1a, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_INBOUND_IPPACKET_V6,
	    0x8f2a5c1b, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_OUTBOUND_IPPACKET_V6,
	    0x8f2a5c1c, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);
DEFINE_GUID(UFW_CALLOUT_STREAM_V4,
	    0x8f2a5c1d, 0x7b3d, 0x4e91, 0xa2, 0x6c, 0x11, 0x9d, 0x4f, 0x83, 0x0b, 0x71);

/*
 * The classify function each callout provides.
 *
 * They are all thin: extract the layer's field indices into UFW_FLOW_FACTS,
 * call UfwClassify with the right scope, translate the answer back into
 * WFP's terms. Everything interesting is in classify.c, which is what makes
 * the equivalence argument reviewable — there is one decision procedure, not
 * nine.
 */

#define UFW_CALLOUT_DECL(name) \
	VOID NTAPI name##ClassifyFn( \
		_In_ const FWPS_INCOMING_VALUES *inFixedValues, \
		_In_ const FWPS_INCOMING_METADATA_VALUES *inMetaValues, \
		_Inout_opt_ VOID *layerData, \
		_In_opt_ const VOID *classifyContext, \
		_In_ const FWPS_FILTER *filter, \
		_In_ UINT64 flowContext, \
		_Inout_ FWPS_CLASSIFY_OUT *classifyOut); \
	NTSTATUS NTAPI name##NotifyFn( \
		_In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType, \
		_In_ const GUID *filterKey, \
		_Inout_ FWPS_FILTER *filter)

UFW_CALLOUT_DECL(UfwAleConnect);
UFW_CALLOUT_DECL(UfwAleRecvAccept);
UFW_CALLOUT_DECL(UfwInboundIpv4);
UFW_CALLOUT_DECL(UfwOutboundIpv4);
UFW_CALLOUT_DECL(UfwInboundIpv6);
UFW_CALLOUT_DECL(UfwOutboundIpv6);
UFW_CALLOUT_DECL(UfwStream);

/* The stream callout also needs flow-delete notification, so the reassembly
 * context is released when the flow ends rather than waiting for a timeout. */
VOID NTAPI UfwStreamFlowDeleteFn(_In_ UINT16 layerId, _In_ UINT32 calloutId,
				 _In_ UINT64 flowContext);

/*
 * Translate a decision into what WFP expects, and apply enforcement mode.
 *
 * Shared by every callout so that monitor mode cannot be implemented in eight
 * places and forgotten in one. FWPS_RIGHT_ACTION_WRITE is cleared on a block
 * so that no lower-weight filter can override it — a policy denial is final
 * within this sublayer.
 */
FORCEINLINE VOID UfwApplyDecision(_In_ const UFW_DECISION *decision,
				  _Inout_ FWPS_CLASSIFY_OUT *classifyOut)
{
	LONG mode = InterlockedCompareExchange(&g_ufw.mode, 0, 0);

	if (mode == UFW_MODE_EMERGENCY_ALLOW) {
		classifyOut->actionType = FWP_ACTION_PERMIT;
		return;
	}

	if (decision->action == FWP_ACTION_BLOCK) {
		UFW_COUNT(packetsDenied);
		if (mode == UFW_MODE_MONITOR) {
			/* Computed, logged, not enforced. This is how a
			 * deployment builds the inventory a default-deny
			 * policy needs without an outage first. */
			classifyOut->actionType = FWP_ACTION_PERMIT;
			return;
		}
		classifyOut->actionType = FWP_ACTION_BLOCK;
		classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
		return;
	}

	UFW_COUNT(packetsAllowed);
	classifyOut->actionType = FWP_ACTION_PERMIT;
}
