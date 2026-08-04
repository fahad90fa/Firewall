/*
 * Unified Firewall — the decision, Windows.
 *
 * This is the Windows half of the equivalence claim: everything here must
 * agree with `CompiledPolicy::evaluate` in shared/src/policy_types.rs, with
 * kernel/linux/src/classify.c, and with the Swift RuleEngine, for every
 * input. The compiler's equivalence verifier checks that claim at build time
 * against a scenario corpus derived from the policy.
 *
 * The structure is intentionally identical to the Linux classifier: stages in
 * a fixed order, filters within a stage in a fixed order, first terminal
 * action wins. Where the two files differ, they differ because the platform
 * forced it, and each such place carries a comment saying so. Reading them
 * side by side should be boring; anywhere it is interesting is a place to
 * look when the verifier disagrees.
 *
 * The one structural difference: `scope`. WFP calls this function from
 * several layers, and the layers see overlapping traffic. Scope is what keeps
 * two layers from both deciding one flow. See UFW_PROTOCOL_SCOPE.
 */

#include "../inc/driver.h"

#ifdef ALLOC_PRAGMA
/* Deliberately not pageable. Classification runs at DISPATCH_LEVEL, where a
 * page fault is a bugcheck. */
#endif

/* --- address and port matching --------------------------------------------- */

BOOLEAN UfwCidrContains(_In_ const UFW_CIDR *cidr,
			_In_reads_(16) const UINT8 *addr, _In_ BOOLEAN isV6)
{
	UINT8 fullBytes, restBits, mask;
	const UINT8 *base;

	/* A v4 filter never matches a v6 address. An IPv4-mapped v6 address
	 * would otherwise satisfy a v4 CIDR through one path and not another
	 * depending on how WFP presented it, and that ambiguity is exactly
	 * the kind that becomes a bypass. */
	if ((cidr->family == 6) != (isV6 != FALSE))
		return FALSE;

	/* The union arm is chosen by family, so a v4 entry never reads the
	 * twelve bytes of padding a v6 entry would have occupied. */
	base = (cidr->family == 6) ? cidr->addr6 : cidr->addr;

	fullBytes = (UINT8)(cidr->prefix / 8);
	restBits = (UINT8)(cidr->prefix % 8);

	if (fullBytes && RtlCompareMemory(base, addr, fullBytes) != fullBytes)
		return FALSE;

	if (restBits) {
		mask = (UINT8)(0xFFu << (8 - restBits));
		if ((base[fullBytes] & mask) != (addr[fullBytes] & mask))
			return FALSE;
	}
	return TRUE;
}

static BOOLEAN UfwAddrMatch(_In_reads_opt_(count) const UFW_CIDR *cidrs,
			    _In_ UINT8 count, _In_ UINT8 zoneMask,
			    _In_reads_(16) const UINT8 *addr,
			    _In_ BOOLEAN isV6, _In_ UINT8 zone,
			    _In_ BOOLEAN negate)
{
	BOOLEAN hit = FALSE;
	UINT8 i;

	if (count == 0 && zoneMask == 0)
		return TRUE;

	for (i = 0; i < count && i < UFW_MAX_CIDRS_PER_RULE; i++) {
		if (UfwCidrContains(&cidrs[i], addr, isV6)) {
			hit = TRUE;
			break;
		}
	}
	if (!hit && zoneMask)
		hit = (zoneMask & (1u << zone)) != 0;

	return negate ? !hit : hit;
}

static BOOLEAN UfwPortMatch(_In_reads_opt_(count) const UFW_PORT_RANGE *ranges,
			    _In_ UINT8 count, _In_ UINT16 port,
			    _In_ UINT8 protocol)
{
	UINT8 i;

	if (count == 0)
		return TRUE;

	/*
	 * A port constraint on a protocol with no ports never matches, not
	 * even negated. "Port is not 53" is not vacuously true for ICMP — it
	 * is unanswerable, and an unanswerable predicate must not permit.
	 * Identical to the Linux classifier and the reference; one of the
	 * places the three implementations most easily drift.
	 */
	if (protocol != IPPROTO_TCP && protocol != IPPROTO_UDP &&
	    protocol != UFW_PROTO_ANY)
		return FALSE;

	for (i = 0; i < count && i < UFW_MAX_PORT_RANGES; i++) {
		if (port >= ranges[i].lo && port <= ranges[i].hi)
			return TRUE;
	}
	return FALSE;
}

/* --- identity matching ------------------------------------------------------- */

BOOLEAN UfwPathMatch(_In_z_ const wchar_t *pattern, _In_opt_z_ const wchar_t *path,
		     _In_ BOOLEAN caseInsensitive)
{
	const wchar_t *p = pattern, *s = path;
	const wchar_t *star = NULL, *starS = NULL;

	if (!path)
		return FALSE;

	/*
	 * Iterative glob with one backtrack point. The recursive form is
	 * exponential on patterns like `*a*a*a*b`, and an image path is
	 * attacker-influenced: a process can be named anything. This form is
	 * O(n*m) worst case with no stack growth, which is what DISPATCH_LEVEL
	 * requires — there is no room to recurse and no way to recover from
	 * exhausting the kernel stack.
	 */
	while (*s) {
		wchar_t pc = *p, sc = *s;

		if (caseInsensitive) {
			if (pc >= L'A' && pc <= L'Z')
				pc = (wchar_t)(pc + 32);
			if (sc >= L'A' && sc <= L'Z')
				sc = (wchar_t)(sc + 32);
		}

		if (*p == L'?' || (*p && pc == sc)) {
			p++;
			s++;
		} else if (*p == L'*') {
			star = p++;
			starS = s;
		} else if (star) {
			p = star + 1;
			s = ++starS;
		} else {
			return FALSE;
		}
	}
	while (*p == L'*')
		p++;
	return *p == L'\0';
}

static BOOLEAN UfwStringEqual(_In_opt_z_ const wchar_t *a,
			      _In_opt_z_ const wchar_t *b)
{
	if (!a || !b)
		return FALSE;
	while (*a && *b) {
		if (*a != *b)
			return FALSE;
		a++;
		b++;
	}
	return *a == *b;
}

static BOOLEAN UfwFingerprintMatch(_In_ const UFW_FINGERPRINT *fp,
				   _In_ const UFW_FLOW_FACTS *facts)
{
	BOOLEAN ok;
	UINT8 i;

	/* Conjunctive: a fingerprint naming both a path and a signer means
	 * "this image, signed by them", not "either". */
	if (fp->pathCount) {
		ok = FALSE;
		for (i = 0; i < fp->pathCount && i < UFW_MAX_PATHS_PER_FP; i++) {
			if (UfwPathMatch(fp->paths[i], facts->imagePath,
					 fp->caseInsensitive)) {
				ok = TRUE;
				break;
			}
		}
		if (!ok)
			return FALSE;
	}

	if (fp->hashCount) {
		ok = FALSE;
		for (i = 0; i < fp->hashCount && i < UFW_MAX_HASHES_PER_FP; i++) {
			if (fp->hashes[i] &&
			    RtlCompareMemory(fp->hashes[i], facts->sha256, 32) == 32) {
				ok = TRUE;
				break;
			}
		}
		if (!ok)
			return FALSE;
	}

	if (fp->signerCount) {
		ok = FALSE;
		for (i = 0; i < fp->signerCount && i < UFW_MAX_SIGNERS_PER_FP; i++) {
			if (UfwStringEqual(fp->signers[i], facts->signer)) {
				ok = TRUE;
				break;
			}
		}
		if (!ok)
			return FALSE;
	}

	return TRUE;
}

static BOOLEAN UfwAppMatch(_In_ const UFW_APP_MATCH *m,
			   _In_ const UFW_FLOW_FACTS *facts)
{
	BOOLEAN hit;
	UINT8 i;

	/*
	 * The fail-closed asymmetry.
	 *
	 * An unresolved identity does not match an application predicate, and
	 * does not match a negated one either. If it did, "deny anything that
	 * is not our signed binary" would be satisfied by any process the
	 * driver could not inspect — which, at DISPATCH_LEVEL with an
	 * asynchronous resolver, is a set an attacker can arrange to be in
	 * simply by being new.
	 */
	if (!facts->identityValid)
		return FALSE;

	if (m->trustMask && !(m->trustMask & (1u << facts->trust)))
		return FALSE;

	if (m->requireValidSignature && !facts->signatureValid)
		return FALSE;

	/* Fingerprints are disjunctive across platforms. */
	if (m->fingerprintCount == 0) {
		hit = TRUE;
	} else {
		hit = FALSE;
		for (i = 0; i < m->fingerprintCount && i < UFW_MAX_FINGERPRINTS; i++) {
			if (UfwFingerprintMatch(&m->fingerprints[i], facts)) {
				hit = TRUE;
				break;
			}
		}
	}

	return m->negate ? !hit : hit;
}

/* --- DPI matching -------------------------------------------------------------- */

static BOOLEAN UfwDpiMatch(_In_ const UFW_DPI_MATCH *m,
			   _In_ const UFW_FLOW_FACTS *facts)
{
	BOOLEAN hit;
	UINT8 i, j;

	if (!facts->dpiValid)
		return FALSE;

	if (m->l7Count) {
		hit = FALSE;
		for (i = 0; i < m->l7Count && i < UFW_MAX_L7_PER_RULE; i++) {
			if (m->l7[i] == facts->l7) {
				hit = TRUE;
				break;
			}
		}
		if (!hit)
			return FALSE;
	}

	if (m->signatureCount == 0)
		return TRUE;

	for (i = 0; i < m->signatureCount && i < UFW_MAX_SIGNATURES_PER_RULE; i++) {
		for (j = 0; j < facts->matchedCount &&
			    j < UFW_MAX_SIGNATURES_PER_RULE; j++) {
			if (m->signatureIds[i] == facts->matchedSignatures[j])
				return TRUE;
		}
	}
	return FALSE;
}

/* --- schedule ------------------------------------------------------------------- */

static BOOLEAN UfwScheduleMatch(_In_ const UFW_SCHEDULE *s,
				_In_ const UFW_FLOW_FACTS *facts)
{
	UINT16 day, minuteOfDay;

	/* No clock, no match. A scheduled rule whose window cannot be
	 * evaluated stands down rather than applying at the wrong time. */
	if (!facts->minuteValid)
		return FALSE;

	day = (UINT16)(facts->minuteOfWeek / 1440u);
	minuteOfDay = (UINT16)(facts->minuteOfWeek % 1440u);

	if (!(s->dayMask & (1u << day)))
		return FALSE;

	/* A window written `start: "22:00", end: "06:00"` wraps midnight and
	 * is two intervals rather than one. */
	if (s->startMinute <= s->endMinute)
		return minuteOfDay >= s->startMinute && minuteOfDay < s->endMinute;
	return minuteOfDay >= s->startMinute || minuteOfDay < s->endMinute;
}

/* --- stage gating ----------------------------------------------------------------- */

/*
 * Whether a stage runs at all for this protocol.
 *
 * Identity, app-dpi and stream need a socket with an owning process and a
 * payload. ICMP has neither: ALE never fires for it, and the IP packet layers
 * that do fire carry no process context. Gating on the *stage* rather than on
 * the individual predicates matters for a filter that sits at one of those
 * stages without an app or DPI clause — a terminal `layer: stream` deny, say.
 * Without this check the three platforms would agree on the verdict for an
 * ICMP packet while disagreeing about which rule produced it, which breaks
 * cross-platform log correlation and which a verdict-only comparison would
 * never see.
 */
static BOOLEAN UfwStageApplies(_In_ UINT8 stage, _In_ UINT8 protocol)
{
	switch (stage) {
	case UFW_STAGE_PERIMETER:
	case UFW_STAGE_PACKET:
		return TRUE;
	default:
		return protocol == IPPROTO_TCP || protocol == IPPROTO_UDP ||
		       protocol == UFW_PROTO_ANY;
	}
}

/*
 * Whether this filter belongs to the layer that is asking.
 *
 * A filter scoped to connection-oriented traffic is installed at ALE and must
 * not be evaluated again by the IP packet callouts, which see the same
 * packets afterwards. Without this the two layers would each apply the rule
 * and the second could contradict the first — and because WFP's layer order
 * is direction-dependent, *which* one contradicted would depend on which way
 * the packet was going.
 */
static BOOLEAN UfwScopeApplies(_In_ UINT8 filterScope, _In_ UFW_PROTOCOL_SCOPE asking)
{
	if (asking == UFW_SCOPE_ALL || filterScope == UFW_SCOPE_ALL)
		return TRUE;
	return filterScope == (UINT8)asking;
}

/* --- the filter --------------------------------------------------------------------- */

static BOOLEAN UfwFilterMatches(_In_ const UFW_FILTER_SPEC *filter,
				_In_ const UFW_FLOW_FACTS *facts,
				_In_ UFW_PROTOCOL_SCOPE scope)
{
	if (!UfwScopeApplies(filter->protocolScope, scope))
		return FALSE;

	if (!UfwStageApplies(filter->stage, facts->protocol))
		return FALSE;

	if (filter->direction != UFW_DIR_ANY && filter->direction != facts->direction)
		return FALSE;

	if (filter->protocol != UFW_PROTO_ANY && filter->protocol != facts->protocol)
		return FALSE;

	if (!UfwAddrMatch(filter->srcCidrs, filter->srcCidrCount,
			  filter->srcZoneMask, facts->srcAddr, facts->isV6,
			  facts->srcZone,
			  (filter->flags & UFW_FLAG_NEGATE_SRC) != 0))
		return FALSE;

	if (!UfwAddrMatch(filter->dstCidrs, filter->dstCidrCount,
			  filter->dstZoneMask, facts->dstAddr, facts->isV6,
			  facts->dstZone,
			  (filter->flags & UFW_FLAG_NEGATE_DST) != 0))
		return FALSE;

	if (!UfwPortMatch(filter->srcPorts, filter->srcPortCount,
			  facts->srcPort, facts->protocol))
		return FALSE;

	if (!UfwPortMatch(filter->dstPorts, filter->dstPortCount,
			  facts->dstPort, facts->protocol))
		return FALSE;

	if ((filter->flags & UFW_FLAG_HAS_SCHEDULE) &&
	    !UfwScheduleMatch(&filter->schedule, facts))
		return FALSE;

	if ((filter->flags & UFW_FLAG_NEEDS_IDENTITY) &&
	    !UfwAppMatch(&filter->app, facts))
		return FALSE;

	if ((filter->flags & UFW_FLAG_NEEDS_DPI) &&
	    !UfwDpiMatch(&filter->dpi, facts))
		return FALSE;

	return TRUE;
}

/* A filter with a DPI clause contributes the clause's onMatch action, which
 * is what makes `action: allow` + `on_match: deny` mean "permit unless the
 * payload trips". */
static UINT8 UfwEffectiveAction(_In_ const UFW_FILTER_SPEC *filter)
{
	if (filter->flags & UFW_FLAG_NEEDS_DPI)
		return filter->dpi.onMatch;
	return filter->action == FWP_ACTION_BLOCK ? UFW_ACTION_DENY : UFW_ACTION_ALLOW;
}

/* --- the loop ------------------------------------------------------------------------ */

VOID UfwClassify(_In_ const UFW_FLOW_FACTS *facts,
		 _In_ UFW_PROTOCOL_SCOPE scope,
		 _Out_ UFW_DECISION *decision)
{
	UFW_POLICY_TABLE *table;
	KIRQL oldIrql;
	UINT8 stage;
	BOOLEAN provisionalAllow = FALSE;
	UINT32 provisionalRule = UFW_RULE_ID_DEFAULT;
	const char *provisionalName = NULL;

	decision->action = FWP_ACTION_BLOCK;
	decision->stage = UFW_STAGE_PACKET;
	decision->ruleId = UFW_RULE_ID_NO_POLICY;
	decision->ruleName = "no-policy";
	decision->logged = 1;

	table = UfwPolicyAcquire(&oldIrql);
	if (!table) {
		/* Loaded, callouts registered, holding no policy. Blocking is
		 * the only honest verdict: the driver is either starting up or
		 * its daemon died, and neither is a reason to stop filtering. */
		UfwPolicyRelease(oldIrql);
		return;
	}

	for (stage = 0; stage < UFW_STAGE_COUNT; stage++) {
		UINT32 i;
		UINT32 begin = table->stageStart[stage];
		UINT32 end = table->stageStart[stage + 1];

		for (i = begin; i < end && i < table->filterCount; i++) {
			const UFW_FILTER_SPEC *filter = &table->filters[i];
			UINT8 action;

			if (!UfwFilterMatches(filter, facts, scope))
				continue;

			action = UfwEffectiveAction(filter);

			if (action == UFW_ACTION_ALLOW) {
				decision->action = FWP_ACTION_PERMIT;
				decision->stage = stage;
				decision->ruleId = filter->ruleId;
				decision->ruleName = filter->name;
				decision->logged = (filter->flags & UFW_FLAG_LOG) ? 1 : 0;
				UfwPolicyRelease(oldIrql);
				return;
			}
			if (action == UFW_ACTION_DENY) {
				decision->action = FWP_ACTION_BLOCK;
				decision->stage = stage;
				decision->ruleId = filter->ruleId;
				decision->ruleName = filter->name;
				decision->logged = (filter->flags & UFW_FLAG_LOG) ? 1 : 0;
				UfwPolicyRelease(oldIrql);
				return;
			}
			if (action == UFW_ACTION_ALLOW_INSPECT) {
				/* A provisional permit: remember it and keep
				 * going, because a later stage may still deny.
				 * Only the first is recorded, so the log names
				 * the rule that granted the permit rather than
				 * the last one that would have. */
				if (!provisionalAllow) {
					provisionalAllow = TRUE;
					provisionalRule = filter->ruleId;
					provisionalName = filter->name;
				}
				continue;
			}
			if (action == UFW_ACTION_ALERT) {
				UFW_DECISION alert;

				alert.action = FWP_ACTION_PERMIT;
				alert.stage = stage;
				alert.logged = 1;
				alert.reserved = 0;
				alert.ruleId = filter->ruleId;
				alert.ruleName = filter->name;
				UfwLogDecision(facts, &alert);
				continue;
			}
			/* UFW_ACTION_CONTINUE and anything unrecognised fall
			 * through to the next filter. An unrecognised action
			 * must not decide anything: it means the driver and
			 * the compiler disagree, and the safe reading is that
			 * this filter contributed nothing. */
		}
	}

	if (provisionalAllow) {
		decision->action = FWP_ACTION_PERMIT;
		decision->ruleId = provisionalRule;
		decision->ruleName = provisionalName;
		decision->stage = UFW_STAGE_PACKET;
		decision->logged = 1;
	} else {
		decision->action = (table->defaultAction == UFW_ACTION_ALLOW)
			? FWP_ACTION_PERMIT : FWP_ACTION_BLOCK;
		decision->ruleId = UFW_RULE_ID_DEFAULT;
		decision->ruleName = "policy-default";
		decision->stage = UFW_STAGE_PACKET;
		decision->logged = 1;
	}

	UfwPolicyRelease(oldIrql);
}

/* --- fact extraction --------------------------------------------------------------------- */

/*
 * WFP hands the same conceptual field at a different index in every layer, so
 * each callout passes its own indices in. Rather than a table of index
 * mappings — which is easy to get subtly wrong and impossible to notice —
 * each callout builds the facts it can and this helper fills in what is
 * derivable from them.
 */
NTSTATUS UfwFactsFromClassify(_In_ const FWPS_INCOMING_VALUES *inFixedValues,
			      _In_ const FWPS_INCOMING_METADATA_VALUES *metadata,
			      _In_ UINT8 direction,
			      _Out_ UFW_FLOW_FACTS *facts)
{
	UNREFERENCED_PARAMETER(inFixedValues);

	RtlZeroMemory(facts, sizeof(*facts));
	facts->direction = direction;

	if (metadata &&
	    FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_PROCESS_ID)) {
		facts->processId = (UINT32)metadata->processId;
	}
	if (metadata &&
	    FWPS_IS_METADATA_FIELD_PRESENT(metadata, FWPS_METADATA_FIELD_FLOW_HANDLE)) {
		facts->flowId = metadata->flowHandle;
	}

	return STATUS_SUCCESS;
}

/* --- zones ------------------------------------------------------------------------------- */

static UFW_CIDR g_internalZones[UFW_MAX_CIDRS_PER_RULE];
static UINT8 g_internalZoneCount;
static UFW_CIDR g_perimeterZones[UFW_MAX_CIDRS_PER_RULE];
static UINT8 g_perimeterZoneCount;

VOID UfwZoneInstall(_In_reads_(internalCount) const UFW_CIDR *internal,
		    _In_ UINT8 internalCount,
		    _In_reads_(perimeterCount) const UFW_CIDR *perimeter,
		    _In_ UINT8 perimeterCount)
{
	if (internalCount > UFW_MAX_CIDRS_PER_RULE)
		internalCount = UFW_MAX_CIDRS_PER_RULE;
	if (perimeterCount > UFW_MAX_CIDRS_PER_RULE)
		perimeterCount = UFW_MAX_CIDRS_PER_RULE;

	RtlCopyMemory(g_internalZones, internal, internalCount * sizeof(UFW_CIDR));
	g_internalZoneCount = internalCount;
	RtlCopyMemory(g_perimeterZones, perimeter, perimeterCount * sizeof(UFW_CIDR));
	g_perimeterZoneCount = perimeterCount;
}

UINT8 UfwZoneOf(_In_reads_(16) const UINT8 *addr, _In_ BOOLEAN isV6)
{
	static const UINT8 v6Loopback[16] = { 0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,1 };
	UINT8 i;

	if (!isV6) {
		if (addr[0] == 127)
			return UFW_ZONE_LOCAL;
	} else if (RtlCompareMemory(addr, v6Loopback, 16) == 16) {
		return UFW_ZONE_LOCAL;
	}

	/* Perimeter before internal: the two overlap (a DMZ range is usually
	 * inside RFC1918) and the more specific classification is the one the
	 * operator meant. */
	for (i = 0; i < g_perimeterZoneCount; i++) {
		if (UfwCidrContains(&g_perimeterZones[i], addr, isV6))
			return UFW_ZONE_PERIMETER;
	}
	for (i = 0; i < g_internalZoneCount; i++) {
		if (UfwCidrContains(&g_internalZones[i], addr, isV6))
			return UFW_ZONE_INTERNAL;
	}
	return UFW_ZONE_EXTERNAL;
}
