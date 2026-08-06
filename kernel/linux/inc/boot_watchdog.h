/*
 * Unified Firewall — the ring-0 fault latch.
 *
 * This is the kernel-side companion to the daemon's watchdog
 * (`daemon/src/watchdog.rs`). The daemon's watchdog keeps a *running* host
 * reachable when the control channel faults; this one bounds the blast radius
 * of a bug in the module's own data path, which the daemon cannot see or fix
 * because it is happening below it, on every packet.
 *
 * # The failure this exists to bound
 *
 * New kernel code has bugs, and a bug in a per-packet hook is the worst-placed
 * bug there is: it runs on every packet, and if it wedges the network path it
 * takes out the very channel an operator would use to fix it. A firewall that
 * can brick the host it protects is a worse outage than the threat it stops.
 *
 * A hard oops is the kernel's to handle. What this latch handles is the
 * softer, more common shape: the module's own classifier producing something
 * impossible — a verdict outside the enum, a corrupted decision — repeatedly.
 * Continuing to trust a classifier that has demonstrably lost its mind, on
 * every subsequent packet, is how a transient corruption becomes a permanent
 * outage. After a bounded number of such faults inside a window, the latch
 * trips: the handler stops classifying and returns a single, known-safe
 * verdict instead, and says so loudly. It is *sticky* — unlike the daemon's
 * watchdog it does not auto-recover, because re-running code that has proven
 * itself broken, per packet, is worse than staying in a defined safe state
 * until an operator reloads a fixed module.
 *
 * # Why a header, and hosted-testable
 *
 * The decision — "have I seen too many faults too fast?" — needs no kernel
 * API: no allocation, no locking, no sleeping. Keeping it free of those is
 * what lets `daemon/tests/boot_watchdog_tests.rs` compile this exact code with
 * a hosted compiler and run the escalation ladder as a unit test, the same way
 * the DPI headers are checked. The `.c` that wires it into the hook path adds
 * the locking and the verdict; the *policy* — when to trip — lives here where
 * it can be exercised without crash-looping a real kernel to observe it.
 */

#ifndef UFW_BOOT_WATCHDOG_H
#define UFW_BOOT_WATCHDOG_H

#ifdef __KERNEL__
#include <linux/types.h>
#else
#include <stddef.h>
#include <stdint.h>
typedef uint8_t  __u8;
typedef uint32_t __u32;
typedef uint64_t __u64;
#endif

/*
 * The ring of recent fault timestamps. Bounded on purpose: a latch is exactly
 * the component a crash-loop stresses, so it must not itself grow without
 * bound while a machine faults for a week. Once this many faults are inside the
 * window the verdict is already "latch", so keeping more buys nothing. It also
 * caps `max_faults`, since a threshold the ring cannot hold could never trip.
 */
#define UFW_LATCH_RING 16

/*
 * What the handler does once latched. The default is BYPASS — accept traffic,
 * keep the host reachable — because the governing rule is the same as the
 * daemon watchdog's: a data-path fault must never cost an operator remote
 * access. An operator who would rather a broken firewall drop everything than
 * pass everything chooses FAIL_CLOSED explicitly; it is a real trade (a
 * reachable-but-unfiltered host versus an unreachable-but-sealed one) and the
 * module does not guess which the deployment wants.
 */
enum ufw_latch_action {
	UFW_LATCH_BYPASS = 0,	/* accept all — reachable, unfiltered */
	UFW_LATCH_FAIL_CLOSED = 1,	/* drop all — sealed, unreachable */
};

struct ufw_fault_latch {
	__u32 max_faults;	/* faults within the window that trip the latch */
	__u64 window_ns;	/* sliding window over which faults are counted */
	__u64 times[UFW_LATCH_RING];	/* recent fault timestamps */
	__u32 count;		/* live entries in the ring */
	__u32 head;		/* next write slot */
	__u8  latched;		/* sticky: once set, stays until an explicit reset */
	__u64 total_faults;	/* faults ever recorded, for reporting */
	__u64 trips;		/* times the latch has tripped, for reporting */
};

/*
 * Initialise a latch. `max_faults` is clamped to at least 1 and at most the
 * ring size — a threshold below 1 would trip on the zeroth fault, and one above
 * the ring could never be reached.
 */
static inline void ufw_latch_init(struct ufw_fault_latch *l, __u32 max_faults,
				  __u64 window_ns)
{
	__u32 i;

	if (max_faults < 1)
		max_faults = 1;
	if (max_faults > UFW_LATCH_RING)
		max_faults = UFW_LATCH_RING;

	l->max_faults = max_faults;
	l->window_ns = window_ns;
	for (i = 0; i < UFW_LATCH_RING; i++)
		l->times[i] = 0;
	l->count = 0;
	l->head = 0;
	l->latched = 0;
	l->total_faults = 0;
	l->trips = 0;
}

/*
 * Record a data-path fault at `now_ns`. Returns non-zero once the latch is
 * tripped — the caller then switches the handler to the safe verdict and logs.
 *
 * The latch is sticky: after it trips, further faults keep returning tripped
 * without re-counting, so a machine that keeps faulting neither churns the ring
 * nor double-counts its trips.
 */
static inline __u8 ufw_latch_on_fault(struct ufw_fault_latch *l, __u64 now_ns)
{
	__u32 i, within = 0;

	l->total_faults++;

	if (l->latched)
		return 1;

	/*
	 * Overwrite in place and saturate the count at the ring size. Because
	 * writes start at index 0 and `count` saturates, the live entries are
	 * always exactly indices [0, count), so counting them needs no ring
	 * arithmetic.
	 */
	l->times[l->head] = now_ns;
	l->head = (l->head + 1) % UFW_LATCH_RING;
	if (l->count < UFW_LATCH_RING)
		l->count++;

	for (i = 0; i < l->count; i++) {
		__u64 t = l->times[i];
		/* now_ns >= t guards a clock that appears to move backwards:
		 * such a sample is simply not counted as within-window, which
		 * is the fail-safe direction (it can only delay a trip). */
		if (now_ns >= t && (now_ns - t) <= l->window_ns)
			within++;
	}

	if (within >= l->max_faults) {
		l->latched = 1;
		l->trips++;
		return 1;
	}
	return 0;
}

static inline __u8 ufw_latch_is_tripped(const struct ufw_fault_latch *l)
{
	return l->latched;
}

/*
 * Trip the latch immediately, unconditionally. This is the boot-recovery path:
 * an operator who cannot reach a box adds the module's bypass parameter on the
 * kernel command line, and the module comes up already latched — present but
 * out of the packet path — so the host boots reachable.
 */
static inline void ufw_latch_force(struct ufw_fault_latch *l)
{
	if (!l->latched) {
		l->latched = 1;
		l->trips++;
	}
}

/*
 * Clear the latch. Not called from the hot path — only when an operator or a
 * module reload re-arms enforcement, because the whole point of stickiness is
 * that the module does not decide on its own that a proven-broken path is fixed.
 */
static inline void ufw_latch_reset(struct ufw_fault_latch *l)
{
	__u32 i;

	for (i = 0; i < UFW_LATCH_RING; i++)
		l->times[i] = 0;
	l->count = 0;
	l->head = 0;
	l->latched = 0;
}

#endif /* UFW_BOOT_WATCHDOG_H */
