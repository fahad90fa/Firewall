// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — the log path, and where back-pressure stops.
 *
 * # The rule
 *
 * A packet never waits for a log event. Not for the daemon, not for the
 * queue, not for an allocation. If a log event cannot be produced, it is
 * dropped and counted, and the packet's decision proceeds unchanged.
 *
 * This is the single most important property in this file, and it is worth
 * being explicit about what it costs. A SIEM collector that stops reading
 * causes the daemon's socket buffer to fill, which causes the daemon to stop
 * draining this queue, which causes this queue to fill, which causes events
 * to be dropped. Logs are lost. The alternative — blocking — means a
 * collector outage becomes a network outage on every host that ships to it,
 * which is a far larger incident, and one where the firewall is the cause.
 *
 * # Oldest-first
 *
 * When the queue is full the *oldest* event is discarded, not the newest.
 * During an incident the interesting events are the ones happening now, and a
 * newest-first policy would preferentially discard exactly those while
 * retaining a backlog of routine traffic from before anything happened.
 *
 * The drop count is itself reported, so a gap in the log is visible as a gap
 * rather than as an absence of activity.
 */

#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/spinlock.h>
#include <linux/string.h>
#include <linux/workqueue.h>

#include "../inc/module.h"

/* One page of events. Enough to absorb a burst; small enough that a stalled
 * daemon costs bounded memory. */
#define UFW_LOG_QUEUE_DEPTH 4096

/*
 * The wire form of one event.
 *
 * Fixed-size and flat, matching what the daemon's protocol decoder expects.
 * Everything variable-length is truncated into a fixed buffer here rather
 * than being sent by reference: the alternative is holding a pointer into an
 * skb that has long since been freed by the time the workqueue runs.
 */
struct ufw_log_event {
	__u64 timestamp_ns;
	__u32 rule_id;
	__u8  verdict;
	__u8  stage;
	__u8  protocol;
	__u8  direction;
	__u8  is_v6;
	__u8  src_zone;
	__u8  dst_zone;
	__u8  l7;
	__u8  src_addr[16];
	__u8  dst_addr[16];
	__u16 src_port;
	__u16 dst_port;
	__u32 pid;
	__u8  trust;
	__u8  identity_valid;
	__u8  dpi_truncated;
	__u8  matched_count;
	__u32 matched_signatures[UFW_MAX_SIGNATURES_PER_RULE];
	char  rule_name[UFW_MAX_RULE_NAME];
	char  path[UFW_MAX_PATH_LEN];
};

/*
 * A ring buffer, not a linked list.
 *
 * The producer runs in softirq context where an allocation can fail; a ring
 * of preallocated slots cannot fail to accept an event for want of memory,
 * which removes the one path where a memory shortage would silently stop
 * logging at exactly the moment logging matters.
 */
static struct ufw_log_event *ufw_log_ring;
static unsigned int ufw_log_head;	/* next slot to write */
static unsigned int ufw_log_tail;	/* next slot to send */
static unsigned int ufw_log_used;
static DEFINE_SPINLOCK(ufw_log_lock);

static void ufw_log_work_fn(struct work_struct *work);
static DECLARE_WORK(ufw_log_work, ufw_log_work_fn);

int ufw_log_init(void)
{
	ufw_log_ring = kvcalloc(UFW_LOG_QUEUE_DEPTH,
				sizeof(struct ufw_log_event), GFP_KERNEL);
	if (!ufw_log_ring)
		return -ENOMEM;
	ufw_log_head = 0;
	ufw_log_tail = 0;
	ufw_log_used = 0;
	return 0;
}

void ufw_log_exit(void)
{
	cancel_work_sync(&ufw_log_work);
	kvfree(ufw_log_ring);
	ufw_log_ring = NULL;
}

/*
 * Drain the ring to the daemon.
 *
 * Runs on the system workqueue, which is process context: netlink send can
 * allocate and can sleep, neither of which is available where the events were
 * produced. One event is copied out under the lock and sent outside it, so a
 * slow send never holds the producer off.
 */
static void ufw_log_work_fn(struct work_struct *work)
{
	struct ufw_log_event event;
	unsigned long flags;

	for (;;) {
		spin_lock_irqsave(&ufw_log_lock, flags);
		if (!ufw_log_used) {
			spin_unlock_irqrestore(&ufw_log_lock, flags);
			return;
		}
		event = ufw_log_ring[ufw_log_tail];
		ufw_log_tail = (ufw_log_tail + 1) % UFW_LOG_QUEUE_DEPTH;
		ufw_log_used--;
		spin_unlock_irqrestore(&ufw_log_lock, flags);

		if (ufw_log_send(&event, sizeof(event)) < 0) {
			/*
			 * The daemon went away mid-drain. The event is
			 * already dequeued and is not put back: re-queueing
			 * would spin this work item against a disconnected
			 * socket, burning a CPU to no purpose. It is counted
			 * as a drop, which is what it is.
			 */
			UFW_COUNT(log_events_dropped);
			return;
		}
	}
}

void ufw_log_decision(const struct ufw_flow_facts *facts,
		      const struct ufw_decision *decision)
{
	struct ufw_log_event *slot;
	unsigned long flags;
	__u8 i;

	if (!ufw_log_ring)
		return;

	spin_lock_irqsave(&ufw_log_lock, flags);

	if (ufw_log_used == UFW_LOG_QUEUE_DEPTH) {
		/* Full. Discard the oldest — see the file header for why it
		 * is the oldest and not this one. */
		ufw_log_tail = (ufw_log_tail + 1) % UFW_LOG_QUEUE_DEPTH;
		ufw_log_used--;
		UFW_COUNT(log_events_dropped);
	}

	slot = &ufw_log_ring[ufw_log_head];
	memset(slot, 0, sizeof(*slot));

	slot->timestamp_ns = ktime_get_real_ns();
	slot->rule_id = decision->rule_id;
	slot->verdict = decision->verdict;
	slot->stage = decision->stage;
	slot->protocol = facts->protocol;
	slot->direction = facts->direction;
	slot->is_v6 = facts->is_v6;
	slot->src_zone = facts->src_zone;
	slot->dst_zone = facts->dst_zone;
	slot->l7 = facts->l7;
	memcpy(slot->src_addr, facts->src_addr, 16);
	memcpy(slot->dst_addr, facts->dst_addr, 16);
	slot->src_port = facts->src_port;
	slot->dst_port = facts->dst_port;
	slot->pid = facts->pid;
	slot->trust = facts->trust;
	slot->identity_valid = facts->identity_valid;
	slot->dpi_truncated = facts->dpi_truncated;

	slot->matched_count = facts->matched_count;
	for (i = 0; i < facts->matched_count &&
		    i < UFW_MAX_SIGNATURES_PER_RULE; i++)
		slot->matched_signatures[i] = facts->matched_signatures[i];

	if (decision->rule_name)
		strscpy(slot->rule_name, decision->rule_name, UFW_MAX_RULE_NAME);
	if (facts->identity_valid)
		memcpy(slot->path, facts->path, UFW_MAX_PATH_LEN);

	ufw_log_head = (ufw_log_head + 1) % UFW_LOG_QUEUE_DEPTH;
	ufw_log_used++;
	spin_unlock_irqrestore(&ufw_log_lock, flags);

	/* Hand off to process context. schedule_work() on an already-queued
	 * item is a no-op, so a burst of packets does not queue a burst of
	 * work items. */
	schedule_work(&ufw_log_work);
}

void ufw_log_note(const char *fmt, ...)
{
	struct va_format vaf;
	va_list args;

	/*
	 * Operational notes go to the kernel log rather than through the
	 * event ring. They are rare, they are about the module rather than
	 * about traffic, and an operator diagnosing a module that cannot
	 * reach its daemon needs them somewhere that does not depend on the
	 * daemon.
	 */
	va_start(args, fmt);
	vaf.fmt = fmt;
	vaf.va = &args;
	pr_info(UFW_MODULE_NAME ": %pV\n", &vaf);
	va_end(args);
}
