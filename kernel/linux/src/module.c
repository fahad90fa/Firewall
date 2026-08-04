// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — Linux kernel module entry points.
 *
 * # Initialisation order
 *
 *   stats -> dpi -> stream -> identity -> logging -> netlink -> hooks
 *
 * Hooks are registered last, and that is the only ordering constraint that
 * really matters: from the instant the first hook is live, packets arrive. A
 * subsystem that is not ready at that point either has to handle being called
 * before it is initialised — which is a class of bug that shows up as a rare
 * crash under load — or the hooks come last. They come last.
 *
 * Teardown is exactly the reverse, and for the same reason: hooks go first,
 * then synchronize_rcu(), so that every in-flight classification has finished
 * before anything it might dereference is freed.
 *
 * # What happens if the daemon never appears
 *
 * The module comes up with no policy installed, which classify.c treats as
 * fail-closed: every packet is dropped. That is intentional and it is
 * aggressive, so the module refuses to load with no policy *only* if
 * `fail_closed=1` (the default). Booting a machine whose management daemon is
 * broken into a state where it cannot be reached over the network is a real
 * risk, and `fail_closed=0` exists for the recovery case — it starts in
 * emergency-allow, logs loudly, and waits for the daemon.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/moduleparam.h>

#include "../inc/module.h"

static bool fail_closed = true;
module_param(fail_closed, bool, 0444);
MODULE_PARM_DESC(fail_closed,
		 "Drop traffic until the daemon installs a policy (default: yes). "
		 "Set to 0 only for recovery: the module will start in "
		 "emergency-allow and enforce nothing until a policy arrives.");

static unsigned int log_queue_size = 4096;
module_param(log_queue_size, uint, 0444);
MODULE_PARM_DESC(log_queue_size,
		 "Bounded log event queue depth. Full means the oldest event "
		 "is dropped and counted, never that a packet waits.");

static int __init ufw_init(void)
{
	int err;

	ufw_stats_reset();

	err = ufw_dpi_init();
	if (err)
		goto fail;

	err = ufw_stream_init();
	if (err)
		goto fail_dpi;

	err = ufw_identity_init();
	if (err)
		goto fail_stream;

	err = ufw_log_init();
	if (err)
		goto fail_identity;

	err = ufw_policy_sync_init();
	if (err)
		goto fail_log;

	if (!fail_closed) {
		ufw_set_mode(UFW_MODE_EMERGENCY_ALLOW);
		pr_warn(UFW_MODULE_NAME
			": loaded with fail_closed=0 — NOTHING IS BEING FILTERED "
			"until the daemon installs a policy and sets a mode\n");
	}

	/* Last. From here, packets arrive. */
	err = ufw_hooks_init();
	if (err)
		goto fail_sync;

	pr_info(UFW_MODULE_NAME ": %s loaded (ABI %d, %s)\n",
		UFW_MODULE_VERSION, UFW_ABI_REVISION,
		fail_closed ? "fail-closed" : "fail-open, RECOVERY MODE");
	return 0;

fail_sync:
	ufw_policy_sync_exit();
fail_log:
	ufw_log_exit();
fail_identity:
	ufw_identity_exit();
fail_stream:
	ufw_stream_exit();
fail_dpi:
	ufw_dpi_exit();
fail:
	pr_err(UFW_MODULE_NAME ": initialisation failed: %d\n", err);
	return err;
}

static void __exit ufw_exit(void)
{
	struct ufw_policy_table *table;

	/* First. No new classifications after this returns. */
	ufw_hooks_exit();

	/*
	 * Every classification runs under rcu_read_lock() and dereferences
	 * the published table. Waiting for a grace period here is what makes
	 * freeing it below safe: without this, a packet already inside
	 * ufw_classify() would be walking rules that had been returned to the
	 * allocator.
	 */
	synchronize_rcu();

	ufw_policy_sync_exit();
	ufw_log_exit();
	ufw_identity_exit();
	ufw_stream_exit();
	ufw_dpi_exit();

	table = ufw_policy_install(NULL);
	if (table) {
		/* One more grace period: install() published NULL, and a
		 * reader that had already loaded the old pointer is still
		 * using it. */
		synchronize_rcu();
		ufw_policy_free(table);
	}

	pr_info(UFW_MODULE_NAME ": unloaded\n");
}

module_init(ufw_init);
module_exit(ufw_exit);

MODULE_LICENSE("Dual MIT/GPL");
MODULE_AUTHOR("Unified Firewall project");
MODULE_DESCRIPTION("Unified cross-platform kernel-level firewall: Linux enforcement module");
MODULE_VERSION(UFW_MODULE_VERSION);
