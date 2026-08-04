// SPDX-License-Identifier: Apache-2.0
/*
 * Unified Firewall — the netlink channel to the daemon.
 *
 * Generic netlink rather than a character device or a sysfs tree, for three
 * reasons that all come down to the same thing: this channel carries the
 * policy, and the policy is the security boundary.
 *
 *   - Netlink gives per-message credentials. Every request arrives with the
 *     sender's uid, so "only root may install a policy" is a check on a fact
 *     the kernel supplied rather than on file permissions somebody can
 *     change.
 *   - It is message-oriented. A character device would need framing, and
 *     hand-written framing over a stream is where partial reads become
 *     partially-applied policies.
 *   - Multicast lets the module push log events and identity queries to a
 *     subscriber without the daemon polling, which is what keeps the log path
 *     from needing a thread on either side.
 *
 * # Policy installation is atomic
 *
 * A policy arrives as one message, is validated in full, is built into a
 * complete new table, and only then replaces the published pointer. There is
 * no incremental path that mutates the live table, and there will not be one:
 * an in-place edit has a window during which the table is neither the old
 * policy nor the new one, and a packet arriving in that window is decided by
 * a policy that no operator ever wrote.
 *
 * Hot reload is still incremental *on the wire* — the daemon sends a delta —
 * but the module expands the delta against the current table into a whole new
 * table before publishing. The saving is bandwidth and daemon-side work, not
 * a shortcut through the swap.
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/mutex.h>
#include <linux/sort.h>
#include <linux/string.h>
#include <net/genetlink.h>
#include <net/sock.h>

#include "../inc/module.h"
#include "../inc/netfilter_hooks.h"

enum ufw_genl_attr {
	UFW_ATTR_UNSPEC = 0,
	UFW_ATTR_ABI_REVISION,	/* u8  */
	UFW_ATTR_REVISION,	/* u64 */
	UFW_ATTR_RULESET_HASH,	/* binary, 32 bytes */
	UFW_ATTR_RULE_COUNT,	/* u32 */
	UFW_ATTR_DEFAULT_VERDICT, /* u8 */
	UFW_ATTR_RULES,		/* binary: rule_count * sizeof(struct ufw_rule) */
	UFW_ATTR_PROFILE,	/* binary: struct ufw_network_profile */
	UFW_ATTR_SIGNATURES,	/* binary: the daemon's signature encoding */
	UFW_ATTR_MODE,		/* u8  */
	UFW_ATTR_STATS,		/* binary: struct ufw_stats */
	UFW_ATTR_PID,		/* u32 */
	UFW_ATTR_COOKIE,	/* u64 */
	UFW_ATTR_TRUST,		/* u8  */
	UFW_ATTR_SIG_VALID,	/* u8  */
	UFW_ATTR_PATH,		/* string */
	UFW_ATTR_SIGNER,	/* string */
	UFW_ATTR_SHA256,	/* binary, 32 bytes */
	UFW_ATTR_MESSAGE,	/* string */
	UFW_ATTR_MINUTE_OF_WEEK, /* u16 */
	__UFW_ATTR_MAX,
};
#define UFW_ATTR_MAX (__UFW_ATTR_MAX - 1)

enum ufw_genl_cmd {
	UFW_CMD_UNSPEC = 0,
	UFW_CMD_HELLO,
	UFW_CMD_INSTALL_POLICY,
	UFW_CMD_INSTALL_SIGNATURES,
	UFW_CMD_SET_MODE,
	UFW_CMD_GET_STATS,
	UFW_CMD_FLUSH,
	UFW_CMD_IDENTITY_QUERY,		/* module -> daemon */
	UFW_CMD_IDENTITY_RESPONSE,	/* daemon -> module */
	UFW_CMD_LOG_EVENT,		/* module -> daemon */
	__UFW_CMD_MAX,
};

static const struct nla_policy ufw_genl_policy[UFW_ATTR_MAX + 1] = {
	[UFW_ATTR_ABI_REVISION]	  = { .type = NLA_U8 },
	[UFW_ATTR_REVISION]	  = { .type = NLA_U64 },
	[UFW_ATTR_RULESET_HASH]	  = { .type = NLA_BINARY, .len = 32 },
	[UFW_ATTR_RULE_COUNT]	  = { .type = NLA_U32 },
	[UFW_ATTR_DEFAULT_VERDICT] = { .type = NLA_U8 },
	[UFW_ATTR_RULES]	  = { .type = NLA_BINARY },
	[UFW_ATTR_PROFILE]	  = { .type = NLA_BINARY,
				      .len = sizeof(struct ufw_network_profile) },
	[UFW_ATTR_SIGNATURES]	  = { .type = NLA_BINARY },
	[UFW_ATTR_MODE]		  = { .type = NLA_U8 },
	[UFW_ATTR_PID]		  = { .type = NLA_U32 },
	[UFW_ATTR_COOKIE]	  = { .type = NLA_U64 },
	[UFW_ATTR_TRUST]	  = { .type = NLA_U8 },
	[UFW_ATTR_SIG_VALID]	  = { .type = NLA_U8 },
	[UFW_ATTR_PATH]		  = { .type = NLA_NUL_STRING,
				      .len = UFW_MAX_PATH_LEN - 1 },
	[UFW_ATTR_SIGNER]	  = { .type = NLA_NUL_STRING,
				      .len = UFW_MAX_SIGNER_LEN - 1 },
	[UFW_ATTR_SHA256]	  = { .type = NLA_BINARY, .len = 32 },
	[UFW_ATTR_MINUTE_OF_WEEK] = { .type = NLA_U16 },
};

static struct genl_family ufw_genl_family;

/* The daemon's portid, or 0 when nothing is listening. Read from softirq
 * context on every identity miss, so it is atomic rather than mutex-guarded. */
static atomic_t ufw_daemon_portid = ATOMIC_INIT(0);

/* Policy installation is serialised: two concurrent installs would each build
 * a table from a different base and one would silently win. */
static DEFINE_MUTEX(ufw_install_lock);

bool ufw_daemon_connected(void)
{
	return atomic_read(&ufw_daemon_portid) != 0;
}

/* --- table management ---------------------------------------------------- */

struct ufw_policy_table *ufw_policy_alloc(__u32 rule_count)
{
	struct ufw_policy_table *table;

	if (rule_count > UFW_MAX_RULES)
		return NULL;

	/* kvzalloc because a full table is tens of megabytes and will not
	 * come from the page allocator's contiguous ranges. */
	table = kvzalloc(struct_size(table, rules, rule_count), GFP_KERNEL);
	if (!table)
		return NULL;
	table->rule_count = rule_count;
	table->abi_revision = UFW_ABI_REVISION;
	return table;
}

void ufw_policy_free(struct ufw_policy_table *table)
{
	kvfree(table);
}

/*
 * Build the stage index, and refuse a table that is not sorted.
 *
 * The classifier walks stages using stage_start[] as bounds, which is only
 * correct if rules are grouped by stage in ascending order. The daemon sorts
 * before sending, so an unsorted table means either a bug there or a message
 * that was tampered with; either way the right answer is to reject the whole
 * install rather than publish a table that evaluates stages out of order.
 */
int ufw_policy_index(struct ufw_policy_table *table)
{
	__u32 i;
	__u8 stage = 0;

	for (i = 0; i <= UFW_STAGE__COUNT; i++)
		table->stage_start[i] = table->rule_count;

	table->stage_start[0] = 0;
	for (i = 0; i < table->rule_count; i++) {
		__u8 s = table->rules[i].stage;

		if (s >= UFW_STAGE__COUNT)
			return -EINVAL;
		if (s < stage)
			return -EINVAL;
		while (stage < s) {
			stage++;
			table->stage_start[stage] = i;
		}
	}
	while (stage < UFW_STAGE__COUNT) {
		stage++;
		table->stage_start[stage] = table->rule_count;
	}
	return 0;
}

struct ufw_policy_table *ufw_policy_install(struct ufw_policy_table *table)
{
	struct ufw_policy_table *old;

	mutex_lock(&ufw_install_lock);
	old = rcu_dereference_protected(ufw_policy,
					lockdep_is_held(&ufw_install_lock));
	rcu_assign_pointer(ufw_policy, table);
	mutex_unlock(&ufw_install_lock);
	return old;
}

/* --- command handlers ---------------------------------------------------- */

static int ufw_cmd_hello(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *reply;
	void *hdr;

	atomic_set(&ufw_daemon_portid, info->snd_portid);

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
			  &ufw_genl_family, 0, UFW_CMD_HELLO);
	if (!hdr) {
		nlmsg_free(reply);
		return -EMSGSIZE;
	}

	/*
	 * The ABI revision goes back in the handshake so the daemon can
	 * refuse to install rather than sending a rule table this module
	 * would misparse. A mismatched table is worse than no table: it
	 * filters, but not what the operator wrote.
	 */
	if (nla_put_u8(reply, UFW_ATTR_ABI_REVISION, UFW_ABI_REVISION) ||
	    nla_put_string(reply, UFW_ATTR_MESSAGE, UFW_MODULE_VERSION)) {
		genlmsg_cancel(reply, hdr);
		nlmsg_free(reply);
		return -EMSGSIZE;
	}

	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);
}

static int ufw_cmd_install_policy(struct sk_buff *skb, struct genl_info *info)
{
	struct ufw_policy_table *table, *old;
	const struct ufw_rule *rules;
	__u32 rule_count;
	size_t expected;
	int err;

	if (!info->attrs[UFW_ATTR_RULE_COUNT] || !info->attrs[UFW_ATTR_RULES])
		return -EINVAL;

	if (!info->attrs[UFW_ATTR_ABI_REVISION] ||
	    nla_get_u8(info->attrs[UFW_ATTR_ABI_REVISION]) != UFW_ABI_REVISION)
		return -EPROTO;

	rule_count = nla_get_u32(info->attrs[UFW_ATTR_RULE_COUNT]);
	if (rule_count > UFW_MAX_RULES)
		return -E2BIG;

	/*
	 * The declared count and the payload length must agree exactly. A
	 * payload longer than the count would leave trailing bytes; shorter
	 * would leave rules uninitialised. Either is a parse desynchronisation
	 * between the daemon and the module, and this is the one place to
	 * catch it.
	 */
	expected = (size_t)rule_count * sizeof(struct ufw_rule);
	if (nla_len(info->attrs[UFW_ATTR_RULES]) != (int)expected)
		return -EINVAL;

	table = ufw_policy_alloc(rule_count);
	if (!table)
		return -ENOMEM;

	rules = nla_data(info->attrs[UFW_ATTR_RULES]);
	memcpy(table->rules, rules, expected);

	if (info->attrs[UFW_ATTR_REVISION])
		table->revision = nla_get_u64(info->attrs[UFW_ATTR_REVISION]);
	if (info->attrs[UFW_ATTR_RULESET_HASH])
		memcpy(table->ruleset_hash,
		       nla_data(info->attrs[UFW_ATTR_RULESET_HASH]), 32);
	table->default_verdict = info->attrs[UFW_ATTR_DEFAULT_VERDICT]
		? nla_get_u8(info->attrs[UFW_ATTR_DEFAULT_VERDICT])
		: UFW_VERDICT_DROP;

	err = ufw_policy_index(table);
	if (err) {
		ufw_policy_free(table);
		return err;
	}

	if (info->attrs[UFW_ATTR_PROFILE]) {
		ufw_profile_install(nla_data(info->attrs[UFW_ATTR_PROFILE]));
	}

	/* Published only now that the whole table is built and validated. */
	old = ufw_policy_install(table);
	if (old) {
		/* A packet already inside ufw_classify() is still walking the
		 * old table. */
		synchronize_rcu();
		ufw_policy_free(old);
	}

	/* Identity and stream state are keyed on facts, not on rules, so a
	 * reload does not invalidate them — deliberately. Flushing on every
	 * reload would mean a policy update costs a resolution storm, and
	 * hot reload is supposed to be cheap enough to use. */

	ufw_log_note("installed policy revision %llu (%u rules)",
		     table->revision, rule_count);
	return 0;
}

static int ufw_cmd_install_signatures(struct sk_buff *skb,
				      struct genl_info *info)
{
	if (!info->attrs[UFW_ATTR_SIGNATURES])
		return -EINVAL;

	return ufw_dpi_install(nla_data(info->attrs[UFW_ATTR_SIGNATURES]),
			       nla_len(info->attrs[UFW_ATTR_SIGNATURES]));
}

static int ufw_cmd_set_mode(struct sk_buff *skb, struct genl_info *info)
{
	__u8 mode;

	if (!info->attrs[UFW_ATTR_MODE])
		return -EINVAL;

	mode = nla_get_u8(info->attrs[UFW_ATTR_MODE]);
	if (mode > UFW_MODE_EMERGENCY_ALLOW)
		return -EINVAL;

	ufw_set_mode((enum ufw_mode)mode);
	return 0;
}

static int ufw_cmd_get_stats(struct sk_buff *skb, struct genl_info *info)
{
	struct ufw_stats stats;
	struct sk_buff *reply;
	void *hdr;

	ufw_stats_sum(&stats);

	reply = genlmsg_new(NLMSG_GOODSIZE, GFP_KERNEL);
	if (!reply)
		return -ENOMEM;

	hdr = genlmsg_put(reply, info->snd_portid, info->snd_seq,
			  &ufw_genl_family, 0, UFW_CMD_GET_STATS);
	if (!hdr) {
		nlmsg_free(reply);
		return -EMSGSIZE;
	}
	if (nla_put(reply, UFW_ATTR_STATS, sizeof(stats), &stats)) {
		genlmsg_cancel(reply, hdr);
		nlmsg_free(reply);
		return -EMSGSIZE;
	}
	genlmsg_end(reply, hdr);
	return genlmsg_reply(reply, info);
}

static int ufw_cmd_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct ufw_policy_table *old = ufw_policy_install(NULL);

	if (old) {
		synchronize_rcu();
		ufw_policy_free(old);
	}
	ufw_identity_flush();
	ufw_stream_flush();

	/* With no table installed the classifier fails closed. That is the
	 * intended meaning of "flush": remove every rule, leaving the default
	 * action — which is deny. */
	ufw_log_note("policy flushed; classifier is fail-closed until a policy is installed");
	return 0;
}

static int ufw_cmd_identity_response(struct sk_buff *skb,
				     struct genl_info *info)
{
	const char *path = NULL, *signer = NULL;
	const __u8 *sha256 = NULL;
	__u32 pid;
	__u64 cookie;

	if (!info->attrs[UFW_ATTR_PID] || !info->attrs[UFW_ATTR_COOKIE])
		return -EINVAL;

	pid = nla_get_u32(info->attrs[UFW_ATTR_PID]);
	cookie = nla_get_u64(info->attrs[UFW_ATTR_COOKIE]);

	if (info->attrs[UFW_ATTR_PATH])
		path = nla_data(info->attrs[UFW_ATTR_PATH]);
	if (info->attrs[UFW_ATTR_SIGNER])
		signer = nla_data(info->attrs[UFW_ATTR_SIGNER]);
	if (info->attrs[UFW_ATTR_SHA256])
		sha256 = nla_data(info->attrs[UFW_ATTR_SHA256]);

	ufw_identity_deliver(pid, cookie,
			     info->attrs[UFW_ATTR_TRUST]
				     ? nla_get_u8(info->attrs[UFW_ATTR_TRUST])
				     : UFW_TRUST_UNTRUSTED,
			     info->attrs[UFW_ATTR_SIG_VALID]
				     ? nla_get_u8(info->attrs[UFW_ATTR_SIG_VALID])
				     : 0,
			     path, signer, sha256);
	return 0;
}

/* --- module -> daemon ----------------------------------------------------- */

void ufw_identity_query_send(__u32 pid, __u64 cookie)
{
	struct sk_buff *msg;
	void *hdr;
	int portid = atomic_read(&ufw_daemon_portid);

	if (!portid)
		return;

	/* GFP_ATOMIC: this is called from softirq context on a cache miss. A
	 * failed allocation simply means the query is not sent, and the
	 * retry throttle in identity.c will try again shortly. */
	msg = genlmsg_new(NLMSG_GOODSIZE, GFP_ATOMIC);
	if (!msg)
		return;

	hdr = genlmsg_put(msg, 0, 0, &ufw_genl_family, 0, UFW_CMD_IDENTITY_QUERY);
	if (!hdr) {
		nlmsg_free(msg);
		return;
	}
	if (nla_put_u32(msg, UFW_ATTR_PID, pid) ||
	    nla_put_u64_64bit(msg, UFW_ATTR_COOKIE, cookie, 0)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return;
	}
	genlmsg_end(msg, hdr);
	genlmsg_unicast(&init_net, msg, portid);
}

int ufw_log_send(const void *payload, size_t len)
{
	struct sk_buff *msg;
	void *hdr;
	int portid = atomic_read(&ufw_daemon_portid);

	if (!portid)
		return -ENOTCONN;

	msg = genlmsg_new(nla_total_size(len), GFP_ATOMIC);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, 0, 0, &ufw_genl_family, 0, UFW_CMD_LOG_EVENT);
	if (!hdr) {
		nlmsg_free(msg);
		return -EMSGSIZE;
	}
	if (nla_put(msg, UFW_ATTR_STATS, len, payload)) {
		genlmsg_cancel(msg, hdr);
		nlmsg_free(msg);
		return -EMSGSIZE;
	}
	genlmsg_end(msg, hdr);
	return genlmsg_unicast(&init_net, msg, portid);
}

/* --- family -------------------------------------------------------------- */

static const struct genl_ops ufw_genl_ops[] = {
	{
		.cmd = UFW_CMD_HELLO,
		.doit = ufw_cmd_hello,
		/* Read-only handshake; anyone may ask what version is loaded. */
	},
	{
		.cmd = UFW_CMD_INSTALL_POLICY,
		.doit = ufw_cmd_install_policy,
		/* GENL_ADMIN_PERM is CAP_NET_ADMIN. Installing a policy is
		 * the most privileged operation the module offers: it decides
		 * what the machine may talk to. */
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UFW_CMD_INSTALL_SIGNATURES,
		.doit = ufw_cmd_install_signatures,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UFW_CMD_SET_MODE,
		.doit = ufw_cmd_set_mode,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UFW_CMD_GET_STATS,
		.doit = ufw_cmd_get_stats,
	},
	{
		.cmd = UFW_CMD_FLUSH,
		.doit = ufw_cmd_flush,
		.flags = GENL_ADMIN_PERM,
	},
	{
		.cmd = UFW_CMD_IDENTITY_RESPONSE,
		.doit = ufw_cmd_identity_response,
		/* An identity answer decides whether a rule matches, so a
		 * forged one is a policy bypass. Admin only. */
		.flags = GENL_ADMIN_PERM,
	},
};

static struct genl_family ufw_genl_family = {
	.name = UFW_GENL_FAMILY,
	.version = UFW_GENL_VERSION,
	.maxattr = UFW_ATTR_MAX,
	.policy = ufw_genl_policy,
	.netnsok = false,
	.module = THIS_MODULE,
	.ops = ufw_genl_ops,
	.n_ops = ARRAY_SIZE(ufw_genl_ops),
};

int ufw_policy_sync_init(void)
{
	return genl_register_family(&ufw_genl_family);
}

void ufw_policy_sync_exit(void)
{
	atomic_set(&ufw_daemon_portid, 0);
	genl_unregister_family(&ufw_genl_family);
}
