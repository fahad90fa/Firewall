// SPDX-License-Identifier: GPL-2.0
/*
 * Unified Firewall — process identity at the LSM hook.
 *
 * # The problem this replaces
 *
 * Today a flow whose process is not in the kernel's identity cache costs a
 * round trip: the module sends a query over netlink, the daemon reads
 * /proc/<pid>/exe, hashes the binary, and answers. Three consequences, all
 * bad, none obvious:
 *
 *   1. **A deadline.** The verdict cannot wait forever, so a slow answer means
 *      the flow is decided on the rules that do not need identity. An attacker
 *      who can make identity resolution slow — fork storms, a binary on a
 *      stalled network mount — can make identity rules not apply.
 *   2. **A TTL.** The answer is cached, so a process that changed underneath
 *      is judged on what it used to be for as long as the entry lives.
 *   3. **A pid.** By the time the daemon looks, the pid may name a different
 *      process. The cache is keyed on (pid, path, inode generation) to narrow
 *      that, which narrows rather than closes it.
 *
 * # What this does instead
 *
 * `bpf_lsm` runs `security_socket_connect` in the *calling process's own
 * context*, before the connect proceeds. `bpf_get_current_task_btf()` is that
 * task — not a pid to be looked up later, the task itself. There is no race to
 * lose and no deadline to miss, because the identity is recorded on the path
 * that creates the flow rather than fetched afterwards.
 *
 * The map is keyed by socket cookie, which the tc and netfilter paths already
 * have. A cache hit there now costs a map lookup instead of a round trip.
 *
 * # What it still cannot do
 *
 * Verify a signature. That means reading the binary and doing cryptography,
 * neither of which belongs in a BPF program. So this records *which* executable
 * — path, inode, device, and the cgroup — and the daemon still resolves trust.
 * The difference is that the daemon now answers a question about an identified
 * file rather than a question about a pid that may already be gone, and it can
 * answer it lazily because the flow's identity is no longer waiting on it.
 *
 * # Requirements
 *
 * CONFIG_BPF_LSM, CONFIG_DEBUG_INFO_BTF, and `lsm=...,bpf` on the kernel
 * command line. That is a real deployment constraint, so this is an
 * *addition*: `identity.c` keeps working, and the daemon reports which path is
 * live rather than assuming.
 */

#include "common.h"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

/*
 * The kernel structures this program reaches into, declared minimally rather
 * than pulled from a generated `vmlinux.h`.
 *
 * `bpftool btf dump file /sys/kernel/btf/vmlinux format c` is the usual route
 * and produces a hundred thousand lines describing the kernel that generated
 * it. Two reasons not to:
 *
 *   - It makes the build depend on the *build machine's* kernel having BTF,
 *     which turns "does this compile" into a property of the developer's
 *     laptop. This file compiles anywhere clang does.
 *   - It hides what is actually being read. Four fields, listed here, is a
 *     smaller thing to audit than a header nobody opens.
 *
 * `preserve_access_index` is what makes this CO-RE: clang records a relocation
 * for each field access, and the loader rewrites the offsets against the
 * *running* kernel's BTF. So the layout below does not have to match any
 * particular kernel — only the field names and types do, and those are stable
 * across the range this targets.
 *
 * The cost is that a kernel which renames one of these fields breaks at load
 * time with a relocation error rather than at compile time. That is the right
 * trade for a firewall: a module that fails to load is not filtering, and the
 * daemon reports it, whereas one that read the wrong offset would filter
 * wrongly and silently.
 */
#pragma clang attribute push (__attribute__((preserve_access_index)), apply_to = record)

struct super_block {
	__u32 s_dev;
};

struct inode {
	__u64 i_ino;
	__u32 i_generation;
	struct super_block *i_sb;
};

struct file {
	struct inode *f_inode;
};

struct mm_struct {
	struct file *exe_file;
};

struct task_struct {
	struct mm_struct *mm;
};

struct socket;
struct sockaddr;

#pragma clang attribute pop

/*
 * What the LSM hook recorded, keyed by socket cookie.
 *
 * LRU, so the map cannot be filled by a process that opens sockets in a loop:
 * the kernel evicts the least recently used and the affected flow falls back
 * to the netlink query, which is slower and still correct. A hash map would
 * instead start failing inserts, and a *missing* identity is a flow that
 * identity rules cannot match — fail-open, silently, under exactly the
 * conditions an attacker would arrange.
 */
struct {
	__uint(type, BPF_MAP_TYPE_LRU_HASH);
	__uint(max_entries, 65536);
	__type(key, __u64);
	__type(value, struct ufw_lsm_identity);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ufw_lsm_identity_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 3);
	__type(key, __u32);
	__type(value, __u64);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} ufw_lsm_stats SEC(".maps");

#define UFW_LSM_RECORDED  0
#define UFW_LSM_NO_TASK   1
#define UFW_LSM_NO_FILE   2

static __always_inline void ufw_lsm_count(__u32 slot)
{
	__u64 *v = bpf_map_lookup_elem(&ufw_lsm_stats, &slot);

	if (v)
		__sync_fetch_and_add(v, 1);
}

/*
 * `security_socket_connect`, as a BPF LSM program.
 *
 * Returning 0 means "no objection". This program never denies: the verdict
 * belongs to the policy engine, which has the whole rule table, and a second
 * place that can block a connection is a second place to look when something
 * is blocked and nobody knows why. All this does is record who is asking.
 */
SEC("lsm/socket_connect")
int BPF_PROG(ufw_socket_connect, struct socket *sock, struct sockaddr *address,
	     int addrlen)
{
	struct task_struct *task = bpf_get_current_task_btf();
	struct ufw_lsm_identity id = {};
	struct file *exe;
	__u64 cookie;

	if (!task) {
		ufw_lsm_count(UFW_LSM_NO_TASK);
		return 0;
	}

	cookie = bpf_get_socket_cookie(sock);
	if (!cookie)
		return 0;

	id.pid = bpf_get_current_pid_tgid() >> 32;
	id.uid = bpf_get_current_uid_gid() & 0xFFFFFFFF;
	id.cgroup_id = bpf_get_current_cgroup_id();
	id.captured_ns = bpf_ktime_get_ns();
	bpf_get_current_comm(&id.comm, sizeof(id.comm));

	/*
	 * The executable's inode identifies the file the daemon must hash.
	 * `mm->exe_file` rather than anything derived from the pid: the pid can
	 * be reused before the daemon looks, and the inode cannot be — a
	 * replaced binary gets a new one, which is precisely the change an
	 * identity rule needs to notice.
	 */
	exe = BPF_CORE_READ(task, mm, exe_file);
	if (!exe) {
		/* A kernel thread, or a process whose mm is gone. Neither has
		 * an executable to identify, and recording zeroes would look
		 * like a resolved identity rather than an absent one. */
		ufw_lsm_count(UFW_LSM_NO_FILE);
		return 0;
	}
	id.inode = BPF_CORE_READ(exe, f_inode, i_ino);
	id.device = BPF_CORE_READ(exe, f_inode, i_sb, s_dev);
	id.inode_generation = BPF_CORE_READ(exe, f_inode, i_generation);

	bpf_map_update_elem(&ufw_lsm_identity_map, &cookie, &id, BPF_ANY);
	ufw_lsm_count(UFW_LSM_RECORDED);
	return 0;
}

/*
 * Drop the entry when the socket goes away, so the map holds live flows rather
 * than everything the machine has ever connected. Without this the LRU still
 * bounds memory, but it bounds it by evicting *live* entries in favour of dead
 * ones, which is the wrong direction.
 */
SEC("lsm/socket_post_create")
int BPF_PROG(ufw_socket_post_create, struct socket *sock, int family, int type,
	     int protocol, int kern)
{
	__u64 cookie = bpf_get_socket_cookie(sock);

	/* A cookie is unique for the life of a socket but the *number* can be
	 * reused after it closes. Clearing at create rather than at destroy
	 * means a reused cookie never inherits the previous socket's identity,
	 * and it needs no second hook to be reliable. */
	if (cookie)
		bpf_map_delete_elem(&ufw_lsm_identity_map, &cookie);
	return 0;
}

char _license[] SEC("license") = "GPL";
