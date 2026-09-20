// SPDX-License-Identifier: GPL-2.0
/*
 * labs/21-randstruct/vuln_randstruct.c
 *
 * Target driver for demonstrating CONFIG_RANDSTRUCT (Structure Layout Randomization):
 *   1. Demonstrates compile-time structure member layout randomization.
 *   2. Compares standard sequential member ordering (Baseline) vs randomized member offsets (Hardened).
 *   3. Exposes real kernel struct cred member offsets (uid, gid, euid).
 *   4. Evaluates fixed-offset overwrite attacks (overwriting uid or function pointer using hardcoded offsets).
 *
 * Exposes /proc/vuln_randstruct (mode 0666) for non-privileged user-space inspection
 * and automated testing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/cred.h>
#include <linux/string.h>
#include <linux/stddef.h>

#define PROC_FILENAME "vuln_randstruct"
#define VICTIM_MAGIC 0x56494354494d3031ULL /* "VICTIM01" */

/*
 * Victim structure marked with __randomize_layout.
 * Standard sequential declaration order:
 *   offset 0:  magic (8 bytes)
 *   offset 8:  privileged_op (8 bytes function pointer)
 *   offset 16: uid (4 bytes)
 *   offset 20: gid (4 bytes)
 *   offset 24: session_token (16 bytes)
 *   offset 40: callback (8 bytes function pointer)
 * Total size: 48 bytes.
 */
struct victim_struct {
	uint64_t magic;
	void (*privileged_op)(void);
	uint32_t uid;
	uint32_t gid;
	char session_token[16];
	void (*callback)(void);
} __randomize_layout;

static void safe_privileged_handler(void)
{
	pr_info("vuln_randstruct: safe_privileged_handler() called\n");
}

static void normal_callback(void)
{
	pr_info("vuln_randstruct: normal_callback() called\n");
}

static void hijacked_target_fn(void)
{
	pr_warn("vuln_randstruct: [CRITICAL] hijacked_target_fn() EXECUTED!\n");
}

static struct victim_struct g_victim;
static int g_hijack_called = 0;

static void init_victim(void)
{
	memset(&g_victim, 0, sizeof(g_victim));
	g_victim.magic = VICTIM_MAGIC;
	g_victim.privileged_op = safe_privileged_handler;
	g_victim.uid = 1000;
	g_victim.gid = 1000;
	memcpy(g_victim.session_token, "AUTHENTIC_USER!", 16);
	g_victim.callback = normal_callback;
	g_hijack_called = 0;
}

static ssize_t vuln_randstruct_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	char status_buf[1536];
	int len = 0;

	if (*ppos > 0)
		return 0;

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=== [Linux Kernel Hardening Lab: RANDSTRUCT] ===\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Feature Status:\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_RANDSTRUCT      : %s\n",
			 IS_ENABLED(CONFIG_RANDSTRUCT) ? "ENABLED (Active Defense)" : "DISABLED");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_RANDSTRUCT_FULL : %s\n",
			 IS_ENABLED(CONFIG_RANDSTRUCT_FULL) ? "ENABLED" : "DISABLED");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_RANDSTRUCT_NONE : %s\n\n",
			 IS_ENABLED(CONFIG_RANDSTRUCT_NONE) ? "ENABLED (Baseline)" : "DISABLED");

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Target Victim Struct (struct victim_struct, size=%zu):\n",
			 sizeof(struct victim_struct));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(magic)          : %3zu (baseline:  0)\n", offsetof(struct victim_struct, magic));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(privileged_op)  : %3zu (baseline:  8)\n", offsetof(struct victim_struct, privileged_op));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(uid)            : %3zu (baseline: 16)\n", offsetof(struct victim_struct, uid));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(gid)            : %3zu (baseline: 20)\n", offsetof(struct victim_struct, gid));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(session_token)  : %3zu (baseline: 24)\n", offsetof(struct victim_struct, session_token));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(callback)       : %3zu (baseline: 40)\n\n", offsetof(struct victim_struct, callback));

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Kernel Core Struct (struct cred, size=%zu):\n",
			 sizeof(struct cred));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(cred->uid)      : %3zu (baseline:  8)\n", offsetof(struct cred, uid));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(cred->gid)      : %3zu (baseline: 12)\n", offsetof(struct cred, gid));
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  offset(cred->euid)     : %3zu (baseline: 24)\n\n", offsetof(struct cred, euid));

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Current Victim Instance State:\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  magic                  : 0x%016llx\n", (unsigned long long)g_victim.magic);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  uid                    : %u\n", g_victim.uid);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  gid                    : %u\n", g_victim.gid);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  session_token          : '%.16s'\n", g_victim.session_token);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  hijack_called          : %d\n", g_hijack_called);

	if (count < len)
		return -EINVAL;

	if (copy_to_user(buf, status_buf, len))
		return -EFAULT;

	*ppos = len;
	return len;
}

static ssize_t vuln_randstruct_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[64];
	size_t to_copy;
	uint8_t *raw_victim = (uint8_t *)&g_victim;

	if (count == 0)
		return 0;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;

	kbuf[to_copy] = '\0';
	/* Strip trailing newline */
	if (to_copy > 0 && kbuf[to_copy - 1] == '\n')
		kbuf[to_copy - 1] = '\0';

	if (strcmp(kbuf, "reset") == 0) {
		init_victim();
		pr_info("vuln_randstruct: g_victim reset to defaults (uid=1000, gid=1000)\n");
	} else if (strcmp(kbuf, "exploit_fixed_uid") == 0) {
		/*
		 * Attacker assumes baseline layout where offset(uid) == 16.
		 * Overwrites 4 bytes at offset 16 with 0x00000000 (root).
		 */
		pr_info("vuln_randstruct: Attacker attempting fixed-offset overwrite at offset 16 (assumed uid)...\n");
		*(uint32_t *)(raw_victim + 16) = 0;

		if (g_victim.uid == 0) {
			pr_err("vuln_randstruct: [EXPLOIT SUCCEEDED] g_victim.uid changed to 0! Fixed-offset attack worked!\n");
		} else {
			pr_info("vuln_randstruct: [EXPLOIT FAILED] g_victim.uid remains %u! Offset 16 hit a different field!\n",
				g_victim.uid);
		}
	} else if (strcmp(kbuf, "exploit_fixed_callback") == 0) {
		/*
		 * Attacker assumes baseline layout where offset(callback) == 40.
		 * Overwrites 8 bytes at offset 40 with hijacked_target_fn.
		 */
		pr_info("vuln_randstruct: Attacker attempting fixed-offset pointer overwrite at offset 40...\n");
		*(void **)(raw_victim + 40) = (void *)hijacked_target_fn;

		if (g_victim.callback == hijacked_target_fn) {
			pr_err("vuln_randstruct: [EXPLOIT SUCCEEDED] callback hijacked to hijacked_target_fn!\n");
			g_hijack_called = 1;
		} else {
			pr_info("vuln_randstruct: [EXPLOIT FAILED] callback not modified! Offset 40 did not hit callback!\n");
		}
	} else {
		pr_warn("vuln_randstruct: unknown command '%s'\n", kbuf);
	}

	return count;
}

static const struct proc_ops vuln_randstruct_fops = {
	.proc_read  = vuln_randstruct_read,
	.proc_write = vuln_randstruct_write,
	.proc_lseek = default_llseek,
};

static struct proc_dir_entry *proc_entry;

static int __init vuln_randstruct_init(void)
{
	init_victim();
	proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_randstruct_fops);
	if (!proc_entry) {
		pr_err("vuln_randstruct: failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_randstruct: loaded. /proc/%s ready (mode 0666)\n", PROC_FILENAME);
	pr_info("vuln_randstruct: RANDSTRUCT=%d, offset(uid)=%zu (baseline=16), cred->uid=%zu (baseline=8)\n",
		IS_ENABLED(CONFIG_RANDSTRUCT),
		offsetof(struct victim_struct, uid),
		offsetof(struct cred, uid));
	return 0;
}

static void __exit vuln_randstruct_exit(void)
{
	if (proc_entry) {
		proc_remove(proc_entry);
		pr_info("vuln_randstruct: unloaded successfully\n");
	}
}

module_init(vuln_randstruct_init);
module_exit(vuln_randstruct_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerability Lab Driver for CONFIG_RANDSTRUCT");
MODULE_LICENSE("GPL");

