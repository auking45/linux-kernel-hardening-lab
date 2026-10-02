// SPDX-License-Identifier: GPL-2.0
/*
 * labs/33-lockdown/vuln_lockdown.c
 *
 * Target driver demonstrating Linux Kernel Lockdown LSM:
 *   1. Integrity Mode: Prevents userland (even root) from modifying running kernel memory,
 *      hardware I/O ports, or loading unsigned modules.
 *   2. Confidentiality Mode: Extends integrity mode to prevent root from extracting
 *      confidential kernel secrets (e.g., reading /dev/mem, /proc/kcore, BPF kprobe probes).
 *   3. Triple Mode:
 *      - Mode 0 (None): No lockdown restrictions active.
 *      - Mode 1 (Integrity): Integrity modifications strictly blocked (-EPERM).
 *      - Mode 2 (Confidentiality): Both integrity and confidentiality operations blocked (-EPERM).
 *
 * Exposes /proc/vuln_lockdown (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_lockdown"

/* 0 = None, 1 = Integrity, 2 = Confidentiality */
static int g_lockdown_level = 2;

/* Statistics */
static unsigned long g_total_requests = 0;
static unsigned long g_granted_requests = 0;
static unsigned long g_denied_requests = 0;
static unsigned long g_integrity_denials = 0;
static unsigned long g_confidentiality_denials = 0;

/* Lockdown evaluation operations */
enum lockdown_test_op {
	OP_LEGIT_USER_ACCESS = 0, /* Normal userspace execution and data access */
	OP_INTEGRITY_TAMPER,      /* Attempt to write to raw memory (/dev/mem) or kernel text */
	OP_CONFIDENTIALITY_LEAK,  /* Attempt to inspect kernel secrets (/proc/kcore read) */
};

/*
 * Evaluates operation against Lockdown policy
 */
static int evaluate_lockdown(enum lockdown_test_op op, const char **reason)
{
	g_total_requests++;

	switch (op) {
	case OP_LEGIT_USER_ACCESS:
		pr_info("lockdown: [EVAL] op=USER_ACCESS comm=\"%s\" pid=%d -> ALLOWED (ret = 0)\n",
			current->comm, current->pid);
		*reason = "user_access (Safe userland execution allowed)";
		g_granted_requests++;
		return 0;

	case OP_INTEGRITY_TAMPER:
		if (g_lockdown_level >= 1) {
			pr_notice("Lockdown: %s: raw memory/kernel text write is restricted; see man kernel_lockdown.7\n",
				  current->comm);
			pr_err("lockdown: [INTEGRITY_VIOLATION] Blocked raw memory tamper (-EPERM)!\n");
			*reason = "integrity_tamper (BLOCKED by Lockdown Integrity mode: -EPERM)";
			g_denied_requests++;
			g_integrity_denials++;
			return -EPERM;
		}
		pr_warn("lockdown: [NONE_MODE] Raw memory write permitted in Mode 0 (None)\n");
		*reason = "integrity_tamper (ALLOWED in None mode)";
		g_granted_requests++;
		return 0;

	case OP_CONFIDENTIALITY_LEAK:
		if (g_lockdown_level >= 2) {
			pr_notice("Lockdown: %s: reading kernel core dump /proc/kcore is restricted; see man kernel_lockdown.7\n",
				  current->comm);
			pr_err("lockdown: [CONFIDENTIALITY_VIOLATION] Blocked kernel memory read (-EPERM)!\n");
			*reason = "confidentiality_leak (BLOCKED by Lockdown Confidentiality mode: -EPERM)";
			g_denied_requests++;
			g_confidentiality_denials++;
			return -EPERM;
		}
		pr_warn("lockdown: [PERMISSIVE/INTEGRITY] Reading kernel memory permitted (level=%d < 2)\n",
			g_lockdown_level);
		*reason = "confidentiality_leak (ALLOWED in None/Integrity mode)";
		g_granted_requests++;
		return 0;

	default:
		*reason = "invalid_op";
		return -EINVAL;
	}
}

static ssize_t vuln_lockdown_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	const char *level_str = "None";

	if (g_lockdown_level == 1)
		level_str = "Integrity";
	else if (g_lockdown_level == 2)
		level_str = "Confidentiality";

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"        Kernel Lockdown LSM Status Report               \n"
		"========================================================\n"
		"Current Lockdown Level  : [%d] %s\n"
		"SecurityFS String       : %s\n"
		"Total Evaluated Requests: %lu\n"
		"Requests Granted        : %lu\n"
		"Requests Denied         : %lu\n"
		"  - Integrity Denials   : %lu\n"
		"  - Confidentiality Den : %lu\n"
		"Available Commands      :\n"
		"  echo 'mode none'             > /proc/%s\n"
		"  echo 'mode integrity'        > /proc/%s\n"
		"  echo 'mode confidentiality'  > /proc/%s\n"
		"  echo 'test legit'            > /proc/%s\n"
		"  echo 'test integrity'        > /proc/%s\n"
		"  echo 'test confidentiality'  > /proc/%s\n"
		"  echo 'reset'                 > /proc/%s\n"
		"========================================================\n",
		g_lockdown_level, level_str,
		(g_lockdown_level == 0) ? "[none] integrity confidentiality" :
		(g_lockdown_level == 1) ? "none [integrity] confidentiality" :
					  "none integrity [confidentiality]",
		g_total_requests,
		g_granted_requests,
		g_denied_requests,
		g_integrity_denials,
		g_confidentiality_denials,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_lockdown_write(struct file *file, const char __user *buf,
				   size_t count, loff_t *ppos)
{
	char kbuf[128];
	const char *reason = "";
	int ret;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';
	strim(kbuf);

	if (strcmp(kbuf, "mode none") == 0) {
		g_lockdown_level = 0;
		pr_info("vuln_lockdown: Set Mode 0: None ([none] integrity confidentiality)\n");
		return count;
	}

	if (strcmp(kbuf, "mode integrity") == 0) {
		g_lockdown_level = 1;
		pr_info("vuln_lockdown: Set Mode 1: Integrity (none [integrity] confidentiality)\n");
		return count;
	}

	if (strcmp(kbuf, "mode confidentiality") == 0) {
		g_lockdown_level = 2;
		pr_info("vuln_lockdown: Set Mode 2: Confidentiality (none integrity [confidentiality])\n");
		return count;
	}

	if (strcmp(kbuf, "test legit") == 0) {
		ret = evaluate_lockdown(OP_LEGIT_USER_ACCESS, &reason);
		pr_info("vuln_lockdown: Request 'legit': %s (%s)\n",
			(ret == 0) ? "GRANTED" : "DENIED", reason);
		return (ret == 0) ? count : ret;
	}

	if (strcmp(kbuf, "test integrity") == 0) {
		ret = evaluate_lockdown(OP_INTEGRITY_TAMPER, &reason);
		if (ret != 0) {
			pr_warn("vuln_lockdown: Request 'integrity': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_lockdown: Request 'integrity': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test confidentiality") == 0) {
		ret = evaluate_lockdown(OP_CONFIDENTIALITY_LEAK, &reason);
		if (ret != 0) {
			pr_warn("vuln_lockdown: Request 'confidentiality': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_lockdown: Request 'confidentiality': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_requests = 0;
		g_granted_requests = 0;
		g_denied_requests = 0;
		g_integrity_denials = 0;
		g_confidentiality_denials = 0;
		pr_info("vuln_lockdown: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_lockdown: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_lockdown_proc_ops = {
	.proc_read  = vuln_lockdown_read,
	.proc_write = vuln_lockdown_write,
};
#else
static const struct file_operations vuln_lockdown_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_lockdown_read,
	.write = vuln_lockdown_write,
};
#endif

static int __init vuln_lockdown_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_lockdown_proc_ops);
	if (!entry) {
		pr_err("vuln_lockdown: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_lockdown: Target driver loaded (/proc/%s, level=%d [Confidentiality])\n",
		PROC_FILENAME, g_lockdown_level);
	return 0;
}

static void __exit vuln_lockdown_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_lockdown: Driver unloaded\n");
}

module_init(vuln_lockdown_init);
module_exit(vuln_lockdown_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Linux Kernel Lockdown LSM");
MODULE_LICENSE("GPL");
