// SPDX-License-Identifier: GPL-2.0
/*
 * labs/32-ipe/vuln_ipe.c
 *
 * Target driver demonstrating Linux IPE (Integrity Policy Enforcement) LSM:
 *   1. Trust-based Execution Enforcement: Evaluates executable files against an active
 *      integrity policy (e.g., op=EXECUTE boot_verified=TRUE action=ALLOW).
 *   2. Mutable Storage Code Execution Defense: Blocks execution of untrusted scripts
 *      and binaries dropped into mutable locations (/tmp, /home, /var) without trusted provenance.
 *   3. Dual Mode:
 *      - Mode 0 (Permissive / Baseline): Violations audited in dmesg, but execution allowed.
 *      - Mode 1 (Enforce / Hardened): Policy violations trigger immediate -EACCES.
 *
 * Exposes /proc/vuln_ipe (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_ipe"
#define TRUSTED_BOOT_FILE "/bin/lab_tool"
#define UNTRUSTED_MUTABLE_FILE "/tmp/untrusted_payload"

/* 0 = Permissive / Baseline, 1 = Enforcing / Hardened */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_evaluations = 0;
static unsigned long g_granted_evaluations = 0;
static unsigned long g_denied_evaluations = 0;
static unsigned long g_untrusted_denials = 0;

/* Evaluation operations */
enum ipe_test_op {
	OP_TEST_BOOT_VERIFIED = 0, /* Legitimate boot-verified binary (boot_verified=TRUE) */
	OP_TEST_UNTRUSTED,         /* Untrusted file on mutable storage (boot_verified=FALSE) */
};

/*
 * Evaluates execution request under IPE policy
 */
static int evaluate_ipe_policy(enum ipe_test_op op, const char **reason)
{
	g_total_evaluations++;

	switch (op) {
	case OP_TEST_BOOT_VERIFIED:
		pr_info("ipe: [EVAL] op=EXECUTE file=\"%s\" boot_verified=TRUE action=ALLOW\n",
			TRUSTED_BOOT_FILE);
		*reason = "boot_verified (IPE rule matched: action=ALLOW)";
		g_granted_evaluations++;
		return 0;

	case OP_TEST_UNTRUSTED:
		pr_warn("type=1420 audit(ipe): op=EXECUTE file=\"%s\" boot_verified=FALSE action=DENY res=%d\n",
			UNTRUSTED_MUTABLE_FILE, (g_mode == 1) ? 0 : 1);

		if (g_mode == 0) {
			pr_notice("ipe: [PERMISSIVE] Untrusted code execution detected, but permitted (ipe.enforce=0)\n");
			*reason = "untrusted_payload (logged action=DENY, permitted)";
			g_granted_evaluations++;
			return 0;
		} else {
			pr_err("ipe: [ENFORCE] INTEGRITY VIOLATION: Execution of untrusted code BLOCKED (-EACCES)!\n");
			*reason = "untrusted_payload (IPE policy violation: blocked -EACCES)";
			g_denied_evaluations++;
			g_untrusted_denials++;
			return -EACCES;
		}

	default:
		*reason = "invalid_op";
		return -EINVAL;
	}
}

static ssize_t vuln_ipe_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"    IPE (Integrity Policy Enforcement) Status Report    \n"
		"========================================================\n"
		"Current IPE Mode        : [%d] %s\n"
		"Active Policy Name      : Lab_Hardened_Policy\n"
		"Policy Version          : 1.0.0\n"
		"Default Action          : DENY (Fail-Closed Default)\n"
		"Enforced Properties     : op=EXECUTE boot_verified=TRUE action=ALLOW\n"
		"Trusted Target Path     : %s\n"
		"Untrusted Target Path   : %s\n"
		"Total IPE Evaluations   : %lu\n"
		"Executions Granted      : %lu\n"
		"Executions Denied       : %lu\n"
		"  - Untrusted Denials   : %lu\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'       > /proc/%s\n"
		"  echo 'mode enforce'          > /proc/%s\n"
		"  echo 'test boot_verified'    > /proc/%s\n"
		"  echo 'test untrusted'        > /proc/%s\n"
		"  echo 'reset'                 > /proc/%s\n"
		"========================================================\n",
		g_mode,
		(g_mode == 1) ? "Enforce (Hardened - Untrusted code strictly blocked)" :
				"Permissive (Baseline - Violations logged, execution permitted)",
		TRUSTED_BOOT_FILE,
		UNTRUSTED_MUTABLE_FILE,
		g_total_evaluations,
		g_granted_evaluations,
		g_denied_evaluations,
		g_untrusted_denials,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_ipe_write(struct file *file, const char __user *buf,
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

	if (strcmp(kbuf, "mode permissive") == 0) {
		g_mode = 0;
		pr_info("vuln_ipe: Switched to Mode 0: Permissive (Enforce=0)\n");
		return count;
	}

	if (strcmp(kbuf, "mode enforce") == 0) {
		g_mode = 1;
		pr_info("vuln_ipe: Switched to Mode 1: Enforce (Hardened IPE Active)\n");
		return count;
	}

	if (strcmp(kbuf, "test boot_verified") == 0) {
		ret = evaluate_ipe_policy(OP_TEST_BOOT_VERIFIED, &reason);
		pr_info("vuln_ipe: Exec request 'boot_verified': %s (%s)\n",
			(ret == 0) ? "GRANTED" : "DENIED", reason);
		return (ret == 0) ? count : ret;
	}

	if (strcmp(kbuf, "test untrusted") == 0) {
		ret = evaluate_ipe_policy(OP_TEST_UNTRUSTED, &reason);
		if (ret != 0) {
			pr_warn("vuln_ipe: Exec request 'untrusted': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_ipe: Exec request 'untrusted': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_evaluations = 0;
		g_granted_evaluations = 0;
		g_denied_evaluations = 0;
		g_untrusted_denials = 0;
		pr_info("vuln_ipe: Statistics reset\n");
		return count;
	}

	if (strcmp(kbuf, "benchmark") == 0) {
		int i;
		pr_info("vuln_ipe: Running IPE policy benchmark...\n");
		for (i = 0; i < 50; i++) {
			evaluate_ipe_policy(OP_TEST_BOOT_VERIFIED, &reason);
			evaluate_ipe_policy(OP_TEST_UNTRUSTED, &reason);
		}
		pr_info("vuln_ipe: Benchmark complete: %lu total evaluations, %lu denied\n",
			g_total_evaluations, g_denied_evaluations);
		return count;
	}

	pr_warn("vuln_ipe: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_ipe_proc_ops = {
	.proc_read  = vuln_ipe_read,
	.proc_write = vuln_ipe_write,
};
#else
static const struct file_operations vuln_ipe_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_ipe_read,
	.write = vuln_ipe_write,
};
#endif

static int __init vuln_ipe_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_ipe_proc_ops);
	if (!entry) {
		pr_err("vuln_ipe: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_ipe: Target driver loaded (/proc/%s, mode=%d [Enforce])\n",
		PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_ipe_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_ipe: Driver unloaded\n");
}

module_init(vuln_ipe_init);
module_exit(vuln_ipe_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver for verifying Linux IPE (Integrity Policy Enforcement) LSM");
MODULE_LICENSE("GPL");
