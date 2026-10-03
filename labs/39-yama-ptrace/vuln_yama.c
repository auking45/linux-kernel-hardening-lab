// SPDX-License-Identifier: GPL-2.0
/*
 * labs/39-yama-ptrace/vuln_yama.c
 *
 * Target driver demonstrating Linux Yama LSM (Ptrace Scope Restrictions):
 *   CONFIG_SECURITY_YAMA=y (kernel.yama.ptrace_scope = 0, 1, 2, 3):
 *     - Scope 0 (Classic DAC): Any process can ptrace any other process with the same UID.
 *     - Scope 1 (Restricted): Processes can only ptrace direct children or targets
 *       declaring permission via prctl(PR_SET_PTRACER, pid). Blocks sibling attacks!
 *     - Scope 2 (Admin Only): Only processes with CAP_SYS_PTRACE (root) can use ptrace.
 *     - Scope 3 (No Ptrace): Ptrace is completely disabled system-wide; cannot be reversed.
 *
 * Exposes /proc/vuln_yama (mode 0666) to evaluate ptrace relationships and defenses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/capability.h>

#define PROC_FILENAME "vuln_yama"

/* 0: Classic DAC, 1: Restricted (Default), 2: Admin Only, 3: No Ptrace */
static int g_ptrace_scope = 1;

/* Statistics */
static unsigned long g_total_attempts = 0;
static unsigned long g_allowed_traces = 0;
static unsigned long g_denied_traces = 0;

enum yama_test_relation {
	REL_PARENT_CHILD = 0,   /* Tracing a direct child process */
	REL_SAME_UID_SIBLING,   /* Tracing a sibling/unrelated process of the same UID */
	REL_ADMIN_ATTACH,       /* Tracing using CAP_SYS_PTRACE */
};

static int evaluate_yama_ptrace(enum yama_test_relation rel, const char **reason)
{
	g_total_attempts++;

	switch (g_ptrace_scope) {
	case 0: /* Classic DAC */
		pr_info("yama: [ALLOWED] Ptrace allowed under Scope 0 (Classic DAC: Same UID)\n");
		*reason = "allowed (Scope 0: Classic DAC permitted)";
		g_allowed_traces++;
		return 0;

	case 1: /* Restricted: Parent->Child only */
		if (rel == REL_PARENT_CHILD || rel == REL_ADMIN_ATTACH) {
			pr_info("yama: [ALLOWED] Ptrace of direct child or with admin rights permitted under Scope 1\n");
			*reason = "allowed (Scope 1: Direct parent-child relationship verified)";
			g_allowed_traces++;
			return 0;
		}
		pr_err("yama: [DENIED] Sibling ptrace attack blocked! Sibling-to-sibling ptrace forbidden under Scope 1 (-EPERM)\n");
		*reason = "sibling_trace (BLOCKED by Yama Scope 1: -EPERM)";
		g_denied_traces++;
		return -EPERM;

	case 2: /* Admin Only */
		if (rel == REL_ADMIN_ATTACH || capable(CAP_SYS_PTRACE)) {
			pr_info("yama: [ALLOWED] Admin ptrace permitted under Scope 2 (CAP_SYS_PTRACE)\n");
			*reason = "allowed (Scope 2: Caller holds CAP_SYS_PTRACE)";
			g_allowed_traces++;
			return 0;
		}
		pr_err("yama: [DENIED] Non-admin ptrace blocked under Scope 2 (-EPERM)\n");
		*reason = "non_admin_trace (BLOCKED by Yama Scope 2: -EPERM)";
		g_denied_traces++;
		return -EPERM;

	case 3: /* No Ptrace */
		pr_err("yama: [DENIED] Ptrace is permanently disabled system-wide under Scope 3 (-EPERM)\n");
		*reason = "no_ptrace (BLOCKED by Yama Scope 3: Permanently disabled)";
		g_denied_traces++;
		return -EPERM;

	default:
		*reason = "invalid_scope";
		return -EINVAL;
	}
}

static ssize_t vuln_yama_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	const char *scope_str = "1 (Restricted: Parent-Child only)";

	if (g_ptrace_scope == 0)
		scope_str = "0 (Classic DAC: Same-UID unrestricted)";
	else if (g_ptrace_scope == 2)
		scope_str = "2 (Admin Only: CAP_SYS_PTRACE required)";
	else if (g_ptrace_scope == 3)
		scope_str = "3 (No Ptrace: System-wide disabled)";

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"        Linux Yama LSM Ptrace Scope Status              \n"
		"========================================================\n"
		"Current Ptrace Scope    : [%d] %s\n"
		"LSM Registered          : CONFIG_SECURITY_YAMA=y\n"
		"Total Ptrace Probes     : %lu\n"
		"Ptrace Attach Granted   : %lu\n"
		"Ptrace Attach Denied    : %lu (-EPERM)\n"
		"Available Commands      :\n"
		"  echo 'scope 0'          > /proc/%s\n"
		"  echo 'scope 1'          > /proc/%s\n"
		"  echo 'scope 2'          > /proc/%s\n"
		"  echo 'scope 3'          > /proc/%s\n"
		"  echo 'test child'       > /proc/%s\n"
		"  echo 'test sibling'     > /proc/%s\n"
		"  echo 'test admin'       > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_ptrace_scope, scope_str,
		g_total_attempts,
		g_allowed_traces,
		g_denied_traces,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_yama_write(struct file *file, const char __user *buf,
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

	if (strcmp(kbuf, "scope 0") == 0) {
		g_ptrace_scope = 0;
		pr_info("vuln_yama: Set ptrace_scope = 0 (Classic DAC)\n");
		return count;
	}

	if (strcmp(kbuf, "scope 1") == 0) {
		g_ptrace_scope = 1;
		pr_info("vuln_yama: Set ptrace_scope = 1 (Restricted Parent-Child)\n");
		return count;
	}

	if (strcmp(kbuf, "scope 2") == 0) {
		g_ptrace_scope = 2;
		pr_info("vuln_yama: Set ptrace_scope = 2 (Admin Only)\n");
		return count;
	}

	if (strcmp(kbuf, "scope 3") == 0) {
		g_ptrace_scope = 3;
		pr_info("vuln_yama: Set ptrace_scope = 3 (No Ptrace)\n");
		return count;
	}

	if (strcmp(kbuf, "test child") == 0) {
		ret = evaluate_yama_ptrace(REL_PARENT_CHILD, &reason);
		if (ret != 0) {
			pr_warn("vuln_yama: Test 'child': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_yama: Test 'child': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test sibling") == 0) {
		ret = evaluate_yama_ptrace(REL_SAME_UID_SIBLING, &reason);
		if (ret != 0) {
			pr_warn("vuln_yama: Test 'sibling': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_yama: Test 'sibling': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test admin") == 0) {
		ret = evaluate_yama_ptrace(REL_ADMIN_ATTACH, &reason);
		if (ret != 0) {
			pr_warn("vuln_yama: Test 'admin': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_yama: Test 'admin': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_attempts = 0;
		g_allowed_traces = 0;
		g_denied_traces = 0;
		pr_info("vuln_yama: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_yama: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_yama_proc_ops = {
	.proc_read  = vuln_yama_read,
	.proc_write = vuln_yama_write,
};
#else
static const struct file_operations vuln_yama_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_yama_read,
	.write = vuln_yama_write,
};
#endif

static int __init vuln_yama_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_yama_proc_ops);
	if (!entry) {
		pr_err("vuln_yama: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_yama: Target driver loaded (/proc/%s, scope=%d)\n",
		PROC_FILENAME, g_ptrace_scope);
	return 0;
}

static void __exit vuln_yama_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_yama: Driver unloaded\n");
}

module_init(vuln_yama_init);
module_exit(vuln_yama_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Yama LSM Ptrace Scope Restrictions");
MODULE_LICENSE("GPL");
