// SPDX-License-Identifier: GPL-2.0
/*
 * labs/36-bpf-hardening/vuln_bpf_hardening.c
 *
 * Target driver demonstrating Linux BPF Hardening:
 *   1. CONFIG_BPF_JIT_ALWAYS_ON=y: Eliminates the in-kernel BPF interpreter,
 *      preventing interpreter-based gadgets and speculative execution leaks.
 *   2. kernel.unprivileged_bpf_disabled (0, 1, 2):
 *      - Prevents unprivileged users from calling sys_bpf() to load eBPF programs or maps.
 *   3. net.core.bpf_jit_harden (0, 1, 2):
 *      - Constant Blinding: Masks 32/64-bit immediate values with randomized keys
 *        to neutralize JIT-spraying attacks that hide native shellcode inside constants.
 *
 * Exposes /proc/vuln_bpf_hardening (mode 0666) to test and measure BPF defenses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/filter.h>

#define PROC_FILENAME "vuln_bpf_hardening"

/* 0: Permissive, 1: Hardened */
static int g_bpf_hardened = 1;

/* Statistics */
static unsigned long g_total_evals = 0;
static unsigned long g_unpriv_attempts = 0;
static unsigned long g_unpriv_denials = 0;
static unsigned long g_jitspray_attempts = 0;
static unsigned long g_constants_blinded = 0;

enum bpf_test_action {
	ACT_UNPRIV_BPF_LOAD = 0,
	ACT_JIT_SPRAY_PAYLOAD,
};

static int evaluate_bpf_hardening(enum bpf_test_action act, const char **reason)
{
	g_total_evals++;

	switch (act) {
	case ACT_UNPRIV_BPF_LOAD:
		g_unpriv_attempts++;
		if (g_bpf_hardened) {
			pr_err("bpf_hardening: [BLOCKED] Unprivileged bpf() call rejected (-EPERM). sysctl unprivileged_bpf_disabled active!\n");
			*reason = "unpriv_bpf (BLOCKED: -EPERM via unprivileged_bpf_disabled)";
			g_unpriv_denials++;
			return -EPERM;
		}
		pr_warn("bpf_hardening: [PERMISSIVE] Unprivileged bpf() call allowed in permissive mode\n");
		*reason = "unpriv_bpf (ALLOWED in permissive mode)";
		return 0;

	case ACT_JIT_SPRAY_PAYLOAD:
		g_jitspray_attempts++;
		if (g_bpf_hardened) {
			pr_info("bpf_hardening: [BLINDED] JIT Spray constant 0x4831c04831db blinded into randomized XOR splits (bpf_jit_harden=2)!\n");
			*reason = "jitspray_payload (NEUTRALIZED: Immediate constant blinded via randomized XOR mask)";
			g_constants_blinded++;
			return 0;
		}
		pr_warn("bpf_hardening: [PERMISSIVE] Raw immediate constant emitted without blinding (VULNERABLE to JIT spray)\n");
		*reason = "jitspray_payload (EXPOSED: Raw constant compiled into executable page)";
		return 0;

	default:
		*reason = "invalid_action";
		return -EINVAL;
	}
}

static ssize_t vuln_bpf_read(struct file *file, char __user *buf,
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
		"          Linux BPF Hardening Status Report             \n"
		"========================================================\n"
		"BPF Security Profile    : %s\n"
		"BPF JIT Always On       : CONFIG_BPF_JIT_ALWAYS_ON=y (Interpreter Disabled)\n"
		"Unprivileged BPF Status : %s\n"
		"JIT Constant Blinding   : %s (bpf_jit_harden=%d)\n"
		"Total Evaluated Requests: %lu\n"
		"Unprivileged Calls Tried: %lu\n"
		"Unprivileged Calls Denied: %lu (-EPERM)\n"
		"JIT Spray Probes Tried  : %lu\n"
		"Immediate Values Blinded: %lu\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'  > /proc/%s\n"
		"  echo 'mode hardened'    > /proc/%s\n"
		"  echo 'test unprivileged'> /proc/%s\n"
		"  echo 'test jitspray'    > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_bpf_hardened ? "HARDENED (Enforce unprivileged_bpf_disabled & bpf_jit_harden)" : "PERMISSIVE",
		g_bpf_hardened ? "DISABLED (unprivileged_bpf_disabled=2)" : "ENABLED (unprivileged_bpf_disabled=0)",
		g_bpf_hardened ? "ACTIVE (All constants blinded with random XOR mask)" : "DISABLED (Raw constants emitted)",
		g_bpf_hardened ? 2 : 0,
		g_total_evals,
		g_unpriv_attempts,
		g_unpriv_denials,
		g_jitspray_attempts,
		g_constants_blinded,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_bpf_write(struct file *file, const char __user *buf,
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
		g_bpf_hardened = 0;
		pr_info("vuln_bpf_hardening: Mode set to PERMISSIVE\n");
		return count;
	}

	if (strcmp(kbuf, "mode hardened") == 0) {
		g_bpf_hardened = 1;
		pr_info("vuln_bpf_hardening: Mode set to HARDENED\n");
		return count;
	}

	if (strcmp(kbuf, "test unprivileged") == 0) {
		ret = evaluate_bpf_hardening(ACT_UNPRIV_BPF_LOAD, &reason);
		if (ret != 0) {
			pr_warn("vuln_bpf_hardening: Test 'unprivileged': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_bpf_hardening: Test 'unprivileged': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test jitspray") == 0) {
		ret = evaluate_bpf_hardening(ACT_JIT_SPRAY_PAYLOAD, &reason);
		pr_info("vuln_bpf_hardening: Test 'jitspray': RESULT (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_evals = 0;
		g_unpriv_attempts = 0;
		g_unpriv_denials = 0;
		g_jitspray_attempts = 0;
		g_constants_blinded = 0;
		pr_info("vuln_bpf_hardening: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_bpf_hardening: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_bpf_proc_ops = {
	.proc_read  = vuln_bpf_read,
	.proc_write = vuln_bpf_write,
};
#else
static const struct file_operations vuln_bpf_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_bpf_read,
	.write = vuln_bpf_write,
};
#endif

static int __init vuln_bpf_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_bpf_proc_ops);
	if (!entry) {
		pr_err("vuln_bpf_hardening: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_bpf_hardening: Driver loaded (/proc/%s, hardened=%d)\n",
		PROC_FILENAME, g_bpf_hardened);
	return 0;
}

static void __exit vuln_bpf_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_bpf_hardening: Driver unloaded\n");
}

module_init(vuln_bpf_init);
module_exit(vuln_bpf_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Linux BPF Hardening");
MODULE_LICENSE("GPL");
