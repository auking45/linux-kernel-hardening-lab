// SPDX-License-Identifier: GPL-2.0
/*
 * labs/40-kexec-restrict/vuln_kexec.c
 *
 * Target driver demonstrating Linux Kexec Restrictions and Hardening:
 *   1. /proc/sys/kernel/kexec_load_disabled:
 *      - One-way security latch (0 -> 1). Once disabled, cannot be re-enabled without reboot.
 *      - Completely forbids sys_kexec_load and sys_kexec_file_load syscalls (-EPERM).
 *   2. Raw kexec_load vs kexec_file_load:
 *      - kexec_load: Userspace passes raw memory segments. Allows arbitrary kernel replacement
 *        without cryptographic verification, bypassing Secure Boot and integrity mechanisms.
 *      - kexec_file_load: Kernel reads the kernel image file directly and verifies PE/IMA/PKCS#7
 *        cryptographic signatures (CONFIG_KEXEC_SIG, CONFIG_KEXEC_SIG_FORCE).
 *   3. Kernel Lockdown LSM Interaction:
 *      - In Lockdown Integrity or Confidentiality mode, raw kexec_load is prohibited entirely,
 *        and kexec_file_load requires valid cryptographic signatures.
 *
 * Exposes /proc/vuln_kexec (mode 0666) to evaluate kexec restriction mechanics.
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

#define PROC_FILENAME "vuln_kexec"

/* Simulated restriction states */
static int g_kexec_load_disabled = 0;       /* 0: allowed, 1: permanently disabled */
static int g_sig_force_enforced = 1;        /* CONFIG_KEXEC_SIG_FORCE */
static int g_lockdown_level = 0;            /* 0: none, 1: integrity, 2: confidentiality */

/* Statistics */
static unsigned long g_total_attempts = 0;
static unsigned long g_raw_attempts = 0;
static unsigned long g_raw_blocked = 0;
static unsigned long g_file_attempts = 0;
static unsigned long g_file_blocked = 0;
static unsigned long g_allowed_boots = 0;

enum kexec_type {
	KEXEC_TYPE_RAW_SEGMENTS = 0, /* sys_kexec_load (arbitrary userspace memory segments) */
	KEXEC_TYPE_FILE_UNSIGNED,    /* sys_kexec_file_load without signature */
	KEXEC_TYPE_FILE_SIGNED,      /* sys_kexec_file_load with valid signature */
};

static int evaluate_kexec_load(enum kexec_type type, const char **reason)
{
	g_total_attempts++;

	/* 1. Global one-way latch check: kexec_load_disabled */
	if (g_kexec_load_disabled) {
		pr_err("kexec_restrict: [BLOCKED] kexec rejected: kernel.kexec_load_disabled = 1 (-EPERM)\n");
		*reason = "blocked by kernel.kexec_load_disabled = 1 (one-way latch active)";
		if (type == KEXEC_TYPE_RAW_SEGMENTS)
			g_raw_blocked++;
		else
			g_file_blocked++;
		return -EPERM;
	}

	/* 2. Raw memory segment kexec (sys_kexec_load) evaluation */
	if (type == KEXEC_TYPE_RAW_SEGMENTS) {
		g_raw_attempts++;
		/* Kernel Lockdown blocks raw kexec_load */
		if (g_lockdown_level >= 1) {
			pr_err("kexec_restrict: [BLOCKED] Raw kexec_load prohibited under Kernel Lockdown (%s) (-EPERM)\n",
			       g_lockdown_level == 1 ? "integrity" : "confidentiality");
			*reason = "blocked: raw kexec_load forbidden by Kernel Lockdown";
			g_raw_blocked++;
			return -EPERM;
		}

		/* Without lockdown or kexec_load_disabled, raw loading is permitted (VULNERABLE!) */
		pr_warn("kexec_restrict: [VULNERABLE] Raw kexec_load allowed! Arbitrary kernel code execution possible.\n");
		*reason = "allowed (VULNERABLE: raw kexec permitted without signature verification)";
		g_allowed_boots++;
		return 0;
	}

	/* 3. File-based kexec (sys_kexec_file_load) evaluation */
	g_file_attempts++;
	if (type == KEXEC_TYPE_FILE_UNSIGNED) {
		if (g_sig_force_enforced || g_lockdown_level >= 1) {
			pr_err("kexec_restrict: [BLOCKED] Unsigned kexec image rejected (CONFIG_KEXEC_SIG_FORCE / Lockdown) (-EKEYREJECTED)\n");
			*reason = "blocked: unsigned image rejected by KEXEC_SIG_FORCE / Lockdown";
			g_file_blocked++;
			return -EKEYREJECTED;
		}

		pr_warn("kexec_restrict: [WARNING] Unsigned kexec image permitted (signature verification disabled)\n");
		*reason = "allowed (unsigned kernel image allowed)";
		g_allowed_boots++;
		return 0;
	}

	/* Signed image permitted */
	pr_info("kexec_restrict: [ALLOWED] Signed kernel image verified and accepted for kexec.\n");
	*reason = "allowed (valid signature verified)";
	g_allowed_boots++;
	return 0;
}

static ssize_t vuln_kexec_read(struct file *file, char __user *buf,
			       size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
			 "=== Linux Kexec Restrictions & Hardening Status ===\n");
	len += scnprintf(page + len, 2048 - len,
			 "kexec_load_disabled      : %d (%s)\n",
			 g_kexec_load_disabled,
			 g_kexec_load_disabled ? "DISABLED (One-way latch active)" : "ENABLED");
	len += scnprintf(page + len, 2048 - len,
			 "CONFIG_KEXEC_SIG_FORCE   : %s\n",
			 g_sig_force_enforced ? "ENABLED (Mandatory Signature)" : "DISABLED");
	len += scnprintf(page + len, 2048 - len,
			 "Simulated Lockdown Level : %s\n",
			 g_lockdown_level == 0 ? "none" :
			 (g_lockdown_level == 1 ? "integrity" : "confidentiality"));
	len += scnprintf(page + len, 2048 - len,
			 "Total Execution Attempts : %lu\n", g_total_attempts);
	len += scnprintf(page + len, 2048 - len,
			 "Raw kexec_load Attempts  : %lu (Blocked: %lu)\n",
			 g_raw_attempts, g_raw_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "File kexec Attempts      : %lu (Blocked: %lu)\n",
			 g_file_attempts, g_file_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "Allowed Kernel Boots     : %lu\n", g_allowed_boots);
	len += scnprintf(page + len, 2048 - len,
			 "====================================================\n");
	len += scnprintf(page + len, 2048 - len,
			 "Available Commands:\n");
	len += scnprintf(page + len, 2048 - len,
			 "  load_raw              - Attempt raw unverified kexec_load\n");
	len += scnprintf(page + len, 2048 - len,
			 "  load_file signed      - Attempt signed kexec_file_load\n");
	len += scnprintf(page + len, 2048 - len,
			 "  load_file unsigned    - Attempt unsigned kexec_file_load\n");
	len += scnprintf(page + len, 2048 - len,
			 "  set_disabled <0|1>    - Set kexec_load_disabled (1 is one-way latch)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  set_lockdown <lvl>    - Set lockdown (none, integrity, confidentiality)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  reset                 - Reset statistics and unlatch states\n");

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_kexec_write(struct file *file, const char __user *buf,
				size_t count, loff_t *ppos)
{
	char kbuf[128];
	size_t to_copy;
	const char *reason = "";
	int res;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;
	kbuf[to_copy] = '\0';

	/* Strip trailing newline */
	if (to_copy > 0 && kbuf[to_copy - 1] == '\n')
		kbuf[to_copy - 1] = '\0';

	if (strncmp(kbuf, "load_raw", 8) == 0) {
		res = evaluate_kexec_load(KEXEC_TYPE_RAW_SEGMENTS, &reason);
		if (res < 0)
			return res;
		return count;
	}

	if (strncmp(kbuf, "load_file signed", 16) == 0) {
		res = evaluate_kexec_load(KEXEC_TYPE_FILE_SIGNED, &reason);
		if (res < 0)
			return res;
		return count;
	}

	if (strncmp(kbuf, "load_file unsigned", 18) == 0) {
		res = evaluate_kexec_load(KEXEC_TYPE_FILE_UNSIGNED, &reason);
		if (res < 0)
			return res;
		return count;
	}

	if (strncmp(kbuf, "set_disabled 1", 14) == 0) {
		g_kexec_load_disabled = 1;
		pr_info("kexec_restrict: [SYSCTL] kexec_load_disabled set to 1. Latch locked permanently.\n");
		return count;
	}

	if (strncmp(kbuf, "set_disabled 0", 14) == 0) {
		if (g_kexec_load_disabled == 1) {
			pr_err("kexec_restrict: [LATCH REJECTED] Cannot reset kexec_load_disabled back to 0! (-EPERM)\n");
			return -EPERM;
		}
		g_kexec_load_disabled = 0;
		return count;
	}

	if (strncmp(kbuf, "set_lockdown integrity", 22) == 0) {
		g_lockdown_level = 1;
		pr_info("kexec_restrict: Simulated lockdown level set to 'integrity'\n");
		return count;
	}

	if (strncmp(kbuf, "set_lockdown confidentiality", 28) == 0) {
		g_lockdown_level = 2;
		pr_info("kexec_restrict: Simulated lockdown level set to 'confidentiality'\n");
		return count;
	}

	if (strncmp(kbuf, "set_lockdown none", 17) == 0) {
		g_lockdown_level = 0;
		pr_info("kexec_restrict: Simulated lockdown level set to 'none'\n");
		return count;
	}

	if (strncmp(kbuf, "reset", 5) == 0) {
		g_kexec_load_disabled = 0;
		g_lockdown_level = 0;
		g_total_attempts = 0;
		g_raw_attempts = 0;
		g_raw_blocked = 0;
		g_file_attempts = 0;
		g_file_blocked = 0;
		g_allowed_boots = 0;
		pr_info("kexec_restrict: Diagnostics and latch state reset.\n");
		return count;
	}

	pr_warn("kexec_restrict: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

static const struct proc_ops vuln_kexec_proc_ops = {
	.proc_read  = vuln_kexec_read,
	.proc_write = vuln_kexec_write,
};

static int __init vuln_kexec_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_kexec_proc_ops);
	if (!entry) {
		pr_err("vuln_kexec: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_kexec: Loaded module. Restriction interface at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_kexec_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_kexec: Unloaded module.\n");
}

module_init(vuln_kexec_init);
module_exit(vuln_kexec_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Kexec Restrictions and Signature Enforcement Target Driver");
MODULE_VERSION("1.0");
