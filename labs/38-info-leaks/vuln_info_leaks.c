// SPDX-License-Identifier: GPL-2.0
/*
 * labs/38-info-leaks/vuln_info_leaks.c
 *
 * Target driver demonstrating Kernel Information Leak Defenses:
 *   1. CONFIG_SECURITY_DMESG_RESTRICT=y (kernel.dmesg_restrict=1):
 *      - Restricts unprivileged users from reading dmesg / syslog buffer.
 *      - Requires CAP_SYSLOG to inspect kernel messages, preventing KASLR leaks.
 *   2. kernel.kptr_restrict (0, 1, 2):
 *      - 0: Raw kernel pointers printed via %pK (vulnerable to KASLR break).
 *      - 1: %pK pointers hidden (zeros) for unprivileged callers without CAP_SYSLOG.
 *      - 2: %pK pointers unconditionally hidden for all users (even root).
 *   3. Modern %p Pointer Hashing (SipHash):
 *      - Normal %p format specifiers are automatically hashed to prevent address exposure.
 *
 * Exposes /proc/vuln_info_leaks (mode 0666) to test pointer redaction and dmesg gating.
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

#define PROC_FILENAME "vuln_info_leaks"

/* 0: Permissive (leaks enabled), 1: Hardened (kptr_restrict=2, dmesg_restrict=1) */
static int g_info_leaks_hardened = 1;

/* Dummy secret kernel address to simulate symbol/stack leak */
static void *g_dummy_kernel_symbol = (void *)0xffff800081234567UL;

/* Statistics */
static unsigned long g_total_probes = 0;
static unsigned long g_leaks_prevented = 0;
static unsigned long g_dmesg_denials = 0;

static int evaluate_dmesg_access(const char **reason)
{
	g_total_probes++;

	if (g_info_leaks_hardened) {
		/* Simulate dmesg_restrict check: requires CAP_SYSLOG */
		if (!capable(CAP_SYSLOG) && !capable(CAP_SYS_ADMIN)) {
			pr_err("info_leaks: [DENIED] Unprivileged access to kernel log buffer blocked (-EPERM). dmesg_restrict active!\n");
			*reason = "dmesg_read (BLOCKED: -EPERM via kernel.dmesg_restrict=1)";
			g_dmesg_denials++;
			return -EPERM;
		}
		*reason = "dmesg_read (ALLOWED: Caller possesses CAP_SYSLOG)";
		return 0;
	}

	pr_warn("info_leaks: [PERMISSIVE] Unprivileged dmesg read permitted! (KASLR pointers exposed)\n");
	*reason = "dmesg_read (ALLOWED in permissive mode: Vulnerable to KASLR bypass)";
	return 0;
}

static ssize_t vuln_info_leaks_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	char kptr_str[32];

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	/* Format pointer according to active hardening state */
	if (g_info_leaks_hardened) {
		/* Redacted to all zeros under kptr_restrict */
		scnprintf(kptr_str, sizeof(kptr_str), "0000000000000000");
		g_leaks_prevented++;
	} else {
		/* Exposed raw hex address in permissive mode */
		scnprintf(kptr_str, sizeof(kptr_str), "%px", g_dummy_kernel_symbol);
	}

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"    Linux Kernel Information Leak Defense Status        \n"
		"========================================================\n"
		"Hardening Profile       : %s\n"
		"Dmesg Restriction       : %s (CONFIG_SECURITY_DMESG_RESTRICT=y)\n"
		"Kptr Restriction        : %s (kptr_restrict=%d)\n"
		"Caller Capabilities     : CAP_SYSLOG=%s, CAP_SYS_ADMIN=%s\n"
		"Sample Kernel Symbol (%%pK): %s\n"
		"Hashed Pointer Format (%%p) : %p\n"
		"Total Security Probes   : %lu\n"
		"Kernel Leaks Prevented  : %lu\n"
		"Dmesg Reads Denied      : %lu (-EPERM)\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'  > /proc/%s\n"
		"  echo 'mode hardened'    > /proc/%s\n"
		"  echo 'test kptr'        > /proc/%s\n"
		"  echo 'test dmesg'       > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_info_leaks_hardened ? "HARDENED (dmesg_restrict=1, kptr_restrict=2)" : "PERMISSIVE (Leaks active)",
		g_info_leaks_hardened ? "RESTRICTED (CAP_SYSLOG required)" : "UNRESTRICTED (Public dmesg)",
		g_info_leaks_hardened ? "REDACTED (Zeros)" : "EXPOSED (Raw Hex)",
		g_info_leaks_hardened ? 2 : 0,
		capable(CAP_SYSLOG) ? "YES" : "NO",
		capable(CAP_SYS_ADMIN) ? "YES" : "NO",
		kptr_str,
		g_dummy_kernel_symbol,
		g_total_probes,
		g_leaks_prevented,
		g_dmesg_denials,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_info_leaks_write(struct file *file, const char __user *buf,
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
		g_info_leaks_hardened = 0;
		pr_info("vuln_info_leaks: Mode set to PERMISSIVE (leaks allowed)\n");
		return count;
	}

	if (strcmp(kbuf, "mode hardened") == 0) {
		g_info_leaks_hardened = 1;
		pr_info("vuln_info_leaks: Mode set to HARDENED (kptr=2, dmesg=1)\n");
		return count;
	}

	if (strcmp(kbuf, "test kptr") == 0) {
		g_total_probes++;
		if (g_info_leaks_hardened) {
			pr_info("vuln_info_leaks: %%pK redacted to 0000000000000000 (Safe)\n");
			g_leaks_prevented++;
		} else {
			pr_warn("vuln_info_leaks: %%pK raw pointer exposed: %px (VULNERABLE)\n",
				g_dummy_kernel_symbol);
		}
		return count;
	}

	if (strcmp(kbuf, "test dmesg") == 0) {
		ret = evaluate_dmesg_access(&reason);
		if (ret != 0) {
			pr_warn("vuln_info_leaks: Test 'dmesg': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_info_leaks: Test 'dmesg': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_probes = 0;
		g_leaks_prevented = 0;
		g_dmesg_denials = 0;
		pr_info("vuln_info_leaks: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_info_leaks: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_info_leaks_proc_ops = {
	.proc_read  = vuln_info_leaks_read,
	.proc_write = vuln_info_leaks_write,
};
#else
static const struct file_operations vuln_info_leaks_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_info_leaks_read,
	.write = vuln_info_leaks_write,
};
#endif

static int __init vuln_info_leaks_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_info_leaks_proc_ops);
	if (!entry) {
		pr_err("vuln_info_leaks: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_info_leaks: Driver loaded (/proc/%s, hardened=%d)\n",
		PROC_FILENAME, g_info_leaks_hardened);
	return 0;
}

static void __exit vuln_info_leaks_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_info_leaks: Driver unloaded\n");
}

module_init(vuln_info_leaks_init);
module_exit(vuln_info_leaks_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Kernel Information Leak Defenses");
MODULE_LICENSE("GPL");
