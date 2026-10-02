// SPDX-License-Identifier: GPL-2.0
/*
 * labs/34-module-sig/vuln_module_sig.c
 *
 * Target driver demonstrating Linux Kernel Module Signature Verification:
 *   - CONFIG_MODULE_SIG=y: Enables cryptographic module signature checking.
 *   - CONFIG_MODULE_SIG_FORCE=y: Enforces that all loaded modules MUST possess
 *     a valid cryptographic signature signed by a trusted key in the kernel keyring.
 *   - sysfs parameter: /sys/module/module/parameters/sig_enforce
 *
 * Exposes /proc/vuln_module_sig (mode 0666) to evaluate module load attempts:
 *   - Test 1: Signed with trusted built-in key (Valid PKCS#7/CMS signature)
 *   - Test 2: Unsigned module (No signature appended)
 *   - Test 3: Tampered/invalid signature (Digest mismatch)
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_module_sig"

/* 0: Permissive (warning only), 1: Enforced (strict rejection) */
static int g_sig_enforce = 1;

/* Statistics */
static unsigned long g_total_loads = 0;
static unsigned long g_granted_loads = 0;
static unsigned long g_denied_loads = 0;
static unsigned long g_unsigned_denials = 0;
static unsigned long g_tampered_denials = 0;

enum mod_sig_test_type {
	MOD_TEST_SIGNED = 0,
	MOD_TEST_UNSIGNED,
	MOD_TEST_TAMPERED,
};

static int evaluate_module_signature(enum mod_sig_test_type type, const char **reason)
{
	g_total_loads++;

	switch (type) {
	case MOD_TEST_SIGNED:
		pr_info("module_sig: [VERIFIED] Valid PKCS#7 signature verified against .builtin_trusted_keys (ret = 0)\n");
		*reason = "signed (Valid signature verified against trusted keyring)";
		g_granted_loads++;
		return 0;

	case MOD_TEST_UNSIGNED:
		if (g_sig_enforce) {
			pr_err("module_sig: [REJECTED] Loading of unsigned module is rejected: -ENOKEY\n");
			pr_notice("PKCS#7 signature missing or not found in kernel trusted keyring\n");
			*reason = "unsigned (BLOCKED by sig_enforce: -ENOKEY)";
			g_denied_loads++;
			g_unsigned_denials++;
			return -ENOKEY;
		}
		pr_warn("module_sig: [PERMISSIVE] Loading of unsigned module permitted (sig_enforce=0, taint flag set: TAINT_UNSIGNED_MODULE)\n");
		*reason = "unsigned (ALLOWED in permissive mode: TAINT_UNSIGNED_MODULE)";
		g_granted_loads++;
		return 0;

	case MOD_TEST_TAMPERED:
		if (g_sig_enforce) {
			pr_err("module_sig: [REJECTED] Module signature verification failed: -EKEYREJECTED (hash mismatch / key invalid)\n");
			pr_notice("PKCS#7 signature digest does not match module payload\n");
			*reason = "tampered (BLOCKED by sig_enforce: -EKEYREJECTED)";
			g_denied_loads++;
			g_tampered_denials++;
			return -EKEYREJECTED;
		}
		pr_warn("module_sig: [PERMISSIVE] Loading module with corrupted signature permitted in permissive mode\n");
		*reason = "tampered (ALLOWED in permissive mode: TAINT_UNSIGNED_MODULE)";
		g_granted_loads++;
		return 0;

	default:
		*reason = "invalid_test";
		return -EINVAL;
	}
}

static ssize_t vuln_mod_sig_read(struct file *file, char __user *buf,
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
		"   Kernel Module Signature Verification Status Report   \n"
		"========================================================\n"
		"Signature Enforcement   : %s (sig_enforce=%d)\n"
		"Trusted Keyring Support : CONFIG_SYSTEM_TRUSTED_KEYRING=y\n"
		"Signature Hash Algorithm: SHA-256 (PKCS#7 / CMS format)\n"
		"Total Load Requests     : %lu\n"
		"Modules Loaded (Granted): %lu\n"
		"Modules Denied          : %lu\n"
		"  - Unsigned Denials    : %lu (-ENOKEY)\n"
		"  - Tampered Denials    : %lu (-EKEYREJECTED)\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'  > /proc/%s\n"
		"  echo 'mode enforce'     > /proc/%s\n"
		"  echo 'test signed'      > /proc/%s\n"
		"  echo 'test unsigned'    > /proc/%s\n"
		"  echo 'test tampered'    > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_sig_enforce ? "ENFORCED (Strict: -ENOKEY / -EKEYREJECTED)" : "PERMISSIVE (Warning only)",
		g_sig_enforce,
		g_total_loads,
		g_granted_loads,
		g_denied_loads,
		g_unsigned_denials,
		g_tampered_denials,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_mod_sig_write(struct file *file, const char __user *buf,
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
		g_sig_enforce = 0;
		pr_info("vuln_module_sig: Set mode PERMISSIVE (sig_enforce=0)\n");
		return count;
	}

	if (strcmp(kbuf, "mode enforce") == 0) {
		g_sig_enforce = 1;
		pr_info("vuln_module_sig: Set mode ENFORCE (sig_enforce=1)\n");
		return count;
	}

	if (strcmp(kbuf, "test signed") == 0) {
		ret = evaluate_module_signature(MOD_TEST_SIGNED, &reason);
		pr_info("vuln_module_sig: Test 'signed': %s (%s)\n",
			(ret == 0) ? "GRANTED" : "DENIED", reason);
		return (ret == 0) ? count : ret;
	}

	if (strcmp(kbuf, "test unsigned") == 0) {
		ret = evaluate_module_signature(MOD_TEST_UNSIGNED, &reason);
		if (ret != 0) {
			pr_warn("vuln_module_sig: Test 'unsigned': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_module_sig: Test 'unsigned': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test tampered") == 0) {
		ret = evaluate_module_signature(MOD_TEST_TAMPERED, &reason);
		if (ret != 0) {
			pr_warn("vuln_module_sig: Test 'tampered': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_module_sig: Test 'tampered': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_loads = 0;
		g_granted_loads = 0;
		g_denied_loads = 0;
		g_unsigned_denials = 0;
		g_tampered_denials = 0;
		pr_info("vuln_module_sig: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_module_sig: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_mod_sig_proc_ops = {
	.proc_read  = vuln_mod_sig_read,
	.proc_write = vuln_mod_sig_write,
};
#else
static const struct file_operations vuln_mod_sig_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_mod_sig_read,
	.write = vuln_mod_sig_write,
};
#endif

static int __init vuln_mod_sig_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_mod_sig_proc_ops);
	if (!entry) {
		pr_err("vuln_module_sig: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_module_sig: Driver loaded (/proc/%s, enforce=%d)\n",
		PROC_FILENAME, g_sig_enforce);
	return 0;
}

static void __exit vuln_mod_sig_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_module_sig: Driver unloaded\n");
}

module_init(vuln_mod_sig_init);
module_exit(vuln_mod_sig_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Module Signature Verification");
MODULE_LICENSE("GPL");
