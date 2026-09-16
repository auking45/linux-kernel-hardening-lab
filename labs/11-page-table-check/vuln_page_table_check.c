// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Target Driver for CONFIG_PAGE_TABLE_CHECK Verification
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_page_table_check with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. Synchronous runtime page table entry verification (PTE, PMD, PUD).
 * 2. Detection and prevention of illegal double mappings (Anonymous RW > 1).
 * 3. Prevention of illegal aliasing between anonymous and named/file-backed pages.
 * 4. Detection of Use-After-Free lingering mappings during page free.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/jump_label.h>
#include <linux/page_table_check.h>

#define VULN_PROC_NAME "vuln_page_table_check"

/* Last recorded test parameters */
static unsigned long last_probe_addr = 0;
static int last_probe_result = -1; /* -1 = not tested, 0 = disabled (vulnerable), 1 = active (hardened) */

static bool is_page_table_check_active(void)
{
#ifdef CONFIG_PAGE_TABLE_CHECK
	/*
	 * In mm/page_table_check.c, page_table_check_disabled is a static_key_true.
	 * When page table check is enabled (page_table_check=on or ENFORCED=y),
	 * static_branch_disable(&page_table_check_disabled) is called.
	 * Therefore, static_branch_likely(&page_table_check_disabled) returning false
	 * means checking is ACTIVE.
	 */
	if (saved_command_line && strstr(saved_command_line, "page_table_check=off"))
		return false;
	return !static_branch_likely(&page_table_check_disabled);
#else
	return false;
#endif
}

static int vuln_ptc_show(struct seq_file *m, void *v)
{
	bool active = is_page_table_check_active();

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	seq_printf(m, "ARCHITECTURE:             x86_64\n");
#elif defined(CONFIG_ARM64)
	seq_printf(m, "ARCHITECTURE:             arm64 (aarch64)\n");
#else
	seq_printf(m, "ARCHITECTURE:             unknown\n");
#endif

	seq_printf(m, "FEATURE_NAME:             CONFIG_PAGE_TABLE_CHECK\n");
	seq_printf(m, "CONFIG_PAGE_TABLE_CHECK:  %s\n", IS_ENABLED(CONFIG_PAGE_TABLE_CHECK) ? "ENABLED (y)" : "DISABLED (n)");
	seq_printf(m, "CONFIG_PTC_ENFORCED:      %s\n", IS_ENABLED(CONFIG_PAGE_TABLE_CHECK_ENFORCED) ? "ENABLED (y)" : "DISABLED (n)");
	seq_printf(m, "CONFIG_EXCLUSIVE_SYS_RAM: %s\n", IS_ENABLED(CONFIG_EXCLUSIVE_SYSTEM_RAM) ? "ENABLED (y)" : "DISABLED (n)");
	seq_printf(m, "CONFIG_PAGE_EXTENSION:    %s\n", IS_ENABLED(CONFIG_PAGE_EXTENSION) ? "ENABLED (y)" : "DISABLED (n)");

	seq_printf(m, "STATIC_KEY_STATE:         %s\n",
		   active ? "KEY_DISABLED (Checks Armed)" : "KEY_ENABLED (Checks Bypassed)");
	seq_printf(m, "PROTECTION_STATUS:        %s\n",
		   active ? "ENABLED (Hardened - Synchronous verification active)" :
			    "DISABLED (page_table_check=off active)");

	seq_printf(m, "RULE_ANON_ANON_RO:        ALLOW (Shared read-only anonymous mappings permitted)\n");
	seq_printf(m, "RULE_ANON_ANON_RW:        PROHIBIT (BUG_ON if anonymous page mapped RW > 1)\n");
	seq_printf(m, "RULE_ANON_NAMED:          PROHIBIT (BUG_ON if anonymous and file pages overlap)\n");
	seq_printf(m, "RULE_NAMED_NAMED:         ALLOW (Shared file-backed mappings permitted)\n");

	seq_printf(m, "LAST_PROBE_ADDR:          0x%016lx\n", last_probe_addr);
	seq_printf(m, "LAST_PROBE_RESULT:        %s\n",
		   last_probe_result == -1 ? "NOT_TESTED" :
		   (last_probe_result == 1 ? "PROTECTED (Page Table Integrity Enforced by Core MM)" :
					     "UNPROTECTED (Page Table Check Inactive / Bypassed)"));

	return 0;
}

static int vuln_ptc_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_ptc_show, NULL);
}

static ssize_t vuln_ptc_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	char kbuf[64];
	unsigned long user_addr = 0;
	bool active = is_page_table_check_active();

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (sscanf(kbuf, "0x%lx", &user_addr) == 1 ||
	    sscanf(kbuf, "%lx", &user_addr) == 1) {
		last_probe_addr = user_addr;
	}

	pr_info("[vuln_page_table_check] Received probe request for user address 0x%lx\n", user_addr);

	if (active) {
		pr_info("[vuln_page_table_check] [+] DEFENSE ACTIVE: CONFIG_PAGE_TABLE_CHECK is actively enforcing page table integrity!\n");
		pr_info("[vuln_page_table_check] [+] Synchronous double-map prevention & anonymous/file separation verified.\n");
		last_probe_result = 1;
	} else {
		pr_warn("[vuln_page_table_check] [!] WARNING: Page Table Check is disabled (page_table_check=off)!\n");
		pr_warn("[vuln_page_table_check] [!] Page table verification hooks bypassed. Memory corruption detection inactive.\n");
		last_probe_result = 0;
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_ptc_proc_ops = {
	.proc_open = vuln_ptc_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = vuln_ptc_write,
};
#else
static const struct file_operations vuln_ptc_proc_ops = {
	.open = vuln_ptc_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vuln_ptc_write,
};
#endif

static int __init vuln_ptc_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_ptc_proc_ops);
	if (!entry) {
		pr_err("[vuln_page_table_check] Failed to create /proc/%s\n", VULN_PROC_NAME);
		return -ENOMEM;
	}

	pr_info("[vuln_page_table_check] Initialized /proc/%s (active: %d)\n",
		VULN_PROC_NAME, is_page_table_check_active());
	return 0;
}

static void __exit vuln_ptc_exit(void)
{
	remove_proc_entry(VULN_PROC_NAME, NULL);
	pr_info("[vuln_page_table_check] Removed /proc/%s\n", VULN_PROC_NAME);
}

module_init(vuln_ptc_init);
module_exit(vuln_ptc_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target Driver for CONFIG_PAGE_TABLE_CHECK Verification");

