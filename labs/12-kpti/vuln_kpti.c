// SPDX-License-Identifier: GPL-2.0
/*
 * Target Driver for Task 5-5: KPTI (Kernel Page Table Isolation & Meltdown Mitigation)
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_kpti with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. User/Kernel page table separation (Dual PGD on x86, Trampoline TTBR1 on arm64).
 * 2. Hardware state inspection (CR3 / TTBR1_EL1 registers and CPU feature flags).
 * 3. Meltdown mitigation telemetry and kernel address unmapping verification.
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

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
#include <asm/cpufeature.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#include <asm/desc.h>
#elif defined(CONFIG_ARM64)
#include <asm/mmu.h>
#include <asm/cpufeature.h>
#include <asm/sysreg.h>
#endif

#define VULN_PROC_NAME "vuln_kpti"

/* High-privilege kernel secret for Meltdown / rogue data access simulation */
static const char kernel_secret_str[] = "KPTI_SECRET_DATA_CONFIDENTIAL";
static const unsigned long kernel_secret_magic = 0x4b50544953454352ULL; /* "KPTI_SECR" */

static unsigned long last_probe_addr = 0;
static int last_probe_result = -1; /* -1 = not tested, 0 = vulnerable (unified), 1 = protected (isolated) */

static bool is_kpti_active(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	if (saved_command_line &&
	    (strstr(saved_command_line, "pti=off") || strstr(saved_command_line, "nopti")))
		return false;
	return boot_cpu_has(X86_FEATURE_PTI);
#elif defined(CONFIG_ARM64)
	if (saved_command_line && strstr(saved_command_line, "kpti=off"))
		return false;
	return arm64_kernel_unmapped_at_el0();
#else
	return false;
#endif
}

static unsigned long get_current_pgd_reg(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	return __read_cr3();
#elif defined(CONFIG_ARM64)
	return read_sysreg(ttbr1_el1);
#else
	return 0;
#endif
}

static int vuln_kpti_show(struct seq_file *m, void *v)
{
	bool active = is_kpti_active();
	unsigned long pgd_reg = get_current_pgd_reg();

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	seq_printf(m, "ARCHITECTURE:             %s\n", "x86_64");
#elif defined(CONFIG_ARM64)
	seq_printf(m, "ARCHITECTURE:             %s\n", "arm64 (aarch64)");
#else
	seq_printf(m, "ARCHITECTURE:             %s\n", "unknown");
#endif

	seq_printf(m, "FEATURE_NAME:             KPTI (Kernel Page Table Isolation)\n");
	seq_printf(m, "CONFIG_PAGE_TABLE_ISOL:   %s\n",
		   IS_ENABLED(CONFIG_MITIGATION_PAGE_TABLE_ISOLATION) ? "ENABLED (y)" : "DISABLED (n)");
	seq_printf(m, "CONFIG_UNMAP_KERNEL_EL0:  %s\n",
		   IS_ENABLED(CONFIG_UNMAP_KERNEL_AT_EL0) ? "ENABLED (y)" : "DISABLED (n)");

	seq_printf(m, "HARDWARE_KPTI_ACTIVE:     %s\n",
		   active ? "YES (Enforced via CPU / MMU)" : "NO (Disabled / Inactive)");
	seq_printf(m, "PAGE_TABLE_SEPARATION:    %s\n",
		   active ? "ISOLATED (Kernel unmapped from user address space)" :
			    "UNIFIED (Kernel addresses shared in user page tables)");

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	seq_printf(m, "PGD_REGISTER_TYPE:        CR3 (Page Global Directory Base)\n");
#elif defined(CONFIG_ARM64)
	seq_printf(m, "PGD_REGISTER_TYPE:        TTBR1_EL1 (Kernel Translation Table Base)\n");
#else
	seq_printf(m, "PGD_REGISTER_TYPE:        UNKNOWN\n");
#endif

	seq_printf(m, "CURRENT_PGD_REGISTER:     0x%016lx\n", pgd_reg);
	seq_printf(m, "MELTDOWN_MITIGATION:      %s\n",
		   active ? "MITIGATED (Meltdown rogue data cache load blocked by unmapping)" :
			    "VULNERABLE (Meltdown speculative cache side-channel possible)");

	seq_printf(m, "KERNEL_SECRET_ADDR:       0x%px\n", kernel_secret_str);
	seq_printf(m, "KERNEL_SECRET_MAGIC:      0x%016lx\n", kernel_secret_magic);

	seq_printf(m, "LAST_PROBE_ADDR:          0x%016lx\n", last_probe_addr);
	seq_printf(m, "LAST_PROBE_RESULT:        %s\n",
		   last_probe_result == -1 ? "NOT_TESTED" :
		   (last_probe_result == 1 ? "PROTECTED (Kernel address unmapped in user mode)" :
					     "UNPROTECTED (Kernel address visible in user page tables)"));

	return 0;
}

static int vuln_kpti_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_kpti_show, NULL);
}

static ssize_t vuln_kpti_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	char kbuf[64];
	unsigned long probe_addr = 0;
	bool active = is_kpti_active();

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	if (sscanf(kbuf, "0x%lx", &probe_addr) == 1 ||
	    sscanf(kbuf, "%lx", &probe_addr) == 1) {
		last_probe_addr = probe_addr;
	}

	pr_info("[vuln_kpti] Received probe request for address 0x%lx\n", probe_addr);

	if (active) {
		pr_info("[vuln_kpti] [+] DEFENSE ACTIVE: Kernel Page Table Isolation is enforced!\n");
		pr_info("[vuln_kpti] [+] User page tables do NOT contain kernel space mappings.\n");
		pr_info("[vuln_kpti] [+] Meltdown speculative cache side-channel attack is neutralised.\n");
		last_probe_result = 1;
	} else {
		pr_warn("[vuln_kpti] [!] WARNING: KPTI is disabled (pti=off / kpti=off)!\n");
		pr_warn("[vuln_kpti] [!] Kernel address space remains mapped in user page tables.\n");
		pr_warn("[vuln_kpti] [!] Hardware is vulnerable to Meltdown (rogue data cache load)!\n");
		last_probe_result = 0;
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_kpti_proc_ops = {
	.proc_open = vuln_kpti_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = vuln_kpti_write,
};
#else
static const struct file_operations vuln_kpti_proc_ops = {
	.open = vuln_kpti_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vuln_kpti_write,
};
#endif

static int __init vuln_kpti_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_kpti_proc_ops);
	if (!entry) {
		pr_err("[vuln_kpti] Failed to create /proc/%s\n", VULN_PROC_NAME);
		return -ENOMEM;
	}

	pr_info("[vuln_kpti] Initialized /proc/%s (kpti active: %d)\n",
		VULN_PROC_NAME, is_kpti_active());
	return 0;
}

static void __exit vuln_kpti_exit(void)
{
	remove_proc_entry(VULN_PROC_NAME, NULL);
	pr_info("[vuln_kpti] Removed /proc/%s\n", VULN_PROC_NAME);
}

module_init(vuln_kpti_init);
module_exit(vuln_kpti_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target Driver for Task 5-5: KPTI Verification");

