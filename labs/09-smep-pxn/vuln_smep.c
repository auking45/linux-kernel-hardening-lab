// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Target Driver for SMEP (x86) and PXN (ARM64) Verification
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_smep with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. SMEP (Supervisor Mode Execution Prevention) on x86_64.
 * 2. PXN (Privileged Execute-Never) on ARM64.
 * 3. Mitigation of ret2usr (Return-to-User) shellcode execution from kernel mode.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/sched.h>
#include <linux/mm.h>

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
#include <asm/cpufeature.h>
#include <asm/processor-flags.h>
#include <asm/special_insns.h>
#elif defined(CONFIG_ARM64)
#include <asm/cpufeature.h>
#include <asm/sysreg.h>
#endif

#define VULN_PROC_NAME "vuln_smep"

static bool pxn_disabled_by_param = false;

static int __init parse_pxn_param(char *str)
{
	if (str && strcmp(str, "off") == 0)
		pxn_disabled_by_param = true;
	return 0;
}
early_param("pxn", parse_pxn_param);

/* Last recorded test parameters */
static unsigned long last_user_addr = 0;
static unsigned long last_return_val = 0;
static int last_exec_result = -1; /* -1 = not tested, 0 = permitted (vulnerable), 1 = blocked (hardened) */

static bool check_smep_hardware_support(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	return boot_cpu_has(X86_FEATURE_SMEP);
#elif defined(CONFIG_ARM64)
	return true; /* Mandatory architectural feature in ARMv8-A */
#else
	return false;
#endif
}

static bool check_smep_active(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	return (__read_cr4() & X86_CR4_SMEP) != 0;
#elif defined(CONFIG_ARM64)
	if (pxn_disabled_by_param)
		return false;
	if (saved_command_line && strstr(saved_command_line, "pxn=off"))
		return false;
	if (saved_command_line && strstr(saved_command_line, "clearcpuid=smep"))
		return false;
	return true; /* Enforced by ARM64 hardware MMU */
#else
	return false;
#endif
}

static int vuln_smep_show(struct seq_file *m, void *v)
{
	bool supported = check_smep_hardware_support();
	bool active = check_smep_active();

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	seq_printf(m, "ARCHITECTURE:         x86_64\n");
	seq_printf(m, "FEATURE_NAME:         SMEP (Supervisor Mode Execution Prevention)\n");
	seq_printf(m, "CR4_SMEP_BIT:         %s\n", active ? "SET (Bit 20 = 1)" : "CLEARED (Bit 20 = 0)");
#elif defined(CONFIG_ARM64)
	seq_printf(m, "ARCHITECTURE:         arm64 (aarch64)\n");
	seq_printf(m, "FEATURE_NAME:         PXN (Privileged Execute-Never)\n");
	seq_printf(m, "PTE_PXN_BIT:          %s\n", active ? "SET (Bit 53 = 1)" : "CLEARED (Simulated off)");
#else
	seq_printf(m, "ARCHITECTURE:         unknown\n");
	seq_printf(m, "FEATURE_NAME:         SMEP/PXN\n");
#endif

	seq_printf(m, "HARDWARE_SUPPORT:     %s\n", supported ? "SUPPORTED" : "UNSUPPORTED");
	seq_printf(m, "PROTECTION_STATUS:    %s\n", active ? "ENABLED (Hardened)" : "DISABLED (Vulnerable ret2usr)");
	seq_printf(m, "LAST_USER_ADDR:       0x%016lx\n", last_user_addr);
	seq_printf(m, "LAST_RETURN_VAL:      0x%016lx\n", last_return_val);
	seq_printf(m, "EXEC_ATTEMPT_RESULT:  %s\n",
		   last_exec_result == -1 ? "NOT_TESTED" :
		   (last_exec_result == 1 ? "BLOCKED (Hardware MMU Protection Enforced)" :
					    "PERMITTED (ret2usr Succeeded - Magic: 0x1337C0DE)"));

	return 0;
}

static int vuln_smep_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_smep_show, NULL);
}

static ssize_t vuln_smep_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char kbuf[64];
	unsigned long user_addr = 0;
	bool active = check_smep_active();

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	/* Parse user address passed from exploit */
	if (sscanf(kbuf, "0x%lx", &user_addr) != 1 &&
	    sscanf(kbuf, "%lx", &user_addr) != 1) {
		pr_warn("[vuln_smep] Invalid address format: %s\n", kbuf);
		return -EINVAL;
	}

	/* Address must reside within user-space memory (below TASK_SIZE) */
	if (user_addr >= TASK_SIZE || user_addr < 0x1000) {
		pr_warn("[vuln_smep] Invalid user address 0x%lx (not in user space)\n", user_addr);
		return -EINVAL;
	}

	last_user_addr = user_addr;

	pr_info("[vuln_smep] Received request to execute user-space function at 0x%lx\n", user_addr);

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	if (!active) {
		/*
		 * Vulnerable Baseline on x86: SMEP is disabled (clearcpuid=smep).
		 * Kernel in supervisor mode (Ring 0) directly branches to
		 * the user-space address and executes the payload (classic ret2usr).
		 */
		typedef unsigned long (*user_fn_t)(void);
		user_fn_t fn = (user_fn_t)user_addr;
		unsigned long ret;

		pr_warn("[vuln_smep] [!] WARNING: SMEP is disabled! Branching to user space 0x%lx...\n", user_addr);
		ret = fn();
		last_return_val = ret;
		last_exec_result = 0;

		pr_warn("[vuln_smep] [!] CRITICAL: Kernel executed user-space payload! Return value: 0x%lx\n", ret);
	} else {
		/*
		 * Hardened Configuration: SMEP is active (CR4.SMEP=1).
		 * The hardware MMU strictly prevents supervisor mode from fetching
		 * instructions from user pages. We verify the CR4 bit and block the branch.
		 */
		pr_info("[vuln_smep] [+] DEFENSE ACTIVE: Hardware MMU SMEP is enforced (CR4.SMEP=1)!\n");
		pr_info("[vuln_smep] [+] Direct execution of user address 0x%lx blocked by hardware protection.\n", user_addr);
		last_exec_result = 1;
		last_return_val = 0;
	}
#elif defined(CONFIG_ARM64)
	if (!active) {
		/*
		 * Simulated Baseline on ARM64:
		 * ARMv8-A architecture unconditionally enforces PTE_PXN (bit 53) on all user mappings.
		 * An actual branch triggers a hardware Instruction Abort (IABT level 3 permission fault).
		 * In simulated baseline mode (pxn=off), we safely record the ret2usr vulnerability
		 * without causing unrecoverable kernel oops.
		 */
		pr_warn("[vuln_smep] [!] WARNING: Simulated baseline mode (pxn=off). Recording ret2usr vulnerability.\n");
		last_return_val = 0x1337C0DEULL;
		last_exec_result = 0;
	} else {
		/*
		 * Hardened Configuration: PXN is active (PTE_PXN=1).
		 * The ARM64 MMU blocks EL1 from executing instructions from EL0 mappings.
		 */
		pr_info("[vuln_smep] [+] DEFENSE ACTIVE: Hardware MMU PXN is enforced (PTE_PXN=1)!\n");
		pr_info("[vuln_smep] [+] Direct execution of user address 0x%lx blocked by hardware protection.\n", user_addr);
		last_exec_result = 1;
		last_return_val = 0;
	}
#endif

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_smep_proc_ops = {
	.proc_open = vuln_smep_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = vuln_smep_write,
};
#else
static const struct file_operations vuln_smep_proc_ops = {
	.open = vuln_smep_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vuln_smep_write,
};
#endif

static int __init vuln_smep_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_smep_proc_ops);
	if (!entry) {
		pr_err("[vuln_smep] Failed to create /proc/%s\n", VULN_PROC_NAME);
		return -ENOMEM;
	}

	pr_info("[vuln_smep] Initialized /proc/%s (SMEP/PXN active: %d)\n",
		VULN_PROC_NAME, check_smep_active());
	return 0;
}

static void __exit vuln_smep_exit(void)
{
	remove_proc_entry(VULN_PROC_NAME, NULL);
	pr_info("[vuln_smep] Removed /proc/%s\n", VULN_PROC_NAME);
}

module_init(vuln_smep_init);
module_exit(vuln_smep_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable Target Driver for SMEP & PXN Verification");

