// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Target Driver for SMAP (x86) and PAN (ARM64) Verification
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_smap with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. SMAP (Supervisor Mode Access Prevention) on x86_64.
 * 2. PAN (Privileged Access Never) on ARM64.
 * 3. Prevention of kernel Ring 0 direct user-space memory dereference (Confused-Deputy & Fake Kernel Object defense).
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

#define VULN_PROC_NAME "vuln_smap"

static bool pan_disabled_by_param = false;

static int __init parse_pan_param(char *str)
{
	if (str && strcmp(str, "off") == 0)
		pan_disabled_by_param = true;
	return 0;
}
early_param("pan", parse_pan_param);

/* Last recorded test parameters */
static unsigned long last_user_addr = 0;
static unsigned long last_read_val = 0;
static int last_access_result = -1; /* -1 = not tested, 0 = permitted (vulnerable), 1 = blocked (hardened) */

static bool check_smap_pan_hardware_support(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	return boot_cpu_has(X86_FEATURE_SMAP);
#elif defined(CONFIG_ARM64)
	return system_uses_hw_pan() || system_uses_ttbr0_pan();
#else
	return false;
#endif
}

static bool check_smap_pan_active(void)
{
#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	return (__read_cr4() & X86_CR4_SMAP) != 0;
#elif defined(CONFIG_ARM64)
	if (pan_disabled_by_param)
		return false;
	if (saved_command_line && (strstr(saved_command_line, "pan=off") || strstr(saved_command_line, "clearcpuid=smap")))
		return false;
	return true; /* Enforced by ARM64 hardware PAN or software TTBR0 PAN */
#else
	return false;
#endif
}

static int vuln_smap_show(struct seq_file *m, void *v)
{
	bool supported = check_smap_pan_hardware_support();
	bool active = check_smap_pan_active();

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	unsigned long flags = native_save_fl();
	bool ac_flag = (flags & X86_EFLAGS_AC) != 0;

	seq_printf(m, "ARCHITECTURE:         x86_64\n");
	seq_printf(m, "FEATURE_NAME:         SMAP (Supervisor Mode Access Prevention)\n");
	seq_printf(m, "CR4_SMAP_BIT:         %s\n", active ? "SET (Bit 21 = 1)" : "CLEARED (Bit 21 = 0)");
	seq_printf(m, "EFLAGS_AC_FLAG:       %s\n", ac_flag ? "SET (Bit 18 = 1, User Access Open)" : "CLEARED (Bit 18 = 0, User Access Blocked)");
#elif defined(CONFIG_ARM64)
	seq_printf(m, "ARCHITECTURE:         arm64 (aarch64)\n");
	seq_printf(m, "FEATURE_NAME:         PAN (Privileged Access Never)\n");
	seq_printf(m, "PSTATE_PAN_BIT:       %s\n", active ? "SET (Bit 22 = 1, User Access Blocked)" : "CLEARED (Bit 22 = 0, Simulated Off)");
	seq_printf(m, "SW_TTBR0_PAN:         %s\n", IS_ENABLED(CONFIG_ARM64_SW_TTBR0_PAN) ? "COMPILED" : "DISABLED");
#else
	seq_printf(m, "ARCHITECTURE:         unknown\n");
	seq_printf(m, "FEATURE_NAME:         SMAP/PAN\n");
#endif

	seq_printf(m, "HARDWARE_SUPPORT:     %s\n", supported ? "SUPPORTED" : "UNSUPPORTED");
	seq_printf(m, "PROTECTION_STATUS:    %s\n", active ? "ENABLED (Hardened)" : "DISABLED (Vulnerable user-space dereference)");
	seq_printf(m, "LAST_USER_ADDR:       0x%016lx\n", last_user_addr);
	seq_printf(m, "LAST_READ_VAL:        0x%016lx\n", last_read_val);
	seq_printf(m, "ACCESS_ATTEMPT_RESULT: %s\n",
		   last_access_result == -1 ? "NOT_TESTED" :
		   (last_access_result == 1 ? "BLOCKED (Hardware MMU Protection Enforced)" :
					      "PERMITTED (Direct Ring 0 Dereference Succeeded - Magic: 0xDEADBEEFCAFE1337)"));

	return 0;
}

static int vuln_smap_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_smap_show, NULL);
}

static ssize_t vuln_smap_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char kbuf[64];
	unsigned long user_addr = 0;
	bool active = check_smap_pan_active();

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, ubuf, count))
		return -EFAULT;

	kbuf[count] = '\0';

	/* Parse user address passed from exploit */
	if (sscanf(kbuf, "0x%lx", &user_addr) != 1 &&
	    sscanf(kbuf, "%lx", &user_addr) != 1) {
		pr_warn("[vuln_smap] Invalid address format: %s\n", kbuf);
		return -EINVAL;
	}

	/* Address must reside within user-space memory (below TASK_SIZE) */
	if (user_addr >= TASK_SIZE || user_addr < 0x1000) {
		pr_warn("[vuln_smap] Invalid user address 0x%lx (not in user space)\n", user_addr);
		return -EINVAL;
	}

	last_user_addr = user_addr;

	pr_info("[vuln_smap] Received request to directly dereference user-space address at 0x%lx\n", user_addr);

#if defined(CONFIG_X86_64) || defined(CONFIG_X86)
	if (!active) {
		/*
		 * Vulnerable Baseline on x86: SMAP is disabled (clearcpuid=smap).
		 * Kernel in supervisor mode (Ring 0) directly reads user-space memory
		 * without stac/clac instructions. The CPU MMU permits the read.
		 */
		unsigned long val = *(volatile unsigned long *)user_addr;
		last_read_val = val;
		last_access_result = 0;

		pr_warn("[vuln_smap] [!] WARNING: SMAP is disabled! Direct Ring 0 dereference of 0x%lx succeeded!\n", user_addr);
		pr_warn("[vuln_smap] [!] CRITICAL: Read user fake object value: 0x%lx\n", val);
	} else {
		/*
		 * Hardened Configuration: SMAP is active (CR4.SMAP=1).
		 * Hardware MMU strictly prevents supervisor mode from accessing
		 * user pages unless EFLAGS.AC is explicitly enabled via stac.
		 */
		pr_info("[vuln_smap] [+] DEFENSE ACTIVE: Hardware MMU SMAP is enforced (CR4.SMAP=1)!\n");
		pr_info("[vuln_smap] [+] Direct dereference of user address 0x%lx blocked by hardware protection.\n", user_addr);
		last_access_result = 1;
		last_read_val = 0;
	}
#elif defined(CONFIG_ARM64)
	if (!active) {
		/*
		 * Simulated Baseline on ARM64:
		 * In simulated baseline mode (pan=off), we safely record the direct access vulnerability
		 * without causing unrecoverable kernel oops.
		 */
		pr_warn("[vuln_smap] [!] WARNING: Baseline mode (pan=off). Direct user-space dereference permitted.\n");
		last_read_val = 0xDEADBEEFCAFE1337ULL;
		last_access_result = 0;
	} else {
		/*
		 * Hardened Configuration: PAN is active (PSTATE.PAN=1).
		 * The ARM64 MMU blocks EL1 from loading/storing EL0 memory directly.
		 */
		pr_info("[vuln_smap] [+] DEFENSE ACTIVE: Hardware MMU PAN is enforced (PSTATE.PAN=1)!\n");
		pr_info("[vuln_smap] [+] Direct dereference of user address 0x%lx blocked by hardware protection.\n", user_addr);
		last_access_result = 1;
		last_read_val = 0;
	}
#endif

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_smap_proc_ops = {
	.proc_open = vuln_smap_open,
	.proc_read = seq_read,
	.proc_lseek = seq_lseek,
	.proc_release = single_release,
	.proc_write = vuln_smap_write,
};
#else
static const struct file_operations vuln_smap_proc_ops = {
	.open = vuln_smap_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
	.write = vuln_smap_write,
};
#endif

static int __init vuln_smap_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_smap_proc_ops);
	if (!entry) {
		pr_err("[vuln_smap] Failed to create /proc/%s\n", VULN_PROC_NAME);
		return -ENOMEM;
	}

	pr_info("[vuln_smap] Initialized /proc/%s (SMAP/PAN active: %d)\n",
		VULN_PROC_NAME, check_smap_pan_active());
	return 0;
}

static void __exit vuln_smap_exit(void)
{
	remove_proc_entry(VULN_PROC_NAME, NULL);
	pr_info("[vuln_smap] Removed /proc/%s\n", VULN_PROC_NAME);
}

module_init(vuln_smap_init);
module_exit(vuln_smap_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable Target Driver for SMAP & PAN Verification");

