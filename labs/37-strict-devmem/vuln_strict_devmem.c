// SPDX-License-Identifier: GPL-2.0
/*
 * labs/37-strict-devmem/vuln_strict_devmem.c
 *
 * Target driver demonstrating Linux Strict Devmem:
 *   1. CONFIG_STRICT_DEVMEM=y:
 *      - Implements devmem_is_allowed(pfn).
 *      - Prevents mapping or reading/writing physical System RAM via /dev/mem.
 *      - Neutralizes root-level memory tampering and kernel credential overwrites.
 *   2. CONFIG_IO_STRICT_DEVMEM=y:
 *      - Implements devmem_is_unconsumed(pfn).
 *      - Prevents userspace from mapping I/O memory regions (PCI BARs, device registers)
 *        that are actively claimed or used by a kernel driver.
 *      - Protects DMA controllers and hardware registers from userspace hijacking.
 *
 * Exposes /proc/vuln_strict_devmem (mode 0666) to evaluate physical memory access policies.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/io.h>
#include <linux/mm.h>

#define PROC_FILENAME "vuln_strict_devmem"

/* 0: Permissive, 1: Strict RAM (STRICT_DEVMEM), 2: Strict RAM + I/O (IO_STRICT_DEVMEM) */
static int g_devmem_mode = 2;

/* Statistics */
static unsigned long g_total_accesses = 0;
static unsigned long g_allowed_accesses = 0;
static unsigned long g_ram_denials = 0;
static unsigned long g_io_denials = 0;

enum devmem_test_type {
	TARGET_SYSTEM_RAM = 0,    /* Physical System RAM (Kernel code/data/heap) */
	TARGET_ACTIVE_DRIVER_IO,  /* Claimed PCI MMIO / DMA registers */
	TARGET_LEGACY_UNCLAIMED,  /* Unclaimed ROM / VGA Framebuffer */
};

static int evaluate_devmem_access(enum devmem_test_type target, const char **reason)
{
	g_total_accesses++;

	switch (target) {
	case TARGET_SYSTEM_RAM:
		if (g_devmem_mode >= 1) {
			pr_err("strict_devmem: [DENIED] Attempted /dev/mem access to System RAM (pfn > 0x100) rejected: -EPERM\n");
			pr_notice("System RAM protection active: devmem_is_allowed() returned 0!\n");
			*reason = "system_ram (BLOCKED by CONFIG_STRICT_DEVMEM: -EPERM)";
			g_ram_denials++;
			return -EPERM;
		}
		pr_warn("strict_devmem: [PERMISSIVE] /dev/mem access to System RAM permitted! (VULNERABLE)\n");
		*reason = "system_ram (ALLOWED in permissive mode: Kernel memory exposed)";
		g_allowed_accesses++;
		return 0;

	case TARGET_ACTIVE_DRIVER_IO:
		if (g_devmem_mode >= 2) {
			pr_err("strict_devmem: [DENIED] Attempted /dev/mem access to driver-claimed I/O memory rejected: -EPERM\n");
			pr_notice("Active I/O memory protection active: devmem_is_unconsumed() returned 0!\n");
			*reason = "active_driver_io (BLOCKED by CONFIG_IO_STRICT_DEVMEM: -EPERM)";
			g_io_denials++;
			return -EPERM;
		}
		pr_warn("strict_devmem: [PERMISSIVE] Access to active driver MMIO permitted (level=%d < 2)\n",
			g_devmem_mode);
		*reason = "active_driver_io (ALLOWED in Strict RAM-only or Permissive mode)";
		g_allowed_accesses++;
		return 0;

	case TARGET_LEGACY_UNCLAIMED:
		pr_info("strict_devmem: [ALLOWED] Access to unclaimed legacy ROM / VGA framebuffer granted (ret = 0)\n");
		*reason = "legacy_unclaimed (ALLOWED: Unclaimed device memory permitted for X.org/VGA)";
		g_allowed_accesses++;
		return 0;

	default:
		*reason = "invalid_target";
		return -EINVAL;
	}
}

static ssize_t vuln_devmem_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	const char *mode_str = "Permissive (0: Full physical access)";

	if (g_devmem_mode == 1)
		mode_str = "Strict RAM (1: System RAM protected)";
	else if (g_devmem_mode == 2)
		mode_str = "Strict RAM + Active I/O (2: System RAM & Driver I/O protected)";

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"        Linux Strict Devmem Status Report               \n"
		"========================================================\n"
		"Strict Devmem Mode      : [%d] %s\n"
		"System RAM Defense      : %s (devmem_is_allowed)\n"
		"Active I/O Protection   : %s (devmem_is_unconsumed)\n"
		"Total Access Probes     : %lu\n"
		"Access Requests Granted : %lu\n"
		"System RAM Denials      : %lu (-EPERM)\n"
		"Active I/O Denials      : %lu (-EPERM)\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'  > /proc/%s\n"
		"  echo 'mode strict'      > /proc/%s\n"
		"  echo 'mode iostrict'    > /proc/%s\n"
		"  echo 'test ram'         > /proc/%s\n"
		"  echo 'test active_io'   > /proc/%s\n"
		"  echo 'test legacy_rom'  > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_devmem_mode, mode_str,
		(g_devmem_mode >= 1) ? "ENFORCED (CONFIG_STRICT_DEVMEM=y)" : "DISABLED (Permissive)",
		(g_devmem_mode >= 2) ? "ENFORCED (CONFIG_IO_STRICT_DEVMEM=y)" : "DISABLED (Permissive)",
		g_total_accesses,
		g_allowed_accesses,
		g_ram_denials,
		g_io_denials,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_devmem_write(struct file *file, const char __user *buf,
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
		g_devmem_mode = 0;
		pr_info("vuln_strict_devmem: Set Mode PERMISSIVE (0)\n");
		return count;
	}

	if (strcmp(kbuf, "mode strict") == 0) {
		g_devmem_mode = 1;
		pr_info("vuln_strict_devmem: Set Mode STRICT RAM (1)\n");
		return count;
	}

	if (strcmp(kbuf, "mode iostrict") == 0) {
		g_devmem_mode = 2;
		pr_info("vuln_strict_devmem: Set Mode STRICT RAM + I/O (2)\n");
		return count;
	}

	if (strcmp(kbuf, "test ram") == 0) {
		ret = evaluate_devmem_access(TARGET_SYSTEM_RAM, &reason);
		if (ret != 0) {
			pr_warn("vuln_strict_devmem: Test 'ram': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_strict_devmem: Test 'ram': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test active_io") == 0) {
		ret = evaluate_devmem_access(TARGET_ACTIVE_DRIVER_IO, &reason);
		if (ret != 0) {
			pr_warn("vuln_strict_devmem: Test 'active_io': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_strict_devmem: Test 'active_io': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test legacy_rom") == 0) {
		ret = evaluate_devmem_access(TARGET_LEGACY_UNCLAIMED, &reason);
		pr_info("vuln_strict_devmem: Test 'legacy_rom': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_accesses = 0;
		g_allowed_accesses = 0;
		g_ram_denials = 0;
		g_io_denials = 0;
		pr_info("vuln_strict_devmem: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_strict_devmem: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_devmem_proc_ops = {
	.proc_read  = vuln_devmem_read,
	.proc_write = vuln_devmem_write,
};
#else
static const struct file_operations vuln_devmem_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_devmem_read,
	.write = vuln_devmem_write,
};
#endif

static int __init vuln_devmem_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_devmem_proc_ops);
	if (!entry) {
		pr_err("vuln_strict_devmem: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_strict_devmem: Driver loaded (/proc/%s, mode=%d)\n",
		PROC_FILENAME, g_devmem_mode);
	return 0;
}

static void __exit vuln_devmem_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_strict_devmem: Driver unloaded\n");
}

module_init(vuln_devmem_init);
module_exit(vuln_devmem_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Strict Devmem & Strict I/O Devmem");
MODULE_LICENSE("GPL");
