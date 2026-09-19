// SPDX-License-Identifier: GPL-2.0
/*
 * labs/20-structleak/vuln_structleak.c
 *
 * Target driver for demonstrating CONFIG_INIT_STACK_ALL_ZERO / CONFIG_GCC_PLUGIN_STRUCTLEAK:
 *   1. Demonstrates kernel stack information disclosure via structure alignment padding holes.
 *      Even when all struct members are explicitly assigned, alignment padding between fields
 *      remains uninitialized on the stack and leaks kernel data across copy_to_user().
 *   2. Demonstrates by-reference uninitialized stack variable exposure (CVE-2013-2141 / CVE-2017-1000410).
 *      When a stack struct pointer is passed to a helper function, compiler warnings
 *      (-Wmaybe-uninitialized) are suppressed, leaving untouched members exposed.
 *
 * Exposes /proc/vuln_structleak (mode 0666) for non-privileged user-space inspection
 * and automated testing.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/string.h>
#include <linux/compiler.h>

#define PROC_FILENAME "vuln_structleak"
#define STACK_POISON_VAL 0x53544b5f4c45414bULL /* "STK_LEAK" */

enum lab_mode {
	MODE_STATUS = 0,
	MODE_PADDING_LEAK = 1,
	MODE_BYREF_LEAK = 2,
};

/*
 * Struct 1: Demonstrates Alignment Padding Hole Leak
 * Size: 32 bytes on 64-bit architectures
 * Offset 0..3: header (4 bytes)
 * Offset 4..7: ALIGNMENT PADDING HOLE (4 bytes) - never explicitly written!
 * Offset 8..15: timestamp (8 bytes)
 * Offset 16..31: msg (16 bytes)
 */
struct demo_padding_leak {
	uint32_t header;
	/* 4 bytes padding here inserted by compiler for 64-bit alignment */
	uint64_t timestamp;
	char msg[16];
};

/*
 * Struct 2: Demonstrates By-Reference Uninitialized Struct Leak
 * Size: 48 bytes
 * Passed by pointer to helper function which only initializes command and status.
 * kernel_secret and canary_leak remain untouched.
 */
struct demo_byref_leak {
	uint32_t command;
	uint32_t status;
	char kernel_secret[32];
	uint64_t canary_leak;
};

static enum lab_mode g_current_mode = MODE_STATUS;

/*
 * Force stack poisoning in caller frame without being optimized away.
 * Uses volatile and barrier() to ensure compiler writes known tokens to stack.
 */
static noinline void poison_kernel_stack(void)
{
	volatile unsigned long poison_frame[16];
	size_t i;

	for (i = 0; i < 16; i++) {
		poison_frame[i] = STACK_POISON_VAL ^ (unsigned long)i;
	}
	barrier();
}

/*
 * Helper that only partially initializes the struct passed by reference.
 * Note: compiler cannot warn about uninitialized struct members because address is taken.
 */
static noinline void helper_partial_init(struct demo_byref_leak *info)
{
	info->command = 0x1337;
	info->status = 0x0;
	/* info->kernel_secret and info->canary_leak are deliberately not initialized */
	barrier();
}

/*
 * Mode 1 handler: Alignment padding leak test
 */
static noinline ssize_t trigger_padding_leak(char __user *buf, size_t count)
{
	struct demo_padding_leak s;

	/* First dirty the stack so uninitialized holes contain poison markers */
	poison_kernel_stack();

	/*
	 * Explicitly assign all visible struct members.
	 * Notice: The 4-byte padding between header and timestamp is NEVER assigned!
	 */
	s.header = 0x44454d4f; /* "DEMO" */
	s.timestamp = 0x1122334455667788ULL;
	memcpy(s.msg, "STRUCT_PADDING!", 16);

	if (count < sizeof(s))
		return -EINVAL;

	if (copy_to_user(buf, &s, sizeof(s)))
		return -EFAULT;

	return sizeof(s);
}

/*
 * Mode 2 handler: By-reference uninitialized struct leak test
 */
static noinline ssize_t trigger_byref_leak(char __user *buf, size_t count)
{
	struct demo_byref_leak info;

	/* First dirty the stack so uninitialized fields contain poison markers */
	poison_kernel_stack();

	/* Pass pointer to helper which only initializes partial fields */
	helper_partial_init(&info);

	if (count < sizeof(info))
		return -EINVAL;

	if (copy_to_user(buf, &info, sizeof(info)))
		return -EFAULT;

	return sizeof(info);
}

static ssize_t vuln_structleak_read(struct file *file, char __user *buf,
				    size_t count, loff_t *ppos)
{
	char status_buf[1024];
	int len = 0;

	if (*ppos > 0)
		return 0;

	if (g_current_mode == MODE_PADDING_LEAK) {
		pr_info("vuln_structleak: [MODE_PADDING_LEAK] Serving struct with alignment padding hole\n");
		*ppos = sizeof(struct demo_padding_leak);
		return trigger_padding_leak(buf, count);
	} else if (g_current_mode == MODE_BYREF_LEAK) {
		pr_info("vuln_structleak: [MODE_BYREF_LEAK] Serving by-reference uninitialized struct\n");
		*ppos = sizeof(struct demo_byref_leak);
		return trigger_byref_leak(buf, count);
	}

	/* MODE_STATUS: Human readable report */
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=== [Linux Kernel Hardening Lab: STRUCTLEAK / INIT_STACK] ===\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Feature Status:\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_INIT_STACK_ALL_ZERO : %s\n",
			 IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO) ? "ENABLED (Active Defense)" : "DISABLED");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_INIT_STACK_NONE     : %s\n",
			 IS_ENABLED(CONFIG_INIT_STACK_NONE) ? "ENABLED (Vulnerable Baseline)" : "DISABLED");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  CONFIG_GCC_PLUGIN_STRUCTLEAK: %s\n",
			 IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK) ? "ENABLED" : "DISABLED");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Active Lab Mode: %d (%s)\n\n",
			 g_current_mode,
			 g_current_mode == MODE_PADDING_LEAK ? "PADDING_LEAK (32B)" :
			 g_current_mode == MODE_BYREF_LEAK ? "BYREF_LEAK (48B)" : "STATUS");

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Available Commands:\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  echo 0 > /proc/%s  -> Switch to status information\n", PROC_FILENAME);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  echo 1 > /proc/%s  -> Switch to Mode 1: Struct Alignment Padding Hole Leak\n", PROC_FILENAME);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  echo 2 > /proc/%s  -> Switch to Mode 2: By-Reference Uninitialized Struct Leak\n", PROC_FILENAME);

	if (count < len)
		return -EINVAL;

	if (copy_to_user(buf, status_buf, len))
		return -EFAULT;

	*ppos = len;
	return len;
}

static ssize_t vuln_structleak_write(struct file *file, const char __user *buf,
				     size_t count, loff_t *ppos)
{
	char kbuf[16];
	size_t to_copy;

	if (count == 0)
		return 0;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;

	kbuf[to_copy] = '\0';

	if (kbuf[0] == '1') {
		g_current_mode = MODE_PADDING_LEAK;
		pr_info("vuln_structleak: switched to MODE_PADDING_LEAK (Mode 1)\n");
	} else if (kbuf[0] == '2') {
		g_current_mode = MODE_BYREF_LEAK;
		pr_info("vuln_structleak: switched to MODE_BYREF_LEAK (Mode 2)\n");
	} else if (kbuf[0] == '0') {
		g_current_mode = MODE_STATUS;
		pr_info("vuln_structleak: switched to MODE_STATUS (Mode 0)\n");
	} else {
		pr_warn("vuln_structleak: unknown command '%c'\n", kbuf[0]);
	}

	return count;
}

static const struct proc_ops vuln_structleak_fops = {
	.proc_read  = vuln_structleak_read,
	.proc_write = vuln_structleak_write,
	.proc_lseek = default_llseek,
};

static struct proc_dir_entry *proc_entry;

static int __init vuln_structleak_init(void)
{
	proc_entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_structleak_fops);
	if (!proc_entry) {
		pr_err("vuln_structleak: failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_structleak: loaded successfully. /proc/%s ready (mode 0666)\n", PROC_FILENAME);
	pr_info("vuln_structleak: INIT_STACK_ALL_ZERO=%d, GCC_PLUGIN_STRUCTLEAK=%d\n",
		IS_ENABLED(CONFIG_INIT_STACK_ALL_ZERO),
		IS_ENABLED(CONFIG_GCC_PLUGIN_STRUCTLEAK));
	return 0;
}

static void __exit vuln_structleak_exit(void)
{
	if (proc_entry) {
		proc_remove(proc_entry);
		pr_info("vuln_structleak: unloaded successfully\n");
	}
}

module_init(vuln_structleak_init);
module_exit(vuln_structleak_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerability Lab Driver for CONFIG_INIT_STACK_ALL_ZERO / STRUCTLEAK");
MODULE_LICENSE("GPL");

