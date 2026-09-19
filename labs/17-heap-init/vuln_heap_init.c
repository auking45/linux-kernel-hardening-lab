// SPDX-License-Identifier: GPL-2.0
/*
 * labs/17-heap-init/vuln_heap_init.c
 *
 * Target driver for demonstrating Heap Memory Zeroing Hardening:
 *   1. CONFIG_INIT_ON_ALLOC_DEFAULT_ON - Zeroes slab objects and page allocator
 *      pages on allocation (slab_post_alloc_hook), preventing stale data disclosure.
 *   2. CONFIG_INIT_ON_FREE_DEFAULT_ON  - Zeroes slab objects and pages immediately
 *      upon free (slab_free_hook), minimizing residual data lifetime and mitigating
 *      Use-After-Free information exposure.
 *
 * Exposes /proc/vuln_heap_init (mode 0666) for non-privileged user-space inspection
 * and automated LKDTM / PoC test execution.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>
#include <linux/mm.h>

#define PROC_FILENAME "vuln_heap_init"
#define LEAK_OBJ_SIZE 256
#define SECRET_CANARY_STRING "CONFIDENTIAL_KERNEL_KEY_7777"

struct uaf_canary {
	unsigned long pad0;       /* offset 0 */
	unsigned long payload;    /* offset 8: avoids freepointer at offset 0 or 32 */
	char token[32];           /* offset 16 */
	void (*func_ptr)(void);
};


static unsigned long g_leak_test_runs = 0;
static bool g_leak_clean = false;
static unsigned int g_dirty_bytes_found = 0;
static char g_last_leaked_sample[64] = "NONE";

static unsigned long g_uaf_test_runs = 0;
static bool g_uaf_wiped = false;
static unsigned long g_uaf_stale_magic = 0;

static void run_leak_test(void)
{
	u8 *first_buf = NULL;
	u8 *second_buf = NULL;
	unsigned int dirty_count = 0;
	int i;

	g_leak_test_runs++;

	/* Step 1: Allocate first object and fill with secret canary data */
	first_buf = kmalloc(LEAK_OBJ_SIZE, GFP_KERNEL);
	if (!first_buf) {
		pr_err("vuln_heap_init: failed to allocate first buffer\n");
		return;
	}

	memset(first_buf, 0x5A, LEAK_OBJ_SIZE);
	memcpy(first_buf, SECRET_CANARY_STRING, strlen(SECRET_CANARY_STRING));

	/* Step 2: Free the object back to the SLUB allocator */
	kfree(first_buf);

	/*
	 * Step 3: Reallocate an object of the same size class WITHOUT __GFP_ZERO.
	 * In hardened mode (init_on_alloc or init_on_free), this memory MUST be
	 * guaranteed to be 100% zeroes.
	 * In baseline mode, stale bytes (0x5A or secret canary) remain in memory.
	 */
	second_buf = kmalloc(LEAK_OBJ_SIZE, GFP_KERNEL);
	if (!second_buf) {
		pr_err("vuln_heap_init: failed to allocate second buffer\n");
		return;
	}

	/* Step 4: Inspect second_buf for residual dirty bytes */
	for (i = 0; i < LEAK_OBJ_SIZE; i++) {
		if (second_buf[i] != 0x00)
			dirty_count++;
	}

	g_dirty_bytes_found = dirty_count;
	if (dirty_count == 0) {
		g_leak_clean = true;
		snprintf(g_last_leaked_sample, sizeof(g_last_leaked_sample), "CLEAN (100%% zeroes)");
		pr_info("vuln_heap_init: [LEAK_TEST] PASS - 100%% zeroed allocation, 0 leaks detected\n");
	} else {
		g_leak_clean = false;
		if (memchr(second_buf, 0x5A, LEAK_OBJ_SIZE) ||
		    strstr((char *)second_buf, "CONFIDENTIAL")) {
			snprintf(g_last_leaked_sample, sizeof(g_last_leaked_sample),
				 "LEAKED CANARY: %.32s", second_buf);
		} else {
			snprintf(g_last_leaked_sample, sizeof(g_last_leaked_sample),
				 "DIRTY BYTES: %u non-zero bytes (sample: 0x%02x)",
				 dirty_count, second_buf[0]);
		}
		pr_warn("vuln_heap_init: [LEAK_TEST] FAIL - %u dirty bytes found in newly allocated heap!\n",
			dirty_count);
	}

	kfree(second_buf);
}

static void dummy_callback(void)
{
	pr_info("vuln_heap_init: dummy callback invoked\n");
}

static void run_uaf_test(void)
{
	struct uaf_canary *canary = NULL;
	volatile struct uaf_canary *dangling = NULL;

	g_uaf_test_runs++;

	/* Step 1: Allocate structure with sensitive token and function pointer */
	canary = kmalloc(sizeof(*canary), GFP_KERNEL);
	if (!canary) {
		pr_err("vuln_heap_init: failed to allocate uaf canary struct\n");
		return;
	}

	memset(canary->token, 0, sizeof(canary->token));
	strscpy(canary->token, "TOP_SECRET_SESSION_TOKEN_9999", sizeof(canary->token));
	canary->payload = 0xCAFEBABE12345678ULL;
	canary->func_ptr = dummy_callback;

	dangling = canary;

	/* Step 2: Free the structure */
	kfree(canary);

	/*
	 * Step 3: Inspect freed structure via dangling pointer.
	 * If CONFIG_INIT_ON_FREE_DEFAULT_ON=y (or init_on_free=1),
	 * slab_free_hook() zeroes the object memory immediately.
	 */
	g_uaf_stale_magic = dangling->payload;

	if (dangling->payload == 0 && dangling->token[0] == 0) {
		g_uaf_wiped = true;
		pr_info("vuln_heap_init: [UAF_TEST] PASS - freed object contents wiped to 0x00\n");
	} else {
		g_uaf_wiped = false;
		pr_warn("vuln_heap_init: [UAF_TEST] EXPOSED - freed object retains stale token: %.16s, payload: 0x%lx\n",
			(char *)dangling->token, dangling->payload);
	}
}

static int vuln_proc_show(struct seq_file *m, void *v)
{
	bool init_alloc_active = want_init_on_alloc(GFP_KERNEL);
	bool init_free_active = want_init_on_free();

	seq_puts(m, "=== Linux Kernel Heap Initialization Telemetry ===\n");
	seq_printf(m, "Feature: CONFIG_INIT_ON_ALLOC_DEFAULT_ON : %s\n",
		   IS_ENABLED(CONFIG_INIT_ON_ALLOC_DEFAULT_ON) ? "y" : "n");
	seq_printf(m, "Feature: CONFIG_INIT_ON_FREE_DEFAULT_ON  : %s\n",
		   IS_ENABLED(CONFIG_INIT_ON_FREE_DEFAULT_ON) ? "y" : "n");
	seq_printf(m, "Runtime status: init_on_alloc           : %s\n",
		   init_alloc_active ? "ACTIVE (ON)" : "INACTIVE (OFF)");
	seq_printf(m, "Runtime status: init_on_free            : %s\n",
		   init_free_active ? "ACTIVE (ON)" : "INACTIVE (OFF)");
	seq_puts(m, "\n");

	seq_puts(m, "[--- 1. Uninitialized Heap Leak Test ---]\n");
	seq_printf(m, "Test Runs Completed : %lu\n", g_leak_test_runs);
	seq_printf(m, "Alloc Zeroing Status: %s\n",
		   g_leak_clean ? "PASS (100% Zeroed, No Residual Secrets)"
				: "FAIL (Stale Heap Memory Leaked)");
	seq_printf(m, "Dirty Bytes Found   : %u / %d\n", g_dirty_bytes_found, LEAK_OBJ_SIZE);
	seq_printf(m, "Sample Content      : %s\n", g_last_leaked_sample);
	seq_puts(m, "\n");

	seq_puts(m, "[--- 2. Use-After-Free Memory Wipe Test ---]\n");
	seq_printf(m, "Test Runs Completed : %lu\n", g_uaf_test_runs);
	seq_printf(m, "Free Wiping Status  : %s\n",
		   g_uaf_wiped ? "WIPED (Memory Cleared upon kfree)"
			       : "EXPOSED (Stale Struct Retained in Memory)");
	seq_printf(m, "Post-Free Magic     : 0x%016lx\n", g_uaf_stale_magic);
	seq_puts(m, "\n");

	if (init_alloc_active || init_free_active) {
		seq_puts(m, "[+] VERDICT: HARDENED (Heap Zeroing Defense is active)\n");
	} else {
		seq_puts(m, "[-] VERDICT: VULNERABLE (Uninitialized Heap Memory Exposure)\n");
	}

	return 0;
}

static int vuln_proc_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_proc_show, NULL);
}

static ssize_t vuln_proc_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char kbuf[32];
	size_t len = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;

	kbuf[len] = '\0';

	if (sysfs_streq(kbuf, "leak")) {
		run_leak_test();
	} else if (sysfs_streq(kbuf, "uaf")) {
		run_uaf_test();
	} else if (sysfs_streq(kbuf, "all") || sysfs_streq(kbuf, "test")) {
		run_leak_test();
		run_uaf_test();
	} else if (sysfs_streq(kbuf, "reset")) {
		g_leak_test_runs = 0;
		g_leak_clean = false;
		g_dirty_bytes_found = 0;
		snprintf(g_last_leaked_sample, sizeof(g_last_leaked_sample), "RESET");
		g_uaf_test_runs = 0;
		g_uaf_wiped = false;
		g_uaf_stale_magic = 0;
		pr_info("vuln_heap_init: telemetry statistics reset\n");
	} else {
		pr_info("vuln_heap_init: unknown command '%s'. Supported: leak, uaf, all, reset\n", kbuf);
	}

	return count;
}

static const struct proc_ops vuln_proc_ops = {
	.proc_open    = vuln_proc_open,
	.proc_read    = seq_read,
	.proc_write   = vuln_proc_write,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
};

static int __init vuln_heap_init_module_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_proc_ops);
	if (!entry) {
		pr_err("vuln_heap_init: failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	/* Run initial baseline test suite */
	run_leak_test();
	run_uaf_test();

	pr_info("vuln_heap_init: lab driver initialized at /proc/%s (mode 0666)\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_heap_init_module_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_heap_init: lab driver unloaded\n");
}

module_init(vuln_heap_init_module_init);
module_exit(vuln_heap_init_module_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver for demonstrating CONFIG_INIT_ON_ALLOC and CONFIG_INIT_ON_FREE");

