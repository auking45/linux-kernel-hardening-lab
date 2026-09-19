// SPDX-License-Identifier: GPL-2.0
/*
 * labs/16-slab-freelist/vuln_slab_freelist.c
 *
 * Target driver for demonstrating SLUB allocator hardening features:
 *   1. CONFIG_SLAB_FREELIST_RANDOM - Randomizes freelist order within slab pages.
 *   2. CONFIG_SLAB_FREELIST_HARDENED - Obfuscates freelist pointers via XOR with
 *      per-cache random cookies and byte-swapping to block freelist hijacking.
 *
 * Exposes /proc/vuln_slab_freelist (mode 0666) with allocation layout telemetry,
 * freelist pointer encoding state, and controlled test triggers.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/slab.h>

#define PROC_FILENAME "vuln_slab_freelist"
#define TEST_OBJ_SIZE 64
#define NUM_TEST_OBJS 8

static struct kmem_cache *g_test_cache = NULL;
static unsigned long g_alloc_count = 0;
static unsigned int g_last_sequential_matches = 0;
static bool g_last_pointer_obfuscated = false;
static unsigned long g_last_sample_ptrs[NUM_TEST_OBJS];
static unsigned long g_last_raw_next_ptr = 0;
static unsigned long g_last_stored_freeptr = 0;
static char g_last_result[64] = "READY";

static void run_slab_allocation_test(void)
{
	void *objs[NUM_TEST_OBJS];
	int i;
	unsigned int seq_count = 0;

	if (!g_test_cache)
		return;

	memset(objs, 0, sizeof(objs));

	/* Allocate sequential objects from our dedicated slab cache */
	for (i = 0; i < NUM_TEST_OBJS; i++) {
		objs[i] = kmem_cache_alloc(g_test_cache, GFP_KERNEL);
		if (objs[i]) {
			g_last_sample_ptrs[i] = (unsigned long)objs[i];
			*(unsigned long *)objs[i] = 0xdeadbeef00000000ULL | i;
		} else {
			g_last_sample_ptrs[i] = 0;
		}
	}

	/* Analyze adjacency / sequential linearity between consecutive allocations */
	for (i = 0; i < NUM_TEST_OBJS - 1; i++) {
		if (g_last_sample_ptrs[i] && g_last_sample_ptrs[i + 1]) {
			long diff = (long)(g_last_sample_ptrs[i + 1] - g_last_sample_ptrs[i]);
			if (diff == TEST_OBJ_SIZE)
				seq_count++;
		}
	}

	g_last_sequential_matches = seq_count;

	/*
	 * Inspect freelist pointer obfuscation:
	 * Free two consecutive objects. In a LIFO/FIFO freelist, the first freed object
	 * holds the pointer to the next free object (or NULL).
	 */
	if (objs[0] && objs[1]) {
		unsigned long target_addr = (unsigned long)objs[0];
		unsigned long expected_next = (unsigned long)objs[1];
		unsigned long stored_val = 0;

		kmem_cache_free(g_test_cache, objs[1]);
		kmem_cache_free(g_test_cache, objs[0]);
		objs[0] = NULL;
		objs[1] = NULL;

		/* Read first 8 bytes of freed object (where freeptr resides) */
		copy_from_kernel_nofault(&stored_val, (void *)target_addr, sizeof(stored_val));

		g_last_raw_next_ptr = expected_next;
		g_last_stored_freeptr = stored_val;

		/*
		 * If hardened, stored_val is encoded (stored_val != expected_next)
		 * and does not look like a canonical kernel virtual address.
		 * If unhardened baseline, stored_val == expected_next.
		 */
		g_last_pointer_obfuscated = (stored_val != expected_next && stored_val != 0);
	}

	/* Free remaining test objects */
	for (i = 2; i < NUM_TEST_OBJS; i++) {
		if (objs[i]) {
			kmem_cache_free(g_test_cache, objs[i]);
			objs[i] = NULL;
		}
	}

	g_alloc_count++;
	snprintf(g_last_result, sizeof(g_last_result), "ALLOC_TEST_OK (seq=%u/%d)",
		 g_last_sequential_matches, NUM_TEST_OBJS - 1);
	pr_info("[vuln_slab_freelist] Allocation test complete: sequential matches=%u/%d, freeptr obfuscated=%s\n",
		g_last_sequential_matches, NUM_TEST_OBJS - 1,
		g_last_pointer_obfuscated ? "YES" : "NO");
}

static int vuln_slab_freelist_show(struct seq_file *m, void *v)
{
	int i;
	unsigned int seq_pct = (g_last_sequential_matches * 100) / (NUM_TEST_OBJS - 1);

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "  Linux Kernel Hardening Lab - SLUB Freelist Telemetry\n");
	seq_puts(m, "=========================================================\n");

#if defined(__x86_64__)
	seq_puts(m, "TARGET_ARCH:             x86_64\n");
#elif defined(__aarch64__)
	seq_puts(m, "TARGET_ARCH:             arm64\n");
#else
	seq_puts(m, "TARGET_ARCH:             unknown\n");
#endif

#ifdef CONFIG_SLAB_FREELIST_HARDENED
	seq_puts(m, "CONFIG_SLAB_FREELIST_HARDENED: ENABLED\n");
#else
	seq_puts(m, "CONFIG_SLAB_FREELIST_HARDENED: DISABLED\n");
#endif

#ifdef CONFIG_SLAB_FREELIST_RANDOM
	seq_puts(m, "CONFIG_SLAB_FREELIST_RANDOM:   ENABLED\n");
#else
	seq_puts(m, "CONFIG_SLAB_FREELIST_RANDOM:   DISABLED\n");
#endif

	seq_printf(m, "ALLOC_TEST_RUNS:         %lu\n", g_alloc_count);
	seq_printf(m, "SEQUENTIAL_ADJACENCY:    %u%% (%u/%d linear matches)\n",
		   seq_pct, g_last_sequential_matches, NUM_TEST_OBJS - 1);
	seq_printf(m, "FREELIST_PTR_OBFUSCATED: %s\n",
		   g_last_pointer_obfuscated ? "YES" : "NO");
	seq_printf(m, "LAST_RAW_NEXT_PTR:       0x%016lx\n", g_last_raw_next_ptr);
	seq_printf(m, "LAST_STORED_FREEPTR:     0x%016lx\n", g_last_stored_freeptr);
	seq_printf(m, "LAST_RESULT:             %s\n", g_last_result);

	seq_puts(m, "---------------------------------------------------------\n");
	seq_puts(m, "Recent Allocation Sample Addresses:\n");
	for (i = 0; i < NUM_TEST_OBJS; i++) {
		seq_printf(m, "  [%d] 0x%016lx\n", i, g_last_sample_ptrs[i]);
	}

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "Supported write commands:\n");
	seq_puts(m, "  echo 'alloc_test'  > /proc/vuln_slab_freelist  (run layout & pointer test)\n");
	seq_puts(m, "  echo 'double_free' > /proc/vuln_slab_freelist  (trigger double-free detection)\n");
	return 0;
}

static int vuln_slab_freelist_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_slab_freelist_show, NULL);
}

static ssize_t vuln_slab_freelist_write(struct file *file, const char __user *ubuf,
					size_t count, loff_t *ppos)
{
	char kbuf[32];
	size_t len = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[len - 1] = '\0';

	pr_info("[vuln_slab_freelist] Received write command: '%s'\n", kbuf);

	if (strcmp(kbuf, "1") == 0 || strcmp(kbuf, "alloc_test") == 0) {
		run_slab_allocation_test();
	} else if (strcmp(kbuf, "2") == 0 || strcmp(kbuf, "double_free") == 0) {
		void *test_obj;
		pr_info("[vuln_slab_freelist] Executing controlled double-free test...\n");
		test_obj = kmem_cache_alloc(g_test_cache, GFP_KERNEL);
		if (test_obj) {
			kmem_cache_free(g_test_cache, test_obj);
#ifdef CONFIG_SLAB_FREELIST_HARDENED
			pr_info("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_HARDENED is active: BUG_ON(object == fp) will trap double-free!\n");
#else
			pr_warn("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_HARDENED is disabled: free pointer corruption may go undetected!\n");
#endif
			kmem_cache_free(g_test_cache, test_obj);
		}
	} else {
		pr_warn("[vuln_slab_freelist] Unknown command '%s'. Use 'alloc_test' or 'double_free'.\n", kbuf);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops vuln_slab_freelist_proc_ops = {
	.proc_open    = vuln_slab_freelist_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = vuln_slab_freelist_write,
};

static int __init vuln_slab_freelist_init(void)
{
	struct proc_dir_entry *entry;

	/* Create dedicated slab cache for freelist layout and pointer inspection */
	g_test_cache = kmem_cache_create("vuln_slab_freelist", TEST_OBJ_SIZE, 0,
					 SLAB_PANIC | SLAB_ACCOUNT, NULL);
	if (!g_test_cache) {
		pr_err("[vuln_slab_freelist] Failed to create dedicated kmem_cache\n");
		return -ENOMEM;
	}

	/* Run initial test to populate baseline telemetry */
	run_slab_allocation_test();

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_slab_freelist_proc_ops);
	if (!entry) {
		kmem_cache_destroy(g_test_cache);
		pr_err("[vuln_slab_freelist] Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("[vuln_slab_freelist] Initialized /proc/%s interface (mode 0666)\n", PROC_FILENAME);
#ifdef CONFIG_SLAB_FREELIST_HARDENED
	pr_info("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_HARDENED is ACTIVE\n");
#else
	pr_info("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_HARDENED is DISABLED\n");
#endif
#ifdef CONFIG_SLAB_FREELIST_RANDOM
	pr_info("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_RANDOM is ACTIVE\n");
#else
	pr_info("[vuln_slab_freelist] CONFIG_SLAB_FREELIST_RANDOM is DISABLED\n");
#endif
	return 0;
}

static void __exit vuln_slab_freelist_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	if (g_test_cache) {
		kmem_cache_destroy(g_test_cache);
		g_test_cache = NULL;
	}
	pr_info("[vuln_slab_freelist] Removed /proc/%s and destroyed test cache\n", PROC_FILENAME);
}

module_init(vuln_slab_freelist_init);
module_exit(vuln_slab_freelist_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("SLAB Freelist Hardening & Randomization verification driver");

