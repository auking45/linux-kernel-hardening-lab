// SPDX-License-Identifier: GPL-2.0
/*
 * labs/19-kfence/vuln_kfence.c
 *
 * Target driver for demonstrating KFENCE (Kernel Electric Fence):
 *   1. Low-overhead sampling-based memory error detector for production kernels.
 *   2. Uses hardware MMU guard pages (non-present pages) surrounding guarded objects
 *      to trap Out-of-Bounds (OOB) memory accesses.
 *   3. Marks freed object pages as non-present to trap Use-After-Free (UAF) accesses.
 *   4. Places canary patterns to detect small buffer corruptions.
 *
 * Exposes /proc/vuln_kfence (mode 0666) for non-privileged user-space inspection
 * and automated test execution.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/kfence.h>
#include <linux/delay.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_kfence"
#define TEST_ALLOC_SIZE 32
#define SECRET_TOKEN "CONFIDENTIAL_KFENCE_KEY_8888"

static unsigned long g_oob_attempts = 0;
static unsigned long g_uaf_attempts = 0;
static unsigned long g_kfence_alloc_count = 0;
static unsigned long g_slab_alloc_count = 0;

static void *alloc_guarded_object(size_t size, bool *is_guarded)
{
	void *ptr = NULL;
#ifdef CONFIG_KFENCE
	unsigned long timeout = jiffies + msecs_to_jiffies(1000);
	int attempts = 0;

	/*
	 * With kfence.sample_interval=10, the allocation gate opens periodically.
	 * Loop until an allocation is serviced from __kfence_pool.
	 */
	while (time_before(jiffies, timeout) && attempts < 500) {
		ptr = kmalloc(size, GFP_KERNEL);
		if (ptr && is_kfence_address(ptr)) {
			*is_guarded = true;
			g_kfence_alloc_count++;
			pr_info("vuln_kfence: successfully obtained KFENCE guarded object at %px (attempts: %d)\n",
				ptr, attempts);
			return ptr;
		}
		kfree(ptr);
		attempts++;
		usleep_range(500, 1500);
	}
	pr_info("vuln_kfence: sample timeout; regular slab allocation obtained\n");
#endif
	*is_guarded = false;
	g_slab_alloc_count++;
	return kmalloc(size, GFP_KERNEL);
}

static void trigger_oob_test(void)
{
	bool is_guarded = false;
	u8 *buf = alloc_guarded_object(TEST_ALLOC_SIZE, &is_guarded);
	volatile u8 val;

	if (!buf) {
		pr_err("vuln_kfence: failed to allocate memory for OOB test\n");
		return;
	}

	g_oob_attempts++;
	memset(buf, 0x41, TEST_ALLOC_SIZE);

	if (is_guarded) {
		/*
		 * In KFENCE:
		 *   - Left-aligned object (PAGE_ALIGNED): guard page is at buf - 1.
		 *   - Right-aligned object (!PAGE_ALIGNED): guard page is at buf + TEST_ALLOC_SIZE.
		 */
		if (PAGE_ALIGNED(buf)) {
			pr_info("vuln_kfence: [OOB_TEST] Left-aligned guarded object at %px. Probing guard page at %px...\n",
				buf, buf - 1);
			val = *(volatile u8 *)(buf - 1);
		} else {
			pr_info("vuln_kfence: [OOB_TEST] Right-aligned guarded object at %px. Probing guard page at %px...\n",
				buf, buf + TEST_ALLOC_SIZE);
			val = *(volatile u8 *)(buf + TEST_ALLOC_SIZE);
		}
		pr_info("vuln_kfence: [OOB_TEST] Completed probe (val=0x%02x)\n", val);
	} else {
		pr_info("vuln_kfence: [OOB_TEST] Regular slab object at %px. Probing buf + size...\n", buf);
		val = *(volatile u8 *)(buf + TEST_ALLOC_SIZE);
		pr_info("vuln_kfence: [OOB_TEST] Regular slab read succeeded silently (val=0x%02x) - no guard page!\n", val);
	}

	kfree(buf);
}

static void trigger_uaf_test(void)
{
	bool is_guarded = false;
	u8 *buf = alloc_guarded_object(TEST_ALLOC_SIZE, &is_guarded);
	volatile u8 val;

	if (!buf) {
		pr_err("vuln_kfence: failed to allocate memory for UAF test\n");
		return;
	}

	g_uaf_attempts++;
	memset(buf, 0x42, TEST_ALLOC_SIZE);
	memcpy(buf, SECRET_TOKEN, min((size_t)TEST_ALLOC_SIZE, strlen(SECRET_TOKEN)));

	pr_info("vuln_kfence: [UAF_TEST] Freeing %s object at %px...\n",
		is_guarded ? "KFENCE guarded" : "regular slab", buf);
	kfree(buf);

	/*
	 * Trigger Use-After-Free:
	 *   - If KFENCE guarded: the freed page is marked non-present by kfence_guarded_free().
	 *     Accessing it triggers a hardware page fault -> BUG: KFENCE: use-after-free.
	 *   - If regular slab: stale memory is read silently without MMU fault.
	 */
	pr_info("vuln_kfence: [UAF_TEST] Attempting Use-After-Free read from freed pointer %px...\n", buf);
	val = *(volatile u8 *)buf;
	pr_info("vuln_kfence: [UAF_TEST] Read after free executed (val=0x%02x)\n", val);
}

static ssize_t vuln_kfence_read(struct file *file, char __user *buf,
				size_t count, loff_t *ppos)
{
	char status_buf[1024];
	int len = 0;

	if (*ppos > 0)
		return 0;

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  KFENCE Verification Driver (/proc/%s)\n", PROC_FILENAME);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");

#ifdef CONFIG_KFENCE
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Kernel Configuration : CONFIG_KFENCE=y [ENABLED]\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Sample Interval      : %lu ms (configurable via kfence.sample_interval)\n",
			 kfence_sample_interval);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Protection Status    : ACTIVE (Sampling guard pages & UAF page protection)\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Debugfs Interface    : /sys/kernel/debug/kfence/stats\n");
#else
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Kernel Configuration : CONFIG_KFENCE is not set [DISABLED]\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Protection Status    : VULNERABLE (Standard SLUB without electric guard pages)\n");
#endif

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "OOB Probes Triggered : %lu\n", g_oob_attempts);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "UAF Probes Triggered : %lu\n", g_uaf_attempts);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Guarded Allocations  : %lu\n", g_kfence_alloc_count);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Regular Allocations  : %lu\n", g_slab_alloc_count);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Commands             : 'oob', 'uaf', 'reset'\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");

	return simple_read_from_buffer(buf, count, ppos, status_buf, len);
}

static ssize_t vuln_kfence_write(struct file *file, const char __user *ubuf,
				 size_t count, loff_t *ppos)
{
	char kbuf[64];
	size_t copy_len;

	if (count == 0)
		return 0;

	copy_len = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, ubuf, copy_len))
		return -EFAULT;

	kbuf[copy_len] = '\0';
	if (copy_len > 0 && kbuf[copy_len - 1] == '\n')
		kbuf[copy_len - 1] = '\0';

	if (strcmp(kbuf, "oob") == 0) {
		pr_info("vuln_kfence: executing Out-of-Bounds (OOB) memory test...\n");
		trigger_oob_test();
	} else if (strcmp(kbuf, "uaf") == 0) {
		pr_info("vuln_kfence: executing Use-After-Free (UAF) memory test...\n");
		trigger_uaf_test();
	} else if (strcmp(kbuf, "reset") == 0) {
		g_oob_attempts = 0;
		g_uaf_attempts = 0;
		g_kfence_alloc_count = 0;
		g_slab_alloc_count = 0;
		pr_info("vuln_kfence: statistics reset\n");
	} else {
		pr_info("vuln_kfence: unknown command '%s'. Supported: oob, uaf, reset\n", kbuf);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_kfence_proc_ops = {
	.proc_read = vuln_kfence_read,
	.proc_write = vuln_kfence_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_kfence_proc_ops = {
	.owner = THIS_MODULE,
	.read = vuln_kfence_read,
	.write = vuln_kfence_write,
	.llseek = default_llseek,
};
#endif

static int __init vuln_kfence_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_kfence_proc_ops);
	if (!entry) {
		pr_err("vuln_kfence: failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_kfence: lab driver initialized at /proc/%s (mode 0666)\n",
		PROC_FILENAME);
	return 0;
}

static void __exit vuln_kfence_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_kfence: lab driver unloaded\n");
}

module_init(vuln_kfence_init);
module_exit(vuln_kfence_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable driver for KFENCE demonstration");

