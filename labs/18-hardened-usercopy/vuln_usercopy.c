// SPDX-License-Identifier: GPL-2.0
/*
 * labs/18-hardened-usercopy/vuln_usercopy.c
 *
 * Target driver for demonstrating CONFIG_HARDENED_USERCOPY:
 *   1. Intercepts copy_to_user() and copy_from_user() via check_object_size().
 *   2. Validates slab heap boundaries (__check_heap_object) to prevent
 *      out-of-bounds heap reading/writing across slab object boundaries.
 *   3. Prevents arbitrary kernel text (.text) reading (check_kernel_text_object),
 *      blocking direct leaks of kernel code and defeating KASLR bypasses.
 *   4. Validates stack frame bounds (check_stack_object).
 *
 * Exposes /proc/vuln_usercopy (mode 0666) for non-privileged user-space inspection
 * and automated LKDTM / PoC test execution.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_usercopy"
#define CHUNK_SIZE 64
#define SECRET_TOKEN "CONFIDENTIAL_KEY_IN_CHUNK_B_9999"
#define PUBLIC_HEADER "PUBLIC_CHUNK_A_HEADER: Welcome to Hardened Usercopy Lab!"

enum lab_mode {
	MODE_STATUS = 0,
	MODE_SLAB_LEAK,
	MODE_TEXT_LEAK,
};

static enum lab_mode g_current_mode = MODE_STATUS;
static volatile size_t g_unconst = 0;

static unsigned long g_slab_leak_attempts = 0;
static unsigned long g_text_leak_attempts = 0;

static ssize_t vuln_usercopy_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char status_buf[1024];
	int len = 0;
	u8 *chunk_a = NULL;
	u8 *chunk_b = NULL;
	unsigned long uncopied;

	if (g_current_mode == MODE_SLAB_LEAK) {
		g_slab_leak_attempts++;
		pr_info("vuln_usercopy: [SLAB_LEAK] Preparing adjacent 64-byte SLUB allocations...\n");

		chunk_a = kmalloc(g_unconst + CHUNK_SIZE, GFP_KERNEL);
		chunk_b = kmalloc(g_unconst + CHUNK_SIZE, GFP_KERNEL);

		if (!chunk_a || !chunk_b) {
			pr_err("vuln_usercopy: failed to allocate test chunks\n");
			kfree(chunk_a);
			kfree(chunk_b);
			g_current_mode = MODE_STATUS;
			return -ENOMEM;
		}

		memset(chunk_a, 'A', CHUNK_SIZE);
		strncpy((char *)chunk_a, PUBLIC_HEADER, CHUNK_SIZE - 1);

		memset(chunk_b, 'B', CHUNK_SIZE);
		strncpy((char *)chunk_b, SECRET_TOKEN, CHUNK_SIZE - 1);

		pr_info("vuln_usercopy: chunk_a at %px (size %d), chunk_b at %px (size %d)\n",
			chunk_a, CHUNK_SIZE, chunk_b, CHUNK_SIZE);
		pr_info("vuln_usercopy: attempting copy_to_user(buf, chunk_a, 128) - exceeding 64-byte boundary!\n");

		/*
		 * If CONFIG_HARDENED_USERCOPY=y:
		 *   check_object_size() -> __check_heap_object() catches the 128-byte
		 *   copy exceeding chunk_a's 64-byte usersize.
		 *   Calls usercopy_abort("SLUB object", ...) -> BUG().
		 *
		 * If CONFIG_HARDENED_USERCOPY is disabled:
		 *   copy_to_user() succeeds silently, reading past chunk_a into
		 *   adjacent heap data (chunk_b secret or slab metadata)!
		 */
		uncopied = copy_to_user(buf, chunk_a, g_unconst + (CHUNK_SIZE * 2));

		kfree(chunk_a);
		kfree(chunk_b);
		g_current_mode = MODE_STATUS;

		if (uncopied == 0) {
			pr_warn("vuln_usercopy: [VULNERABLE] copy_to_user succeeded! Leaked 128 bytes of heap!\n");
			return CHUNK_SIZE * 2;
		} else {
			pr_info("vuln_usercopy: copy_to_user partial/failed (uncopied=%lu)\n", uncopied);
			return -EFAULT;
		}
	} else if (g_current_mode == MODE_TEXT_LEAK) {
		g_text_leak_attempts++;
		pr_info("vuln_usercopy: [TEXT_LEAK] Attempting copy_to_user from kernel text (%px, size 64)...\n",
			vuln_usercopy_read);

		/*
		 * If CONFIG_HARDENED_USERCOPY=y:
		 *   check_kernel_text_object() detects pointer inside kernel text.
		 *   Calls usercopy_abort("kernel text", ...) -> BUG().
		 *
		 * If CONFIG_HARDENED_USERCOPY is disabled:
		 *   copy_to_user() copies raw executable instructions into userspace!
		 */
		uncopied = copy_to_user(buf, (const void *)vuln_usercopy_read, g_unconst + 64);
		g_current_mode = MODE_STATUS;

		if (uncopied == 0) {
			pr_warn("vuln_usercopy: [VULNERABLE] copy_to_user leaked kernel .text instructions!\n");
			return 64;
		} else {
			return -EFAULT;
		}
	}

	/* Default: MODE_STATUS display */
	if (*ppos > 0)
		return 0;

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "  Hardened Usercopy Verification Driver (/proc/%s)\n", PROC_FILENAME);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");

#ifdef CONFIG_HARDENED_USERCOPY
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Kernel Configuration : CONFIG_HARDENED_USERCOPY=y [ENABLED]\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Protection Status    : ACTIVE (Slab boundaries & kernel text enforced)\n");
#else
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Kernel Configuration : CONFIG_HARDENED_USERCOPY is not set [DISABLED]\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Protection Status    : VULNERABLE (Unchecked copy_to/from_user allowed)\n");
#endif

	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Slab Leak Attempts   : %lu\n", g_slab_leak_attempts);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Text Leak Attempts   : %lu\n", g_text_leak_attempts);
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "Supported Commands   : 'slab_leak', 'text_leak', 'status', 'reset'\n");
	len += scnprintf(status_buf + len, sizeof(status_buf) - len,
			 "=========================================================\n");

	return simple_read_from_buffer(buf, count, ppos, status_buf, len);
}

static ssize_t vuln_usercopy_write(struct file *file, const char __user *ubuf,
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

	if (strcmp(kbuf, "slab_leak") == 0) {
		g_current_mode = MODE_SLAB_LEAK;
		pr_info("vuln_usercopy: mode armed -> MODE_SLAB_LEAK (read next to trigger copy_to_user)\n");
	} else if (strcmp(kbuf, "text_leak") == 0) {
		g_current_mode = MODE_TEXT_LEAK;
		pr_info("vuln_usercopy: mode armed -> MODE_TEXT_LEAK (read next to trigger copy_to_user)\n");
	} else if (strcmp(kbuf, "reset") == 0) {
		g_current_mode = MODE_STATUS;
		g_slab_leak_attempts = 0;
		g_text_leak_attempts = 0;
		pr_info("vuln_usercopy: telemetry statistics reset\n");
	} else {
		g_current_mode = MODE_STATUS;
		pr_info("vuln_usercopy: mode set to MODE_STATUS\n");
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_usercopy_proc_ops = {
	.proc_read = vuln_usercopy_read,
	.proc_write = vuln_usercopy_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_usercopy_proc_ops = {
	.owner = THIS_MODULE,
	.read = vuln_usercopy_read,
	.write = vuln_usercopy_write,
	.llseek = default_llseek,
};
#endif

static int __init vuln_usercopy_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_usercopy_proc_ops);
	if (!entry) {
		pr_err("vuln_usercopy: failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_usercopy: lab driver initialized at /proc/%s (mode 0666)\n",
		PROC_FILENAME);
	return 0;
}

static void __exit vuln_usercopy_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_usercopy: lab driver unloaded\n");
}

module_init(vuln_usercopy_init);
module_exit(vuln_usercopy_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable driver for Hardened Usercopy demonstration");

