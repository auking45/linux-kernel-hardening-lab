// SPDX-License-Identifier: GPL-2.0
/*
 * labs/13-kcfi/vuln_kcfi.c
 *
 * Vulnerable target driver for demonstrating Clang kCFI (Kernel Control Flow Integrity)
 * forward-edge indirect function call protection.
 * Exposes /proc/vuln_kcfi (mode 0666) with hardware/compiler telemetry and
 * controllable indirect call trigger vectors.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/cfi.h>

#define PROC_FILENAME "vuln_kcfi"

/* Function pointer prototype: Expected legitimate caller signature */
typedef void (*kcfi_legit_fn_t)(unsigned long val);

/* Function pointer prototype: Mismatched prototype signature */
typedef void (*kcfi_mismatched_fn_t)(int a, int b, const char *msg);

/* Function pointer prototype: Arbitrary 0-arg function signature */
typedef void (*kcfi_hijack_fn_t)(void);

static unsigned long g_call_count = 0;
static int g_last_call_result = 0; /* 0: None, 1: Legit OK, 2: Mismatch Hijacked, 3: Arbitrary Hijacked */

/* Legitimate target function: matches kcfi_legit_fn_t */
static noinline void kcfi_legit_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 1;
	pr_info("[vuln_kcfi] [+] Legitimate function executed: val=0x%lx (call_count=%lu)\n",
		val, g_call_count);
}

/* Mismatched target function: does NOT match kcfi_legit_fn_t */
static noinline void kcfi_mismatch_target(int a, int b, const char *msg)
{
	g_call_count++;
	g_last_call_result = 2;
	pr_warn("[vuln_kcfi] [!] VULNERABLE: Mismatched prototype target executed!\n");
	pr_warn("[vuln_kcfi] [!] Control flow hijacked via function pointer mismatch: a=%d, b=%d\n",
		a, b);
}

/* Arbitrary target function: simulates attacker-chosen gadget */
static noinline void kcfi_hijacked_target(void)
{
	g_call_count++;
	g_last_call_result = 3;
	pr_emerg("[vuln_kcfi] [!] =========================================================\n");
	pr_emerg("[vuln_kcfi] [!] CRITICAL: Arbitrary hijacked target function executed!\n");
	pr_emerg("[vuln_kcfi] [!] Function pointer was successfully redirected.\n");
	pr_emerg("[vuln_kcfi] [!] =========================================================\n");
}

/* Indirect call dispatcher: invokes func_ptr via kcfi_legit_fn_t */
static noinline void kcfi_dispatch_call(kcfi_legit_fn_t func_ptr, unsigned long arg)
{
	pr_info("[vuln_kcfi] Dispatching indirect function call to %px with arg 0x%lx...\n",
		(void *)func_ptr, arg);
	/*
	 * When CONFIG_CFI_CLANG is enabled:
	 *   Compiler injects a prelude check verifying that the 4-byte type hash
	 *   tag preceding 'func_ptr' matches the type hash of kcfi_legit_fn_t.
	 *   If it does not match, a trap (ud2 on x86, brk on ARM64) is triggered!
	 *
	 * When CONFIG_CFI_CLANG is disabled:
	 *   The CPU unconditionally branches to 'func_ptr', executing any target.
	 */
	func_ptr(arg);
}

static int vuln_kcfi_show(struct seq_file *m, void *v)
{
	u32 legit_type_tag = 0;
	u32 mismatch_type_tag = 0;
	u32 hijack_type_tag = 0;

	/* Attempt to read 4-byte type tag placed before function entry point */
	copy_from_kernel_nofault(&legit_type_tag, (void *)kcfi_legit_target - 4, sizeof(legit_type_tag));
	copy_from_kernel_nofault(&mismatch_type_tag, (void *)kcfi_mismatch_target - 4, sizeof(mismatch_type_tag));
	copy_from_kernel_nofault(&hijack_type_tag, (void *)kcfi_hijacked_target - 4, sizeof(hijack_type_tag));

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "  Linux Kernel Hardening Lab - Clang kCFI Telemetry\n");
	seq_puts(m, "=========================================================\n");

#ifdef CONFIG_CFI_CLANG
	seq_puts(m, "KCFI_STATUS:             ENABLED\n");
#else
	seq_puts(m, "KCFI_STATUS:             DISABLED\n");
#endif

#ifdef CONFIG_CFI_PERMISSIVE
	seq_puts(m, "CFI_PERMISSIVE:          1 (Warning on mismatch)\n");
#else
	seq_puts(m, "CFI_PERMISSIVE:          0 (Panic / BUG on mismatch)\n");
#endif

#if defined(__clang__)
	seq_printf(m, "COMPILER:                Clang %d.%d.%d\n",
		   __clang_major__, __clang_minor__, __clang_patchlevel__);
#elif defined(__GNUC__)
	seq_printf(m, "COMPILER:                GCC %d.%d.%d\n",
		   __GNUC__, __GNUC_MINOR__, __GNUC_PATCHLEVEL__);
#else
	seq_puts(m, "COMPILER:                Unknown\n");
#endif

	seq_printf(m, "LEGIT_TARGET_ADDR:       %px\n", (void *)kcfi_legit_target);
	seq_printf(m, "MISMATCH_TARGET_ADDR:    %px\n", (void *)kcfi_mismatch_target);
	seq_printf(m, "HIJACK_TARGET_ADDR:      %px\n", (void *)kcfi_hijacked_target);

	seq_printf(m, "LEGIT_TYPE_TAG:          0x%08x\n", legit_type_tag);
	seq_printf(m, "MISMATCH_TYPE_TAG:       0x%08x\n", mismatch_type_tag);
	seq_printf(m, "HIJACK_TYPE_TAG:         0x%08x\n", hijack_type_tag);

	seq_printf(m, "TOTAL_CALLS:             %lu\n", g_call_count);
	seq_printf(m, "LAST_CALL_RESULT:        %s\n",
		   g_last_call_result == 1 ? "LEGIT_MATCHED_SUCCESS" :
		   (g_last_call_result == 2 ? "MISMATCH_HIJACKED_EXECUTED" :
		   (g_last_call_result == 3 ? "ARBITRARY_HIJACKED_EXECUTED" : "NONE")));

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "Supported write commands:\n");
	seq_puts(m, "  echo 'legit'    > /proc/vuln_kcfi  (call matching prototype)\n");
	seq_puts(m, "  echo 'mismatch' > /proc/vuln_kcfi  (call mismatched prototype)\n");
	seq_puts(m, "  echo 'hijack'   > /proc/vuln_kcfi  (call arbitrary target)\n");
	return 0;
}

static int vuln_kcfi_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_kcfi_show, NULL);
}

static ssize_t vuln_kcfi_write(struct file *file, const char __user *ubuf,
			       size_t count, loff_t *ppos)
{
	char kbuf[32];
	size_t len = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;

	kbuf[len] = '\0';

	/* Strip trailing newline */
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[len - 1] = '\0';

	pr_info("[vuln_kcfi] Received command: '%s'\n", kbuf);

	if (strcmp(kbuf, "1") == 0 || strcmp(kbuf, "legit") == 0) {
		pr_info("[vuln_kcfi] Testing Test 1: Legitimate indirect call (Matched prototype)...\n");
		kcfi_dispatch_call(kcfi_legit_target, 0x1337);
	} else if (strcmp(kbuf, "2") == 0 || strcmp(kbuf, "mismatch") == 0) {
		pr_info("[vuln_kcfi] Testing Test 2: Mismatched prototype indirect call...\n");
		/* Deliberately cast mismatched function into expected signature */
		kcfi_dispatch_call((kcfi_legit_fn_t)kcfi_mismatch_target, 0xcafe);
	} else if (strcmp(kbuf, "3") == 0 || strcmp(kbuf, "hijack") == 0) {
		pr_info("[vuln_kcfi] Testing Test 3: Arbitrary hijacked indirect call...\n");
		/* Deliberately cast arbitrary target into expected signature */
		kcfi_dispatch_call((kcfi_legit_fn_t)kcfi_hijacked_target, 0xdead);
	} else {
		pr_warn("[vuln_kcfi] Unknown command '%s'. Use 'legit', 'mismatch', or 'hijack'.\n", kbuf);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops vuln_kcfi_proc_ops = {
	.proc_open    = vuln_kcfi_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = vuln_kcfi_write,
};

static int __init vuln_kcfi_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_kcfi_proc_ops);
	if (!entry) {
		pr_err("[vuln_kcfi] Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("[vuln_kcfi] Initialized /proc/%s interface (mode 0666)\n", PROC_FILENAME);
#ifdef CONFIG_CFI_CLANG
	pr_info("[vuln_kcfi] CONFIG_CFI_CLANG is ACTIVE (Forward-edge CFI protection enabled)\n");
#else
	pr_info("[vuln_kcfi] CONFIG_CFI_CLANG is DISABLED (Vulnerable to indirect call hijacking)\n");
#endif
	return 0;
}

static void __exit vuln_kcfi_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("[vuln_kcfi] Removed /proc/%s\n", PROC_FILENAME);
}

module_init(vuln_kcfi_init);
module_exit(vuln_kcfi_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Clang kCFI forward-edge indirect call verification driver");

