// SPDX-License-Identifier: GPL-2.0
/*
 * labs/14-ibt-shstk/vuln_ibt.c
 *
 * Vulnerable target driver for demonstrating Intel CET (Control-flow Enforcement
 * Technology) features on x86_64:
 *   1. Kernel IBT (Indirect Branch Tracking - CONFIG_X86_KERNEL_IBT)
 *   2. User-space Shadow Stack (CONFIG_X86_USER_SHADOW_STACK)
 *
 * Exposes /proc/vuln_ibt (mode 0666) with CPU/compiler telemetry and
 * controlled indirect branch test vectors.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>

#if defined(__x86_64__)
#include <asm/cpufeatures.h>
#include <asm/ibt.h>
#endif

#define PROC_FILENAME "vuln_ibt"
#define ENDBR64_OPCODE 0xfa1e0ff3U /* 0xf3, 0x0f, 0x1e, 0xfa (endbr64) */

typedef void (*ibt_fn_t)(unsigned long arg);

static unsigned long g_call_count = 0;
static int g_last_call_result = 0; /* 0: None, 1: Legit OK, 2: Missing ENDBR Hijacked */

/* Legitimate indirect call target: Contains endbr64 when CONFIG_X86_KERNEL_IBT=y */
static noinline void ibt_legit_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 1;
	pr_info("[vuln_ibt] [+] Legitimate target executed: val=0x%lx (call_count=%lu)\n",
		val, g_call_count);
}

/*
 * Deliberately missing ENDBR target:
 * On x86_64 with IBT, entering this function directly or via offset
 * simulates an attacker jumping to an arbitrary non-entrypoint instruction.
 */
#if defined(__x86_64__)
static noinline __noendbr void ibt_noendbr_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 2;
	pr_warn("[vuln_ibt] [!] VULNERABLE: Function without ENDBR executed!\n");
	pr_warn("[vuln_ibt] [!] Control flow hijacked to non-instrumented target: val=0x%lx\n", val);
}
#else
static noinline void ibt_noendbr_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 2;
	pr_info("[vuln_ibt] Target executed on non-x86 architecture: val=0x%lx\n", val);
}
#endif

/* Indirect call dispatcher */
static noinline void ibt_dispatch_call(ibt_fn_t func_ptr, unsigned long arg)
{
	pr_info("[vuln_ibt] Dispatching indirect call to %px with arg 0x%lx...\n",
		(void *)func_ptr, arg);
	func_ptr(arg);
}

static int vuln_ibt_show(struct seq_file *m, void *v)
{
	u32 legit_first_insn = 0;
	u32 noendbr_first_insn = 0;
	bool hw_ibt = false;
	bool hw_shstk = false;

#if defined(__x86_64__)
	copy_from_kernel_nofault(&legit_first_insn, (void *)ibt_legit_target, sizeof(legit_first_insn));
	copy_from_kernel_nofault(&noendbr_first_insn, (void *)ibt_noendbr_target, sizeof(noendbr_first_insn));
	hw_ibt = boot_cpu_has(X86_FEATURE_IBT);
	hw_shstk = boot_cpu_has(X86_FEATURE_SHSTK);
#endif

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "  Linux Kernel Hardening Lab - Intel CET / IBT Telemetry\n");
	seq_puts(m, "=========================================================\n");

#if defined(__x86_64__)
	seq_puts(m, "TARGET_ARCH:             x86_64\n");
#ifdef CONFIG_X86_KERNEL_IBT
	seq_puts(m, "KERNEL_IBT:              ENABLED\n");
#else
	seq_puts(m, "KERNEL_IBT:              DISABLED\n");
#endif

#ifdef CONFIG_X86_USER_SHADOW_STACK
	seq_puts(m, "USER_SHADOW_STACK:       ENABLED\n");
#else
	seq_puts(m, "USER_SHADOW_STACK:       DISABLED\n");
#endif

#ifdef CONFIG_X86_CET
	seq_puts(m, "CONFIG_X86_CET:          ENABLED\n");
#else
	seq_puts(m, "CONFIG_X86_CET:          DISABLED\n");
#endif

	seq_printf(m, "HW_IBT_SUPPORTED:        %s\n", hw_ibt ? "YES" : "NO");
	seq_printf(m, "HW_SHSTK_SUPPORTED:      %s\n", hw_shstk ? "YES" : "NO");

	seq_printf(m, "LEGIT_TARGET_ADDR:       %px (Insn: 0x%08x%s)\n",
		   (void *)ibt_legit_target, legit_first_insn,
		   legit_first_insn == ENDBR64_OPCODE ? " [ENDBR64]" : "");
	seq_printf(m, "NOENDBR_TARGET_ADDR:     %px (Insn: 0x%08x%s)\n",
		   (void *)ibt_noendbr_target, noendbr_first_insn,
		   noendbr_first_insn == ENDBR64_OPCODE ? " [ENDBR64]" : " [NO_ENDBR]");

	seq_printf(m, "COMPILER_ENDBR_DETECTED: %s\n",
		   legit_first_insn == ENDBR64_OPCODE ? "YES (0xfa1e0ff3)" : "NO");

#else /* Non-x86 architecture (e.g. ARM64) */
	seq_puts(m, "TARGET_ARCH:             arm64 (Non-x86)\n");
	seq_puts(m, "KERNEL_IBT:              NOT_SUPPORTED_ON_ARM64\n");
	seq_puts(m, "USER_SHADOW_STACK:       NOT_SUPPORTED_ON_ARM64\n");
	seq_puts(m, "NOTE:                    x86 CET is Intel-specific. ARM64 uses BTI & PAC in Lab 15.\n");
#endif

	seq_printf(m, "TOTAL_CALLS:             %lu\n", g_call_count);
	seq_printf(m, "LAST_CALL_RESULT:        %s\n",
		   g_last_call_result == 1 ? "LEGIT_SUCCESS" :
		   (g_last_call_result == 2 ? "NOENDBR_EXECUTED" : "NONE"));

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "Supported write commands:\n");
	seq_puts(m, "  echo 'legit'   > /proc/vuln_ibt  (indirect call to target with ENDBR64)\n");
	seq_puts(m, "  echo 'noendbr' > /proc/vuln_ibt  (indirect call to target lacking ENDBR64)\n");
	return 0;
}

static int vuln_ibt_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_ibt_show, NULL);
}

static ssize_t vuln_ibt_write(struct file *file, const char __user *ubuf,
			      size_t count, loff_t *ppos)
{
	char kbuf[32];
	size_t len = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[len - 1] = '\0';

	pr_info("[vuln_ibt] Received write command: '%s'\n", kbuf);

	if (strcmp(kbuf, "1") == 0 || strcmp(kbuf, "legit") == 0) {
		pr_info("[vuln_ibt] Executing legitimate indirect call with ENDBR64 target...\n");
		ibt_dispatch_call(ibt_legit_target, 0x1337);
	} else if (strcmp(kbuf, "2") == 0 || strcmp(kbuf, "noendbr") == 0) {
		pr_info("[vuln_ibt] Executing indirect call to target without ENDBR64...\n");
#if defined(__x86_64__)
#ifdef CONFIG_X86_KERNEL_IBT
		pr_info("[vuln_ibt] CONFIG_X86_KERNEL_IBT is active. Target missing ENDBR triggers #CP if hardware CET supported.\n");
#else
		pr_warn("[vuln_ibt] CONFIG_X86_KERNEL_IBT is disabled. Indirect call proceeds unconditionally.\n");
#endif
#endif
		ibt_dispatch_call((ibt_fn_t)(uintptr_t)ibt_noendbr_target, 0xdeadbeef);
	} else {
		pr_warn("[vuln_ibt] Unknown command '%s'. Use 'legit' or 'noendbr'.\n", kbuf);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops vuln_ibt_proc_ops = {
	.proc_open    = vuln_ibt_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = vuln_ibt_write,
};

static int __init vuln_ibt_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_ibt_proc_ops);
	if (!entry) {
		pr_err("[vuln_ibt] Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("[vuln_ibt] Initialized /proc/%s interface (mode 0666)\n", PROC_FILENAME);
#if defined(__x86_64__)
#ifdef CONFIG_X86_KERNEL_IBT
	pr_info("[vuln_ibt] CONFIG_X86_KERNEL_IBT is ACTIVE\n");
#else
	pr_info("[vuln_ibt] CONFIG_X86_KERNEL_IBT is DISABLED\n");
#endif
#ifdef CONFIG_X86_USER_SHADOW_STACK
	pr_info("[vuln_ibt] CONFIG_X86_USER_SHADOW_STACK is ACTIVE\n");
#else
	pr_info("[vuln_ibt] CONFIG_X86_USER_SHADOW_STACK is DISABLED\n");
#endif
#else
	pr_info("[vuln_ibt] Initialized on non-x86 architecture\n");
#endif
	return 0;
}

static void __exit vuln_ibt_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("[vuln_ibt] Removed /proc/%s\n", PROC_FILENAME);
}

module_init(vuln_ibt_init);
module_exit(vuln_ibt_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Intel CET x86 IBT and Shadow Stack verification driver");
