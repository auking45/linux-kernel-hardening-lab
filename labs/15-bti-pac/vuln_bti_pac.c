// SPDX-License-Identifier: GPL-2.0
/*
 * labs/15-bti-pac/vuln_bti_pac.c
 *
 * Vulnerable target driver for demonstrating ARM64 Control Flow Integrity (CFI):
 *   1. Branch Target Identification (BTI) - Forward-edge CFI (JOP/COP defense)
 *   2. Pointer Authentication Code (PAC) - Backward-edge CFI (ROP defense)
 *
 * Exposes /proc/vuln_bti_pac (mode 0666) with CPU/compiler telemetry and
 * controlled indirect branch and PAC test vectors.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/seq_file.h>
#include <linux/string.h>

#if defined(__aarch64__)
#include <asm/cpufeature.h>
#include <asm/pointer_auth.h>
#define __nobti __attribute__((target("branch-protection=none")))
#else
#define __nobti
#endif

#define PROC_FILENAME "vuln_bti_pac"

/* ARM64 A64 Instruction Encodings */
#define BTI_C_OPCODE     0xd503245fU /* hint #34 (bti c) */
#define PACIASP_OPCODE   0xd503233fU /* hint #25 (paciasp - Key A, signs LR with SP) */
#define AUTIASP_OPCODE   0xd50323bfU /* hint #29 (autiasp - Key A, authenticates LR) */

typedef void (*bti_fn_t)(unsigned long arg);

static unsigned long g_call_count = 0;
static int g_last_call_result = 0; /* 0: None, 1: Legit OK, 2: Missing BTI Hijacked, 3: PAC Corrupt Tested */
static unsigned long g_last_pac_signed = 0;
static unsigned long g_last_pac_tampered = 0;
static unsigned long g_last_pac_authed = 0;

/* Legitimate indirect call target: Contains paciasp or bti c when compiled with branch protection */
static noinline void bti_legit_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 1;
	pr_info("[vuln_bti_pac] [+] Legitimate target executed: val=0x%lx (call_count=%lu)\n",
		val, g_call_count);
}

/*
 * Deliberately un-instrumented target:
 * On ARM64 with BTI enabled, calling this function via indirect branch (BLR)
 * violates forward-edge CFI because the entry instruction is not a valid BTI landing pad.
 */
static noinline __nobti void bti_nobti_target(unsigned long val)
{
	g_call_count++;
	g_last_call_result = 2;
	pr_warn("[vuln_bti_pac] [!] VULNERABLE: Function without BTI landing pad executed!\n");
	pr_warn("[vuln_bti_pac] [!] Control flow redirected to non-BTI target: val=0x%lx\n", val);
}

/* Indirect call dispatcher */
static noinline void bti_dispatch_call(bti_fn_t func_ptr, unsigned long arg)
{
	pr_info("[vuln_bti_pac] Dispatching indirect call to %px with arg 0x%lx...\n",
		(void *)func_ptr, arg);
	func_ptr(arg);
}

/* PAC Sign & Authenticate Verification */
static void run_pac_test(void)
{
#if defined(__aarch64__)
	unsigned long orig_ptr = (unsigned long)bti_legit_target;
	unsigned long signed_ptr = 0;
	unsigned long authed_ptr = 0;
	unsigned long tampered_ptr = 0;

	/* Sign LR with Key A and SP modifier */
	asm volatile(
		"mov x30, %[in]\n\t"
		"hint #25\n\t" /* paciasp */
		"mov %[out], x30\n\t"
		: [out] "=r" (signed_ptr)
		: [in] "r" (orig_ptr)
		: "x30"
	);

	/* Tamper with pointer bits (simulate ROP / pointer forgery) */
	tampered_ptr = signed_ptr ^ (1UL << 20);

	/* Authenticate tampered pointer */
	asm volatile(
		"mov x30, %[in]\n\t"
		"hint #29\n\t" /* autiasp */
		"mov %[out], x30\n\t"
		: [out] "=r" (authed_ptr)
		: [in] "r" (tampered_ptr)
		: "x30"
	);

	g_last_pac_signed = signed_ptr;
	g_last_pac_tampered = tampered_ptr;
	g_last_pac_authed = authed_ptr;
	g_call_count++;
	g_last_call_result = 3;

	pr_info("[vuln_bti_pac] [PAC Test] Orig:     0x%016lx\n", orig_ptr);
	pr_info("[vuln_bti_pac] [PAC Test] Signed:   0x%016lx\n", signed_ptr);
	pr_info("[vuln_bti_pac] [PAC Test] Tampered: 0x%016lx\n", tampered_ptr);
	pr_info("[vuln_bti_pac] [PAC Test] Authed:   0x%016lx\n", authed_ptr);

	if (signed_ptr != orig_ptr) {
		pr_info("[vuln_bti_pac] [PAC Test] Hardware PAC signature detected in high bits!\n");
	}
	if (authed_ptr != orig_ptr) {
		pr_info("[vuln_bti_pac] [PAC Test] PAC mismatch detected! Pointer mangled to prevent execution.\n");
	}
#else
	g_call_count++;
	g_last_call_result = 3;
	pr_info("[vuln_bti_pac] PAC test skipped on non-ARM64 architecture.\n");
#endif
}

static int vuln_bti_pac_show(struct seq_file *m, void *v)
{
	u32 legit_first_insn = 0;
	u32 nobti_first_insn = 0;
	bool hw_bti_user = false;
	bool hw_bti_kernel = false;
	bool hw_pac_addr = false;
	bool hw_pac_generic = false;

#if defined(__aarch64__)
	copy_from_kernel_nofault(&legit_first_insn, (void *)bti_legit_target, sizeof(legit_first_insn));
	copy_from_kernel_nofault(&nobti_first_insn, (void *)bti_nobti_target, sizeof(nobti_first_insn));

	hw_bti_user = system_supports_bti();
	hw_bti_kernel = system_supports_bti_kernel();
	hw_pac_addr = system_supports_address_auth();
	hw_pac_generic = system_supports_generic_auth();
#endif

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "  Linux Kernel Hardening Lab - ARM64 BTI & PAC Telemetry\n");
	seq_puts(m, "=========================================================\n");

#if defined(__aarch64__)
	seq_puts(m, "TARGET_ARCH:             arm64\n");
#ifdef CONFIG_ARM64_PTR_AUTH
	seq_puts(m, "CONFIG_ARM64_PTR_AUTH:   ENABLED\n");
#else
	seq_puts(m, "CONFIG_ARM64_PTR_AUTH:   DISABLED\n");
#endif

#ifdef CONFIG_ARM64_PTR_AUTH_KERNEL
	seq_puts(m, "CONFIG_ARM64_PTR_AUTH_K: ENABLED\n");
#else
	seq_puts(m, "CONFIG_ARM64_PTR_AUTH_K: DISABLED\n");
#endif

#ifdef CONFIG_ARM64_BTI
	seq_puts(m, "CONFIG_ARM64_BTI:        ENABLED\n");
#else
	seq_puts(m, "CONFIG_ARM64_BTI:        DISABLED\n");
#endif

#ifdef CONFIG_ARM64_BTI_KERNEL
	seq_puts(m, "CONFIG_ARM64_BTI_KERNEL: ENABLED\n");
#else
	seq_puts(m, "CONFIG_ARM64_BTI_KERNEL: DISABLED\n");
#endif

	seq_printf(m, "HW_BTI_USER_SUPPORT:     %s\n", hw_bti_user ? "YES" : "NO");
	seq_printf(m, "HW_BTI_KERNEL_SUPPORT:   %s\n", hw_bti_kernel ? "YES" : "NO");
	seq_printf(m, "HW_PAC_ADDR_SUPPORT:     %s\n", hw_pac_addr ? "YES" : "NO");
	seq_printf(m, "HW_PAC_GENERIC_SUPPORT:  %s\n", hw_pac_generic ? "YES" : "NO");

	seq_printf(m, "LEGIT_TARGET_ADDR:       %px (Insn: 0x%08x%s%s)\n",
		   (void *)bti_legit_target, legit_first_insn,
		   legit_first_insn == PACIASP_OPCODE ? " [PACIASP/BTI]" : "",
		   legit_first_insn == BTI_C_OPCODE ? " [BTI_C]" : "");
	seq_printf(m, "NOBTI_TARGET_ADDR:       %px (Insn: 0x%08x%s)\n",
		   (void *)bti_nobti_target, nobti_first_insn,
		   (nobti_first_insn != PACIASP_OPCODE && nobti_first_insn != BTI_C_OPCODE) ? " [NO_BTI]" : " [INSTRUMENTED]");

	seq_printf(m, "COMPILER_BTI_DETECTED:   %s\n",
		   (legit_first_insn == PACIASP_OPCODE || legit_first_insn == BTI_C_OPCODE) ? "YES" : "NO");
	seq_printf(m, "COMPILER_PAC_DETECTED:   %s\n",
		   legit_first_insn == PACIASP_OPCODE ? "YES (paciasp 0xd503233f)" : "NO");

#else /* Non-ARM64 architecture (e.g. x86_64) */
	seq_puts(m, "TARGET_ARCH:             x86_64 (Non-ARM64)\n");
	seq_puts(m, "ARM64_BTI:               NOT_SUPPORTED_ON_X86\n");
	seq_puts(m, "ARM64_PTR_AUTH:          NOT_SUPPORTED_ON_X86\n");
	seq_puts(m, "NOTE:                    ARM64 BTI & PAC are ARMv8.3/v8.5 features. x86 uses Intel CET in Lab 14.\n");
#endif

	seq_printf(m, "TOTAL_CALLS:             %lu\n", g_call_count);
	seq_printf(m, "LAST_CALL_RESULT:        %s\n",
		   g_last_call_result == 1 ? "LEGIT_SUCCESS" :
		   (g_last_call_result == 2 ? "NOBTI_EXECUTED" :
		   (g_last_call_result == 3 ? "PAC_CORRUPT_TESTED" : "NONE")));

	if (g_last_pac_signed) {
		seq_printf(m, "LAST_PAC_SIGNED:         0x%016lx\n", g_last_pac_signed);
		seq_printf(m, "LAST_PAC_TAMPERED:       0x%016lx\n", g_last_pac_tampered);
		seq_printf(m, "LAST_PAC_AUTHED:         0x%016lx\n", g_last_pac_authed);
	}

	seq_puts(m, "=========================================================\n");
	seq_puts(m, "Supported write commands:\n");
	seq_puts(m, "  echo 'legit'       > /proc/vuln_bti_pac  (indirect call to target with BTI/PAC)\n");
	seq_puts(m, "  echo 'nobti'       > /proc/vuln_bti_pac  (indirect call to target lacking BTI)\n");
	seq_puts(m, "  echo 'pac_corrupt' > /proc/vuln_bti_pac  (sign pointer, tamper bits, authenticate)\n");
	return 0;
}

static int vuln_bti_pac_open(struct inode *inode, struct file *file)
{
	return single_open(file, vuln_bti_pac_show, NULL);
}

static ssize_t vuln_bti_pac_write(struct file *file, const char __user *ubuf,
				  size_t count, loff_t *ppos)
{
	char kbuf[32];
	size_t len = min(count, sizeof(kbuf) - 1);

	if (copy_from_user(kbuf, ubuf, len))
		return -EFAULT;

	kbuf[len] = '\0';
	if (len > 0 && kbuf[len - 1] == '\n')
		kbuf[len - 1] = '\0';

	pr_info("[vuln_bti_pac] Received write command: '%s'\n", kbuf);

	if (strcmp(kbuf, "1") == 0 || strcmp(kbuf, "legit") == 0) {
		pr_info("[vuln_bti_pac] Executing legitimate indirect call with BTI/PAC target...\n");
		bti_dispatch_call(bti_legit_target, 0x1337);
	} else if (strcmp(kbuf, "2") == 0 || strcmp(kbuf, "nobti") == 0) {
		pr_info("[vuln_bti_pac] Executing indirect call to target without BTI...\n");
#if defined(__aarch64__)
#ifdef CONFIG_ARM64_BTI_KERNEL
		pr_info("[vuln_bti_pac] CONFIG_ARM64_BTI_KERNEL is active. Target missing BTI triggers exception if CPU supports BTI.\n");
#else
		pr_warn("[vuln_bti_pac] CONFIG_ARM64_BTI_KERNEL is disabled. Indirect call proceeds unconditionally.\n");
#endif
#endif
		bti_dispatch_call((bti_fn_t)(uintptr_t)bti_nobti_target, 0xdeadbeef);
	} else if (strcmp(kbuf, "3") == 0 || strcmp(kbuf, "pac_corrupt") == 0) {
		pr_info("[vuln_bti_pac] Executing PAC pointer signing and tampering test...\n");
		run_pac_test();
	} else {
		pr_warn("[vuln_bti_pac] Unknown command '%s'. Use 'legit', 'nobti', or 'pac_corrupt'.\n", kbuf);
		return -EINVAL;
	}

	return count;
}

static const struct proc_ops vuln_bti_pac_proc_ops = {
	.proc_open    = vuln_bti_pac_open,
	.proc_read    = seq_read,
	.proc_lseek   = seq_lseek,
	.proc_release = single_release,
	.proc_write   = vuln_bti_pac_write,
};

static int __init vuln_bti_pac_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_bti_pac_proc_ops);
	if (!entry) {
		pr_err("[vuln_bti_pac] Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("[vuln_bti_pac] Initialized /proc/%s interface (mode 0666)\n", PROC_FILENAME);
#if defined(__aarch64__)
#ifdef CONFIG_ARM64_PTR_AUTH
	pr_info("[vuln_bti_pac] CONFIG_ARM64_PTR_AUTH is ACTIVE\n");
#else
	pr_info("[vuln_bti_pac] CONFIG_ARM64_PTR_AUTH is DISABLED\n");
#endif
#ifdef CONFIG_ARM64_BTI
	pr_info("[vuln_bti_pac] CONFIG_ARM64_BTI is ACTIVE\n");
#else
	pr_info("[vuln_bti_pac] CONFIG_ARM64_BTI is DISABLED\n");
#endif
#else
	pr_info("[vuln_bti_pac] Initialized on non-ARM64 architecture\n");
#endif
	return 0;
}

static void __exit vuln_bti_pac_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("[vuln_bti_pac] Removed /proc/%s\n", PROC_FILENAME);
}

module_init(vuln_bti_pac_init);
module_exit(vuln_bti_pac_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("ARM64 BTI and PAC verification driver");

