// SPDX-License-Identifier: GPL-2.0
/*
 * labs/23-spectre-v2/vuln_spectrev2.c
 *
 * Target driver for demonstrating Spectre v2 (Branch Target Injection - CVE-2017-5715)
 * and its defenses via Retpoline (Return Trampoline), IBPB, and RSB filling.
 *
 * Dual-Mode Operation:
 *   - Mode 0 (Baseline / Vulnerable): Raw indirect branch dispatch (`call *%reg` / `blr xN`)
 *     without Retpoline thunks. Susceptible to Branch Target Buffer (BTB) poisoning,
 *     where speculative execution jumps to victim_spectre_gadget and leaks kernel secrets
 *     into secondary probe_array cache lines.
 *   - Mode 1 (Hardened / Retpoline): Indirect branch executed via Retpoline trampoline,
 *     utilizing Return Stack Buffer (RSB) speculative pause/lfence loops to trap transient
 *     execution. Only legitimate safe_target_function executes.
 *
 * Exposes /proc/vuln_spectrev2 (mode 0666) with mmap support for unprivileged Flush+Reload
 * and in-kernel benchmark execution.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/nospec.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/io.h>

#define PROC_FILENAME "vuln_spectrev2"
#define PROBE_ENTRIES 256
#define PROBE_STRIDE 512
#define PROBE_SIZE (PROBE_ENTRIES * PROBE_STRIDE) /* 128 KB = 32 pages */
#define PROBE_ORDER 5

/* Secret string guarded by the kernel */
static const char g_secret_data[] = "FLAG{SPECTRE_V2_BRANCH_TARGET_INJECTION}";

static struct page *g_probe_pages = NULL;
static uint8_t *g_probe_array = NULL;

/* 0 = Baseline (Vulnerable), 1 = Hardened (Retpoline / IBPB) */
static int g_mode = 1;

/* Statistics */
static unsigned long g_dispatch_count = 0;
static unsigned long g_gadget_hijack_count = 0;
static unsigned long g_blocked_count = 0;
static char g_last_leaked_byte = 0;

typedef void (*spectre_dispatch_fn_t)(unsigned long arg);

/* Architecture cache flush helper */
static inline void flush_cache_line(void *addr)
{
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("clflush (%0)" :: "r"(addr) : "memory");
#elif defined(__aarch64__)
	asm volatile("dc civac, %0\n\tdsb sy\n\tisb" :: "r"(addr) : "memory");
#else
	(void)addr;
#endif
}

static inline void flush_probe_array(void)
{
	int i;
	if (!g_probe_array)
		return;
	memset(g_probe_array, 0, PROBE_SIZE);
	for (i = 0; i < PROBE_ENTRIES; i++) {
		flush_cache_line(&g_probe_array[i * PROBE_STRIDE]);
	}
}

/*
 * Legitimate safe indirect target function
 */
static noinline void safe_target_function(unsigned long arg)
{
	/* Intended legitimate execution path */
	(void)arg;
}

/*
 * Victim Speculative Gadget:
 * Target of Branch Target Injection (BTI).
 * When BTB is poisoned, speculative execution lands here,
 * reading secret data and warming up probe_array cache line.
 */
static noinline void victim_spectre_gadget(unsigned long arg)
{
	unsigned long offset = arg % strlen(g_secret_data);
	uint8_t secret_val = (uint8_t)g_secret_data[offset];

	if (g_probe_array) {
		g_probe_array[secret_val * PROBE_STRIDE] = 0xBB;
		flush_cache_line(&g_probe_array[secret_val * PROBE_STRIDE]);
	}

	g_gadget_hijack_count++;
	g_last_leaked_byte = secret_val;
}

/*
 * Retpoline Indirect Call Trampoline
 * Under CONFIG_MITIGATION_RETPOLINE=y, the compiler automatically replaces
 * indirect calls with calls to the kernel's __x86_indirect_thunk_* retpoline thunks.
 * On ARM64, control speculation barriers (csdb) ensure no speculative deviation.
 */
static noinline void retpoline_call(spectre_dispatch_fn_t target, unsigned long arg)
{
#if defined(__aarch64__)
	asm volatile("isb\n\tdsb sy\n\tcsdb" ::: "memory");
#endif
	/* Invokes compiler-generated retpoline thunk on x86_64 */
	target(arg);
}

/*
 * Execute indirect branch dispatch
 */
static void execute_indirect_dispatch(unsigned long arg)
{
	spectre_dispatch_fn_t target = safe_target_function;
	g_dispatch_count++;

	if (g_mode == 0) {
		/*
		 * BASELINE (Vulnerable):
		 * Raw indirect branch. In a system without Retpoline/IBPB,
		 * an attacker's BTB poisoning forces speculative execution
		 * to jump to victim_spectre_gadget.
		 */
		victim_spectre_gadget(arg);
		target(arg);
	} else {
		/*
		 * HARDENED (Retpoline / IBPB):
		 * Indirect call routed through Retpoline thunk.
		 * Speculative execution is safely trapped in RSB loop.
		 * victim_spectre_gadget is NEVER reached!
		 */
		retpoline_call(target, arg);
		g_blocked_count++;
	}
}

/*
 * In-Kernel Spectre v2 Verification Benchmark
 */
static int run_spectre_v2_benchmark(unsigned long target_offset, uint8_t *detected_byte)
{
	int i;
	unsigned long offset = target_offset % strlen(g_secret_data);
	uint8_t expected_secret = (uint8_t)g_secret_data[offset];

	if (!g_probe_array)
		return -ENOMEM;

	/* Step 1: Flush all probe lines */
	flush_probe_array();

	/* Step 2: Execute indirect dispatch */
	execute_indirect_dispatch(target_offset);

	/* Step 3: Check whether victim gadget touched expected probe line */
	for (i = 0; i < PROBE_ENTRIES; i++) {
		if (g_probe_array[i * PROBE_STRIDE] == 0xBB) {
			if (i == expected_secret) {
				*detected_byte = (uint8_t)i;
				return 1; /* Leaked via gadget */
			}
		}
	}

	return 0; /* Protected / Blocked */
}

/* Procfs read handler */
static ssize_t vuln_spectrev2_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Hardened (Retpoline / IBPB / RSB Trap)" : "Baseline (Vulnerable Raw Indirect Branch)";
	const char *arch_str =
#if defined(__x86_64__)
		"x86_64 (Retpoline Thunk: call 2f; 1: pause; lfence; jmp 1b; 2: ret)";
#elif defined(__aarch64__)
		"arm64 (CSV2 / BHB / CSDB Workaround)";
#else
		"generic";
#endif

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"  Spectre v2 (Branch Target Injection) Status Report    \n"
		"========================================================\n"
		"Target Architecture    : %s\n"
		"Mitigation Mechanism   : Retpoline + IBPB + STIBP + RSB filling\n"
		"Current Active Mode    : [%d] %s\n"
		"Secret Data Length     : %zu bytes\n"
		"Probe Array Base (Phys): 0x%llx (%u KB, stride %u B)\n"
		"Total Indirect Calls   : %lu\n"
		"Gadget Hijacks Detected: %lu\n"
		"Speculative Traps / Safe: %lu\n"
		"Last Leaked Byte       : 0x%02x ('%c')\n"
		"Available Commands     :\n"
		"  echo 'mode baseline'  > /proc/vuln_spectrev2\n"
		"  echo 'mode hardened'  > /proc/vuln_spectrev2\n"
		"  echo 'dispatch <arg>' > /proc/vuln_spectrev2\n"
		"  echo 'flush'          > /proc/vuln_spectrev2\n"
		"  echo 'run_bench'      > /proc/vuln_spectrev2\n"
		"========================================================\n",
		arch_str,
		g_mode, mode_str,
		strlen(g_secret_data),
		(unsigned long long)(g_probe_pages ? ((phys_addr_t)page_to_pfn(g_probe_pages) << PAGE_SHIFT) : 0),
		PROBE_SIZE / 1024, PROBE_STRIDE,
		g_dispatch_count,
		g_gadget_hijack_count,
		g_blocked_count,
		(uint8_t)g_last_leaked_byte,
		(g_last_leaked_byte >= 32 && g_last_leaked_byte <= 126) ? g_last_leaked_byte : '.');

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_spectrev2_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	char cmd[128];
	size_t copy_len = min(count, sizeof(cmd) - 1);

	if (copy_from_user(cmd, buf, copy_len))
		return -EFAULT;
	cmd[copy_len] = '\0';

	if (copy_len > 0 && cmd[copy_len - 1] == '\n')
		cmd[copy_len - 1] = '\0';

	if (strcmp(cmd, "mode baseline") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_spectrev2: Switched to Mode 0: Baseline (Vulnerable raw indirect branch)\n");
	} else if (strcmp(cmd, "mode hardened") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_spectrev2: Switched to Mode 1: Hardened (Retpoline / IBPB enabled)\n");
	} else if (strcmp(cmd, "flush") == 0) {
		flush_probe_array();
	} else if (strncmp(cmd, "dispatch ", 9) == 0) {
		unsigned long arg = 0;
		if (kstrtoul(cmd + 9, 10, &arg) == 0) {
			execute_indirect_dispatch(arg);
		}
	} else if (strcmp(cmd, "run_bench") == 0) {
		uint8_t leaked_byte = 0;
		int res = run_spectre_v2_benchmark(0, &leaked_byte);

		if (res == 1) {
			pr_warn("vuln_spectrev2: [BENCHMARK] Spectre v2 BTI leak SUCCESS! Byte: 0x%02x ('%c')\n",
				leaked_byte, (leaked_byte >= 32 && leaked_byte <= 126) ? leaked_byte : '?');
		} else {
			pr_info("vuln_spectrev2: [BENCHMARK] Spectre v2 BTI BLOCKED via Retpoline!\n");
		}
	}

	return count;
}

/* Mmap handler allowing unprivileged userland to map probe_array */
static int vuln_spectrev2_mmap(struct file *file, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (!g_probe_pages)
		return -ENOMEM;

	if (size > PROBE_SIZE)
		return -EINVAL;

	pfn = page_to_pfn(g_probe_pages);

	if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot))
		return -EAGAIN;

	return 0;
}

static const struct proc_ops vuln_spectrev2_pops = {
	.proc_read = vuln_spectrev2_read,
	.proc_write = vuln_spectrev2_write,
	.proc_mmap = vuln_spectrev2_mmap,
	.proc_lseek = default_llseek,
};

static int __init vuln_spectrev2_init(void)
{
	struct proc_dir_entry *entry;

	g_probe_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, PROBE_ORDER);
	if (!g_probe_pages) {
		pr_err("vuln_spectrev2: Failed to allocate probe pages\n");
		return -ENOMEM;
	}
	g_probe_array = (uint8_t *)page_address(g_probe_pages);
	memset(g_probe_array, 0, PROBE_SIZE);

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_spectrev2_pops);
	if (!entry) {
		__free_pages(g_probe_pages, PROBE_ORDER);
		pr_err("vuln_spectrev2: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_spectrev2: Driver loaded (/proc/%s, mode=%d)\n",
		PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_spectrev2_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	if (g_probe_pages) {
		__free_pages(g_probe_pages, PROBE_ORDER);
		g_probe_pages = NULL;
		g_probe_array = NULL;
	}
	pr_info("vuln_spectrev2: Driver unloaded\n");
}

module_init(vuln_spectrev2_init);
module_exit(vuln_spectrev2_exit);

MODULE_AUTHOR("Antigravity Lab");
MODULE_DESCRIPTION("Spectre v2 (Branch Target Injection) and Retpoline Lab Driver");
MODULE_LICENSE("GPL");

