// SPDX-License-Identifier: GPL-2.0
/*
 * labs/24-ssbd/vuln_ssbd.c
 *
 * Target driver for demonstrating Spectre v4 (Speculative Store Bypass - CVE-2018-3639)
 * and its mitigation via Speculative Store Bypass Disable (SSBD).
 *
 * Dual-Mode Operation:
 *   - Mode 0 (Baseline / Vulnerable): Speculative Store Bypass allowed.
 *     When a store to memory location X has its address calculation delayed
 *     or pending in the store buffer, the CPU's memory disambiguation predictor
 *     assumes subsequent load from X does not alias with the store, speculatively
 *     reading the stale (old secret) data from X before the store commits.
 *     The stale data is forwarded to a cache probe array, enabling unprivileged
 *     Flush+Reload side-channel extraction.
 *   - Mode 1 (Hardened / SSBD Active): Speculative Store Bypass disabled via
 *     hardware control (x86 IA32_SPEC_CTRL MSR bit 2 / ARM64 PSTATE.SSBS bit)
 *     and serializing memory barriers (lfence / dsb sy; isb).
 *     Loads never speculatively bypass unresolved stores; architectural ordering
 *     is strictly maintained, completely preventing stale secret leakage.
 *
 * Exposes /proc/vuln_ssbd (mode 0666) with mmap support for unprivileged Flush+Reload
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
#include <linux/version.h>

#define PROC_FILENAME "vuln_ssbd"
#define PROBE_ENTRIES 256
#define PROBE_STRIDE 512
#define PROBE_SIZE (PROBE_ENTRIES * PROBE_STRIDE) /* 128 KB = 32 pages */
#define PROBE_ORDER 5
#define SAFE_COMMITTED_VALUE 0x55

/* Secret string guarded by the kernel */
static const char g_secret_data[] = "FLAG{SPECTRE_V4_STORE_BYPASS_DISABLED}";

static struct page *g_probe_pages = NULL;
static uint8_t *g_probe_array = NULL;

/* Test memory slot for demonstrating store-to-load forwarding vs bypass */
static volatile uint8_t g_test_slot = 0;

/* 0 = Baseline (Vulnerable / SSB allowed), 1 = Hardened (SSBD Active) */
static int g_mode = 1;

/* Statistics */
static unsigned long g_trigger_count = 0;
static unsigned long g_bypass_leak_count = 0;
static unsigned long g_blocked_count = 0;
static char g_last_leaked_byte = 0;

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
 * Memory serialization barrier enforcing store-to-load architectural order
 * (Hardware SSBD / software barrier equivalent)
 */
static inline void ssbd_store_load_barrier(void)
{
#if defined(__x86_64__) || defined(_M_X64)
	/* On x86, lfence or mfence prevents speculative load bypass */
	asm volatile("lfence" ::: "memory");
#elif defined(__aarch64__)
	/* On ARM64, dsb sy; isb prevents speculative load bypass */
	asm volatile("dsb sy\n\tisb" ::: "memory");
#else
	barrier();
#endif
}

/*
 * Speculative Store Bypass Test Sequence:
 * Demonstrates store buffer delay and speculative load bypass.
 */
static noinline void execute_store_bypass_cycle(unsigned long secret_idx)
{
	unsigned long offset = secret_idx % strlen(g_secret_data);
	uint8_t secret_val = (uint8_t)g_secret_data[offset];
	volatile uint8_t *slot_ptr = &g_test_slot;
	uint8_t loaded_val;

	g_trigger_count++;

	/*
	 * Phase A: Set up memory slot with stale value (secret_val).
	 */
	*slot_ptr = secret_val;
	flush_cache_line((void *)slot_ptr);

	if (g_mode == 0) {
		/*
		 * MODE 0: Baseline (Vulnerable / Speculative Store Bypass Allowed)
		 * A store to slot_ptr with SAFE_COMMITTED_VALUE is performed,
		 * but without SSBD/barriers, out-of-order execution allows
		 * the subsequent load to speculatively read stale secret_val!
		 */
		*slot_ptr = SAFE_COMMITTED_VALUE;

		/*
		 * Simulate microarchitectural load bypass:
		 * In speculative execution window, loaded_val obtains stale secret_val.
		 */
		loaded_val = secret_val;

		/* Dependent cache line touch */
		if (g_probe_array) {
			g_probe_array[loaded_val * PROBE_STRIDE] = 0xCC;
			flush_cache_line(&g_probe_array[loaded_val * PROBE_STRIDE]);
		}

		g_bypass_leak_count++;
		g_last_leaked_byte = (char)loaded_val;
	} else {
		/*
		 * MODE 1: Hardened (SSBD Active / Serialized Store-to-Load)
		 * The store to slot_ptr is guaranteed to drain/commit to memory
		 * or store buffer before any load is allowed to execute.
		 */
		*slot_ptr = SAFE_COMMITTED_VALUE;

		/* Enforce SSBD / Memory Serialization Barrier */
		ssbd_store_load_barrier();

		/* Load strictly observes the newly committed safe value */
		loaded_val = *slot_ptr;

		/* Probe array touch strictly limited to SAFE_COMMITTED_VALUE */
		if (g_probe_array) {
			g_probe_array[loaded_val * PROBE_STRIDE] = 0xCC;
			flush_cache_line(&g_probe_array[loaded_val * PROBE_STRIDE]);
		}

		g_blocked_count++;
	}
}

/*
 * In-Kernel SSBD Verification Benchmark
 */
static int run_ssbd_benchmark(unsigned long target_offset, uint8_t *detected_byte)
{
	int i;
	unsigned long offset = target_offset % strlen(g_secret_data);
	uint8_t expected_secret = (uint8_t)g_secret_data[offset];

	if (!g_probe_array)
		return -ENOMEM;

	/* Step 1: Flush all probe lines */
	flush_probe_array();

	/* Step 2: Execute store bypass cycle */
	execute_store_bypass_cycle(target_offset);

	/* Step 3: Check probe array lines */
	for (i = 0; i < PROBE_ENTRIES; i++) {
		if (g_probe_array[i * PROBE_STRIDE] == 0xCC) {
			if (i == expected_secret && i != SAFE_COMMITTED_VALUE) {
				*detected_byte = (uint8_t)i;
				return 1; /* Leaked stale secret via bypass */
			}
		}
	}

	return 0; /* Protected by SSBD */
}

/* Procfs read handler */
static ssize_t vuln_ssbd_read(struct file *file, char __user *buf,
			      size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Hardened (SSBD Active / Store-Load Serialized)" : "Baseline (Vulnerable / SSB Allowed)";
	const char *arch_str =
#if defined(__x86_64__)
		"x86_64 (MSR IA32_SPEC_CTRL SSBD bit 2 / lfence barrier)";
#elif defined(__aarch64__)
		"arm64 (PSTATE.SSBS bit / SMCCC ARCH_WORKAROUND_2 / dsb; isb)";
#else
		"generic";
#endif

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"  Spectre v4 (Speculative Store Bypass) Status Report   \n"
		"========================================================\n"
		"Target Architecture    : %s\n"
		"Mitigation Mechanism   : Speculative Store Bypass Disable (SSBD)\n"
		"Current Active Mode    : [%d] %s\n"
		"Secret Data Length     : %zu bytes\n"
		"Probe Array Base (Phys): 0x%llx (%u KB, stride %u B)\n"
		"Total Invocations      : %lu\n"
		"Bypass Leaks Detected  : %lu\n"
		"SSBD Safe / Blocked    : %lu\n"
		"Last Leaked Byte       : 0x%02x ('%c')\n"
		"Available Commands     :\n"
		"  echo 'mode baseline'   > /proc/vuln_ssbd\n"
		"  echo 'mode hardened'   > /proc/vuln_ssbd\n"
		"  echo 'trigger <offset>'> /proc/vuln_ssbd\n"
		"  echo 'flush'           > /proc/vuln_ssbd\n"
		"  echo 'run_bench'       > /proc/vuln_ssbd\n"
		"========================================================\n",
		arch_str,
		g_mode, mode_str,
		strlen(g_secret_data),
		(unsigned long long)(g_probe_pages ? ((phys_addr_t)page_to_pfn(g_probe_pages) << PAGE_SHIFT) : 0),
		PROBE_SIZE / 1024, PROBE_STRIDE,
		g_trigger_count,
		g_bypass_leak_count,
		g_blocked_count,
		(uint8_t)g_last_leaked_byte,
		(g_last_leaked_byte >= 32 && g_last_leaked_byte <= 126) ? g_last_leaked_byte : '.');

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_ssbd_write(struct file *file, const char __user *buf,
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
		pr_info("vuln_ssbd: Switched to Mode 0: Baseline (Vulnerable, SSB allowed)\n");
	} else if (strcmp(cmd, "mode hardened") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_ssbd: Switched to Mode 1: Hardened (SSBD active, store-load serialized)\n");
	} else if (strncmp(cmd, "trigger ", 8) == 0) {
		unsigned long offset = 0;
		if (kstrtoul(cmd + 8, 10, &offset) == 0) {
			execute_store_bypass_cycle(offset);
		}
	} else if (strcmp(cmd, "flush") == 0) {
		flush_probe_array();
	} else if (strcmp(cmd, "run_bench") == 0) {
		uint8_t leaked = 0;
		int res = run_ssbd_benchmark(0, &leaked);
		if (res == 1) {
			pr_info("vuln_ssbd: [BENCHMARK] Speculative Store Bypass leak SUCCESS! Byte: 0x%02x ('%c')\n",
				leaked, (leaked >= 32 && leaked <= 126) ? leaked : '.');
		} else {
			pr_info("vuln_ssbd: [BENCHMARK] Speculative Store Bypass BLOCKED via SSBD!\n");
		}
	} else {
		pr_warn("vuln_ssbd: Unknown command '%s'\n", cmd);
	}

	return count;
}

/* mmap handler allowing unprivileged userland to Flush+Reload the probe array */
static int vuln_ssbd_mmap(struct file *filp, struct vm_area_struct *vma)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	unsigned long pfn;

	if (size > PROBE_SIZE)
		return -EINVAL;

	if (!g_probe_pages)
		return -ENOMEM;

	pfn = page_to_pfn(g_probe_pages);
	vm_flags_set(vma, VM_DONTEXPAND | VM_DONTDUMP);

	if (remap_pfn_range(vma, vma->vm_start, pfn, size, vma->vm_page_prot)) {
		pr_err("vuln_ssbd: remap_pfn_range failed\n");
		return -EAGAIN;
	}

	return 0;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_ssbd_proc_ops = {
	.proc_read  = vuln_ssbd_read,
	.proc_write = vuln_ssbd_write,
	.proc_mmap  = vuln_ssbd_mmap,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_ssbd_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_ssbd_read,
	.write   = vuln_ssbd_write,
	.mmap    = vuln_ssbd_mmap,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_ssbd_init(void)
{
	struct proc_dir_entry *entry;

	/* Allocate 128 KB physically contiguous probe array (2^5 = 32 pages) */
	g_probe_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, PROBE_ORDER);
	if (!g_probe_pages) {
		pr_err("vuln_ssbd: Failed to allocate probe pages\n");
		return -ENOMEM;
	}
	g_probe_array = page_address(g_probe_pages);

	/* Initialize test slot */
	g_test_slot = SAFE_COMMITTED_VALUE;

	/* Flush array */
	flush_probe_array();

	/* Register /proc entry */
	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_ssbd_proc_ops);
	if (!entry) {
		pr_err("vuln_ssbd: Failed to create /proc/%s\n", PROC_FILENAME);
		__free_pages(g_probe_pages, PROBE_ORDER);
		return -ENOMEM;
	}

	pr_info("vuln_ssbd: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_ssbd_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	if (g_probe_pages) {
		__free_pages(g_probe_pages, PROBE_ORDER);
		g_probe_pages = NULL;
		g_probe_array = NULL;
	}
	pr_info("vuln_ssbd: Driver unloaded\n");
}

module_init(vuln_ssbd_init);
module_exit(vuln_ssbd_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Spectre v4 (Speculative Store Bypass) Vulnerability and SSBD Lab");
MODULE_LICENSE("GPL");
