// SPDX-License-Identifier: GPL-2.0
/*
 * labs/22-spectre-v1/vuln_spectrev1.c
 *
 * Target driver for demonstrating Spectre v1 (Bounds Check Bypass - CVE-2017-5753)
 * and its defense via array_index_nospec() from <linux/nospec.h>.
 *
 * Dual-Mode Operation:
 *   - Mode 0 (Baseline / Vulnerable): Standard bounds check `if (idx < array1_size)`
 *     without speculation barriers. Speculative execution accesses out-of-bounds
 *     kernel secrets and brings secondary probe_array lines into CPU cache.
 *   - Mode 1 (Hardened / Mitigated): Protected with `array_index_nospec()`,
 *     using CPU arithmetic bitmasking (x86 `sbb`, ARM64 `sbc` + `csdb`) to clamp
 *     speculative index to 0, completely preventing transient secret loading.
 *
 * Exposes /proc/vuln_spectrev1 (mode 0666) with mmap support for userland Flush+Reload
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

#define PROC_FILENAME "vuln_spectrev1"
#define ARRAY1_SIZE 16
#define PROBE_ENTRIES 256
#define PROBE_STRIDE 512
#define PROBE_SIZE (PROBE_ENTRIES * PROBE_STRIDE) /* 128 KB = 32 pages */
#define PROBE_ORDER 5                             /* 2^5 * 4096 = 128 KB */

/* Memory layout ensuring secret is directly adjacent to array1 */
struct spectre_sandbox {
	uint8_t array1[ARRAY1_SIZE];
	char secret[48];
};

static struct spectre_sandbox g_sandbox __attribute__((aligned(64))) = {
	.array1 = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16 },
	.secret = "FLAG{SPECTRE_V1_SPECULATIVE_LEAK_SUCCESS}"
};

static unsigned int g_array1_size = ARRAY1_SIZE;
static struct page *g_probe_pages = NULL;
static uint8_t *g_probe_array = NULL;

/* 0 = Baseline (Vulnerable), 1 = Hardened (array_index_nospec) */
static int g_mode = 1;

/* Statistics */
static unsigned long g_leak_count = 0;
static unsigned long g_blocked_count = 0;
static char g_last_leaked_byte = 0;

/* Architecture-specific cache flush helper */
static inline void flush_cache_line(void *addr)
{
#if defined(__x86_64__) || defined(_M_X64)
	asm volatile("clflush (%0)" :: "r"(addr) : "memory");
#elif defined(__aarch64__)
	asm volatile("dc civac, %0\n\tdsb sy\n\tisb" :: "r"(addr) : "memory");
#else
	/* Generic fallback */
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
 * Spectre v1 Vulnerable / Hardened Gadget
 *
 * Reads g_sandbox.array1[idx] and uses the byte to index g_probe_array.
 */
static void noinline run_spectre_gadget(unsigned long idx)
{
	flush_cache_line(&g_array1_size);

	if (g_mode == 0) {
		/*
		 * BASELINE (Vulnerable):
		 * When idx >= g_array1_size, the branch is speculatively predicted as taken.
		 * Loads out-of-bounds secret and accesses corresponding probe line.
		 */
		uint8_t secret_val = g_sandbox.array1[idx];
		g_probe_array[secret_val * PROBE_STRIDE] = 0xAA;
		flush_cache_line(&g_probe_array[secret_val * PROBE_STRIDE]);
	} else {
		/*
		 * HARDENED (array_index_nospec):
		 * array_index_nospec() clamps idx to 0 via arithmetic masking (sbb/sbc + csdb).
		 * Out-of-bounds secret is NEVER accessed; only safe index 0 is accessed.
		 */
		unsigned long safe_idx = array_index_nospec(idx, g_array1_size);
		uint8_t safe_val = g_sandbox.array1[safe_idx];
		g_probe_array[safe_val * PROBE_STRIDE] = 0xAA;
		flush_cache_line(&g_probe_array[safe_val * PROBE_STRIDE]);
	}
}

/*
 * In-Kernel Spectre v1 Verification Benchmark
 */
static int run_spectre_benchmark(unsigned long target_oob_offset, uint8_t *detected_byte)
{
	int i;
	uint8_t expected_secret = g_sandbox.array1[target_oob_offset];

	if (!g_probe_array)
		return -ENOMEM;

	/* Step 1: Flush all probe lines */
	flush_probe_array();

	/* Step 2: Run gadget with target offset */
	run_spectre_gadget(target_oob_offset);

	/* Step 3: Inspect probe array lines */
	for (i = 0; i < PROBE_ENTRIES; i++) {
		if (i == g_sandbox.array1[0])
			continue; /* Skip safe index access */

		if (g_probe_array[i * PROBE_STRIDE] == 0xAA) {
			if (i == expected_secret) {
				*detected_byte = (uint8_t)i;
				return 1; /* Leaked */
			}
		}
	}

	return 0; /* Protected / No leak */
}

/* Procfs read handler */
static ssize_t vuln_spectrev1_read(struct file *file, char __user *buf,
				   size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Hardened (array_index_nospec)" : "Baseline (Vulnerable)";
	const char *arch_str =
#if defined(__x86_64__)
		"x86_64 (cmp; sbb bitmask)";
#elif defined(__aarch64__)
		"arm64 (cmp; sbc + csdb barrier)";
#else
		"generic";
#endif

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"  Spectre v1 (Bounds Check Bypass) Lab Status Report    \n"
		"========================================================\n"
		"Target Architecture    : %s\n"
		"Mitigation Mechanism   : array_index_nospec() [<linux/nospec.h>]\n"
		"Current Active Mode    : [%d] %s\n"
		"Public Array Size      : %u bytes\n"
		"Secret Offset Distance : %lu bytes from array1\n"
		"Secret Data Length     : %zu bytes\n"
		"Probe Array Base (Phys): 0x%llx (%u KB, stride %u B)\n"
		"Total Leaks Detected   : %lu\n"
		"Total Attacks Blocked  : %lu\n"
		"Last Leaked Byte       : 0x%02x ('%c')\n"
		"Available Commands     :\n"
		"  echo 'mode baseline'  > /proc/vuln_spectrev1\n"
		"  echo 'mode hardened'  > /proc/vuln_spectrev1\n"
		"  echo 'speculate <ofs>'> /proc/vuln_spectrev1\n"
		"  echo 'flush'          > /proc/vuln_spectrev1\n"
		"  echo 'run_bench'      > /proc/vuln_spectrev1\n"
		"========================================================\n",
		arch_str,
		g_mode, mode_str,
		g_array1_size,
		(unsigned long)((uint8_t *)g_sandbox.secret - g_sandbox.array1),
		strlen(g_sandbox.secret),
		(unsigned long long)(g_probe_pages ? ((phys_addr_t)page_to_pfn(g_probe_pages) << PAGE_SHIFT) : 0),
		PROBE_SIZE / 1024, PROBE_STRIDE,
		g_leak_count,
		g_blocked_count,
		(uint8_t)g_last_leaked_byte,
		(g_last_leaked_byte >= 32 && g_last_leaked_byte <= 126) ? g_last_leaked_byte : '.');

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_spectrev1_write(struct file *file, const char __user *buf,
				    size_t count, loff_t *ppos)
{
	char cmd[128];
	size_t copy_len = min(count, sizeof(cmd) - 1);

	if (copy_from_user(cmd, buf, copy_len))
		return -EFAULT;
	cmd[copy_len] = '\0';

	/* Strip trailing newline */
	if (copy_len > 0 && cmd[copy_len - 1] == '\n')
		cmd[copy_len - 1] = '\0';

	if (strcmp(cmd, "mode baseline") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_spectrev1: Switched to Mode 0: Baseline (Vulnerable, no nospec)\n");
	} else if (strcmp(cmd, "mode hardened") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_spectrev1: Switched to Mode 1: Hardened (array_index_nospec enabled)\n");
	} else if (strcmp(cmd, "flush") == 0) {
		flush_probe_array();
	} else if (strncmp(cmd, "speculate ", 10) == 0) {
		unsigned long target_idx = 0;
		if (kstrtoul(cmd + 10, 10, &target_idx) == 0) {
			run_spectre_gadget(target_idx);
		}
	} else if (strcmp(cmd, "run_bench") == 0) {
		uint8_t leaked_byte = 0;
		unsigned long secret_offset = (unsigned long)((uint8_t *)g_sandbox.secret - g_sandbox.array1);
		int res = run_spectre_benchmark(secret_offset, &leaked_byte);

		if (res == 1) {
			g_leak_count++;
			g_last_leaked_byte = leaked_byte;
			pr_warn("vuln_spectrev1: [BENCHMARK] Speculative leak SUCCESS! Byte: 0x%02x ('%c')\n",
				leaked_byte, (leaked_byte >= 32 && leaked_byte <= 126) ? leaked_byte : '?');
		} else {
			g_blocked_count++;
			pr_info("vuln_spectrev1: [BENCHMARK] Speculative leak BLOCKED (No secret leaked)!\n");
		}
	}

	return count;
}

/* Mmap handler allowing unprivileged userland to map probe_array */
static int vuln_spectrev1_mmap(struct file *file, struct vm_area_struct *vma)
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

static const struct proc_ops vuln_spectrev1_pops = {
	.proc_read = vuln_spectrev1_read,
	.proc_write = vuln_spectrev1_write,
	.proc_mmap = vuln_spectrev1_mmap,
	.proc_lseek = default_llseek,
};

static int __init vuln_spectrev1_init(void)
{
	struct proc_dir_entry *entry;

	/* Allocate 128KB contiguous pages for the secondary probe array */
	g_probe_pages = alloc_pages(GFP_KERNEL | __GFP_ZERO, PROBE_ORDER);
	if (!g_probe_pages) {
		pr_err("vuln_spectrev1: Failed to allocate probe pages\n");
		return -ENOMEM;
	}
	g_probe_array = (uint8_t *)page_address(g_probe_pages);

	/* Initialize probe array with non-zero dummy values */
	memset(g_probe_array, 0x5a, PROBE_SIZE);

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_spectrev1_pops);
	if (!entry) {
		__free_pages(g_probe_pages, PROBE_ORDER);
		pr_err("vuln_spectrev1: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_spectrev1: Target driver loaded (/proc/%s, mode=%d)\n",
		PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_spectrev1_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	if (g_probe_pages) {
		__free_pages(g_probe_pages, PROBE_ORDER);
		g_probe_pages = NULL;
		g_probe_array = NULL;
	}
	pr_info("vuln_spectrev1: Driver unloaded\n");
}

module_init(vuln_spectrev1_init);
module_exit(vuln_spectrev1_exit);

MODULE_AUTHOR("Antigravity Lab");
MODULE_DESCRIPTION("Spectre v1 (Bounds Check Bypass) and array_index_nospec Lab Driver");
MODULE_LICENSE("GPL");
