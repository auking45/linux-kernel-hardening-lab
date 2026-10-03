// SPDX-License-Identifier: GPL-2.0
/*
 * labs/41-arm64-mte/vuln_mte.c
 *
 * Target driver demonstrating ARM64 Memory Tagging Extension (MTE):
 *   1. Architectural Concept:
 *      - 4-bit Allocation Tags associated with each 16-byte physical memory granule.
 *      - 4-bit Logical Tags encoded in upper address bits [59:56] using Top-Byte-Ignore (TBI).
 *      - Hardware comparison on every load/store: Logical Tag vs Allocation Tag.
 *      - Tag mismatch triggers hardware exception:
 *        * Synchronous (PR_MTE_TCF_SYNC): Precise SIGSEGV with SEGV_MTESERR.
 *        * Asynchronous (PR_MTE_TCF_ASYNC): Accumulated into TFSR_EL1 register, SEGV_MTEAERR.
 *   2. Defense Against Memory Safety Violations:
 *      - Heap Use-After-Free (UAF): Freed memory is re-tagged with a new color, invalidating
 *        any stale/dangling pointers immediately.
 *      - Heap Out-of-Bounds (OOB): Adjacent allocation granules hold different colors,
 *        trapping buffer overflows before adjacent objects are corrupted.
 *
 * Exposes /proc/vuln_mte (mode 0666) for cross-architecture verification and hardware diagnostics.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/random.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_mte"
#define MTE_GRANULE_SIZE 16
#define MAX_SLOTS 8
#define DEFAULT_SLOT_SIZE 64 /* 4 granules */

struct mte_slot {
	u8 *data;
	size_t size;
	size_t nr_granules;
	u8 *alloc_tags; /* 4-bit allocation tag per granule */
	bool active;
	u8 current_tag;
};

static struct mte_slot g_slots[MAX_SLOTS];
static int g_mte_mode = 1; /* 1: Synchronous (SYNC), 2: Asynchronous (ASYNC) */

/* Diagnostics & Statistics */
static unsigned long g_total_allocations = 0;
static unsigned long g_valid_accesses = 0;
static unsigned long g_uaf_detected = 0;
static unsigned long g_oob_detected = 0;

static void init_slots(void)
{
	int i;
	for (i = 0; i < MAX_SLOTS; i++) {
		if (g_slots[i].data) {
			kfree(g_slots[i].data);
			kfree(g_slots[i].alloc_tags);
		}
		g_slots[i].data = NULL;
		g_slots[i].alloc_tags = NULL;
		g_slots[i].size = 0;
		g_slots[i].nr_granules = 0;
		g_slots[i].active = false;
		g_slots[i].current_tag = 0;
	}
}

static int mte_simulate_alloc(int slot_id, size_t size, u8 requested_tag)
{
	size_t granules;
	int g;
	u8 tag;

	if (slot_id < 0 || slot_id >= MAX_SLOTS)
		return -EINVAL;

	if (g_slots[slot_id].active) {
		kfree(g_slots[slot_id].data);
		kfree(g_slots[slot_id].alloc_tags);
	}

	granules = (size + MTE_GRANULE_SIZE - 1) / MTE_GRANULE_SIZE;
	g_slots[slot_id].data = kzalloc(granules * MTE_GRANULE_SIZE, GFP_KERNEL);
	g_slots[slot_id].alloc_tags = kmalloc(granules, GFP_KERNEL);
	if (!g_slots[slot_id].data || !g_slots[slot_id].alloc_tags)
		return -ENOMEM;

	/* Select 4-bit tag (0x1 - 0xF) */
	if (requested_tag > 0 && requested_tag <= 0xF)
		tag = requested_tag;
	else
		tag = (get_random_u32() % 14) + 1;

	for (g = 0; g < granules; g++)
		g_slots[slot_id].alloc_tags[g] = tag;

	g_slots[slot_id].size = size;
	g_slots[slot_id].nr_granules = granules;
	g_slots[slot_id].active = true;
	g_slots[slot_id].current_tag = tag;
	g_total_allocations++;

	pr_info("mte: Slot %d allocated %zu bytes (%zu granules). Assigned Allocation Tag: 0x%X\n",
		slot_id, size, granules, tag);
	return 0;
}

static int mte_simulate_free(int slot_id)
{
	u8 new_tag;
	int g;

	if (slot_id < 0 || slot_id >= MAX_SLOTS || !g_slots[slot_id].active)
		return -EINVAL;

	/* On free, modern MTE re-tags memory with a different color (or zero) */
	new_tag = ((g_slots[slot_id].current_tag + 5) % 14) + 1;
	for (g = 0; g < g_slots[slot_id].nr_granules; g++)
		g_slots[slot_id].alloc_tags[g] = new_tag;

	g_slots[slot_id].active = false;
	pr_info("mte: Slot %d freed. Granules re-tagged from 0x%X to 0x%X (UAF Trap Arming)\n",
		slot_id, g_slots[slot_id].current_tag, new_tag);
	return 0;
}

static int mte_simulate_access(int slot_id, size_t offset, u8 logical_tag, bool is_write, u8 val)
{
	size_t granule_idx;
	u8 alloc_tag;

	if (slot_id < 0 || slot_id >= MAX_SLOTS)
		return -EINVAL;

	granule_idx = offset / MTE_GRANULE_SIZE;

	/* 1. Check Out-Of-Bounds (OOB) */
	if (offset >= g_slots[slot_id].size) {
		g_oob_detected++;
		pr_err("mte: [HARDWARE TRAP - OOB] Buffer Overflow! Offset %zu >= size %zu. MTE Tag mismatch! (SEGV_MTESERR)\n",
		       offset, g_slots[slot_id].size);
		return -EFAULT;
	}

	/* 2. Check Use-After-Free (UAF) */
	if (!g_slots[slot_id].active) {
		alloc_tag = g_slots[slot_id].alloc_tags[granule_idx];
		g_uaf_detected++;
		pr_err("mte: [HARDWARE TRAP - UAF] Dangling pointer access! Logical Tag 0x%X != Re-tagged Allocation Tag 0x%X. (SEGV_MTESERR)\n",
		       logical_tag, alloc_tag);
		return -EFAULT;
	}

	/* 3. Regular Tag Check */
	alloc_tag = g_slots[slot_id].alloc_tags[granule_idx];
	if (logical_tag != alloc_tag) {
		if (g_mte_mode == 1) {
			pr_err("mte: [SYNC FAULT] Tag Mismatch! Logical: 0x%X vs Allocation: 0x%X at granule %zu. Immediate SIGSEGV\n",
			       logical_tag, alloc_tag, granule_idx);
			return -EFAULT;
		} else {
			pr_warn("mte: [ASYNC FAULT] Tag Mismatch recorded to TFSR_EL1 register! Asynchronous exception.\n");
			return 0;
		}
	}

	/* Successful access */
	if (is_write)
		g_slots[slot_id].data[offset] = val;
	g_valid_accesses++;
	return 0;
}

static ssize_t vuln_mte_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	int i;

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
			 "=== ARM64 MTE (Memory Tagging Extension) Status ===\n");
	len += scnprintf(page + len, 2048 - len,
			 "Kernel MTE Support       : %s\n",
			 IS_ENABLED(CONFIG_ARM64_MTE) ? "CONFIG_ARM64_MTE=y" : "Simulated");
	len += scnprintf(page + len, 2048 - len,
			 "Current Fault Mode       : %s\n",
			 g_mte_mode == 1 ? "Synchronous (PR_MTE_TCF_SYNC)" : "Asynchronous (PR_MTE_TCF_ASYNC)");
	len += scnprintf(page + len, 2048 - len,
			 "Granule Size             : %d bytes (4-bit tag per granule)\n",
			 MTE_GRANULE_SIZE);
	len += scnprintf(page + len, 2048 - len,
			 "Total Allocations        : %lu\n", g_total_allocations);
	len += scnprintf(page + len, 2048 - len,
			 "Valid Tagged Accesses    : %lu\n", g_valid_accesses);
	len += scnprintf(page + len, 2048 - len,
			 "UAF Attacks Trapped      : %lu\n", g_uaf_detected);
	len += scnprintf(page + len, 2048 - len,
			 "OOB Overflows Trapped    : %lu\n", g_oob_detected);
	len += scnprintf(page + len, 2048 - len,
			 "Active Allocated Slots   :\n");
	for (i = 0; i < MAX_SLOTS; i++) {
		if (g_slots[i].active) {
			len += scnprintf(page + len, 2048 - len,
					 "  [Slot %d] Size: %zu B, Granules: %zu, Tag: 0x%X\n",
					 i, g_slots[i].size, g_slots[i].nr_granules, g_slots[i].current_tag);
		}
	}
	len += scnprintf(page + len, 2048 - len,
			 "====================================================\n");
	len += scnprintf(page + len, 2048 - len,
			 "Available Commands:\n");
	len += scnprintf(page + len, 2048 - len,
			 "  alloc <slot> <size> [tag]  - Allocate memory with 4-bit MTE tag\n");
	len += scnprintf(page + len, 2048 - len,
			 "  access <slot> <off> <tag>  - Access using tagged logical pointer\n");
	len += scnprintf(page + len, 2048 - len,
			 "  free <slot>                - Free slot and re-color granules\n");
	len += scnprintf(page + len, 2048 - len,
			 "  mode <sync|async>          - Switch between SYNC and ASYNC trap modes\n");
	len += scnprintf(page + len, 2048 - len,
			 "  reset                      - Clear all slots and reset statistics\n");

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_mte_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char kbuf[128];
	size_t to_copy;
	int slot, res;
	unsigned long size, offset, tag;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;
	kbuf[to_copy] = '\0';

	if (to_copy > 0 && kbuf[to_copy - 1] == '\n')
		kbuf[to_copy - 1] = '\0';

	if (sscanf(kbuf, "alloc %d %lu %lx", &slot, &size, &tag) >= 2) {
		res = mte_simulate_alloc(slot, size, (u8)tag);
		if (res < 0) return res;
		return count;
	}

	if (sscanf(kbuf, "access %d %lu %lx", &slot, &offset, &tag) == 3) {
		res = mte_simulate_access(slot, offset, (u8)tag, false, 0);
		if (res < 0) return res;
		return count;
	}

	if (sscanf(kbuf, "free %d", &slot) == 1) {
		res = mte_simulate_free(slot);
		if (res < 0) return res;
		return count;
	}

	if (strncmp(kbuf, "mode sync", 9) == 0) {
		g_mte_mode = 1;
		pr_info("mte: Fault mode set to Synchronous (PR_MTE_TCF_SYNC)\n");
		return count;
	}

	if (strncmp(kbuf, "mode async", 10) == 0) {
		g_mte_mode = 2;
		pr_info("mte: Fault mode set to Asynchronous (PR_MTE_TCF_ASYNC)\n");
		return count;
	}

	if (strncmp(kbuf, "reset", 5) == 0) {
		init_slots();
		g_total_allocations = 0;
		g_valid_accesses = 0;
		g_uaf_detected = 0;
		g_oob_detected = 0;
		pr_info("mte: Memory slots and statistics reset.\n");
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops vuln_mte_proc_ops = {
	.proc_read  = vuln_mte_read,
	.proc_write = vuln_mte_write,
};

static int __init vuln_mte_init(void)
{
	struct proc_dir_entry *entry;

	init_slots();
	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_mte_proc_ops);
	if (!entry) {
		pr_err("vuln_mte: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_mte: Loaded ARM64 MTE target driver at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_mte_exit(void)
{
	init_slots();
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_mte: Unloaded ARM64 MTE target driver.\n");
}

module_init(vuln_mte_init);
module_exit(vuln_mte_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("ARM64 Memory Tagging Extension Target Driver");
MODULE_VERSION("1.0");
