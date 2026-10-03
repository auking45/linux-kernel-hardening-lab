// SPDX-License-Identifier: GPL-2.0
/*
 * labs/42-armv9-poe/vuln_poe.c
 *
 * Target driver demonstrating ARMv9 POE (Permission Overlay Extension / S1POE):
 *   1. Architectural Concept:
 *      - Memory Protection Keys decoupled from Page Tables.
 *      - Page Table Entries (PTEs) assign a 3-bit or 4-bit Key Index (Domain 0 to 7) to memory pages.
 *      - POR_EL0 (Permission Overlay Register EL0) controls active user permissions per key:
 *        * 0b0000: None (No Read, No Write, No Exec) -> Instant fault on any access.
 *        * 0b0001: Read-Only -> Faults on Write.
 *        * 0b0011: Read-Write -> Full access allowed.
 *   2. Intra-Process Compartmentalization:
 *      - Eliminates costly mprotect() syscalls and TLB shootdown overhead.
 *      - Domain permissions can be toggled in 1 CPU cycle by updating the POR_EL0 register!
 *      - Protects sensitive keys, cryptographic vaults, and JIT buffers against exploit exfiltration.
 *
 * Exposes /proc/vuln_poe (mode 0666) to evaluate POE permission overlays and compartment defenses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_poe"
#define MAX_POE_KEYS 8

/* Overlay Permission Nibbles */
#define POE_PERM_NONE 0x0
#define POE_PERM_R    0x1
#define POE_PERM_RW   0x3
#define POE_PERM_RX   0x5

/* Simulated POR_EL0 register (32-bit register holding 8 x 4-bit key permissions) */
static u32 g_por_el0 = 0x00000033; /* Key 0: RW (0x3), Key 1: RW (0x3) default */

/* Vault memory protected by Key 1 */
static char g_vault_data[128] = "CONFIDENTIAL_PAYLOAD_AES_256_KEY_0xCAFEBABE";
static const int VAULT_KEY = 1;

/* Statistics */
static unsigned long g_total_attempts = 0;
static unsigned long g_read_allowed = 0;
static unsigned long g_read_blocked = 0;
static unsigned long g_write_allowed = 0;
static unsigned long g_write_blocked = 0;

static u8 get_key_perm(int key)
{
	if (key < 0 || key >= MAX_POE_KEYS)
		return POE_PERM_NONE;
	return (g_por_el0 >> (key * 4)) & 0xF;
}

static void set_key_perm(int key, u8 perm)
{
	u32 mask;
	if (key < 0 || key >= MAX_POE_KEYS)
		return;
	mask = ~(0xF << (key * 4));
	g_por_el0 = (g_por_el0 & mask) | ((perm & 0xF) << (key * 4));
}

static const char *perm_to_str(u8 perm)
{
	switch (perm) {
	case POE_PERM_NONE: return "NONE (No Access - Fault on Read/Write)";
	case POE_PERM_R:    return "READ-ONLY (Fault on Write)";
	case POE_PERM_RW:   return "READ-WRITE (Full Access)";
	case POE_PERM_RX:   return "READ-EXEC";
	default:            return "CUSTOM/RESERVED";
	}
}

static int evaluate_poe_access(int key, bool is_write, const char **reason)
{
	u8 perm = get_key_perm(key);
	g_total_attempts++;

	if (is_write) {
		if ((perm & 0x2) == 0) {
			g_write_blocked++;
			pr_err("poe: [OVERLAY FAULT] Write denied on Key %d! POR_EL0 perm: 0x%X (-EACCES / SEGV_PKUERR)\n",
			       key, perm);
			*reason = "blocked: write forbidden by POR_EL0 permission overlay";
			return -EACCES;
		}
		g_write_allowed++;
		pr_info("poe: [ACCESS GRANTED] Write permitted on Key %d (POR_EL0: RW)\n", key);
		*reason = "allowed: write granted";
		return 0;
	} else {
		if ((perm & 0x1) == 0) {
			g_read_blocked++;
			pr_err("poe: [OVERLAY FAULT] Read denied on Key %d! POR_EL0 perm: 0x%X (-EACCES / SEGV_PKUERR)\n",
			       key, perm);
			*reason = "blocked: read forbidden by POR_EL0 permission overlay";
			return -EACCES;
		}
		g_read_allowed++;
		pr_info("poe: [ACCESS GRANTED] Read permitted on Key %d (POR_EL0: R/RW)\n", key);
		*reason = "allowed: read granted";
		return 0;
	}
}

static ssize_t vuln_poe_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	int k;

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
			 "=== ARMv9 POE (Permission Overlay Extension) Status ===\n");
	len += scnprintf(page + len, 2048 - len,
			 "Kernel POE Support       : %s\n",
			 IS_ENABLED(CONFIG_ARM64_POE) ? "CONFIG_ARM64_POE=y" : "Simulated");
	len += scnprintf(page + len, 2048 - len,
			 "Simulated POR_EL0 Reg    : 0x%08X\n", g_por_el0);
	len += scnprintf(page + len, 2048 - len,
			 "Total Access Attempts    : %lu\n", g_total_attempts);
	len += scnprintf(page + len, 2048 - len,
			 "Read Allowed / Blocked   : %lu / %lu\n",
			 g_read_allowed, g_read_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "Write Allowed / Blocked  : %lu / %lu\n",
			 g_write_allowed, g_write_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "Protection Domain Key Table (POR_EL0):\n");
	for (k = 0; k < MAX_POE_KEYS; k++) {
		u8 p = get_key_perm(k);
		len += scnprintf(page + len, 2048 - len,
				 "  [Key %d] Perm: 0x%X - %s%s\n",
				 k, p, perm_to_str(p),
				 (k == VAULT_KEY) ? " <- [PROTECTED SECRET VAULT]" : "");
	}
	len += scnprintf(page + len, 2048 - len,
			 "====================================================\n");
	len += scnprintf(page + len, 2048 - len,
			 "Available Commands:\n");
	len += scnprintf(page + len, 2048 - len,
			 "  set_por <key> <perm>     - Set POR_EL0 perm (0: None, 1: Read, 3: RW)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  read_vault               - Attempt to read protected vault (Key 1)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  write_vault <text>       - Attempt to write to protected vault (Key 1)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  lock_vault               - Set Key 1 to NONE (Full lockdown in 1 cycle)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  unlock_vault             - Set Key 1 to RW (Open compartment)\n");
	len += scnprintf(page + len, 2048 - len,
			 "  reset                    - Reset POR_EL0 and statistics\n");

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_poe_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char kbuf[128];
	size_t to_copy;
	const char *reason = "";
	int key, perm, res;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;
	kbuf[to_copy] = '\0';

	if (to_copy > 0 && kbuf[to_copy - 1] == '\n')
		kbuf[to_copy - 1] = '\0';

	if (sscanf(kbuf, "set_por %d %d", &key, &perm) == 2) {
		set_key_perm(key, (u8)perm);
		pr_info("poe: POR_EL0 updated: Key %d perm set to 0x%X (%s)\n",
			key, perm, perm_to_str((u8)perm));
		return count;
	}

	if (strncmp(kbuf, "lock_vault", 10) == 0) {
		set_key_perm(VAULT_KEY, POE_PERM_NONE);
		pr_info("poe: [LOCKDOWN] Vault compartment (Key 1) locked in POR_EL0 (Perm: NONE)\n");
		return count;
	}

	if (strncmp(kbuf, "unlock_vault", 12) == 0) {
		set_key_perm(VAULT_KEY, POE_PERM_RW);
		pr_info("poe: [UNLOCKED] Vault compartment (Key 1) unlocked in POR_EL0 (Perm: RW)\n");
		return count;
	}

	if (strncmp(kbuf, "read_vault", 10) == 0) {
		res = evaluate_poe_access(VAULT_KEY, false, &reason);
		if (res < 0) return res;
		pr_info("poe: Vault Read Successful: '%s'\n", g_vault_data);
		return count;
	}

	if (strncmp(kbuf, "write_vault", 11) == 0) {
		res = evaluate_poe_access(VAULT_KEY, true, &reason);
		if (res < 0) return res;
		if (strlen(kbuf) > 12) {
			strscpy(g_vault_data, kbuf + 12, sizeof(g_vault_data));
			pr_info("poe: Vault data modified to: '%s'\n", g_vault_data);
		}
		return count;
	}

	if (strncmp(kbuf, "reset", 5) == 0) {
		g_por_el0 = 0x00000033;
		strscpy(g_vault_data, "CONFIDENTIAL_PAYLOAD_AES_256_KEY_0xCAFEBABE", sizeof(g_vault_data));
		g_total_attempts = 0;
		g_read_allowed = 0;
		g_read_blocked = 0;
		g_write_allowed = 0;
		g_write_blocked = 0;
		pr_info("poe: Reset POR_EL0 and vault compartment.\n");
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops vuln_poe_proc_ops = {
	.proc_read  = vuln_poe_read,
	.proc_write = vuln_poe_write,
};

static int __init vuln_poe_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_poe_proc_ops);
	if (!entry) {
		pr_err("vuln_poe: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_poe: Loaded ARMv9 POE target driver at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_poe_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_poe: Unloaded ARMv9 POE target driver.\n");
}

module_init(vuln_poe_init);
module_exit(vuln_poe_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("ARMv9 Permission Overlay Extension (POE) Target Driver");
MODULE_VERSION("1.0");
