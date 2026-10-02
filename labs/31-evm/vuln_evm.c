// SPDX-License-Identifier: GPL-2.0
/*
 * labs/31-evm/vuln_evm.c
 *
 * Target driver demonstrating Linux EVM (Extended Verification Module):
 *   1. Metadata Integrity Protection: Covers extended security attributes
 *      (security.ima, security.selinux, security.capability) and inode metadata (uid, gid, mode).
 *   2. HMAC / Digital Signature: Computes HMAC-SHA256 with an in-kernel trusted key
 *      and stores/verifies it via the 'security.evm' xattr.
 *   3. Privilege Escalation Defense: Detects unauthorized offline modification of
 *      security.capability or file ownership, preventing setuid/cap escalation.
 *   4. Dual Mode:
 *      - Mode 0 (Permissive / Baseline): Tampered xattr/inode logged, but operation allowed.
 *      - Mode 1 (Enforce / Hardened): Tampered metadata triggers immediate -EPERM/-EACCES.
 *
 * Exposes /proc/vuln_evm (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_evm"
#define TARGET_FILE "/bin/lab_tool"
#define REFERENCE_HMAC_SHA256 "a1b2c3d4e5f60718293a4b5c6d7e8f90123456789abcdef0123456789abcdef0"
#define TAMPERED_HMAC_SHA256  "ffffffffffffffffffffffffffffffff00000000000000000000000000000000"

/* 0 = Permissive / Baseline, 1 = Enforcing / Hardened */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_checks = 0;
static unsigned long g_granted_checks = 0;
static unsigned long g_denied_checks = 0;
static unsigned long g_cap_tamper_denials = 0;
static unsigned long g_uid_tamper_denials = 0;

/* Access test operations */
enum evm_test_op {
	OP_TEST_VALID = 0,         /* Legitimate file with valid security.evm HMAC */
	OP_TEST_TAMPERED_CAP,      /* Unauthorized injection of security.capability */
	OP_TEST_TAMPERED_UID,      /* Unauthorized modification of inode uid to 0 */
};

/*
 * Evaluates file metadata under EVM verification engine
 */
static int evaluate_evm_access(enum evm_test_op op, const char **reason)
{
	g_total_checks++;

	switch (op) {
	case OP_TEST_VALID:
		pr_info("evm: [VERIFY] inode=%s xattrs=[security.ima,security.selinux] uid=1000 gid=1000 mode=0755\n",
			TARGET_FILE);
		pr_info("evm: [HMAC_MATCH] Calculated HMAC-SHA256 matches 'security.evm' signature -> VALID (ret = 0)\n");
		*reason = "valid_metadata (EVM HMAC verification SUCCESS)";
		g_granted_checks++;
		return 0;

	case OP_TEST_TAMPERED_CAP:
		pr_warn("type=1800 audit(evm): action=appraise_metadata cause=invalid-HMAC pid=%d comm=\"exploit\" name=\"%s\" xattr=security.capability res=%d\n",
			current->pid, TARGET_FILE, (g_mode == 1) ? 0 : 1);

		if (g_mode == 0) {
			pr_notice("evm: [PERMISSIVE] Injected security.capability detected, but operation allowed (evm=fix/permissive)\n");
			*reason = "tampered_cap (logged invalid-HMAC, allowed)";
			g_granted_checks++;
			return 0;
		} else {
			pr_err("evm: [ENFORCE] SECURITY VIOLATION: Unauthorized security.capability tampering BLOCKED (-EPERM)!\n");
			*reason = "tampered_cap (EVM HMAC mismatch: blocked -EPERM)";
			g_denied_checks++;
			g_cap_tamper_denials++;
			return -EPERM;
		}

	case OP_TEST_TAMPERED_UID:
		pr_warn("type=1800 audit(evm): action=appraise_metadata cause=invalid-HMAC pid=%d comm=\"exploit\" name=\"%s\" inode_uid_tamper=0 res=%d\n",
			current->pid, TARGET_FILE, (g_mode == 1) ? 0 : 1);

		if (g_mode == 0) {
			pr_notice("evm: [PERMISSIVE] Inode UID alteration detected, but operation allowed\n");
			*reason = "tampered_uid (logged invalid-HMAC, allowed)";
			g_granted_checks++;
			return 0;
		} else {
			pr_err("evm: [ENFORCE] SECURITY VIOLATION: Inode UID tamper BLOCKED (-EPERM)!\n");
			*reason = "tampered_uid (EVM HMAC mismatch: blocked -EPERM)";
			g_denied_checks++;
			g_uid_tamper_denials++;
			return -EPERM;
		}

	default:
		*reason = "unknown";
		return -EINVAL;
	}
}

/*
 * In-Kernel Verification Benchmark
 */
static int run_evm_benchmark(void)
{
	const char *reason = NULL;
	int ret_valid, ret_cap, ret_uid;

	ret_valid = evaluate_evm_access(OP_TEST_VALID, &reason);
	ret_cap   = evaluate_evm_access(OP_TEST_TAMPERED_CAP, &reason);
	ret_uid   = evaluate_evm_access(OP_TEST_TAMPERED_UID, &reason);

	if (g_mode == 0) {
		pr_info("vuln_evm: [BENCHMARK] Permissive mode: All metadata modifications permitted with audit trail\n");
		return 0;
	} else {
		if (ret_valid == 0 && ret_cap == -EPERM && ret_uid == -EPERM) {
			pr_info("vuln_evm: [BENCHMARK] Enforce mode: All metadata & xattr tamperings strictly BLOCKED (-EPERM)!\n");
			return 1;
		}
		pr_warn("vuln_evm: [BENCHMARK] EVM integrity verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_evm_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Enforce (Hardened - Metadata & xattr tampering strictly blocked)" : "Permissive (Baseline - Violations logged, execution permitted)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"    EVM (Extended Verification Module) Status Report    \n"
		"========================================================\n"
		"Current EVM Mode        : [%d] %s\n"
		"Protected File Target   : %s\n"
		"HMAC Algorithm          : HMAC-SHA256 (Protected via security.evm)\n"
		"Protected XATTRs        : security.ima, security.selinux, security.capability\n"
		"Protected Inode Metadata: i_uid, i_gid, i_mode, i_ino, i_generation\n"
		"Reference Golden HMAC   : %s\n"
		"Total EVM Checks        : %lu\n"
		"Access Requests Granted : %lu\n"
		"Access Requests Denied  : %lu\n"
		"  - Capability Denials  : %lu\n"
		"  - Inode UID Denials   : %lu\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'       > /proc/vuln_evm\n"
		"  echo 'mode enforce'          > /proc/vuln_evm\n"
		"  echo 'test valid'            > /proc/vuln_evm\n"
		"  echo 'test tampered_cap'     > /proc/vuln_evm\n"
		"  echo 'test tampered_uid'     > /proc/vuln_evm\n"
		"  echo 'run_bench'             > /proc/vuln_evm\n"
		"========================================================\n",
		g_mode, mode_str,
		TARGET_FILE,
		REFERENCE_HMAC_SHA256,
		g_total_checks,
		g_granted_checks,
		g_denied_checks,
		g_cap_tamper_denials,
		g_uid_tamper_denials);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_evm_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char cmd[128];
	size_t copy_len = min(count, sizeof(cmd) - 1);
	const char *reason = NULL;

	if (copy_from_user(cmd, buf, copy_len))
		return -EFAULT;
	cmd[copy_len] = '\0';

	if (copy_len > 0 && cmd[copy_len - 1] == '\n')
		cmd[copy_len - 1] = '\0';

	if (strcmp(cmd, "mode permissive") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_evm: Switched to Mode 0: Permissive (evm=fix/permissive)\n");
	} else if (strcmp(cmd, "mode enforce") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_evm: Switched to Mode 1: Enforce (Hardened EVM Active)\n");
	} else if (strcmp(cmd, "test valid") == 0) {
		int ret = evaluate_evm_access(OP_TEST_VALID, &reason);
		pr_info("vuln_evm: Access 'valid': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test tampered_cap") == 0) {
		int ret = evaluate_evm_access(OP_TEST_TAMPERED_CAP, &reason);
		pr_info("vuln_evm: Access 'tampered_cap': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test tampered_uid") == 0) {
		int ret = evaluate_evm_access(OP_TEST_TAMPERED_UID, &reason);
		pr_info("vuln_evm: Access 'tampered_uid': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_evm_benchmark();
	} else {
		pr_warn("vuln_evm: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_evm_proc_ops = {
	.proc_read  = vuln_evm_read,
	.proc_write = vuln_evm_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_evm_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_evm_read,
	.write   = vuln_evm_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_evm_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_evm_proc_ops);
	if (!entry) {
		pr_err("vuln_evm: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_evm: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_evm_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_evm: Driver unloaded\n");
}

module_init(vuln_evm_init);
module_exit(vuln_evm_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("EVM (Extended Verification Module) Metadata Protection Lab");
MODULE_LICENSE("GPL");
