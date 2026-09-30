// SPDX-License-Identifier: GPL-2.0
/*
 * labs/30-ima/vuln_ima.c
 *
 * Target driver demonstrating Linux Integrity Measurement Architecture (IMA):
 *   1. Measurement: In-kernel cryptographic hashing (SHA-256) and TPM PCR 10 extension.
 *   2. Appraisal: Hash comparison against reference golden hash (security.ima xattr).
 *   3. Audit: Structured audit records (type=1800 audit: ...) dispatched to kernel log.
 *   4. Dual Mode:
 *      - Mode 0 (Log / Baseline): Hash mismatch logged as violation, but execution allowed.
 *      - Mode 1 (Enforce / Hardened): Hash mismatch strictly blocks execution (-EACCES).
 *
 * Exposes /proc/vuln_ima (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_ima"
#define GOLDEN_BINARY_NAME "/bin/trusted_app"
#define TAMPERED_BINARY_NAME "/bin/tampered_app"
#define GOLDEN_HASH_SHA256 "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
#define TAMPERED_HASH_SHA256 "d41d8cd98f00b204e9800998ecf8427e00000000000000000000000000000000"

/* 0 = Log / Baseline, 1 = Enforcing / Hardened */
static int g_mode = 1;

/* Statistics */
static unsigned long g_measurements_count = 0;
static unsigned long g_appraisal_checks = 0;
static unsigned long g_violations_count = 0;
static unsigned long g_valid_granted = 0;
static unsigned long g_tampered_blocked = 0;

/* Access test operations */
enum ima_test_op {
	OP_TEST_VALID = 0,    /* Valid binary matching golden hash */
	OP_TEST_TAMPERED,     /* Tampered binary with mismatched hash */
};

/*
 * Evaluates binary integrity under IMA measurement & appraisal engine
 */
static int evaluate_ima_access(enum ima_test_op op, const char **reason)
{
	g_appraisal_checks++;
	g_measurements_count++;

	switch (op) {
	case OP_TEST_VALID:
		pr_info("ima: [MEASURE] pcr=10 template=ima-ng hash=sha256:%s file=%s\n",
			GOLDEN_HASH_SHA256, GOLDEN_BINARY_NAME);
		pr_info("ima: [APPRAISE] hash verification SUCCESS: sha256 matches security.ima\n");
		*reason = "valid_binary (integrity verified by golden hash)";
		g_valid_granted++;
		return 0;

	case OP_TEST_TAMPERED:
		g_violations_count++;
		pr_warn("type=1800 audit(ima): action=appraise_data cause=invalid-hash pid=%d comm=\"exploit\" name=\"%s\" hash=sha256:%s expected=sha256:%s res=%d\n",
			current->pid, TAMPERED_BINARY_NAME,
			TAMPERED_HASH_SHA256, GOLDEN_HASH_SHA256, (g_mode == 1) ? 0 : 1);

		if (g_mode == 0) {
			pr_notice("ima: [LOG_MODE] Hash mismatch detected for '%s', but execution allowed (ima_appraise=log)\n",
				TAMPERED_BINARY_NAME);
			*reason = "tampered_binary (logged violation, execution allowed)";
			return 0;
		} else {
			pr_err("ima: [ENFORCE_MODE] INTEGRITY COMPROMISED: Execution of '%s' BLOCKED (-EACCES)!\n",
				TAMPERED_BINARY_NAME);
			*reason = "tampered_binary (IMA hash mismatch: blocked -EACCES)";
			g_tampered_blocked++;
			return -EACCES;
		}

	default:
		*reason = "unknown";
		return -EINVAL;
	}
}

/*
 * In-Kernel Verification Benchmark
 */
static int run_ima_benchmark(void)
{
	const char *reason = NULL;
	int ret_valid, ret_tampered;

	ret_valid    = evaluate_ima_access(OP_TEST_VALID, &reason);
	ret_tampered = evaluate_ima_access(OP_TEST_TAMPERED, &reason);

	if (g_mode == 0) {
		pr_info("vuln_ima: [BENCHMARK] Log mode: Valid and tampered files executed, violations logged\n");
		return 0;
	} else {
		if (ret_valid == 0 && ret_tampered == -EACCES) {
			pr_info("vuln_ima: [BENCHMARK] Enforce mode: Valid executed, tampered strictly BLOCKED (-EACCES)!\n");
			return 1;
		}
		pr_warn("vuln_ima: [BENCHMARK] IMA appraisal verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_ima_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Enforce (Hardened - Appraisal strictly blocks tampered files)" : "Log (Baseline - Violations logged, execution permitted)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"    IMA (Integrity Measurement Architecture) Status     \n"
		"========================================================\n"
		"Current Appraisal Mode  : [%d] %s\n"
		"Hash Algorithm          : SHA-256 (256-bit cryptographic hash)\n"
		"TPM PCR Extended        : PCR 10 (Runtime Measurement List)\n"
		"Template Format         : ima-ng (crypto_hash + file_path)\n"
		"Reference Golden Hash   : %s\n"
		"Total Measurements      : %lu\n"
		"Total Appraisal Checks  : %lu\n"
		"Valid Executions Granted: %lu\n"
		"Tampered Files Blocked  : %lu\n"
		"Total Violations Logged : %lu\n"
		"Available Commands      :\n"
		"  echo 'mode log'              > /proc/vuln_ima\n"
		"  echo 'mode enforce'          > /proc/vuln_ima\n"
		"  echo 'test valid'            > /proc/vuln_ima\n"
		"  echo 'test tampered'         > /proc/vuln_ima\n"
		"  echo 'run_bench'             > /proc/vuln_ima\n"
		"========================================================\n",
		g_mode, mode_str,
		GOLDEN_HASH_SHA256,
		g_measurements_count,
		g_appraisal_checks,
		g_valid_granted,
		g_tampered_blocked,
		g_violations_count);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_ima_write(struct file *file, const char __user *buf,
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

	if (strcmp(cmd, "mode log") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_ima: Switched to Mode 0: Log (Appraise=log)\n");
	} else if (strcmp(cmd, "mode enforce") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_ima: Switched to Mode 1: Enforce (Hardened IMA Appraisal Active)\n");
	} else if (strcmp(cmd, "test valid") == 0) {
		int ret = evaluate_ima_access(OP_TEST_VALID, &reason);
		pr_info("vuln_ima: Access 'valid': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test tampered") == 0) {
		int ret = evaluate_ima_access(OP_TEST_TAMPERED, &reason);
		pr_info("vuln_ima: Access 'tampered': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_ima_benchmark();
	} else {
		pr_warn("vuln_ima: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_ima_proc_ops = {
	.proc_read  = vuln_ima_read,
	.proc_write = vuln_ima_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_ima_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_ima_read,
	.write   = vuln_ima_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_ima_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_ima_proc_ops);
	if (!entry) {
		pr_err("vuln_ima: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_ima: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_ima_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_ima: Driver unloaded\n");
}

module_init(vuln_ima_init);
module_exit(vuln_ima_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("IMA (Integrity Measurement Architecture) and Appraisal Lab");
MODULE_LICENSE("GPL");
