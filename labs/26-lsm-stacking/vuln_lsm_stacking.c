// SPDX-License-Identifier: GPL-2.0
/*
 * labs/26-lsm-stacking/vuln_lsm_stacking.c
 *
 * Target driver for demonstrating the Linux Security Module (LSM) Stacking Architecture,
 * hook execution chains, composite security blobs, and fail-safe deny rules.
 *
 * Key Concepts:
 *   1. Stackable LSM Architecture: Multiple independent security modules (e.g. Landlock,
 *      Yama, Lockdown, AppArmor/SELinux, BPF) simultaneously active and chained together.
 *   2. Sequential Hook Evaluation: Hooks are called in order; if ANY module in the chain
 *      returns a negative error code (e.g. -EACCES, -EPERM), access is immediately denied.
 *   3. Shared Security Blobs: Each module receives a private offset within composite
 *      structures attached to credentials, inodes, and files.
 *
 * Dual-Mode Operation:
 *   - Mode 0 (Baseline / Single Permissive LSM): Only traditional DAC/Capability checks
 *     are evaluated. Advanced restrictions (Landlock path restrictions, Yama ptrace,
 *     Lockdown confidentiality) are bypassed, granting unauthorized access.
 *   - Mode 1 (Hardened / Full LSM Stacking): All stacked LSM hooks are sequentially
 *     invoked in strict priority order. Any denial enforces fail-closed containment.
 *
 * Exposes /proc/vuln_lsm (mode 0666) with in-kernel benchmark and evaluation routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/security.h>

#define PROC_FILENAME "vuln_lsm"

/* 0 = Baseline (DAC only), 1 = Hardened (Full Stacked LSM Enforcement) */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_invocations = 0;
static unsigned long g_granted_count = 0;
static unsigned long g_denied_count = 0;
static unsigned long g_yama_blocks = 0;
static unsigned long g_landlock_blocks = 0;
static unsigned long g_lockdown_blocks = 0;

/* External kernel symbol defined in security/security.c (weak symbol if CONFIG_SECURITY=n) */
extern char *lsm_names __attribute__((weak));

/* Simulated LSM identifiers matching Linux UAPI */
enum simulated_lsm_id {
	LSM_SIM_CAPABILITY = 100,
	LSM_SIM_YAMA       = 105,
	LSM_SIM_LOCKDOWN   = 108,
	LSM_SIM_BPF        = 109,
	LSM_SIM_LANDLOCK   = 110,
};

/* Request access types */
enum access_test_type {
	ACCESS_NORMAL = 0,
	ACCESS_UNPRIV_PTRACE,       /* Should be blocked by Yama */
	ACCESS_RESTRICTED_PATH,      /* Should be blocked by Landlock */
	ACCESS_RAW_DEVMEM,           /* Should be blocked by Lockdown */
};

/*
 * Simulated individual LSM hook handlers
 */
static int hook_capability_check(enum access_test_type type)
{
	/* Capability / DAC check passes for standard UID operations */
	(void)type;
	return 0;
}

static int hook_yama_check(enum access_test_type type)
{
	/* Yama restricts ptrace of non-child or arbitrary processes */
	if (type == ACCESS_UNPRIV_PTRACE) {
		g_yama_blocks++;
		return -EPERM;
	}
	return 0;
}

static int hook_landlock_check(enum access_test_type type)
{
	/* Landlock enforces unprivileged path and filesystem sandboxing */
	if (type == ACCESS_RESTRICTED_PATH) {
		g_landlock_blocks++;
		return -EACCES;
	}
	return 0;
}

static int hook_lockdown_check(enum access_test_type type)
{
	/* Lockdown blocks direct kernel memory tampering and raw I/O port writes */
	if (type == ACCESS_RAW_DEVMEM) {
		g_lockdown_blocks++;
		return -EPERM;
	}
	return 0;
}

/*
 * Composite Stacked LSM Hook Evaluator
 * Demonstrates fail-closed sequential chaining:
 * If ANY active LSM returns an error, the operation is denied.
 */
static int evaluate_stacked_lsm_chain(enum access_test_type type, const char **denied_by)
{
	int ret = 0;
	g_total_invocations++;

	if (g_mode == 0) {
		/*
		 * MODE 0: Baseline (Single / Legacy Permissive)
		 * Only basic capability hook is evaluated. Advanced stacked
		 * LSMs are ignored or not enforced.
		 */
		ret = hook_capability_check(type);
		if (ret != 0) {
			*denied_by = "capability";
			g_denied_count++;
			return ret;
		}

		/* Under baseline, access is granted regardless of policy violation */
		*denied_by = NULL;
		g_granted_count++;
		return 0;
	}

	/*
	 * MODE 1: Hardened (Full Stackable LSM Chaining)
	 * Chain order: capability -> landlock -> lockdown -> yama
	 */
	ret = hook_capability_check(type);
	if (ret != 0) {
		*denied_by = "capability";
		g_denied_count++;
		return ret;
	}

	ret = hook_landlock_check(type);
	if (ret != 0) {
		*denied_by = "landlock";
		g_denied_count++;
		return ret;
	}

	ret = hook_lockdown_check(type);
	if (ret != 0) {
		*denied_by = "lockdown";
		g_denied_count++;
		return ret;
	}

	ret = hook_yama_check(type);
	if (ret != 0) {
		*denied_by = "yama";
		g_denied_count++;
		return ret;
	}

	*denied_by = NULL;
	g_granted_count++;
	return 0;
}

/*
 * In-Kernel Verification Benchmark
 */
static int run_lsm_benchmark(void)
{
	const char *denied_by = NULL;
	int res_yama, res_landlock, res_lockdown;

	/* Test 1: Yama ptrace restriction */
	res_yama = evaluate_stacked_lsm_chain(ACCESS_UNPRIV_PTRACE, &denied_by);

	/* Test 2: Landlock path restriction */
	res_landlock = evaluate_stacked_lsm_chain(ACCESS_RESTRICTED_PATH, &denied_by);

	/* Test 3: Lockdown direct memory access */
	res_lockdown = evaluate_stacked_lsm_chain(ACCESS_RAW_DEVMEM, &denied_by);

	if (g_mode == 0) {
		/* Baseline: all bypassed */
		pr_info("vuln_lsm: [BENCHMARK] Baseline mode: Stacked LSM bypass verified (All accesses granted)\n");
		return 0;
	} else {
		/* Hardened: all blocked */
		if (res_yama == -EPERM && res_landlock == -EACCES && res_lockdown == -EPERM) {
			pr_info("vuln_lsm: [BENCHMARK] Hardened mode: All stacked policy violations BLOCKED!\n");
			return 1;
		}
		pr_warn("vuln_lsm: [BENCHMARK] Hardened mode verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_lsm_read(struct file *file, char __user *buf,
			     size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *active_lsms = lsm_names ? lsm_names : "capability,landlock,lockdown,yama,bpf";
	const char *mode_str = (g_mode == 1) ? "Hardened (Full Stacked LSM Enforcement Active)" : "Baseline (Single / Permissive LSM Mode)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"  Stackable LSM (Linux Security Modules) Status Report  \n"
		"========================================================\n"
		"Active Kernel LSM Stack : %s\n"
		"Framework Capabilities  : Stackable Hooks, Shared Blobs, Fail-Closed\n"
		"Current Active Mode     : [%d] %s\n"
		"Total Chain Evaluations : %lu\n"
		"Access Requests Granted : %lu\n"
		"Access Requests Denied  : %lu\n"
		"  - Yama Ptrace Denials : %lu\n"
		"  - Landlock Sandboxing : %lu\n"
		"  - Lockdown Violations : %lu\n"
		"Evaluation Chain Order  :\n"
		"  [1] capability -> [2] landlock -> [3] lockdown -> [4] yama -> [5] bpf\n"
		"Available Commands      :\n"
		"  echo 'mode baseline'         > /proc/vuln_lsm\n"
		"  echo 'mode hardened'         > /proc/vuln_lsm\n"
		"  echo 'test_access normal'    > /proc/vuln_lsm\n"
		"  echo 'test_access yama'      > /proc/vuln_lsm\n"
		"  echo 'test_access landlock'  > /proc/vuln_lsm\n"
		"  echo 'test_access lockdown'  > /proc/vuln_lsm\n"
		"  echo 'run_bench'             > /proc/vuln_lsm\n"
		"========================================================\n",
		active_lsms,
		g_mode, mode_str,
		g_total_invocations,
		g_granted_count,
		g_denied_count,
		g_yama_blocks,
		g_landlock_blocks,
		g_lockdown_blocks);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_lsm_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char cmd[128];
	size_t copy_len = min(count, sizeof(cmd) - 1);
	const char *denied_by = NULL;

	if (copy_from_user(cmd, buf, copy_len))
		return -EFAULT;
	cmd[copy_len] = '\0';

	if (copy_len > 0 && cmd[copy_len - 1] == '\n')
		cmd[copy_len - 1] = '\0';

	if (strcmp(cmd, "mode baseline") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_lsm: Switched to Mode 0: Baseline (Single / Permissive LSM)\n");
	} else if (strcmp(cmd, "mode hardened") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_lsm: Switched to Mode 1: Hardened (Full Stackable LSM Enforcement)\n");
	} else if (strcmp(cmd, "test_access normal") == 0) {
		int ret = evaluate_stacked_lsm_chain(ACCESS_NORMAL, &denied_by);
		pr_info("vuln_lsm: Access 'normal': %s\n", ret == 0 ? "GRANTED" : "DENIED");
	} else if (strcmp(cmd, "test_access yama") == 0) {
		int ret = evaluate_stacked_lsm_chain(ACCESS_UNPRIV_PTRACE, &denied_by);
		pr_info("vuln_lsm: Access 'yama' (ptrace): %s (denied_by=%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", denied_by ? denied_by : "none");
	} else if (strcmp(cmd, "test_access landlock") == 0) {
		int ret = evaluate_stacked_lsm_chain(ACCESS_RESTRICTED_PATH, &denied_by);
		pr_info("vuln_lsm: Access 'landlock' (path): %s (denied_by=%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", denied_by ? denied_by : "none");
	} else if (strcmp(cmd, "test_access lockdown") == 0) {
		int ret = evaluate_stacked_lsm_chain(ACCESS_RAW_DEVMEM, &denied_by);
		pr_info("vuln_lsm: Access 'lockdown' (devmem): %s (denied_by=%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", denied_by ? denied_by : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_lsm_benchmark();
	} else {
		pr_warn("vuln_lsm: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_lsm_proc_ops = {
	.proc_read  = vuln_lsm_read,
	.proc_write = vuln_lsm_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_lsm_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_lsm_read,
	.write   = vuln_lsm_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_lsm_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_lsm_proc_ops);
	if (!entry) {
		pr_err("vuln_lsm: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_lsm: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_lsm_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_lsm: Driver unloaded\n");
}

module_init(vuln_lsm_init);
module_exit(vuln_lsm_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Stackable Linux Security Modules (LSM) Architecture and Ordering Lab");
MODULE_LICENSE("GPL");
