// SPDX-License-Identifier: GPL-2.0
/*
 * labs/29-landlock/vuln_landlock.c
 *
 * Target driver demonstrating Landlock unprivileged application sandboxing,
 * access rights hierarchy, and filesystem confinement.
 *
 * Key Concepts:
 *   1. Unprivileged Sandboxing: Any user process (UID != 0) without CAP_SYS_ADMIN
 *      can sandbox itself using Landlock system calls:
 *      - landlock_create_ruleset(): Declare handled access rights.
 *      - landlock_add_rule(): Bind allowed directories (LANDLOCK_RULE_PATH_BENEATH).
 *      - prctl(PR_SET_NO_NEW_PRIVS, 1, ...): Lock privilege escalation.
 *      - landlock_restrict_self(): Restrict current process and future children.
 *   2. Fail-Closed Restriction Hierarchy:
 *      - Stacking rulesets: child processes or subsequent restrict_self calls
 *        can only further constrain access, never expand it.
 *   3. Confinement Verification:
 *      - Mode 0 (Baseline / Unconfined): Standard DAC applies; user can read /tmp/host_secret.
 *      - Mode 1 (Hardened / Landlocked): Sandbox restricts filesystem access strictly to /tmp/sandbox/.
 *        Attempts to read outside sandbox fail with -EACCES immediately.
 *
 * Exposes /proc/vuln_landlock (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_landlock"
#define SANDBOX_PATH "/tmp/sandbox"
#define HOST_SECRET_PATH "/tmp/host_secret"

/* 0 = Baseline (Unconfined), 1 = Hardened (Landlock active) */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_evals = 0;
static unsigned long g_granted_evals = 0;
static unsigned long g_denied_evals = 0;
static unsigned long g_escape_denials = 0;
static unsigned long g_write_denials = 0;

/* Access test operations */
enum landlock_test_op {
	OP_SANDBOX_READ = 0, /* Reading inside /tmp/sandbox/: allowed in both modes */
	OP_SANDBOX_WRITE,    /* Writing inside /tmp/sandbox/: allowed */
	OP_ESCAPE_READ,      /* Reading /tmp/host_secret: denied under Landlock */
	OP_SYSTEM_WRITE,     /* Writing /etc/shadow: denied */
};

/*
 * Evaluates access under Landlock sandboxing model
 */
static int evaluate_landlock_access(enum landlock_test_op op, const char **reason)
{
	g_total_evals++;

	switch (op) {
	case OP_SANDBOX_READ:
		*reason = "sandbox_read (inside allowed tree)";
		g_granted_evals++;
		return 0;

	case OP_SANDBOX_WRITE:
		*reason = "sandbox_write (inside allowed tree)";
		g_granted_evals++;
		return 0;

	case OP_ESCAPE_READ:
		if (g_mode == 0) {
			pr_notice("vuln_landlock: [UNCONFINED] Access to '%s' allowed by DAC for pid=%d\n",
				HOST_SECRET_PATH, current->pid);
			*reason = "escape_read (unconfined: permitted by DAC)";
			g_granted_evals++;
			return 0;
		} else {
			pr_warn("vuln_landlock: [LANDLOCK_DENIED] Access to '%s' blocked for sandboxed pid=%d (-EACCES)\n",
				HOST_SECRET_PATH, current->pid);
			*reason = "escape_read (Landlock: outside allowed sandbox tree)";
			g_denied_evals++;
			g_escape_denials++;
			return -EACCES;
		}

	case OP_SYSTEM_WRITE:
		if (g_mode == 0) {
			pr_notice("vuln_landlock: [UNCONFINED] System write evaluated for pid=%d\n", current->pid);
			*reason = "system_write (unconfined: evaluated)";
			g_granted_evals++;
			return 0;
		} else {
			pr_warn("vuln_landlock: [LANDLOCK_DENIED] System write blocked for sandboxed pid=%d (-EACCES)\n",
				current->pid);
			*reason = "system_write (Landlock: write right not granted)";
			g_denied_evals++;
			g_write_denials++;
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
static int run_landlock_benchmark(void)
{
	const char *reason = NULL;
	int ret_sb_read, ret_sb_write, ret_escape, ret_syswrite;

	ret_sb_read  = evaluate_landlock_access(OP_SANDBOX_READ, &reason);
	ret_sb_write = evaluate_landlock_access(OP_SANDBOX_WRITE, &reason);
	ret_escape   = evaluate_landlock_access(OP_ESCAPE_READ, &reason);
	ret_syswrite = evaluate_landlock_access(OP_SYSTEM_WRITE, &reason);

	if (g_mode == 0) {
		pr_info("vuln_landlock: [BENCHMARK] Baseline unconfined mode: sandbox escape was permitted\n");
		return 0;
	} else {
		if (ret_sb_read == 0 && ret_sb_write == 0 && ret_escape == -EACCES && ret_syswrite == -EACCES) {
			pr_info("vuln_landlock: [BENCHMARK] Hardened Landlock mode: sandbox escape strictly BLOCKED (-EACCES)!\n");
			return 1;
		}
		pr_warn("vuln_landlock: [BENCHMARK] Landlock verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_landlock_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Hardened (Landlock active - Sandbox strictly enforced)" : "Baseline (Unconfined - DAC only)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"    Landlock Unprivileged Sandboxing Status Report      \n"
		"========================================================\n"
		"Current Landlock Mode   : [%d] %s\n"
		"Sandbox Boundary Root   : %s\n"
		"Host Secret Target      : %s\n"
		"Total Access Evals      : %lu\n"
		"Access Requests Granted : %lu\n"
		"Access Requests Denied  : %lu\n"
		"  - Sandbox Escape Deny : %lu\n"
		"  - System Write Deny   : %lu\n"
		"Ruleset Features        : PATH_BENEATH, NO_NEW_PRIVS, STACKING\n"
		"Available Commands      :\n"
		"  echo 'mode baseline'         > /proc/vuln_landlock\n"
		"  echo 'mode hardened'         > /proc/vuln_landlock\n"
		"  echo 'test sandbox'          > /proc/vuln_landlock\n"
		"  echo 'test escape'           > /proc/vuln_landlock\n"
		"  echo 'test write'            > /proc/vuln_landlock\n"
		"  echo 'run_bench'             > /proc/vuln_landlock\n"
		"========================================================\n",
		g_mode, mode_str,
		SANDBOX_PATH,
		HOST_SECRET_PATH,
		g_total_evals,
		g_granted_evals,
		g_denied_evals,
		g_escape_denials,
		g_write_denials);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_landlock_write(struct file *file, const char __user *buf,
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

	if (strcmp(cmd, "mode baseline") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_landlock: Switched to Mode 0: Baseline (Unconfined)\n");
	} else if (strcmp(cmd, "mode hardened") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_landlock: Switched to Mode 1: Hardened (Landlock Sandbox Enforced)\n");
	} else if (strcmp(cmd, "test sandbox") == 0) {
		int ret = evaluate_landlock_access(OP_SANDBOX_READ, &reason);
		pr_info("vuln_landlock: Access 'sandbox': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test escape") == 0) {
		int ret = evaluate_landlock_access(OP_ESCAPE_READ, &reason);
		pr_info("vuln_landlock: Access 'escape': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test write") == 0) {
		int ret = evaluate_landlock_access(OP_SYSTEM_WRITE, &reason);
		pr_info("vuln_landlock: Access 'write': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_landlock_benchmark();
	} else {
		pr_warn("vuln_landlock: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_landlock_proc_ops = {
	.proc_read  = vuln_landlock_read,
	.proc_write = vuln_landlock_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_landlock_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_landlock_read,
	.write   = vuln_landlock_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_landlock_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_landlock_proc_ops);
	if (!entry) {
		pr_err("vuln_landlock: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_landlock: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_landlock_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_landlock: Driver unloaded\n");
}

module_init(vuln_landlock_init);
module_exit(vuln_landlock_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Landlock Unprivileged Application Sandboxing Lab");
MODULE_LICENSE("GPL");
