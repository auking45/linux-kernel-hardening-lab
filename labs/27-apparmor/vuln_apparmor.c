// SPDX-License-Identifier: GPL-2.0
/*
 * labs/27-apparmor/vuln_apparmor.c
 *
 * Target driver demonstrating AppArmor Path-Based Mandatory Access Control (MAC),
 * profile confinement, DFA path resolution, and Complain vs. Enforce mode semantics.
 *
 * Key Concepts:
 *   1. Path-based Confinement: Profiles bind directly to executable paths and regulate
 *      file accesses by canonical pathname (unlike SELinux's inode-labeling model).
 *   2. Dual-Mode Enforcement:
 *      - Mode 0 (Complain / Audit Mode): Policy violations are logged to dmesg with
 *        audit flags, but the operations are GRANTED (permissive learning mode).
 *      - Mode 1 (Enforce Mode): Policy violations are strictly BLOCKED, returning
 *        -EACCES or -EPERM immediately, protecting against privilege escalation.
 *   3. Regulated Operations: File pathname access, raw socket creation, ptrace inspection.
 *
 * Exposes /proc/vuln_apparmor (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_apparmor"
#define PROFILE_NAME  "vuln_apparmor_service"

/* 0 = Complain / Baseline Mode, 1 = Enforce / Hardened Mode */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_requests = 0;
static unsigned long g_granted_requests = 0;
static unsigned long g_denied_requests = 0;
static unsigned long g_file_violations = 0;
static unsigned long g_net_violations = 0;
static unsigned long g_ptrace_violations = 0;

/* Access operation types */
enum apparmor_op_type {
	AA_OP_NORMAL_READ = 0,
	AA_OP_RESTRICTED_FILE,   /* e.g. /tmp/secret_token or /etc/shadow */
	AA_OP_RAW_SOCKET,        /* network inet raw creation */
	AA_OP_PTRACE_INSPECT,    /* ptrace attached to unconfined process */
};

/*
 * Evaluates access under AppArmor profile confinement rules
 */
static int evaluate_apparmor_policy(enum apparmor_op_type op, const char **violation_reason)
{
	g_total_requests++;

	switch (op) {
	case AA_OP_NORMAL_READ:
		*violation_reason = NULL;
		g_granted_requests++;
		return 0;

	case AA_OP_RESTRICTED_FILE:
		if (g_mode == 0) {
			/* Complain mode: log audit and permit */
			pr_notice("apparmor=\"AUDIT\" operation=\"file_open\" profile=\"%s\" name=\"/tmp/secret_token\" comm=\"exploit\" requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 (COMPLAIN_MODE: ALLOWED)\n",
				PROFILE_NAME);
			*violation_reason = "file_restricted (audited/complain)";
			g_granted_requests++;
			return 0;
		} else {
			/* Enforce mode: block and log deny */
			pr_warn("apparmor=\"DENIED\" operation=\"file_open\" profile=\"%s\" name=\"/tmp/secret_token\" comm=\"exploit\" requested_mask=\"r\" denied_mask=\"r\" fsuid=1000 (ENFORCE_MODE: BLOCKED)\n",
				PROFILE_NAME);
			*violation_reason = "file_restricted (path violation)";
			g_denied_requests++;
			g_file_violations++;
			return -EACCES;
		}

	case AA_OP_RAW_SOCKET:
		if (g_mode == 0) {
			pr_notice("apparmor=\"AUDIT\" operation=\"create\" profile=\"%s\" family=\"inet\" sock_type=\"raw\" protocol=1 comm=\"exploit\" (COMPLAIN_MODE: ALLOWED)\n",
				PROFILE_NAME);
			*violation_reason = "net_raw (audited/complain)";
			g_granted_requests++;
			return 0;
		} else {
			pr_warn("apparmor=\"DENIED\" operation=\"create\" profile=\"%s\" family=\"inet\" sock_type=\"raw\" protocol=1 comm=\"exploit\" (ENFORCE_MODE: BLOCKED)\n",
				PROFILE_NAME);
			*violation_reason = "net_raw (network violation)";
			g_denied_requests++;
			g_net_violations++;
			return -EPERM;
		}

	case AA_OP_PTRACE_INSPECT:
		if (g_mode == 0) {
			pr_notice("apparmor=\"AUDIT\" operation=\"ptrace\" profile=\"%s\" comm=\"exploit\" requested_mask=\"trace\" (COMPLAIN_MODE: ALLOWED)\n",
				PROFILE_NAME);
			*violation_reason = "ptrace_trace (audited/complain)";
			g_granted_requests++;
			return 0;
		} else {
			pr_warn("apparmor=\"DENIED\" operation=\"ptrace\" profile=\"%s\" comm=\"exploit\" requested_mask=\"trace\" (ENFORCE_MODE: BLOCKED)\n",
				PROFILE_NAME);
			*violation_reason = "ptrace_trace (cross-profile violation)";
			g_denied_requests++;
			g_ptrace_violations++;
			return -EPERM;
		}

	default:
		*violation_reason = "unknown";
		return -EINVAL;
	}
}

/*
 * In-Kernel Verification Benchmark
 */
static int run_apparmor_benchmark(void)
{
	const char *reason = NULL;
	int ret_file, ret_net, ret_ptrace;

	ret_file = evaluate_apparmor_policy(AA_OP_RESTRICTED_FILE, &reason);
	ret_net  = evaluate_apparmor_policy(AA_OP_RAW_SOCKET, &reason);
	ret_ptrace = evaluate_apparmor_policy(AA_OP_PTRACE_INSPECT, &reason);

	if (g_mode == 0) {
		pr_info("vuln_apparmor: [BENCHMARK] Complain mode: All violations allowed under audit observation\n");
		return 0;
	} else {
		if (ret_file == -EACCES && ret_net == -EPERM && ret_ptrace == -EPERM) {
			pr_info("vuln_apparmor: [BENCHMARK] Enforce mode: All policy violations strictly BLOCKED!\n");
			return 1;
		}
		pr_warn("vuln_apparmor: [BENCHMARK] Enforce mode verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_apparmor_read(struct file *file, char __user *buf,
				  size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Enforce (Hardened - Access strictly denied)" : "Complain (Baseline - Audited but allowed)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"    AppArmor Profile Confinement Status Report          \n"
		"========================================================\n"
		"Target Service Profile  : %s\n"
		"Current Profile Mode    : [%d] %s\n"
		"Confinement Scope       : Path-based Filesystem, Network Sockets, Ptrace\n"
		"Total Evaluated Requests: %lu\n"
		"Access Requests Granted : %lu\n"
		"Access Requests Denied  : %lu\n"
		"  - Path / File Denials : %lu\n"
		"  - Raw Network Denials : %lu\n"
		"  - Cross-Ptrace Denials: %lu\n"
		"Policy Directives       :\n"
		"  /home/lab/** r,             (Allowed in both modes)\n"
		"  deny /tmp/secret_token rw,  (Restricted path)\n"
		"  deny network raw,           (Restricted socket)\n"
		"  deny ptrace,                (Restricted debug)\n"
		"Available Commands      :\n"
		"  echo 'mode complain'         > /proc/vuln_apparmor\n"
		"  echo 'mode enforce'          > /proc/vuln_apparmor\n"
		"  echo 'test normal'           > /proc/vuln_apparmor\n"
		"  echo 'test file'             > /proc/vuln_apparmor\n"
		"  echo 'test network'          > /proc/vuln_apparmor\n"
		"  echo 'test ptrace'           > /proc/vuln_apparmor\n"
		"  echo 'run_bench'             > /proc/vuln_apparmor\n"
		"========================================================\n",
		PROFILE_NAME,
		g_mode, mode_str,
		g_total_requests,
		g_granted_requests,
		g_denied_requests,
		g_file_violations,
		g_net_violations,
		g_ptrace_violations);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_apparmor_write(struct file *file, const char __user *buf,
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

	if (strcmp(cmd, "mode complain") == 0 || strcmp(cmd, "mode 0") == 0) {
		g_mode = 0;
		pr_info("vuln_apparmor: Switched to Mode 0: Complain (Audit / Permissive)\n");
	} else if (strcmp(cmd, "mode enforce") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_apparmor: Switched to Mode 1: Enforce (Hardened Confinement Active)\n");
	} else if (strcmp(cmd, "test normal") == 0) {
		int ret = evaluate_apparmor_policy(AA_OP_NORMAL_READ, &reason);
		pr_info("vuln_apparmor: Access 'normal': %s\n", ret == 0 ? "GRANTED" : "DENIED");
	} else if (strcmp(cmd, "test file") == 0) {
		int ret = evaluate_apparmor_policy(AA_OP_RESTRICTED_FILE, &reason);
		pr_info("vuln_apparmor: Access 'restricted_file': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test network") == 0) {
		int ret = evaluate_apparmor_policy(AA_OP_RAW_SOCKET, &reason);
		pr_info("vuln_apparmor: Access 'raw_network': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test ptrace") == 0) {
		int ret = evaluate_apparmor_policy(AA_OP_PTRACE_INSPECT, &reason);
		pr_info("vuln_apparmor: Access 'ptrace': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_apparmor_benchmark();
	} else {
		pr_warn("vuln_apparmor: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_apparmor_proc_ops = {
	.proc_read  = vuln_apparmor_read,
	.proc_write = vuln_apparmor_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_apparmor_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_apparmor_read,
	.write   = vuln_apparmor_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_apparmor_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_apparmor_proc_ops);
	if (!entry) {
		pr_err("vuln_apparmor: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_apparmor: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_apparmor_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_apparmor: Driver unloaded\n");
}

module_init(vuln_apparmor_init);
module_exit(vuln_apparmor_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("AppArmor Profile Confinement and Path-Based MAC Lab");
MODULE_LICENSE("GPL");
