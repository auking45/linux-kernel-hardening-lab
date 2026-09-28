// SPDX-License-Identifier: GPL-2.0
/*
 * labs/28-selinux/vuln_selinux.c
 *
 * Target driver demonstrating SELinux (Security-Enhanced Linux) Type Enforcement (TE),
 * Domain Transitions, Multi-Level Security (MLS Bell-LaPadula), and Permissive vs. Enforcing modes.
 *
 * Key Concepts:
 *   1. Type Enforcement (TE): Access decisions are based on the security context triplet:
 *      (Source Subject Type, Target Object Type, Object Class).
 *      Syntax: allow scontext_t tcontext_t:class { perms };
 *   2. Multi-Level Security (MLS): Enforces Bell-LaPadula confidentiality:
 *      - "No Read Up" (Simple Security Property): A subject at sensitivity s0 cannot read s1.
 *      - "No Write Down" (*-Property): A subject at sensitivity s1 cannot write to s0.
 *   3. Dual-Mode Enforcement:
 *      - Mode 0 (Permissive / Baseline): Violations generate AVC audit records in dmesg
 *        with "(permissive)" tag, but requests are GRANTED.
 *      - Mode 1 (Enforcing / Hardened): Violations generate AVC audit records and return
 *        -EACCES immediately, containing the compromised process.
 *
 * Exposes /proc/vuln_selinux (mode 0666) with in-kernel benchmark routines.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_selinux"
#define SUBJECT_SCONTEXT "system_u:system_r:httpd_t:s0"

/* 0 = Permissive / Baseline, 1 = Enforcing / Hardened */
static int g_mode = 1;

/* Statistics */
static unsigned long g_total_checks = 0;
static unsigned long g_granted_checks = 0;
static unsigned long g_denied_checks = 0;
static unsigned long g_te_denials = 0;
static unsigned long g_mls_denials = 0;
static unsigned long g_trans_denials = 0;

/* Access test operations */
enum selinux_test_op {
	OP_ALLOWED_CONTENT = 0, /* httpd_t reading httpd_sys_content_t: allowed */
	OP_SHADOW_ACCESS,       /* httpd_t reading shadow_t: TE violation */
	OP_MLS_READ_UP,         /* httpd_t (s0) reading top_secret_t (s1): MLS violation */
	OP_ILLEGAL_TRANSITION,  /* httpd_t transitioning to unconfined_t: Domain violation */
};

/*
 * Evaluates access under simulated SELinux Type Enforcement & MLS engine
 */
static int evaluate_selinux_avc(enum selinux_test_op op, const char **reason)
{
	g_total_checks++;

	switch (op) {
	case OP_ALLOWED_CONTENT:
		*reason = NULL;
		g_granted_checks++;
		return 0;

	case OP_SHADOW_ACCESS:
		if (g_mode == 0) {
			pr_notice("type=1400 audit(avc): denied { read } for pid=%d comm=\"exploit\" name=\"shadow\" dev=\"vda\" ino=1357 scontext=%s tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=1\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "shadow_access (audited/permissive)";
			g_granted_checks++;
			return 0;
		} else {
			pr_warn("type=1400 audit(avc): denied { read } for pid=%d comm=\"exploit\" name=\"shadow\" dev=\"vda\" ino=1357 scontext=%s tcontext=system_u:object_r:shadow_t:s0 tclass=file permissive=0 (ENFORCING: BLOCKED)\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "shadow_access (TE violation: httpd_t -> shadow_t denied)";
			g_denied_checks++;
			g_te_denials++;
			return -EACCES;
		}

	case OP_MLS_READ_UP:
		if (g_mode == 0) {
			pr_notice("type=1400 audit(avc): denied { read } for pid=%d comm=\"exploit\" name=\"top_secret\" scontext=%s tcontext=system_u:object_r:secret_t:s1:c0 tclass=file permissive=1 (MLS: READ-UP ALLOWED)\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "mls_read_up (audited/permissive)";
			g_granted_checks++;
			return 0;
		} else {
			pr_warn("type=1400 audit(avc): denied { read } for pid=%d comm=\"exploit\" name=\"top_secret\" scontext=%s tcontext=system_u:object_r:secret_t:s1:c0 tclass=file permissive=0 (MLS: NO READ-UP BLOCKED)\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "mls_read_up (Bell-LaPadula: s0 cannot read s1)";
			g_denied_checks++;
			g_mls_denials++;
			return -EACCES;
		}

	case OP_ILLEGAL_TRANSITION:
		if (g_mode == 0) {
			pr_notice("type=1400 audit(avc): denied { transition } for pid=%d comm=\"exploit\" scontext=%s tcontext=unconfined_u:unconfined_r:unconfined_t:s0 tclass=process permissive=1\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "domain_trans (audited/permissive)";
			g_granted_checks++;
			return 0;
		} else {
			pr_warn("type=1400 audit(avc): denied { transition } for pid=%d comm=\"exploit\" scontext=%s tcontext=unconfined_u:unconfined_r:unconfined_t:s0 tclass=process permissive=0 (DOMAIN: BLOCKED)\n",
				current->pid, SUBJECT_SCONTEXT);
			*reason = "domain_trans (Unauthorized domain escape blocked)";
			g_denied_checks++;
			g_trans_denials++;
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
static int run_selinux_benchmark(void)
{
	const char *reason = NULL;
	int ret_shadow, ret_mls, ret_trans;

	ret_shadow = evaluate_selinux_avc(OP_SHADOW_ACCESS, &reason);
	ret_mls    = evaluate_selinux_avc(OP_MLS_READ_UP, &reason);
	ret_trans  = evaluate_selinux_avc(OP_ILLEGAL_TRANSITION, &reason);

	if (g_mode == 0) {
		pr_info("vuln_selinux: [BENCHMARK] Permissive mode: All violations allowed with audit trail\n");
		return 0;
	} else {
		if (ret_shadow == -EACCES && ret_mls == -EACCES && ret_trans == -EACCES) {
			pr_info("vuln_selinux: [BENCHMARK] Enforcing mode: All TE & MLS violations strictly BLOCKED!\n");
			return 1;
		}
		pr_warn("vuln_selinux: [BENCHMARK] Enforcing mode verification mismatch!\n");
		return -1;
	}
}

/* Procfs read handler */
static ssize_t vuln_selinux_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	char kbuf[1024];
	int len = 0;
	const char *mode_str = (g_mode == 1) ? "Enforcing (Hardened - Access strictly denied)" : "Permissive (Baseline - Audited but allowed)";

	len += scnprintf(kbuf + len, sizeof(kbuf) - len,
		"========================================================\n"
		"    SELinux Type Enforcement (TE) & MLS Status Report   \n"
		"========================================================\n"
		"Subject Security Context: %s\n"
		"Current SELinux Mode    : [%d] %s\n"
		"Confinement Architecture: Type Enforcement (TE) + MLS (Bell-LaPadula)\n"
		"Total AVC Evaluations   : %lu\n"
		"Access Requests Granted : %lu\n"
		"Access Requests Denied  : %lu\n"
		"  - TE Shadow Denials   : %lu\n"
		"  - MLS Read-Up Denials : %lu\n"
		"  - Domain Trans Denials: %lu\n"
		"Policy Directives       :\n"
		"  allow httpd_t httpd_sys_content_t:file { read open getattr };\n"
		"  neverallow httpd_t shadow_t:file { read };\n"
		"  mls: s0 dom s0 (s0 cannot dominate s1 -> No Read Up);\n"
		"Available Commands      :\n"
		"  echo 'mode permissive'       > /proc/vuln_selinux\n"
		"  echo 'mode enforcing'        > /proc/vuln_selinux\n"
		"  echo 'test content'          > /proc/vuln_selinux\n"
		"  echo 'test shadow'           > /proc/vuln_selinux\n"
		"  echo 'test mls'              > /proc/vuln_selinux\n"
		"  echo 'test transition'       > /proc/vuln_selinux\n"
		"  echo 'run_bench'             > /proc/vuln_selinux\n"
		"========================================================\n",
		SUBJECT_SCONTEXT,
		g_mode, mode_str,
		g_total_checks,
		g_granted_checks,
		g_denied_checks,
		g_te_denials,
		g_mls_denials,
		g_trans_denials);

	return simple_read_from_buffer(buf, count, ppos, kbuf, len);
}

/* Procfs write handler */
static ssize_t vuln_selinux_write(struct file *file, const char __user *buf,
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
		pr_info("vuln_selinux: Switched to Mode 0: Permissive (Audit only)\n");
	} else if (strcmp(cmd, "mode enforcing") == 0 || strcmp(cmd, "mode 1") == 0) {
		g_mode = 1;
		pr_info("vuln_selinux: Switched to Mode 1: Enforcing (Hardened TE Enforcement Active)\n");
	} else if (strcmp(cmd, "test content") == 0) {
		int ret = evaluate_selinux_avc(OP_ALLOWED_CONTENT, &reason);
		pr_info("vuln_selinux: Access 'content': %s\n", ret == 0 ? "GRANTED" : "DENIED");
	} else if (strcmp(cmd, "test shadow") == 0) {
		int ret = evaluate_selinux_avc(OP_SHADOW_ACCESS, &reason);
		pr_info("vuln_selinux: Access 'shadow': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test mls") == 0) {
		int ret = evaluate_selinux_avc(OP_MLS_READ_UP, &reason);
		pr_info("vuln_selinux: Access 'mls': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "test transition") == 0) {
		int ret = evaluate_selinux_avc(OP_ILLEGAL_TRANSITION, &reason);
		pr_info("vuln_selinux: Access 'transition': %s (%s)\n",
			ret == 0 ? "GRANTED" : "DENIED", reason ? reason : "none");
	} else if (strcmp(cmd, "run_bench") == 0) {
		run_selinux_benchmark();
	} else {
		pr_warn("vuln_selinux: Unknown command '%s'\n", cmd);
	}

	return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_selinux_proc_ops = {
	.proc_read  = vuln_selinux_read,
	.proc_write = vuln_selinux_write,
	.proc_lseek = default_llseek,
};
#else
static const struct file_operations vuln_selinux_proc_ops = {
	.owner   = THIS_MODULE,
	.read    = vuln_selinux_read,
	.write   = vuln_selinux_write,
	.llseek  = default_llseek,
};
#endif

static int __init vuln_selinux_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_selinux_proc_ops);
	if (!entry) {
		pr_err("vuln_selinux: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_selinux: Driver loaded (/proc/%s, mode=%d)\n", PROC_FILENAME, g_mode);
	return 0;
}

static void __exit vuln_selinux_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_selinux: Driver unloaded\n");
}

module_init(vuln_selinux_init);
module_exit(vuln_selinux_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("SELinux Type Enforcement, Domain Transitions, and MLS Lab");
MODULE_LICENSE("GPL");
