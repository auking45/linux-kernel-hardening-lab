// SPDX-License-Identifier: GPL-2.0
/*
 * labs/35-seccomp/vuln_seccomp.c
 *
 * Target driver demonstrating Linux Seccomp (Secure Computing with BPF Filters):
 *   - SECCOMP_MODE_DISABLED (0): No system call filtering active.
 *   - SECCOMP_MODE_STRICT   (1): Only read(), write(), _exit(), sigreturn() permitted.
 *   - SECCOMP_MODE_FILTER   (2): Custom BPF filter rules evaluated on every syscall.
 *
 * Seccomp Return Actions:
 *   - SECCOMP_RET_ALLOW        (0x7fff0000): Syscall proceeds normally.
 *   - SECCOMP_RET_ERRNO        (0x00050000): Syscall rejected with designated errno (-EPERM).
 *   - SECCOMP_RET_KILL_PROCESS (0x00000000): Task abruptly terminated (SIGSYS / core dump).
 *
 * Exposes /proc/vuln_seccomp (mode 0666) to test and measure syscall sandbox policies.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>
#include <linux/sched.h>
#include <linux/seccomp.h>

#define PROC_FILENAME "vuln_seccomp"

/* 0: Disabled, 1: Strict, 2: BPF Filter */
static int g_seccomp_mode = 2;

/* Statistics */
static unsigned long g_total_syscalls = 0;
static unsigned long g_allowed_syscalls = 0;
static unsigned long g_errno_denials = 0;
static unsigned long g_killed_calls = 0;

enum seccomp_test_op {
	OP_SAFE_SYSCALL = 0,    /* read, write, exit_group */
	OP_RESTRICTED_SYSCALL,  /* ptrace, reboot, unshare */
	OP_LETHAL_SYSCALL,      /* critical exploit payload syscall */
};

static int evaluate_seccomp(enum seccomp_test_op op, const char **reason)
{
	g_total_syscalls++;

	switch (op) {
	case OP_SAFE_SYSCALL:
		pr_info("seccomp: [ALLOW] Comm=\"%s\" pid=%d executed safe syscall -> SECCOMP_RET_ALLOW (ret = 0)\n",
			current->comm, current->pid);
		*reason = "safe_syscall (Whitelisted in BPF filter: SECCOMP_RET_ALLOW)";
		g_allowed_syscalls++;
		return 0;

	case OP_RESTRICTED_SYSCALL:
		if (g_seccomp_mode >= 1) {
			pr_warn("seccomp: [DENIED] Comm=\"%s\" attempted restricted syscall -> SECCOMP_RET_ERRNO (-EPERM)\n",
				current->comm);
			*reason = "restricted_syscall (Blocked by filter: SECCOMP_RET_ERRNO -EPERM)";
			g_errno_denials++;
			return -EPERM;
		}
		pr_warn("seccomp: [DISABLED] Restricted syscall permitted in Mode 0 (Disabled)\n");
		*reason = "restricted_syscall (ALLOWED in Disabled mode)";
		g_allowed_syscalls++;
		return 0;

	case OP_LETHAL_SYSCALL:
		if (g_seccomp_mode == 2) {
			pr_err("seccomp: [KILL] Comm=\"%s\" attempted forbidden lethal syscall -> SECCOMP_RET_KILL_PROCESS!\n",
				current->comm);
			*reason = "lethal_syscall (Terminated: SECCOMP_RET_KILL_PROCESS)";
			g_killed_calls++;
			return -EPERM;
		}
		*reason = "lethal_syscall (Permitted in current mode)";
		g_allowed_syscalls++;
		return 0;

	default:
		*reason = "invalid_op";
		return -EINVAL;
	}
}

static ssize_t vuln_seccomp_read(struct file *file, char __user *buf,
				 size_t count, loff_t *ppos)
{
	char *page;
	int len = 0;
	ssize_t ret;
	const char *mode_str = "Disabled (0)";

	if (g_seccomp_mode == 1)
		mode_str = "Strict (1: read/write/exit only)";
	else if (g_seccomp_mode == 2)
		mode_str = "BPF Filter (2: Fine-grained BPF Program)";

	page = kzalloc(2048, GFP_KERNEL);
	if (!page)
		return -ENOMEM;

	len += scnprintf(page + len, 2048 - len,
		"========================================================\n"
		"      Linux Seccomp-BPF Sandbox Status Report           \n"
		"========================================================\n"
		"Current Seccomp Mode    : [%d] %s\n"
		"Caller Seccomp Status   : mode=%d\n"
		"Total Syscalls Screened : %lu\n"
		"Syscalls Allowed (RET_ALLOW) : %lu\n"
		"Syscalls Denied (RET_ERRNO) : %lu\n"
		"Syscalls Killed (RET_KILL)  : %lu\n"
		"Available Commands      :\n"
		"  echo 'mode disabled'    > /proc/%s\n"
		"  echo 'mode strict'      > /proc/%s\n"
		"  echo 'mode filter'      > /proc/%s\n"
		"  echo 'test safe'        > /proc/%s\n"
		"  echo 'test restricted'  > /proc/%s\n"
		"  echo 'test lethal'      > /proc/%s\n"
		"  echo 'reset'            > /proc/%s\n"
		"========================================================\n",
		g_seccomp_mode, mode_str,
#if defined(CONFIG_SECCOMP)
		current->seccomp.mode,
#else
		0,
#endif
		g_total_syscalls,
		g_allowed_syscalls,
		g_errno_denials,
		g_killed_calls,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME,
		PROC_FILENAME, PROC_FILENAME, PROC_FILENAME, PROC_FILENAME);

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_seccomp_write(struct file *file, const char __user *buf,
				  size_t count, loff_t *ppos)
{
	char kbuf[128];
	const char *reason = "";
	int ret;

	if (count == 0 || count >= sizeof(kbuf))
		return -EINVAL;

	if (copy_from_user(kbuf, buf, count))
		return -EFAULT;

	kbuf[count] = '\0';
	strim(kbuf);

	if (strcmp(kbuf, "mode disabled") == 0) {
		g_seccomp_mode = 0;
		pr_info("vuln_seccomp: Set mode DISABLED (0)\n");
		return count;
	}

	if (strcmp(kbuf, "mode strict") == 0) {
		g_seccomp_mode = 1;
		pr_info("vuln_seccomp: Set mode STRICT (1)\n");
		return count;
	}

	if (strcmp(kbuf, "mode filter") == 0) {
		g_seccomp_mode = 2;
		pr_info("vuln_seccomp: Set mode BPF FILTER (2)\n");
		return count;
	}

	if (strcmp(kbuf, "test safe") == 0) {
		ret = evaluate_seccomp(OP_SAFE_SYSCALL, &reason);
		pr_info("vuln_seccomp: Request 'safe': %s (%s)\n",
			(ret == 0) ? "GRANTED" : "DENIED", reason);
		return (ret == 0) ? count : ret;
	}

	if (strcmp(kbuf, "test restricted") == 0) {
		ret = evaluate_seccomp(OP_RESTRICTED_SYSCALL, &reason);
		if (ret != 0) {
			pr_warn("vuln_seccomp: Request 'restricted': DENIED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_seccomp: Request 'restricted': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "test lethal") == 0) {
		ret = evaluate_seccomp(OP_LETHAL_SYSCALL, &reason);
		if (ret != 0) {
			pr_err("vuln_seccomp: Request 'lethal': TERMINATED (%s)\n", reason);
			return ret;
		}
		pr_info("vuln_seccomp: Request 'lethal': GRANTED (%s)\n", reason);
		return count;
	}

	if (strcmp(kbuf, "reset") == 0) {
		g_total_syscalls = 0;
		g_allowed_syscalls = 0;
		g_errno_denials = 0;
		g_killed_calls = 0;
		pr_info("vuln_seccomp: Statistics reset\n");
		return count;
	}

	pr_warn("vuln_seccomp: Unknown command '%s'\n", kbuf);
	return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_seccomp_proc_ops = {
	.proc_read  = vuln_seccomp_read,
	.proc_write = vuln_seccomp_write,
};
#else
static const struct file_operations vuln_seccomp_proc_ops = {
	.owner = THIS_MODULE,
	.read  = vuln_seccomp_read,
	.write = vuln_seccomp_write,
};
#endif

static int __init vuln_seccomp_init(void)
{
	struct proc_dir_entry *entry;

	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_seccomp_proc_ops);
	if (!entry) {
		pr_err("vuln_seccomp: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_seccomp: Driver loaded (/proc/%s, mode=%d)\n",
		PROC_FILENAME, g_seccomp_mode);
	return 0;
}

static void __exit vuln_seccomp_exit(void)
{
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_seccomp: Driver unloaded\n");
}

module_init(vuln_seccomp_init);
module_exit(vuln_seccomp_exit);

MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Target driver demonstrating Seccomp-BPF Syscall Filtering");
MODULE_LICENSE("GPL");
