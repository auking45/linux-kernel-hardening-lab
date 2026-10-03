// SPDX-License-Identifier: GPL-2.0
/*
 * labs/43-avf-pkvm/vuln_avf.c
 *
 * Target driver demonstrating Android Virtualization Framework (AVF) and pKVM:
 *   1. Architectural Concept:
 *      - Protected KVM (pKVM) deprivileges the Host Android OS (EL1).
 *      - Hypervisor runs at EL2 and manages Stage-2 Page Tables (S2PT) independently.
 *      - Micro-guests (pVMs) receive dedicated physical memory pages donated from the host.
 *      - Crucially, pKVM UNMAPS these pages from the Host's Stage-2 address space.
 *   2. Defense Against Compromised Host:
 *      - Even if the Host Android OS is completely rooted (Kernel LPE), any direct attempt
 *        by the host kernel to read or write pVM memory triggers a Stage-2 Data Abort at EL2!
 *      - Host cannot steal biometric templates, DRM keys, or secure enclave credentials.
 *   3. Isolated Inter-VM Communication:
 *      - Communication between Host and pVM occurs strictly over virtio-vsock or hypervisor
 *        controlled shared-memory grants (mem_share hypercalls).
 *
 * Exposes /proc/vuln_avf (mode 0666) to evaluate pKVM Stage-2 isolation and pVM defense mechanics.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_avf"
#define MAX_PVMS 4

struct pvm_instance {
	int id;
	bool active;
	bool stage2_isolated; /* True if unmapped from host stage-2 page tables */
	char secret_payload[128];
};

static struct pvm_instance g_pvms[MAX_PVMS];
static int g_pkvm_enabled = 1; /* 1: pKVM active (Host deprivileged), 0: Legacy KVM */

/* Statistics */
static unsigned long g_total_attempts = 0;
static unsigned long g_host_peeks_blocked = 0;
static unsigned long g_host_tampers_blocked = 0;
static unsigned long g_vsock_messages = 0;

static void init_pvms(void)
{
	int i;
	for (i = 0; i < MAX_PVMS; i++) {
		g_pvms[i].id = i;
		g_pvms[i].active = false;
		g_pvms[i].stage2_isolated = false;
		memset(g_pvms[i].secret_payload, 0, sizeof(g_pvms[i].secret_payload));
	}
}

static int pvm_create(int id, const char *secret)
{
	if (id < 0 || id >= MAX_PVMS)
		return -EINVAL;

	g_pvms[id].active = true;
	g_pvms[id].stage2_isolated = (g_pkvm_enabled != 0);
	strscpy(g_pvms[id].secret_payload, secret, sizeof(g_pvms[id].secret_payload));

	pr_info("avf_pkvm: [PVM-CREATE] Micro-guest pVM #%d spawned. Memory donated. Stage-2 Isolated: %s\n",
		id, g_pvms[id].stage2_isolated ? "YES (Unmapped from Host S2PT)" : "NO (Legacy KVM)");
	return 0;
}

static int pvm_destroy(int id)
{
	if (id < 0 || id >= MAX_PVMS || !g_pvms[id].active)
		return -EINVAL;

	/* Secure memory scrubbing before reclaiming */
	memset(g_pvms[id].secret_payload, 0, sizeof(g_pvms[id].secret_payload));
	g_pvms[id].active = false;
	g_pvms[id].stage2_isolated = false;

	pr_info("avf_pkvm: [PVM-DESTROY] pVM #%d destroyed. Memory scrubbed with zeroes.\n", id);
	return 0;
}

static int pvm_host_peek(int id, char *out_buf, size_t max_len)
{
	g_total_attempts++;
	if (id < 0 || id >= MAX_PVMS || !g_pvms[id].active)
		return -EINVAL;

	if (g_pvms[id].stage2_isolated) {
		g_host_peeks_blocked++;
		pr_err("avf_pkvm: [STAGE-2 DATA ABORT] Host EL1 tried to read pVM #%d memory! pKVM EL2 intercepted and blocked access (-EPERM)\n",
		       id);
		return -EPERM;
	}

	/* Unhardened legacy KVM: Host can snoop guest memory */
	pr_warn("avf_pkvm: [VULNERABLE SNOOP] Host read pVM #%d memory (Legacy KVM without pKVM Stage-2 isolation)\n", id);
	strscpy(out_buf, g_pvms[id].secret_payload, max_len);
	return 0;
}

static int pvm_host_tamper(int id, const char *new_data)
{
	g_total_attempts++;
	if (id < 0 || id >= MAX_PVMS || !g_pvms[id].active)
		return -EINVAL;

	if (g_pvms[id].stage2_isolated) {
		g_host_tampers_blocked++;
		pr_err("avf_pkvm: [STAGE-2 WRITE FAULT] Host EL1 tried to overwrite pVM #%d memory! Blocked by pKVM hypervisor (-EPERM)\n",
		       id);
		return -EPERM;
	}

	pr_warn("avf_pkvm: [VULNERABLE TAMPER] Host modified pVM #%d memory without restriction!\n", id);
	strscpy(g_pvms[id].secret_payload, new_data, sizeof(g_pvms[id].secret_payload));
	return 0;
}

static ssize_t vuln_avf_read(struct file *file, char __user *buf,
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
			 "=== Android Virtualization Framework (AVF / pKVM) Status ===\n");
	len += scnprintf(page + len, 2048 - len,
			 "pKVM Protection Mode     : %s\n",
			 g_pkvm_enabled ? "ENABLED (Protected KVM Active)" : "DISABLED (Legacy KVM)");
	len += scnprintf(page + len, 2048 - len,
			 "Total Host Access Events : %lu\n", g_total_attempts);
	len += scnprintf(page + len, 2048 - len,
			 "Host Peeks Blocked (S2PT): %lu\n", g_host_peeks_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "Host Tampers Blocked     : %lu\n", g_host_tampers_blocked);
	len += scnprintf(page + len, 2048 - len,
			 "Vsock RPC Exchanges      : %lu\n", g_vsock_messages);
	len += scnprintf(page + len, 2048 - len,
			 "Active Micro-Guests (pVMs):\n");
	for (i = 0; i < MAX_PVMS; i++) {
		if (g_pvms[i].active) {
			len += scnprintf(page + len, 2048 - len,
					 "  [pVM #%d] Stage-2 Isolated: %s, Secret Status: [SECURED]\n",
					 i, g_pvms[i].stage2_isolated ? "YES" : "NO");
		}
	}
	len += scnprintf(page + len, 2048 - len,
			 "============================================================\n");
	len += scnprintf(page + len, 2048 - len,
			 "Available Commands:\n");
	len += scnprintf(page + len, 2048 - len,
			 "  create <id> <secret>     - Spawn isolated micro-guest pVM\n");
	len += scnprintf(page + len, 2048 - len,
			 "  host_peek <id>           - Host attempts direct memory read\n");
	len += scnprintf(page + len, 2048 - len,
			 "  host_tamper <id> <data>  - Host attempts direct memory write\n");
	len += scnprintf(page + len, 2048 - len,
			 "  vsock <id> <msg>         - Secure communication over vsock\n");
	len += scnprintf(page + len, 2048 - len,
			 "  mode <pkvm|legacy>       - Toggle pKVM Stage-2 isolation mode\n");
	len += scnprintf(page + len, 2048 - len,
			 "  destroy <id>             - Destroy pVM and scrub memory\n");
	len += scnprintf(page + len, 2048 - len,
			 "  reset                    - Clear all pVMs and statistics\n");

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_avf_write(struct file *file, const char __user *buf,
			      size_t count, loff_t *ppos)
{
	char kbuf[128];
	char out[128];
	size_t to_copy;
	int id, res;

	to_copy = min(count, sizeof(kbuf) - 1);
	if (copy_from_user(kbuf, buf, to_copy))
		return -EFAULT;
	kbuf[to_copy] = '\0';

	if (to_copy > 0 && kbuf[to_copy - 1] == '\n')
		kbuf[to_copy - 1] = '\0';

	if (strncmp(kbuf, "create ", 7) == 0) {
		char secret[64] = "DEFAULT_BIOMETRIC_TOKEN";
		if (sscanf(kbuf + 7, "%d %63s", &id, secret) >= 1) {
			res = pvm_create(id, secret);
			if (res < 0) return res;
			return count;
		}
	}

	if (sscanf(kbuf, "host_peek %d", &id) == 1) {
		res = pvm_host_peek(id, out, sizeof(out));
		if (res < 0) return res;
		pr_info("avf_pkvm: [SNOOP SUCCESS] Secret: '%s'\n", out);
		return count;
	}

	if (strncmp(kbuf, "host_tamper ", 12) == 0) {
		char new_data[64] = "TAMPERED_DATA";
		if (sscanf(kbuf + 12, "%d %63s", &id, new_data) >= 1) {
			res = pvm_host_tamper(id, new_data);
			if (res < 0) return res;
			return count;
		}
	}

	if (sscanf(kbuf, "vsock %d", &id) == 1) {
		if (id >= 0 && id < MAX_PVMS && g_pvms[id].active) {
			g_vsock_messages++;
			pr_info("avf_pkvm: [VSOCK RPC] Authenticated request processed by pVM #%d enclave.\n", id);
			return count;
		}
		return -ENODEV;
	}

	if (strncmp(kbuf, "destroy ", 8) == 0) {
		if (sscanf(kbuf + 8, "%d", &id) == 1) {
			res = pvm_destroy(id);
			if (res < 0) return res;
			return count;
		}
	}

	if (strncmp(kbuf, "mode pkvm", 9) == 0) {
		g_pkvm_enabled = 1;
		pr_info("avf_pkvm: pKVM mode enabled (Host deprivileged from pVM memory).\n");
		return count;
	}

	if (strncmp(kbuf, "mode legacy", 11) == 0) {
		g_pkvm_enabled = 0;
		pr_info("avf_pkvm: Legacy KVM mode set (Host has full access to guest memory).\n");
		return count;
	}

	if (strncmp(kbuf, "reset", 5) == 0) {
		init_pvms();
		g_pkvm_enabled = 1;
		g_total_attempts = 0;
		g_host_peeks_blocked = 0;
		g_host_tampers_blocked = 0;
		g_vsock_messages = 0;
		pr_info("avf_pkvm: Reset all micro-guests and statistics.\n");
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops vuln_avf_proc_ops = {
	.proc_read  = vuln_avf_read,
	.proc_write = vuln_avf_write,
};

static int __init vuln_avf_init(void)
{
	struct proc_dir_entry *entry;

	init_pvms();
	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_avf_proc_ops);
	if (!entry) {
		pr_err("vuln_avf: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_avf: Loaded AVF / pKVM target driver at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_avf_exit(void)
{
	init_pvms();
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_avf: Unloaded AVF / pKVM target driver.\n");
}

module_init(vuln_avf_init);
module_exit(vuln_avf_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Android Virtualization Framework (AVF) and pKVM Target Driver");
MODULE_VERSION("1.0");
