// SPDX-License-Identifier: GPL-2.0
/*
 * labs/44-arm-cca/vuln_cca.c
 *
 * Target driver demonstrating Arm Confidential Compute Architecture (Arm CCA):
 *   1. Four-World Architectural Security Model:
 *      - Root World (EL3): Security Monitor, Root of Trust.
 *      - Realm World (R-EL2 / R-EL1): Realm Management Monitor (RMM) and Realm VMs.
 *      - Secure World (S-EL1 / S-EL0): TrustZone / OP-TEE.
 *      - Non-Secure World (NS-EL2 / NS-EL1): Normal Host OS / Cloud Hypervisor (KVM).
 *   2. Hardware Granule Protection Table (GPT) & Granule Protection Check (GPC):
 *      - Physical memory granules (4KB) are assigned to specific security worlds.
 *      - When a granule is delegated to Realm World (GPT_REALM), the hardware GPC unit
 *        blocks any access attempt originating from Non-Secure World (Host / Hypervisor).
 *      - Direct access by the untrusted hypervisor triggers a Granule Protection Fault (GPF).
 *   3. Cryptographic Measurement & Attestation:
 *      - RMM computes cryptographic SHA-256 hashes of initial Realm code and configuration.
 *      - Enables remote verifiers to mathematically attest that the Realm was booted securely.
 *
 * Exposes /proc/vuln_cca (mode 0666) to evaluate Arm CCA Realm protection and GPC hardware defenses.
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/string.h>
#include <linux/version.h>

#define PROC_FILENAME "vuln_cca"
#define MAX_REALMS 4

/* GPT (Granule Protection Table) State */
enum gpt_state {
	GPT_NON_SECURE = 0,
	GPT_REALM      = 1,
	GPT_SECURE     = 2,
	GPT_ROOT       = 3,
};

struct realm_instance {
	int id;
	bool active;
	enum gpt_state memory_gpt;
	char confidential_data[128];
	char measurement_sha256[65];
};

static struct realm_instance g_realms[MAX_REALMS];
static int g_cca_enabled = 1; /* 1: Arm CCA GPC active, 0: Legacy cloud hypervisor */

/* Statistics */
static unsigned long g_total_access_attempts = 0;
static unsigned long g_gpc_read_faults = 0;
static unsigned long g_gpc_write_faults = 0;
static unsigned long g_attestation_verifications = 0;

static void init_realms(void)
{
	int i;
	for (i = 0; i < MAX_REALMS; i++) {
		g_realms[i].id = i;
		g_realms[i].active = false;
		g_realms[i].memory_gpt = GPT_NON_SECURE;
		memset(g_realms[i].confidential_data, 0, sizeof(g_realms[i].confidential_data));
		memset(g_realms[i].measurement_sha256, 0, sizeof(g_realms[i].measurement_sha256));
	}
}

static int realm_create(int id)
{
	if (id < 0 || id >= MAX_REALMS)
		return -EINVAL;

	g_realms[id].active = true;
	g_realms[id].memory_gpt = GPT_NON_SECURE;
	memset(g_realms[id].confidential_data, 0, sizeof(g_realms[id].confidential_data));
	strscpy(g_realms[id].measurement_sha256,
		"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		sizeof(g_realms[id].measurement_sha256));

	pr_info("arm_cca: [RMI_REALM_CREATE] Realm VM #%d created in Realm World (R-EL1).\n", id);
	return 0;
}

static int realm_delegate_granule(int id, const char *data)
{
	if (id < 0 || id >= MAX_REALMS || !g_realms[id].active)
		return -EINVAL;

	if (g_cca_enabled)
		g_realms[id].memory_gpt = GPT_REALM;
	else
		g_realms[id].memory_gpt = GPT_NON_SECURE;

	strscpy(g_realms[id].confidential_data, data, sizeof(g_realms[id].confidential_data));
	/* Simulated unique measurement hash for this payload */
	strscpy(g_realms[id].measurement_sha256,
		"a3f5b721e89b4317c24df98001aa32de78619bc345ef10928374aabf892301cd",
		sizeof(g_realms[id].measurement_sha256));

	pr_info("arm_cca: [RMI_GRANULE_DELEGATE] Physical granule transitioned to GPT_REALM. Managed by RMM.\n");
	return 0;
}

static int realm_destroy(int id)
{
	if (id < 0 || id >= MAX_REALMS || !g_realms[id].active)
		return -EINVAL;

	/* Cryptographic memory wipe before undelegation */
	memset(g_realms[id].confidential_data, 0, sizeof(g_realms[id].confidential_data));
	memset(g_realms[id].measurement_sha256, 0, sizeof(g_realms[id].measurement_sha256));
	g_realms[id].memory_gpt = GPT_NON_SECURE;
	g_realms[id].active = false;

	pr_info("arm_cca: [RMI_GRANULE_UNDELEGATE] Realm #%d memory zeroed and restored to Non-Secure.\n", id);
	return 0;
}

static int realm_host_access(int id, bool is_write, const char *write_data, char *out_buf, size_t max_len)
{
	g_total_access_attempts++;
	if (id < 0 || id >= MAX_REALMS || !g_realms[id].active)
		return -EINVAL;

	/* Hardware Granule Protection Check (GPC) evaluation */
	if (g_realms[id].memory_gpt == GPT_REALM) {
		if (is_write) {
			g_gpc_write_faults++;
			pr_err("arm_cca: [GRANULE PROTECTION FAULT] Host write denied! GPC: Non-Secure CPU cannot write GPT_REALM (-EPERM)\n");
		} else {
			g_gpc_read_faults++;
			pr_err("arm_cca: [GRANULE PROTECTION FAULT] Host read denied! GPC: Non-Secure CPU cannot read GPT_REALM (-EPERM)\n");
		}
		return -EPERM;
	}

	/* Legacy Cloud Hypervisor: Untrusted Host reads/writes tenant memory */
	if (is_write) {
		pr_warn("arm_cca: [VULNERABLE TAMPER] Host modified tenant VM #%d memory! (Legacy Hypervisor)\n", id);
		strscpy(g_realms[id].confidential_data, write_data, sizeof(g_realms[id].confidential_data));
	} else {
		pr_warn("arm_cca: [VULNERABLE SNOOP] Host read tenant VM #%d memory! (Legacy Hypervisor)\n", id);
		strscpy(out_buf, g_realms[id].confidential_data, max_len);
	}
	return 0;
}

static ssize_t vuln_cca_read(struct file *file, char __user *buf,
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
			 "=== Arm Confidential Compute Architecture (Arm CCA) Status ===\n");
	len += scnprintf(page + len, 2048 - len,
			 "Hardware CCA Engine      : %s\n",
			 g_cca_enabled ? "ENABLED (Granule Protection Active)" : "DISABLED (Legacy Hypervisor)");
	len += scnprintf(page + len, 2048 - len,
			 "Security World Model     : 4-World (Root, Realm, Secure, Non-Secure)\n");
	len += scnprintf(page + len, 2048 - len,
			 "Total Host Access Events : %lu\n", g_total_access_attempts);
	len += scnprintf(page + len, 2048 - len,
			 "GPC Read Faults (GPF)    : %lu\n", g_gpc_read_faults);
	len += scnprintf(page + len, 2048 - len,
			 "GPC Write Faults (GPF)   : %lu\n", g_gpc_write_faults);
	len += scnprintf(page + len, 2048 - len,
			 "Attestation Verifications: %lu\n", g_attestation_verifications);
	len += scnprintf(page + len, 2048 - len,
			 "Active Realm VMs (R-EL1):\n");
	for (i = 0; i < MAX_REALMS; i++) {
		if (g_realms[i].active) {
			len += scnprintf(page + len, 2048 - len,
					 "  [Realm #%d] GPT State: %s, Measurement: %.16s...\n",
					 i, (g_realms[i].memory_gpt == GPT_REALM) ? "GPT_REALM (Hardware Protected)" : "GPT_NON_SECURE",
					 g_realms[i].measurement_sha256);
		}
	}
	len += scnprintf(page + len, 2048 - len,
			 "==============================================================\n");
	len += scnprintf(page + len, 2048 - len,
			 "Available Commands:\n");
	len += scnprintf(page + len, 2048 - len,
			 "  create <id>              - Initialize Realm VM instance\n");
	len += scnprintf(page + len, 2048 - len,
			 "  delegate <id> <secret>   - Delegate physical granule to GPT_REALM\n");
	len += scnprintf(page + len, 2048 - len,
			 "  host_read <id>           - Host attempts direct memory read\n");
	len += scnprintf(page + len, 2048 - len,
			 "  host_write <id> <data>   - Host attempts direct memory write\n");
	len += scnprintf(page + len, 2048 - len,
			 "  attest <id>              - Request cryptographic attestation report\n");
	len += scnprintf(page + len, 2048 - len,
			 "  mode <cca|legacy>        - Toggle Granule Protection Table enforcement\n");
	len += scnprintf(page + len, 2048 - len,
			 "  destroy <id>             - Destroy Realm and undelegate memory\n");
	len += scnprintf(page + len, 2048 - len,
			 "  reset                    - Clear all Realms and reset statistics\n");

	ret = simple_read_from_buffer(buf, count, ppos, page, len);
	kfree(page);
	return ret;
}

static ssize_t vuln_cca_write(struct file *file, const char __user *buf,
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
		if (sscanf(kbuf + 7, "%d", &id) == 1) {
			res = realm_create(id);
			if (res < 0) return res;
			return count;
		}
	}

	if (strncmp(kbuf, "delegate ", 9) == 0) {
		char secret[64] = "DEFAULT_CONFIDENTIAL_KEY";
		if (sscanf(kbuf + 9, "%d %63s", &id, secret) >= 1) {
			res = realm_delegate_granule(id, secret);
			if (res < 0) return res;
			return count;
		}
	}

	if (sscanf(kbuf, "host_read %d", &id) == 1) {
		res = realm_host_access(id, false, NULL, out, sizeof(out));
		if (res < 0) return res;
		pr_info("arm_cca: [SNOOP SUCCESS] Host stole secret: '%s'\n", out);
		return count;
	}

	if (strncmp(kbuf, "host_write ", 11) == 0) {
		char new_data[64] = "TAMPERED_REALM_CODE";
		if (sscanf(kbuf + 11, "%d %63s", &id, new_data) >= 1) {
			res = realm_host_access(id, true, new_data, NULL, 0);
			if (res < 0) return res;
			return count;
		}
	}

	if (sscanf(kbuf, "attest %d", &id) == 1) {
		if (id >= 0 && id < MAX_REALMS && g_realms[id].active) {
			g_attestation_verifications++;
			pr_info("arm_cca: [RMI_ATTESTATION] Cryptographic measurement validated: %s\n",
				g_realms[id].measurement_sha256);
			return count;
		}
		return -ENODEV;
	}

	if (strncmp(kbuf, "mode cca", 8) == 0) {
		g_cca_enabled = 1;
		pr_info("arm_cca: Arm CCA Granule Protection enabled.\n");
		return count;
	}

	if (strncmp(kbuf, "mode legacy", 11) == 0) {
		g_cca_enabled = 0;
		pr_info("arm_cca: Legacy cloud mode set (GPC disabled).\n");
		return count;
	}

	if (strncmp(kbuf, "destroy ", 8) == 0) {
		if (sscanf(kbuf + 8, "%d", &id) == 1) {
			res = realm_destroy(id);
			if (res < 0) return res;
			return count;
		}
	}

	if (strncmp(kbuf, "reset", 5) == 0) {
		init_realms();
		g_cca_enabled = 1;
		g_total_access_attempts = 0;
		g_gpc_read_faults = 0;
		g_gpc_write_faults = 0;
		g_attestation_verifications = 0;
		pr_info("arm_cca: Reset all realms and statistics.\n");
		return count;
	}

	return -EINVAL;
}

static const struct proc_ops vuln_cca_proc_ops = {
	.proc_read  = vuln_cca_read,
	.proc_write = vuln_cca_write,
};

static int __init vuln_cca_init(void)
{
	struct proc_dir_entry *entry;

	init_realms();
	entry = proc_create(PROC_FILENAME, 0666, NULL, &vuln_cca_proc_ops);
	if (!entry) {
		pr_err("vuln_cca: Failed to create /proc/%s\n", PROC_FILENAME);
		return -ENOMEM;
	}

	pr_info("vuln_cca: Loaded Arm CCA target driver at /proc/%s\n", PROC_FILENAME);
	return 0;
}

static void __exit vuln_cca_exit(void)
{
	init_realms();
	remove_proc_entry(PROC_FILENAME, NULL);
	pr_info("vuln_cca: Unloaded Arm CCA target driver.\n");
}

module_init(vuln_cca_init);
module_exit(vuln_cca_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Arm Confidential Compute Architecture (Arm CCA) Target Driver");
MODULE_VERSION("1.0");
