// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Memory Permissions (W^X) Verification Target
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_strict_rwx with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. CONFIG_STRICT_KERNEL_RWX & CONFIG_STRICT_MODULE_RWX (W^X invariant).
 * 2. Hardware MMU write protection of .text, .rodata, and __ro_after_init.
 * 3. Mitigation against rootkit syscall table hooking and in-memory code patching.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/string.h>
#include <linux/kconfig.h>

#define VULN_PROC_NAME "vuln_strict_rwx"

#if defined(CONFIG_STRICT_KERNEL_RWX) || defined(CONFIG_STRICT_MODULE_RWX)
extern bool rodata_enabled;
#else
static bool rodata_enabled = false;
#endif

/* Target function in .text section */
noinline void vuln_target_function(void)
{
    pr_info("[vuln_strict_rwx] vuln_target_function invoked\n");
}

/* Target constant in .rodata section */
static const unsigned long vuln_target_rodata = 0x55AA55AA11223344ULL;

/* Target variable in __ro_after_init section */
static unsigned long vuln_target_ro_after_init __ro_after_init = 0xAA55AA5588776655ULL;

/* Target variable in .data section */
static unsigned long vuln_target_data = 0xCAFEBABE00112233ULL;

/* Last test results: -1 = not tested, 0 = writable (vulnerable), 1 = blocked (hardened) */
static int last_text_result = -1;
static int last_rodata_result = -1;
static int last_ro_after_init_result = -1;

static int vuln_strict_rwx_show(struct seq_file *m, void *v)
{
    bool is_strict_rwx = IS_ENABLED(CONFIG_STRICT_KERNEL_RWX);
    bool is_strict_module = IS_ENABLED(CONFIG_STRICT_MODULE_RWX);
    bool active = is_strict_rwx && rodata_enabled;

    seq_printf(m, "STRICT_KERNEL_RWX:     %s\n", is_strict_rwx ? "CONFIGURED" : "DISABLED");
    seq_printf(m, "STRICT_MODULE_RWX:     %s\n", is_strict_module ? "CONFIGURED" : "DISABLED");
    seq_printf(m, "RODATA_BOOT_PARAM:     %s\n", rodata_enabled ? "rodata=on (Active)" : "rodata=off (Disabled)");
    seq_printf(m, "WX_PROTECTION_STATUS:  %s\n", active ? "ENABLED (Hardened W^X)" : "DISABLED (Vulnerable W+X)");
    seq_printf(m, "TARGET_TEXT_ADDR:      0x%px\n", vuln_target_function);
    seq_printf(m, "TARGET_RODATA_ADDR:    0x%px\n", &vuln_target_rodata);
    seq_printf(m, "TARGET_RO_AFTER_INIT:  0x%px\n", &vuln_target_ro_after_init);
    seq_printf(m, "TARGET_DATA_ADDR:      0x%px\n", &vuln_target_data);
    seq_printf(m, "TEXT_WRITE_RESULT:     %s\n",
               last_text_result == -1 ? "NOT_TESTED" :
               (last_text_result == 1 ? "BLOCKED (Read-Only)" : "PERMITTED (Writable)"));
    seq_printf(m, "RODATA_WRITE_RESULT:   %s\n",
               last_rodata_result == -1 ? "NOT_TESTED" :
               (last_rodata_result == 1 ? "BLOCKED (Read-Only)" : "PERMITTED (Writable)"));
    seq_printf(m, "RO_AFTER_INIT_RESULT:  %s\n",
               last_ro_after_init_result == -1 ? "NOT_TESTED" :
               (last_ro_after_init_result == 1 ? "BLOCKED (Read-Only)" : "PERMITTED (Writable)"));

    return 0;
}

static int vuln_strict_rwx_open(struct inode *inode, struct file *file)
{
    return single_open(file, vuln_strict_rwx_show, NULL);
}

static ssize_t vuln_strict_rwx_write(struct file *file, const char __user *ubuf,
                                     size_t count, loff_t *ppos)
{
    char kbuf[64];
    unsigned char patch_bytes[4] = { 0x90, 0x90, 0x90, 0x90 }; // NOP instructions
    unsigned long new_val = 0xDEADDEADDEADDEADULL;

    if (count == 0 || count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (strstr(kbuf, "test_write_text") || strstr(kbuf, "all")) {
        pr_info("[vuln_strict_rwx] Vector 1: Attempting to patch kernel .text at 0x%px...\n", vuln_target_function);
        if (copy_to_kernel_nofault((void *)vuln_target_function, patch_bytes, sizeof(patch_bytes))) {
            pr_info("[vuln_strict_rwx] [+] DEFENSE ACTIVE: Kernel .text write blocked by MMU (EFAULT)!\n");
            last_text_result = 1;
        } else {
            pr_warn("[vuln_strict_rwx] [!] CRITICAL: Kernel .text successfully modified! Rootkit code patching confirmed!\n");
            last_text_result = 0;
        }
    }

    if (strstr(kbuf, "test_write_rodata") || strstr(kbuf, "all")) {
        pr_info("[vuln_strict_rwx] Vector 2: Attempting to overwrite .rodata at 0x%px...\n", &vuln_target_rodata);
        if (copy_to_kernel_nofault((void *)&vuln_target_rodata, &new_val, sizeof(new_val))) {
            pr_info("[vuln_strict_rwx] [+] DEFENSE ACTIVE: .rodata write blocked by MMU (EFAULT)!\n");
            last_rodata_result = 1;
        } else {
            pr_warn("[vuln_strict_rwx] [!] CRITICAL: .rodata value corrupted to 0x%lx!\n", vuln_target_rodata);
            last_rodata_result = 0;
        }
    }

    if (strstr(kbuf, "test_write_ro_after_init") || strstr(kbuf, "all")) {
        pr_info("[vuln_strict_rwx] Vector 3: Attempting to overwrite __ro_after_init at 0x%px...\n", &vuln_target_ro_after_init);
        if (copy_to_kernel_nofault((void *)&vuln_target_ro_after_init, &new_val, sizeof(new_val))) {
            pr_info("[vuln_strict_rwx] [+] DEFENSE ACTIVE: __ro_after_init write blocked by MMU (EFAULT)!\n");
            last_ro_after_init_result = 1;
        } else {
            pr_warn("[vuln_strict_rwx] [!] CRITICAL: __ro_after_init value corrupted to 0x%lx!\n", vuln_target_ro_after_init);
            last_ro_after_init_result = 0;
        }
    }

    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_strict_rwx_proc_ops = {
    .proc_open = vuln_strict_rwx_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = vuln_strict_rwx_write,
};
#else
static const struct file_operations vuln_strict_rwx_proc_ops = {
    .open = vuln_strict_rwx_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = vuln_strict_rwx_write,
};
#endif

static int __init vuln_strict_rwx_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_strict_rwx_proc_ops);
    if (!entry) {
        pr_err("[vuln_strict_rwx] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_strict_rwx] Initialized /proc/%s (STRICT_RWX=%d, rodata=%d)\n",
            VULN_PROC_NAME, IS_ENABLED(CONFIG_STRICT_KERNEL_RWX), rodata_enabled);
    return 0;
}

device_initcall(vuln_strict_rwx_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("CONFIG_STRICT_KERNEL_RWX Verification Target");

