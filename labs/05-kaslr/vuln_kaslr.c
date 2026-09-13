// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable KASLR Verification Target for Linux Kernel Hardening Lab
 * Creates /proc/vuln_kaslr with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. Deterministic kernel base & gadget locations when KASLR is disabled (nokaslr).
 * 2. Dynamic KASLR Slide randomization and blind ROP/call prevention when KASLR is active.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>

#define VULN_PROC_NAME "vuln_kaslr"

/* Reference to kernel start text symbol */
extern char _text[];

/* Dedicated test target function for exploit demonstration */
noinline void kaslr_target_function(void)
{
    pr_info("[vuln_kaslr] Target function executed! Address = %px\n", kaslr_target_function);
}

/*
 * Static baseline addresses (without KASLR)
 * x86_64: __START_KERNEL_map (0xffffffff80000000) + PHYSICAL_START (0x1000000) = 0xffffffff81000000
 */
#if defined(CONFIG_X86_64)
#define STATIC_TEXT_BASE 0xffffffff81000000ULL
#elif defined(CONFIG_ARM64)
#define STATIC_TEXT_BASE 0xffff800080000000ULL
#else
#define STATIC_TEXT_BASE 0x0ULL
#endif

static int vuln_kaslr_show(struct seq_file *m, void *v)
{
    unsigned long text_addr = (unsigned long)_text;
    unsigned long func_addr = (unsigned long)kaslr_target_function;
    long slide = (long)(text_addr - STATIC_TEXT_BASE);
    bool is_randomized = (slide != 0);

    seq_printf(m, "KERNEL_TEXT_BASE:  0x%016lx\n", text_addr);
    seq_printf(m, "STATIC_TEXT_BASE:  0x%016llx\n", (unsigned long long)STATIC_TEXT_BASE);
    seq_printf(m, "TARGET_FUNC_ADDR:  0x%016lx\n", func_addr);
    seq_printf(m, "KASLR_SLIDE:       0x%016lx\n", (unsigned long)(slide > 0 ? slide : -slide));
    seq_printf(m, "KASLR_STATUS:      %s\n", is_randomized ? "ENABLED" : "DISABLED (Deterministic)");

    return 0;
}

static int vuln_kaslr_open(struct inode *inode, struct file *file)
{
    return single_open(file, vuln_kaslr_show, NULL);
}

/*
 * Write handler: Simulates an attacker dispatching a hijacked function pointer.
 * The attacker provides a target address.
 * If KASLR is disabled, the static precomputed address hits kaslr_target_function.
 * If KASLR is enabled, a blind attack misses the randomized function location.
 */
static ssize_t vuln_kaslr_write(struct file *file, const char __user *ubuf,
                                size_t count, loff_t *ppos)
{
    char kbuf[64];
    unsigned long attempted_addr = 0;
    unsigned long real_addr = (unsigned long)kaslr_target_function;

    if (count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (kstrtoul(kbuf, 0, &attempted_addr))
    {
        // Try hex parse without prefix
        if (sscanf(kbuf, "%lx", &attempted_addr) != 1)
        {
            pr_err("[vuln_kaslr] Invalid address input: %s\n", kbuf);
            return -EINVAL;
        }
    }

    pr_info("[vuln_kaslr] Attacker attempted blind call to 0x%016lx (Real function = 0x%016lx)\n",
            attempted_addr, real_addr);

    if (attempted_addr == real_addr)
    {
        pr_info("[vuln_kaslr] [!] CRITICAL: Target address matched perfectly! Executing target...\n");
        kaslr_target_function();
    }
    else
    {
        pr_warn("[vuln_kaslr] [-] DEFENSE ACTIVE: Address mismatch (diff: 0x%lx). KASLR blocked blind call!\n",
                attempted_addr > real_addr ? attempted_addr - real_addr : real_addr - attempted_addr);
    }

    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_kaslr_proc_ops = {
    .proc_open = vuln_kaslr_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = vuln_kaslr_write,
};
#else
static const struct file_operations vuln_kaslr_proc_ops = {
    .open = vuln_kaslr_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = vuln_kaslr_write,
};
#endif

static int __init vuln_kaslr_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_kaslr_proc_ops);
    if (!entry)
    {
        pr_err("[vuln_kaslr] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_kaslr] Interface /proc/%s initialized (mode 0666)\n", VULN_PROC_NAME);
    return 0;
}

device_initcall(vuln_kaslr_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("KASLR Verification Driver");
