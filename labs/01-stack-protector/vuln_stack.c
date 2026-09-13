// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Stack Buffer Overflow Interface for Linux Kernel Hardening Lab
 * Creates /proc/vuln_stack with world-writable permissions (mode 0666).
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>

#define VULN_PROC_NAME "vuln_stack"
#define STACK_BUFFER_SIZE 64

/*
 * Deliberately vulnerable function with 64-byte local buffer.
 * Performs unbounded copy_from_user directly onto the kernel stack.
 *
 * When CONFIG_STACKPROTECTOR_STRONG is ENABLED:
 *   Compiler inserts a canary between buffer and saved frame pointer/return address.
 *   Overwriting more than 64 bytes corrupts the canary, triggering __stack_chk_fail().
 *
 * When CONFIG_STACKPROTECTOR_STRONG is DISABLED:
 *   No canary is placed. Overflow directly overwrites the saved return address,
 *   allowing attackers to hijack control flow into arbitrary ROP gadgets.
 */
#include <linux/slab.h>

static noinline void copy_to_stack(void *dst, const void *src, size_t len)
{
    volatile unsigned char *d = (volatile unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;
    while (len--)
    {
        *d++ = *s++;
    }
}

static noinline ssize_t vuln_stack_write(struct file *file, const char __user *ubuf,
                                         size_t count, loff_t *ppos)
{
    char stack_buffer[STACK_BUFFER_SIZE]; // Exactly 64 bytes on stack
    char *kbuf;
    size_t copy_len = count > 256 ? 256 : count;

    pr_info("[vuln_stack] Received %zu bytes write from PID %d (%s)\n",
            count, current->pid, current->comm);

    kbuf = kmalloc(copy_len, GFP_KERNEL);
    if (!kbuf)
    {
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, ubuf, copy_len))
    {
        kfree(kbuf);
        return -EFAULT;
    }

    // Unbounded copy into 64-byte stack buffer!
    // Directly targets the stack canary (at offset 64) and return address (at offset 80)
    copy_to_stack(stack_buffer, kbuf, copy_len);

    kfree(kbuf);
    pr_info("[vuln_stack] Finished buffer copy (%zu bytes), returning to caller...\n", copy_len);
    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_stack_proc_ops = {
    .proc_write = vuln_stack_write,
};
#else
static const struct file_operations vuln_stack_proc_ops = {
    .write = vuln_stack_write,
};
#endif

static int __init vuln_stack_init(void)
{
    struct proc_dir_entry *entry;

    // Create /proc/vuln_stack with 0666 permissions (accessible by non-root 'lab' user)
    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_stack_proc_ops);
    if (!entry)
    {
        pr_err("[vuln_stack] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_stack] Interface /proc/%s initialized successfully (mode 0666)\n", VULN_PROC_NAME);
    return 0;
}

device_initcall(vuln_stack_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable Stack Buffer Overflow Target for ROP Lab");
