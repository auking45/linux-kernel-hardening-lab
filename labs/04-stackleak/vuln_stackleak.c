// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Kernel Stack Information Leak Target for Linux Kernel Hardening Lab
 * Creates /proc/vuln_stackleak with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. Residual kernel stack data leakage across syscall boundaries (KASLR Bypass).
 * 2. Mitigation via CONFIG_GCC_PLUGIN_STACKLEAK (Syscall Stack Poisoning: -0xBEEF).
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/compiler.h>

#define VULN_PROC_NAME "vuln_stackleak"
#define STACK_DEPTH_WORDS 64
#define STACK_FRAME_BYTES (STACK_DEPTH_WORDS * sizeof(unsigned long))

/*
 * Step 1: Write Operation (Stack Imprinting)
 * Allocates a deep stack frame (>100 bytes to trigger stackleak_track_stack),
 * stamps sensitive kernel pointers (addresses of kernel code & symbols),
 * and returns to user space.
 *
 * In Base Kernel (CONFIG_GCC_PLUGIN_STACKLEAK=n):
 *   Upon syscall exit, the kernel stack remains intact with sensitive data.
 *
 * In Hardened Kernel (CONFIG_GCC_PLUGIN_STACKLEAK=y):
 *   Upon syscall exit, stackleak_erase() wipes the stack up to lowest_stack
 *   with STACKLEAK_POISON (-0xBEEF == 0xffffffffffff4111 on 64-bit).
 */
static noinline void stamp_kernel_stack(void)
{
    volatile unsigned long stack_arr[STACK_DEPTH_WORDS];
    size_t i;

    for (i = 0; i < STACK_DEPTH_WORDS; i++) {
        // Stamp kernel function address pattern onto stack
        stack_arr[i] = (unsigned long)&stamp_kernel_stack + (i * 0x10);
    }

    // Force memory barrier and memory reference so compiler writes to stack
    asm volatile("" : : "r"(stack_arr) : "memory");
}

static noinline ssize_t vuln_stackleak_write(struct file *file, const char __user *ubuf,
                                             size_t count, loff_t *ppos)
{
    pr_info("[vuln_stackleak] Stamping kernel pointers onto stack (PID %d: %s)...\n",
            current->pid, current->comm);
    stamp_kernel_stack();
    pr_info("[vuln_stackleak] Stack stamped (%zu bytes). Returning to userspace...\n",
            STACK_FRAME_BYTES);
    return count;
}

/*
 * Step 2: Read Operation (Uninitialized Stack Leak Attempt)
 * Helper function allocated at the identical call depth as stamp_kernel_stack.
 */
static noinline ssize_t read_uninit_from_stack(char __user *ubuf, size_t len)
{
    unsigned long uninit_stack[STACK_DEPTH_WORDS] __attribute__((uninitialized));

    if (copy_to_user(ubuf, (const void *)uninit_stack, len))
        return -EFAULT;

    return len;
}

static noinline ssize_t vuln_stackleak_read(struct file *file, char __user *ubuf,
                                            size_t count, loff_t *ppos)
{
    size_t copy_len = STACK_FRAME_BYTES;

    if (count < copy_len)
        copy_len = count;

    ssize_t ret = read_uninit_from_stack(ubuf, copy_len);
    if (ret > 0) {
        pr_info("[vuln_stackleak] Copied %zd bytes uninitialized stack to PID %d\n",
                ret, current->pid);
    }
    return ret;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_stackleak_proc_ops = {
    .proc_read = vuln_stackleak_read,
    .proc_write = vuln_stackleak_write,
};
#else
static const struct file_operations vuln_stackleak_proc_ops = {
    .read = vuln_stackleak_read,
    .write = vuln_stackleak_write,
};
#endif

static int __init vuln_stackleak_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_stackleak_proc_ops);
    if (!entry)
    {
        pr_err("[vuln_stackleak] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_stackleak] Interface /proc/%s initialized successfully (mode 0666)\n",
            VULN_PROC_NAME);
    return 0;
}

device_initcall(vuln_stackleak_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable Stack Information Leak Target for STACKLEAK Lab");
