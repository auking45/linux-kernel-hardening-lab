// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Buffer Overflow Interface for CONFIG_FORTIFY_SOURCE Lab
 * Creates /proc/vuln_fortify with world-writable permissions (mode 0666).
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/string.h>

#define VULN_PROC_NAME "vuln_fortify"
#define FORTIFY_BUF_SIZE 64
#define CANARY_MAGIC 0x1122334455667788ULL

struct fortify_victim {
    char buf[FORTIFY_BUF_SIZE];
    unsigned long canary_marker;
};

/*
 * Deliberately vulnerable write handler.
 * Performs memcpy() into a 64-byte buffer inside struct fortify_victim.
 *
 * When CONFIG_FORTIFY_SOURCE is ENABLED:
 *   __builtin_object_size(victim.buf, 0) detects that the target buffer is 64 bytes.
 *   When count > 64, fortify_memcpy_chk() catches the overflow during the memcpy() call,
 *   invoking __fortify_panic() before adjacent data (canary_marker) is ever overwritten!
 *
 * When CONFIG_FORTIFY_SOURCE is DISABLED:
 *   memcpy() performs raw, unbounded byte copying.
 *   The 64-byte boundary is smashed, corrupting canary_marker and adjacent stack memory.
 */
static noinline ssize_t vuln_fortify_write(struct file *file, const char __user *ubuf,
                                           size_t count, loff_t *ppos)
{
    struct fortify_victim victim;
    char *kbuf;
    size_t copy_len = count > 256 ? 256 : count;

    victim.canary_marker = CANARY_MAGIC;
    memset(victim.buf, 0, sizeof(victim.buf));

    pr_info("[vuln_fortify] Write received: %zu bytes from PID %d (%s)\n",
            count, current->pid, current->comm);

    kbuf = kmalloc(copy_len, GFP_KERNEL);
    if (!kbuf) {
        return -ENOMEM;
    }

    if (copy_from_user(kbuf, ubuf, copy_len)) {
        kfree(kbuf);
        return -EFAULT;
    }

    pr_info("[vuln_fortify] Destination buffer size: %d bytes, Copy length: %zu bytes\n",
            FORTIFY_BUF_SIZE, copy_len);
    pr_info("[vuln_fortify] Triggering memcpy()...\n");

    /*
     * TARGET POINT: If CONFIG_FORTIFY_SOURCE=y, fortify_memcpy_chk()
     * intercepts this call immediately because copy_len > sizeof(victim.buf).
     */
    memcpy(victim.buf, kbuf, copy_len);

    /* Code below only executes if FORTIFY_SOURCE did NOT panic */
    if (victim.canary_marker != CANARY_MAGIC) {
        pr_warn("[vuln_fortify] OVERFLOW DETECTED: canary_marker smashed to 0x%lx (expected 0x%llx)!\n",
                victim.canary_marker, CANARY_MAGIC);
    } else {
        pr_info("[vuln_fortify] Write safely bounded or untouched.\n");
    }

    kfree(kbuf);
    return count;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_fortify_proc_ops = {
    .proc_write = vuln_fortify_write,
};
#else
static const struct file_operations vuln_fortify_proc_ops = {
    .write = vuln_fortify_write,
};
#endif

static int __init vuln_fortify_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_fortify_proc_ops);
    if (!entry) {
        pr_err("[vuln_fortify] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_fortify] Interface /proc/%s initialized successfully (mode 0666)\n", VULN_PROC_NAME);
    return 0;
}

device_initcall(vuln_fortify_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable Target for CONFIG_FORTIFY_SOURCE Lab");
