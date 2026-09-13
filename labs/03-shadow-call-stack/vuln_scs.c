#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/slab.h>
#include <linux/seq_file.h>
#include <linux/compiler_attributes.h>

#define VULN_PROC_NAME "vuln_scs"

/*
 * Deliberate hijack target function.
 * In a vulnerable baseline kernel (CONFIG_SHADOW_CALL_STACK disabled),
 * smashing the saved Link Register (x30 / LR) on the stack causes
 * the function epilogue 'ret' to branch directly here.
 */
static noinline void scs_hijacked_target(void)
{
    pr_emerg("[vuln_scs] [!] =========================================================\n");
    pr_emerg("[vuln_scs] [!] CONTROL FLOW HIJACKED: Successfully executed scs_hijacked_target()!\n");
    pr_emerg("[vuln_scs] [!] Overwritten stack return address (LR) was branched to by 'ret'.\n");
    pr_emerg("[vuln_scs] [!] Shadow Call Stack is NOT active on this kernel (Vulnerable Baseline).\n");
    pr_emerg("[vuln_scs] [!] =========================================================\n");
    panic("vuln_scs: Control flow hijacking confirmed via smashed stack return address");
}

/*
 * Deliberately vulnerable worker function.
 * Uses a 32-byte local stack buffer.
 * __no_stack_protector isolates Shadow Call Stack from Stack Protector interference.
 * The loop copy bypasses FORTIFY_SOURCE (which hooks library functions like memcpy/strcpy).
 *
 * When CONFIG_SHADOW_CALL_STACK is ENABLED:
 *   Prologue: str x30, [x18], #8 (pushes pristine LR to shadow stack at x18)
 *   Epilogue: ldr x30, [x18, #-8]! (pops pristine LR from shadow stack at x18)
 *   Result: Even though regular stack [sp] is smashed with scs_hijacked_target,
 *           'ret' branches to the pristine LR from x18, safely returning to caller!
 *
 * When CONFIG_SHADOW_CALL_STACK is DISABLED:
 *   Epilogue: ldp x29, x30, [sp], #frame_size
 *   Result: Corrupted LR on regular stack is loaded into x30, branching into scs_hijacked_target!
 */
static noinline void __no_stack_protector vulnerable_scs_worker(unsigned long target_addr)
{
    /* Pointer to the saved Link Register (x30 / LR) on the regular stack */
    unsigned long * volatile *stack_lr = (unsigned long **)__builtin_frame_address(0) + 1;

    pr_info("[vuln_scs] vulnerable_scs_worker: saved stack LR = %px, target = %px\n",
            *stack_lr, (void *)target_addr);
    pr_info("[vuln_scs] Overwriting saved stack LR with target address...\n");

    /* Directly corrupt the saved return address on the regular stack frame */
    *stack_lr = (unsigned long *)target_addr;

    pr_info("[vuln_scs] Epilogue executing: if SCS is active, x18 restores true LR...\n");
}

static noinline ssize_t vuln_scs_write(struct file *file, const char __user *ubuf,
                                       size_t count, loff_t *ppos)
{
    char *kbuf;
    size_t copy_len = count > 256 ? 256 : count;
    unsigned long target = (unsigned long)scs_hijacked_target;

    pr_info("[vuln_scs] Write received: %zu bytes from PID %d (%s)\n",
            count, current->pid, current->comm);

    if (copy_len == 0)
        return 0;

    kbuf = kmalloc(copy_len, GFP_KERNEL);
    if (!kbuf)
        return -ENOMEM;

    if (copy_from_user(kbuf, ubuf, copy_len)) {
        kfree(kbuf);
        return -EFAULT;
    }

    /* Extract target address if provided by exploit payload */
    if (copy_len >= 40) {
        memcpy(&target, kbuf + 32, sizeof(unsigned long));
    } else if (copy_len >= sizeof(unsigned long)) {
        memcpy(&target, kbuf, sizeof(unsigned long));
    }

    pr_info("[vuln_scs] Calling vulnerable_scs_worker(target=0x%px)...\n", (void *)target);
    vulnerable_scs_worker(target);

    /*
     * If execution reaches here, Shadow Call Stack successfully restored
     * the original return address from x18!
     */
    pr_info("[vuln_scs] [+] DEFENSE ACTIVE: Returned safely to vuln_scs_write!\n");
    pr_info("[vuln_scs] [+] Shadow Call Stack (x18) thwarted return address hijacking!\n");

    kfree(kbuf);
    return count;
}

static int vuln_scs_show(struct seq_file *m, void *v)
{
    seq_printf(m, "target_addr: 0x%px\n", (void *)scs_hijacked_target);
    seq_printf(m, "scs_enabled: %d\n", IS_ENABLED(CONFIG_SHADOW_CALL_STACK));
#ifdef CONFIG_ARM64
    seq_printf(m, "arch: arm64\n");
#else
    seq_printf(m, "arch: x86_64\n");
#endif
    return 0;
}

static int vuln_scs_open(struct inode *inode, struct file *file)
{
    return single_open(file, vuln_scs_show, NULL);
}

static const struct proc_ops vuln_scs_proc_ops = {
    .proc_open    = vuln_scs_open,
    .proc_read    = seq_read,
    .proc_lseek   = seq_lseek,
    .proc_release = single_release,
    .proc_write   = vuln_scs_write,
};

static int __init vuln_scs_init(void)
{
    struct proc_dir_entry *entry;

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_scs_proc_ops);
    if (!entry) {
        pr_err("[vuln_scs] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_scs] Interface /proc/%s created (target: 0x%px, SCS=%d)\n",
            VULN_PROC_NAME, (void *)scs_hijacked_target,
            IS_ENABLED(CONFIG_SHADOW_CALL_STACK));
    return 0;
}

static void __exit vuln_scs_exit(void)
{
    remove_proc_entry(VULN_PROC_NAME, NULL);
    pr_info("[vuln_scs] Interface /proc/%s removed\n", VULN_PROC_NAME);
}

device_initcall(vuln_scs_init);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("Vulnerable driver for Shadow Call Stack (SCS) return address verification");
