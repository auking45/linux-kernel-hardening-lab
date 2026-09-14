// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable FG-KASLR (Function Granular KASLR) Verification Target
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_fgkaslr with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. Monolithic KASLR Limitation: Fixed relative distance (Delta) between functions.
 *    Single pointer leak -> Delta calculation -> 100% exploit success.
 * 2. FG-KASLR Defense: Function-level layout randomization breaks the fixed Delta,
 *    causing relative-offset ROP / branch attacks to miss the target.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/random.h>
#include <linux/string.h>

#define VULN_PROC_NAME "vuln_fgkaslr"
#define NUM_SLOTS 4

static int fgkaslr_enabled = 0;
static int active_slot = 0;

/* Functions representing distinct candidate slots / functions */
noinline void fgkaslr_leak_source(void)
{
    pr_info("[vuln_fgkaslr] Benign leak function called (Address = %px)\n", fgkaslr_leak_source);
}

noinline void fgkaslr_target_slot0(void)
{
    pr_info("[vuln_fgkaslr] >>> CRITICAL: Target Function Executed at Slot 0 (Default / Monolithic)! <<<\n");
}

noinline void fgkaslr_target_slot1(void)
{
    pr_info("[vuln_fgkaslr] >>> CRITICAL: Target Function Executed at Slot 1 (Shuffled Slot)! <<<\n");
}

noinline void fgkaslr_target_slot2(void)
{
    pr_info("[vuln_fgkaslr] >>> CRITICAL: Target Function Executed at Slot 2 (Shuffled Slot)! <<<\n");
}

noinline void fgkaslr_target_slot3(void)
{
    pr_info("[vuln_fgkaslr] >>> CRITICAL: Target Function Executed at Slot 3 (Shuffled Slot)! <<<\n");
}

typedef void (*target_fn_t)(void);

static const target_fn_t target_slots[NUM_SLOTS] = {
    fgkaslr_target_slot0,
    fgkaslr_target_slot1,
    fgkaslr_target_slot2,
    fgkaslr_target_slot3,
};

static void update_target_slot(void)
{
    if (fgkaslr_enabled) {
        /* In FG-KASLR mode: Randomize slot between 1 and NUM_SLOTS - 1 */
        u32 rnd = get_random_u32();
        active_slot = 1 + (rnd % (NUM_SLOTS - 1));
    } else {
        /* In Monolithic mode: Default fixed sequential slot 0 */
        active_slot = 0;
    }
}

/* Boot parameter handler: fgkaslr=1 or fgkaslr=0 */
static int __init parse_fgkaslr_cmdline(char *str)
{
    if (!str)
        return -EINVAL;
    if (strcmp(str, "1") == 0 || strcmp(str, "on") == 0 || strcmp(str, "enable") == 0) {
        fgkaslr_enabled = 1;
    } else {
        fgkaslr_enabled = 0;
    }
    update_target_slot();
    pr_info("[vuln_fgkaslr] Boot parameter fgkaslr=%s -> state=%s (Slot %d)\n",
            str, fgkaslr_enabled ? "ENABLED" : "DISABLED", active_slot);
    return 0;
}
__setup("fgkaslr=", parse_fgkaslr_cmdline);

static int vuln_fgkaslr_show(struct seq_file *m, void *v)
{
    unsigned long leak_addr = (unsigned long)fgkaslr_leak_source;
    unsigned long target_default = (unsigned long)target_slots[0];
    unsigned long target_active = (unsigned long)target_slots[active_slot];
    long static_delta = (long)(target_default - leak_addr);
    long actual_delta = (long)(target_active - leak_addr);
    long mismatch = actual_delta - static_delta;

    seq_printf(m, "FGKASLR_STATUS:        %s\n", fgkaslr_enabled ? "ENABLED" : "DISABLED");
    seq_printf(m, "LEAK_FUNC_ADDR:        0x%016lx\n", leak_addr);
    seq_printf(m, "DEFAULT_TARGET_ADDR:   0x%016lx\n", target_default);
    seq_printf(m, "ACTIVE_TARGET_ADDR:    0x%016lx\n", target_active);
    seq_printf(m, "STATIC_DELTA:          %ld\n", static_delta);
    seq_printf(m, "ACTUAL_DELTA:          %ld\n", actual_delta);
    seq_printf(m, "DELTA_MISMATCH:        %ld\n", mismatch);
    seq_printf(m, "ACTIVE_SLOT:           %d\n", active_slot);

    return 0;
}

static int vuln_fgkaslr_open(struct inode *inode, struct file *file)
{
    return single_open(file, vuln_fgkaslr_show, NULL);
}

/*
 * Write handler:
 * 1. Mode switch: "mode=fgkaslr" / "mode=monolithic" or "fgkaslr=1" / "fgkaslr=0"
 * 2. Attack execution: hex address string (e.g. "0xffffffff81...")
 */
static ssize_t vuln_fgkaslr_write(struct file *file, const char __user *ubuf,
                                  size_t count, loff_t *ppos)
{
    char kbuf[64];
    unsigned long attempted_addr = 0;
    unsigned long real_addr = (unsigned long)target_slots[active_slot];

    if (count == 0 || count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    /* Handle runtime mode switches */
    if (strncmp(kbuf, "fgkaslr=1", 9) == 0 || strncmp(kbuf, "mode=fgkaslr", 12) == 0) {
        fgkaslr_enabled = 1;
        update_target_slot();
        pr_info("[vuln_fgkaslr] Switched mode: FG-KASLR ENABLED (New Active Slot: %d)\n", active_slot);
        return count;
    }
    if (strncmp(kbuf, "fgkaslr=0", 9) == 0 || strncmp(kbuf, "mode=monolithic", 15) == 0) {
        fgkaslr_enabled = 0;
        update_target_slot();
        pr_info("[vuln_fgkaslr] Switched mode: FG-KASLR DISABLED (Monolithic Slot: %d)\n", active_slot);
        return count;
    }

    /* Parse target jump address */
    if (kstrtoul(kbuf, 0, &attempted_addr)) {
        if (sscanf(kbuf, "%lx", &attempted_addr) != 1) {
            pr_err("[vuln_fgkaslr] Invalid input: %s\n", kbuf);
            return -EINVAL;
        }
    }

    pr_info("[vuln_fgkaslr] Caller attempted dispatch to 0x%016lx (Real Active Target = 0x%016lx, FG-KASLR = %s)\n",
            attempted_addr, real_addr, fgkaslr_enabled ? "ON" : "OFF");

    if (attempted_addr == real_addr) {
        pr_info("[vuln_fgkaslr] [!] CRITICAL: Target address matched perfectly! Executing target slot %d...\n",
                active_slot);
        target_slots[active_slot]();
        return count;
    }

    pr_warn("[vuln_fgkaslr] [-] DEFENSE ACTIVE: Address mismatch (diff: %ld bytes). Hijacked branch thwarted!\n",
            (long)(attempted_addr - real_addr));
    return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_fgkaslr_proc_ops = {
    .proc_open = vuln_fgkaslr_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = vuln_fgkaslr_write,
};
#else
static const struct file_operations vuln_fgkaslr_proc_ops = {
    .open = vuln_fgkaslr_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = vuln_fgkaslr_write,
};
#endif

static int __init vuln_fgkaslr_init(void)
{
    struct proc_dir_entry *entry;

    update_target_slot();

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_fgkaslr_proc_ops);
    if (!entry) {
        pr_err("[vuln_fgkaslr] Failed to create /proc/%s\n", VULN_PROC_NAME);
        return -ENOMEM;
    }

    pr_info("[vuln_fgkaslr] Interface /proc/%s initialized (mode 0666, initial slot: %d, FG-KASLR: %s)\n",
            VULN_PROC_NAME, active_slot, fgkaslr_enabled ? "ENABLED" : "DISABLED");
    return 0;
}

device_initcall(vuln_fgkaslr_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("FG-KASLR Verification Target");
