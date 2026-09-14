// SPDX-License-Identifier: GPL-2.0
/*
 * Vulnerable Direct Memory Mapping (ret2dir) Verification Target
 * Linux Kernel Hardening Lab
 *
 * Creates /proc/vuln_randmem with world-writable permissions (mode 0666).
 *
 * Demonstrates:
 * 1. Predictable Direct Physical Memory Mapping (PAGE_OFFSET) when
 *    CONFIG_RANDOMIZE_MEMORY is disabled, enabling ret2dir (return-to-direct-mapped-memory) attacks.
 * 2. Dynamic Randomization of page_offset_base, vmalloc_base, and vmemmap_base
 *    when CONFIG_RANDOMIZE_MEMORY is active, neutralizing ret2dir attacks.
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/proc_fs.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/seq_file.h>
#include <linux/mm.h>
#include <linux/string.h>
#include <asm/io.h>
#include <asm/page.h>

#define VULN_PROC_NAME "vuln_randmem"
#define RET2DIR_SECRET_PAYLOAD "PWNED_VIA_RET2DIR_DIRECT_MAP"

static char *target_page_ptr;
static unsigned long target_page_phys;
static unsigned long target_direct_virt;
static unsigned long target_static_guess;

#if defined(CONFIG_X86_64)
#include <asm/pgtable.h>
#include <asm/page_types.h>

extern unsigned long page_offset_base;
extern unsigned long vmalloc_base;

static inline unsigned long get_current_direct_base(void)
{
    return page_offset_base;
}

static inline unsigned long get_current_vmalloc_base(void)
{
    return vmalloc_base;
}

static inline unsigned long get_static_direct_base(void)
{
#ifdef CONFIG_X86_5LEVEL
    return pgtable_l5_enabled() ? __PAGE_OFFSET_BASE_L5 : __PAGE_OFFSET_BASE_L4;
#else
    return __PAGE_OFFSET_BASE_L4;
#endif
}

static inline unsigned long calculate_static_guess(unsigned long phys)
{
    return get_static_direct_base() + phys;
}

static inline bool is_memory_randomized(void)
{
    if (!IS_ENABLED(CONFIG_RANDOMIZE_MEMORY))
        return false;
    return (get_current_direct_base() != get_static_direct_base());
}

#elif defined(CONFIG_ARM64)
#include <asm/memory.h>

static inline unsigned long get_current_direct_base(void)
{
    return _PAGE_OFFSET(vabits_actual);
}

static inline unsigned long get_current_vmalloc_base(void)
{
    return VMALLOC_START;
}

static inline unsigned long get_static_direct_base(void)
{
    return _PAGE_OFFSET(vabits_actual);
}

static inline unsigned long calculate_static_guess(unsigned long phys)
{
    /*
     * On ARM64 virt machine, DRAM starts at 0x40000000.
     * Default unrandomized linear mapping maps DRAM base to _PAGE_OFFSET(vabits_actual):
     * virt = (phys - 0x40000000) + _PAGE_OFFSET(vabits_actual)
     */
    return (phys >= 0x40000000UL) ?
        ((phys - 0x40000000UL) + _PAGE_OFFSET(vabits_actual)) :
        (phys + _PAGE_OFFSET(vabits_actual));
}

static inline bool is_memory_randomized(void)
{
    return (target_direct_virt != target_static_guess);
}

#else
static inline unsigned long get_current_direct_base(void)
{
    return PAGE_OFFSET;
}
static inline unsigned long get_current_vmalloc_base(void)
{
    return 0;
}
static inline unsigned long get_static_direct_base(void)
{
    return PAGE_OFFSET;
}
static inline unsigned long calculate_static_guess(unsigned long phys)
{
    return PAGE_OFFSET + phys;
}
static inline bool is_memory_randomized(void)
{
    return false;
}
#endif

static int vuln_randmem_show(struct seq_file *m, void *v)
{
    unsigned long current_base = get_current_direct_base();
    unsigned long static_base = get_static_direct_base();
    unsigned long vmalloc_val = get_current_vmalloc_base();
    long slide = (long)(target_direct_virt - target_static_guess);
    bool is_randomized = is_memory_randomized();

    seq_printf(m, "PAGE_OFFSET_BASE:      0x%016lx\n", current_base);
    seq_printf(m, "STATIC_PAGE_OFFSET:    0x%016lx\n", static_base);
    seq_printf(m, "VMALLOC_BASE:          0x%016lx\n", vmalloc_val);
    seq_printf(m, "RANDMEM_SLIDE:         0x%016lx\n", (unsigned long)(slide > 0 ? slide : -slide));
    seq_printf(m, "RANDMEM_STATUS:        %s\n", is_randomized ? "ENABLED (Randomized)" : "DISABLED (Deterministic)");
    seq_printf(m, "TARGET_PAGE_PHYS:      0x%016lx\n", target_page_phys);
    seq_printf(m, "TARGET_DIRECT_VIRT:    0x%016lx\n", target_direct_virt);
    seq_printf(m, "STATIC_GUESS_VIRT:     0x%016lx\n", target_static_guess);

    return 0;
}

static int vuln_randmem_open(struct inode *inode, struct file *file)
{
    return single_open(file, vuln_randmem_show, NULL);
}

/*
 * Write handler: Simulates an attacker executing or dereferencing sprayed memory in direct map.
 * Attacker inputs a predicted direct-map virtual address.
 * If CONFIG_RANDOMIZE_MEMORY is disabled: static guess == target_direct_virt (exploit success).
 * If CONFIG_RANDOMIZE_MEMORY is active: static guess != target_direct_virt (exploit blocked).
 */
static ssize_t vuln_randmem_write(struct file *file, const char __user *ubuf,
                                  size_t count, loff_t *ppos)
{
    char kbuf[64];
    unsigned long attempted_addr = 0;

    if (count == 0 || count >= sizeof(kbuf))
        return -EINVAL;

    if (copy_from_user(kbuf, ubuf, count))
        return -EFAULT;

    kbuf[count] = '\0';

    if (kstrtoul(kbuf, 0, &attempted_addr)) {
        if (sscanf(kbuf, "%lx", &attempted_addr) != 1) {
            pr_err("[vuln_randmem] Invalid address input: %s\n", kbuf);
            return -EINVAL;
        }
    }

    pr_info("[vuln_randmem] Attacker attempted direct-map access to 0x%016lx (Real Target = 0x%016lx)\n",
            attempted_addr, target_direct_virt);

    if (attempted_addr == target_direct_virt) {
        pr_info("[vuln_randmem] [!] CRITICAL: Direct-map address matched perfectly! Payload: %s\n",
                target_page_ptr ? target_page_ptr : "NULL");
        return count;
    }

    pr_warn("[vuln_randmem] [-] DEFENSE ACTIVE: Direct-map mismatch (diff: 0x%lx bytes). ret2dir attack thwarted!\n",
            attempted_addr > target_direct_virt ? attempted_addr - target_direct_virt : target_direct_virt - attempted_addr);
    return -EINVAL;
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(5, 6, 0)
static const struct proc_ops vuln_randmem_proc_ops = {
    .proc_open = vuln_randmem_open,
    .proc_read = seq_read,
    .proc_lseek = seq_lseek,
    .proc_release = single_release,
    .proc_write = vuln_randmem_write,
};
#else
static const struct file_operations vuln_randmem_proc_ops = {
    .open = vuln_randmem_open,
    .read = seq_read,
    .llseek = seq_lseek,
    .release = single_release,
    .write = vuln_randmem_write,
};
#endif

static int __init vuln_randmem_init(void)
{
    struct proc_dir_entry *entry;

    /* Allocate one dedicated physical page to represent sprayed target buffer */
    target_page_ptr = (char *)__get_free_page(GFP_KERNEL);
    if (!target_page_ptr) {
        pr_err("[vuln_randmem] Failed to allocate target test page\n");
        return -ENOMEM;
    }

    strncpy(target_page_ptr, RET2DIR_SECRET_PAYLOAD, PAGE_SIZE - 1);
    target_page_ptr[PAGE_SIZE - 1] = '\0';

    target_page_phys = virt_to_phys(target_page_ptr);
    target_direct_virt = (unsigned long)target_page_ptr;
    target_static_guess = calculate_static_guess(target_page_phys);

    entry = proc_create(VULN_PROC_NAME, 0666, NULL, &vuln_randmem_proc_ops);
    if (!entry) {
        pr_err("[vuln_randmem] Failed to create /proc/%s\n", VULN_PROC_NAME);
        free_page((unsigned long)target_page_ptr);
        return -ENOMEM;
    }

    pr_info("[vuln_randmem] Initialized /proc/%s (Direct Base: 0x%016lx, Phys: 0x%016lx, Direct Virt: 0x%016lx)\n",
            VULN_PROC_NAME, get_current_direct_base(), target_page_phys, target_direct_virt);
    return 0;
}

device_initcall(vuln_randmem_init);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Linux Kernel Hardening Lab");
MODULE_DESCRIPTION("CONFIG_RANDOMIZE_MEMORY Verification Target");
