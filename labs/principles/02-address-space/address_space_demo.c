/**
 * Linux Kernel Hardening Lab - Principles Track 2: Process Anatomy & Address Space
 * labs/principles/02-address-space/address_space_demo.c
 *
 * Inspects all primary segments of a 64-bit Linux process virtual address space:
 * .text (RX), .rodata (R), .data (RW), .bss (RW), Heap (RW),
 * Memory Mapped Region (libc.so), Stack (RW), and the Kernel Space boundary.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/mman.h>

/* Initialized Data (.data) */
int g_initialized_data = 0x1337;

/* Uninitialized Data (.bss) */
int g_uninitialized_bss;

/* Read-Only Data (.rodata) */
const char g_readonly_str[] = "System Security Principles 2026";

void print_proc_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("[-] Failed to open /proc/self/maps");
        return;
    }

    printf("\n=== Actual Process Virtual Memory Map (/proc/self/maps) ===\n");
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }
    fclose(fp);
    printf("============================================================\n\n");
}

void dummy_function(void)
{
    /* Anchor in .text segment */
}

int main(int argc, char *argv[])
{
    /* Local variable on the stack */
    int local_stack_var = 42;

    /* Dynamic memory on the Heap */
    void *heap_alloc = malloc(256);

    /* Anonymous Memory Mapping (mmap) */
    void *mmap_region = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("============================================================\n");
    printf(" 64-bit Process Virtual Address Space Inspection (PID: %d)\n", getpid());
    printf("============================================================\n");
    printf("[1] Code Segment (.text)       : %p (main)\n", (void *)main);
    printf("                               : %p (dummy_function)\n", (void *)dummy_function);
    printf("[2] Read-Only Data (.rodata)   : %p (\"%s\")\n", (void *)g_readonly_str, g_readonly_str);
    printf("[3] Initialized Data (.data)   : %p (0x%x)\n", (void *)&g_initialized_data, g_initialized_data);
    printf("[4] Uninitialized Data (.bss)  : %p (0x%x)\n", (void *)&g_uninitialized_bss, g_uninitialized_bss);
    printf("[5] Heap Segment (malloc)      : %p (size=256)\n", heap_alloc);
    printf("[6] Memory Mapped Region (mmap): %p (page-aligned)\n", mmap_region);
    printf("[7] Shared Library (libc)      : %p (printf)\n", (void *)printf);
    printf("[8] Stack Segment (RSP area)   : %p (&local_stack_var)\n", (void *)&local_stack_var);
    printf("                               : %p (&argc)\n", (void *)&argc);
    printf("[9] Kernel Space Boundary      : 0xffff800000000000 (x86_64) / 0xffff000000000000 (ARM64)\n");

    /* Dump actual /proc/self/maps */
    if (argc > 1 && strcmp(argv[1], "--maps") == 0) {
        print_proc_maps();
    } else {
        printf("\n[i] Run with './address_space_demo --maps' or 'make run-maps' to inspect raw /proc/self/maps.\n");
    }

    if (heap_alloc) free(heap_alloc);
    if (mmap_region != MAP_FAILED) munmap(mmap_region, 4096);

    return 0;
}
