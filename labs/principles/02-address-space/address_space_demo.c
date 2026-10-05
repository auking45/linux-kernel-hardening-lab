/**
 * Linux Kernel Hardening Lab - Principles Track 2: Process Anatomy & Address Space
 * labs/principles/02-address-space/address_space_demo.c
 *
 * Comprehensive Process Address Space, Variable Layout, COW, and Segfault Inspector.
 * Demonstrates:
 * 1. 64-bit Virtual Memory Segments (.text, .rodata, .data, .bss, Heap, mmap, Stack)
 * 2. Variable Classification & Memory Persistence (Global, Static, Local)
 * 3. Array vs Pointer Anatomy (&arr == arr == &arr[0] vs &ptr != ptr)
 * 4. Process Lifecycle & Copy-on-Write (COW) Memory Isolation (fork)
 * 5. Hardware Memory Protection & SIGSEGV Root Cause Analysis (SEGV_MAPERR vs SEGV_ACCERR)
 *
 * Architecture: Default AArch64 (ARM64) with x86_64 dual-arch support.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mman.h>
#include <sys/wait.h>
#include <stdint.h>

/* [1] Initialized Data Segment (.data) */
int g_initialized_data = 0x1337;

/* [2] Uninitialized Data Segment (.bss, Demand Zeroing) */
int g_uninitialized_bss;

/* [3] Read-Only Data Segment (.rodata) */
const char g_readonly_str[] = "System Security Principles 2026";

/* Static function persistence demonstrator */
void demonstrate_static_persistence(void)
{
    /* Static local variable resides in .data, persisting across invocations */
    static int call_counter = 0;
    call_counter++;
    printf("     - Invocation %d: address=%p, value=%d\n",
           call_counter, (void *)&call_counter, call_counter);
}

/* Signal handler for hardware memory protection violation analysis */
static void segfault_sigaction(int signo, siginfo_t *info, void *ucontext)
{
    (void)signo;
    (void)ucontext;

    const char *code_str = "UNKNOWN";
    if (info->si_code == SEGV_MAPERR) {
        code_str = "SEGV_MAPERR (Address not mapped to any Virtual Memory Area)";
    } else if (info->si_code == SEGV_ACCERR) {
        code_str = "SEGV_ACCERR (Invalid permissions for mapped Virtual Memory Area)";
    }

    printf("\n[!] ========================================================\n");
    printf("[!] HARDWARE PAGE FAULT TRAP: SIGSEGV (Signal %d) Received\n", signo);
    printf("[!] Faulting Memory Address (si_addr) : %p\n", info->si_addr);
    printf("[!] Kernel Diagnostic Code  (si_code) : %d -> %s\n", info->si_code, code_str);
    printf("[!] ========================================================\n");

    /* Terminate cleanly after diagnostic report */
    _exit(0);
}

void print_proc_maps(void)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        perror("[-] Failed to open /proc/self/maps");
        return;
    }

    printf("\n=== Live Process Virtual Memory Map (/proc/self/maps) ===\n");
    char line[512];
    while (fgets(line, sizeof(line), fp)) {
        printf("%s", line);
    }
    fclose(fp);
    printf("==========================================================\n\n");
}

void run_cow_demo(void)
{
    printf("\n============================================================\n");
    printf(" Process Lifecycle & Copy-on-Write (COW) Verification\n");
    printf("============================================================\n");

    int local_cow_var = 100;
    printf("[*] Parent Process (PID: %d) Initial State:\n", getpid());
    printf("    - Global Variable (g_initialized_data) : %p = 0x%x\n",
           (void *)&g_initialized_data, g_initialized_data);
    printf("    - Local Variable  (local_cow_var)      : %p = %d\n",
           (void *)&local_cow_var, local_cow_var);

    printf("\n[*] Invoking fork() system call...\n");
    pid_t pid = fork();

    if (pid < 0) {
        perror("[-] fork failed");
        return;
    }

    if (pid == 0) {
        /* Child Process */
        printf("\n[+] [Child PID: %d] Before Memory Modification:\n", getpid());
        printf("    - Virtual Address g_initialized_data : %p = 0x%x\n",
               (void *)&g_initialized_data, g_initialized_data);
        printf("    - Virtual Address local_cow_var      : %p = %d\n",
               (void *)&local_cow_var, local_cow_var);
        printf("    (Notice: Virtual addresses match parent exactly. MMU pages are shared read-only)\n");

        /* Trigger Copy-on-Write by modifying pages */
        printf("\n[+] [Child PID: %d] Modifying Variables (Triggering MMU COW Page Fault)...\n", getpid());
        g_initialized_data = 0xbeef;
        local_cow_var = 999;

        printf("[+] [Child PID: %d] After Memory Modification:\n", getpid());
        printf("    - Virtual Address g_initialized_data : %p = 0x%x\n",
               (void *)&g_initialized_data, g_initialized_data);
        printf("    - Virtual Address local_cow_var      : %p = %d\n",
               (void *)&local_cow_var, local_cow_var);
        printf("    (MMU allocated private physical frames. Child modifications are isolated!)\n");
        _exit(0);
    } else {
        /* Parent Process */
        waitpid(pid, NULL, 0);
        printf("\n[*] [Parent PID: %d] After Child Termination:\n", getpid());
        printf("    - Virtual Address g_initialized_data : %p = 0x%x\n",
               (void *)&g_initialized_data, g_initialized_data);
        printf("    - Virtual Address local_cow_var      : %p = %d\n",
               (void *)&local_cow_var, local_cow_var);
        printf("    (Parent memory remains completely untouched at 0x1337 and 100)\n");
    }
}

void trigger_segv_null(void)
{
    printf("\n[*] Setting up sigaction for SIGSEGV inspection...\n");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_sigaction;
    sigaction(SIGSEGV, &sa, NULL);

    printf("[*] Triggering NULL Pointer Dereference (*(volatile int *)NULL = 0x41414141)...\n");
    volatile int *null_ptr = NULL;
    *null_ptr = 0x41414141;
}

void trigger_segv_rodata(void)
{
    printf("\n[*] Setting up sigaction for SIGSEGV inspection...\n");
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_flags = SA_SIGINFO;
    sa.sa_sigaction = segfault_sigaction;
    sigaction(SIGSEGV, &sa, NULL);

    printf("[*] Triggering Write to Read-Only (.rodata) Memory: address=%p\n", (void *)g_readonly_str);
    volatile char *ro_target = (volatile char *)g_readonly_str;
    *ro_target = 'X';
}

void dummy_function(void)
{
    /* Anchor in .text segment */
}

int main(int argc, char *argv[])
{
    /* Handle specific demonstration modes */
    if (argc > 1) {
        if (strcmp(argv[1], "--maps") == 0) {
            print_proc_maps();
            return 0;
        } else if (strcmp(argv[1], "--cow") == 0 || strcmp(argv[1], "--fork") == 0) {
            run_cow_demo();
            return 0;
        } else if (strcmp(argv[1], "--segv-null") == 0) {
            trigger_segv_null();
            return 0;
        } else if (strcmp(argv[1], "--segv-rodata") == 0) {
            trigger_segv_rodata();
            return 0;
        }
    }

    /* Stack local variables */
    int local_stack_var = 42;
    char local_char_array[16] = "InlineArray";
    const char *local_char_ptr = "StringPointer";

    /* Dynamic memory on Heap */
    void *heap_alloc = malloc(256);

    /* Anonymous Memory Mapping (mmap) */
    void *mmap_region = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    printf("============================================================\n");
    printf(" 64-bit Process Virtual Address Space Inspection (PID: %d)\n", getpid());
    printf("============================================================\n");

    /* Segment inspection */
    printf("[1] Code Segment (.text)       : %p (main)\n", (void *)main);
    printf("                               : %p (dummy_function)\n", (void *)dummy_function);
    printf("[2] Read-Only Data (.rodata)   : %p (\"%s\")\n", (void *)g_readonly_str, g_readonly_str);
    printf("[3] Initialized Data (.data)   : %p (0x%x)\n", (void *)&g_initialized_data, g_initialized_data);
    printf("[4] Uninitialized Data (.bss)  : %p (0x%x)\n", (void *)&g_uninitialized_bss, g_uninitialized_bss);
    printf("[5] Heap Segment (malloc)      : %p (size=256)\n", heap_alloc);
    printf("[6] Memory Mapped Region (mmap): %p (page-aligned)\n", mmap_region);
    printf("[7] Shared Library (libc)      : %p (printf)\n", (void *)printf);
    printf("[8] Stack Segment (RSP/SP area): %p (&local_stack_var)\n", (void *)&local_stack_var);
    printf("                               : %p (&argc)\n", (void *)&argc);
    printf("[9] Kernel Space Boundary      : 0xffff000000000000 (AArch64 TTBR1) / 0xffff800000000000 (x86_64)\n");

    /* Variable classification & Static persistence demonstration */
    printf("\n------------------------------------------------------------\n");
    printf(" Variable Classification & Static Persistence Analysis\n");
    printf("------------------------------------------------------------\n");
    printf("[*] Static Function-Scope Variable Persistence Across Calls:\n");
    demonstrate_static_persistence();
    demonstrate_static_persistence();
    demonstrate_static_persistence();

    /* Array vs Pointer anatomy demonstration */
    printf("\n------------------------------------------------------------\n");
    printf(" Array vs. Pointer Memory Anatomy in Virtual Memory\n");
    printf("------------------------------------------------------------\n");
    printf("[*] Array Identity Property (&arr == arr == &arr[0]):\n");
    printf("    - Address of array (&local_char_array) : %p\n", (void *)&local_char_array);
    printf("    - Array identifier  (local_char_array)  : %p\n", (void *)local_char_array);
    printf("    - First element     (&local_char_array[0]): %p\n", (void *)&local_char_array[0]);
    printf("    -> Status: All 3 expressions evaluate to the exact same stack address.\n");

    printf("\n[*] Pointer Distinction Property (&ptr != ptr):\n");
    printf("    - Address of pointer variable (&local_char_ptr): %p (Stack)\n", (void *)&local_char_ptr);
    printf("    - Value of pointer variable   (local_char_ptr) : %p (.rodata)\n", (void *)local_char_ptr);
    printf("    -> Status: Pointer variable on stack holds target address located in .rodata.\n");

    printf("\n============================================================\n");
    printf(" Available Verification Modes:\n");
    printf("   ./address_space_demo --maps         : Live /proc/self/maps VMA table\n");
    printf("   ./address_space_demo --cow          : Copy-on-Write (COW) verification\n");
    printf("   ./address_space_demo --segv-null    : Trigger SEGV_MAPERR (NULL pointer)\n");
    printf("   ./address_space_demo --segv-rodata  : Trigger SEGV_ACCERR (Read-only write)\n");
    printf("============================================================\n");

    if (heap_alloc) free(heap_alloc);
    if (mmap_region != MAP_FAILED) munmap(mmap_region, 4096);

    return 0;
}
