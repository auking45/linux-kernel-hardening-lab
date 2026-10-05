/**
 * Linux Kernel Hardening Lab - Principles Track 3: Classic Buffer Overflow & Control Flow Hijacking
 * labs/principles/05-bof-rip/bof_demo.c
 *
 * Demonstrates:
 * 1. Stack memory smashing via boundary-check omission (memcpy).
 * 2. Overwriting stack variables and adjacent function pointers (Instruction Pointer Hijacking).
 * 3. Architectural comparison: x86_64 Saved RIP vs AArch64 Saved X30 (Link Register / LR).
 * 4. Why hardware mitigations (Stack Canary, ASLR, NX, ARM PAC/BTI) are indispensable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define BUFFER_SIZE 64

/* Normal handler */
void normal_worker(void)
{
    printf("[+] Normal worker executed safely. Workflow completed.\n");
}

/* Secret/Admin function that should NEVER be called normally */
__attribute__((noinline))
void unreachable_admin_shell(void)
{
    printf("\n");
    printf("============================================================\n");
    printf(" [!] CRITICAL SECURITY COMPROMISE: Control Flow Hijacked!\n");
    printf("============================================================\n");
    printf(" [★] CPU Instruction Pointer (RIP / PC) redirected to:\n");
    printf("     unreachable_admin_shell() at %p!\n", (void *)unreachable_admin_shell);
    printf(" [★] Attacker gained arbitrary code execution in target process.\n");
    printf("============================================================\n\n");
    exit(0);
}

/* Vulnerable service structure containing stack buffer and adjacent function pointer */
struct ServiceSession {
    char stack_buffer[BUFFER_SIZE];
    void (*dispatch_handler)(void);
};

/* Vulnerable function without bound checks */
__attribute__((noinline))
void vulnerable_service(const char *user_input, size_t input_len)
{
    volatile struct ServiceSession session;
    session.dispatch_handler = normal_worker;

    void *frame_addr = __builtin_frame_address(0);
    void *ret_addr = __builtin_return_address(0);

    printf("--- [Stack State Before Input Copy] ---\n");
    printf("  session.stack_buffer[0] Address : %p\n", (void *)session.stack_buffer);
    printf("  session.dispatch_handler Addr  : %p (points to: %p)\n",
           (void *)&session.dispatch_handler, (void *)session.dispatch_handler);
    printf("  Saved Frame Pointer (FP/RBP)   : %p\n", frame_addr);
    printf("  Saved Return Address (LR/RIP)  : %p\n", ret_addr);
    printf("  Buffer to Handler Distance     : %ld bytes\n",
           (intptr_t)((uintptr_t)&session.dispatch_handler - (uintptr_t)session.stack_buffer));
    printf("---------------------------------------\n");

    /* Vulnerable memory copy exceeding buffer boundary */
    memcpy((void *)session.stack_buffer, user_input, input_len);

    printf("--- [Stack State After Input Copy] ---\n");
    printf("  session.dispatch_handler now   : %p\n", (void *)session.dispatch_handler);
    printf("---------------------------------------\n");

    printf("[+] vulnerable_service() invoking session.dispatch_handler()...\n");
    session.dispatch_handler();
}

void run_normal_mode(void)
{
    printf("\n=== [Mode 1: Normal In-Bounds Operation] ===\n");
    const char safe_msg[] = "STATUS_NORMAL_TELEMETRY_PACKET_OK";
    printf("[+] Sending safe payload (%zu bytes) into %d-byte buffer.\n",
           strlen(safe_msg), BUFFER_SIZE);
    vulnerable_service(safe_msg, strlen(safe_msg) + 1);
    printf("[+] Normal workflow completed.\n");
}

void run_attack_mode(void)
{
    printf("\n=== [Mode 2: Buffer Overflow & Control Flow Hijack Attack] ===\n");

    /* Calculate payload size: BUFFER_SIZE (64 bytes) + function pointer (8 bytes) = 72 bytes */
    size_t payload_len = BUFFER_SIZE + sizeof(void *);
    char *payload = (char *)malloc(payload_len);
    if (!payload) return;

    /* Fill buffer with 'A' (0x41) */
    memset(payload, 'A', BUFFER_SIZE);

    /* Overwrite adjacent function pointer with unreachable_admin_shell address */
    void *target_addr = (void *)unreachable_admin_shell;
    memcpy(payload + BUFFER_SIZE, &target_addr, sizeof(void *));

    printf("[+] Fabricated Exploit Payload (%zu bytes):\n", payload_len);
    printf("    [0..63]  Buffer Padding   : 64 bytes of 'A' (0x41)\n");
    printf("    [64..71] Hijacked Target  : %p (unreachable_admin_shell)\n\n", target_addr);

    printf("[!] Delivering exploit payload into vulnerable_service()...\n");
    vulnerable_service(payload, payload_len);

    /* This line should never execute if control flow is hijacked */
    printf("[-] FATAL: Failed to redirect control flow.\n");
    free(payload);
}

int main(int argc, char *argv[])
{
    printf("============================================================\n");
#if defined(__aarch64__)
    printf(" Classic Buffer Overflow & PC Hijacking Simulator [AArch64]\n");
#elif defined(__x86_64__)
    printf(" Classic Buffer Overflow & RIP Hijacking Simulator [x86_64]\n");
#else
    printf(" Classic Buffer Overflow & Control Flow Simulator\n");
#endif
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
