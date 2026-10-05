/**
 * Linux Kernel Hardening Lab - Principles Track 3: Classic Buffer Overflow & Control Flow Hijacking
 * labs/principles/05-bof-rip/bof_demo.c
 *
 * Demonstrates:
 * 1. Stack memory smashing via boundary-check omission (memcpy / strcpy).
 * 2. Stack-based function pointer corruption (Control Flow Hijacking).
 * 3. Heap-based buffer overflow (Heap BOF - Slide Chapter 8.3 heapexploit2).
 * 4. Stack Return Address Smashing & NOP Sled Simulation (Slide Chapter 8.2 stackexploit1).
 * 5. Architectural comparison: x86_64 Saved RIP vs AArch64 Saved X30 (Link Register / LR).
 * 6. Why hardware mitigations (Stack Canary, ASLR, NX, ARM PAC/BTI) are indispensable.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#define BUFFER_SIZE 64

/* Normal worker callback */
void normal_worker(void)
{
    printf("[+] normal_worker() executed safely. Operation completed.\n");
}

/* Secret/Admin function that should NEVER be called under normal workflow */
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

/* --------------------------------------------------------------------------
 * Vulnerability 1: Stack Structure Function Pointer Overwrite
 * -------------------------------------------------------------------------- */
struct StackSession {
    char stack_buffer[BUFFER_SIZE];
    void (*dispatch_handler)(void);
};

__attribute__((noinline))
void vulnerable_stack_service(const char *user_input, size_t input_len)
{
    volatile struct StackSession session;
    session.dispatch_handler = normal_worker;

    void *frame_addr = __builtin_frame_address(0);
    void *ret_addr = __builtin_return_address(0);

    printf("--- [Stack State Before Input Copy] ---\n");
    printf("  session.stack_buffer[0] Address : %p\n", (void *)session.stack_buffer);
    printf("  session.dispatch_handler Addr   : %p (points to: %p)\n",
           (void *)&session.dispatch_handler, (void *)session.dispatch_handler);
    printf("  Saved Frame Pointer (FP/X29/RBP): %p\n", frame_addr);
    printf("  Saved Return Address (LR/X30/RIP): %p\n", ret_addr);
    printf("  Buffer to Handler Distance      : %ld bytes\n",
           (intptr_t)((uintptr_t)&session.dispatch_handler - (uintptr_t)session.stack_buffer));
    printf("---------------------------------------\n");

    /* Vulnerable memory copy exceeding buffer boundary */
    memcpy((void *)session.stack_buffer, user_input, input_len);

    printf("--- [Stack State After Input Copy] ---\n");
    printf("  session.dispatch_handler now    : %p\n", (void *)session.dispatch_handler);
    printf("---------------------------------------\n");

    printf("[+] Invoking session.dispatch_handler()...\n");
    session.dispatch_handler();
}

/* --------------------------------------------------------------------------
 * Vulnerability 2: Heap Buffer Overflow (Slide Chapter 8.3 heapexploit2)
 * Demonstrates heap buffer overflow corrupting an adjacent function pointer
 * -------------------------------------------------------------------------- */
struct HeapTarget {
    char heap_buffer[BUFFER_SIZE];
    void (*callback)(void);
};

void run_heap_bof_demo(void)
{
    printf("\n=== [Mode 3: Heap Buffer Overflow (Slide Chapter 8.3 heapexploit2)] ===\n");
    printf("[*] Allocating struct HeapTarget (%zu bytes) on heap via malloc()...\n", sizeof(struct HeapTarget));

    struct HeapTarget *target = (struct HeapTarget *)malloc(sizeof(struct HeapTarget));
    if (!target) {
        perror("malloc");
        return;
    }
    target->callback = normal_worker;

    printf("--- [Heap Layout Before Overflow] ---\n");
    printf("  target->heap_buffer[0] Addr   : %p\n", (void *)target->heap_buffer);
    printf("  target->callback Pointer Addr : %p (points to: %p)\n",
           (void *)&target->callback, (void *)target->callback);
    printf("  Buffer to Callback Distance   : %ld bytes\n",
           (intptr_t)((uintptr_t)&target->callback - (uintptr_t)target->heap_buffer));
    printf("-------------------------------------\n");

    /* Fabricate exploit payload for heap */
    size_t payload_len = BUFFER_SIZE + sizeof(void *);
    char *payload = (char *)malloc(payload_len);
    if (!payload) return;

    memset(payload, 'H', BUFFER_SIZE); /* 64 bytes padding */
    void *hijack_target = (void *)unreachable_admin_shell;
    memcpy(payload + BUFFER_SIZE, &hijack_target, sizeof(void *));

    printf("[+] Injecting %zu bytes into %d-byte heap_buffer...\n", payload_len, BUFFER_SIZE);
    memcpy(target->heap_buffer, payload, payload_len);

    printf("--- [Heap Layout After Overflow] ---\n");
    printf("  target->callback Pointer now  : %p\n", (void *)target->callback);
    printf("------------------------------------\n");

    printf("[!] Invoking target->callback() on heap...\n");
    target->callback();

    free(payload);
    free(target);
}

/* --------------------------------------------------------------------------
 * Vulnerability 3: NOP Sledding Simulation (Slide Chapter 8.2 stackexploit1)
 * Demonstrates how a NOP sled absorbs stack pointer drift
 * -------------------------------------------------------------------------- */
void run_nop_sled_simulation(void)
{
    printf("\n=== [Mode 4: NOP Sled Simulation & Address Drift Tolerance] ===\n");
    printf("[*] Classical exploit challenge: Exact stack addresses drift across runs.\n");
    printf("    Pre-pending NOP instructions allows imprecise jumps to glide into payload.\n\n");

#if defined(__aarch64__)
    const char *nop_name = "0xd503201f (AArch64 'nop')";
#elif defined(__x86_64__)
    const char *nop_name = "0x90 (x86 'nop')";
#else
    const char *nop_name = "NOP";
#endif

    printf("  NOP Opcode for Target Architecture : %s\n", nop_name);
    printf("  NOP Sled Size                      : 32 instructions\n");
    printf("  Shellcode Location                 : Offset +32\n\n");

    printf("  [Sled Trace Visualizer]\n");
    printf("  Offset 0x00: [ %s ] (Glide forward)\n", nop_name);
    printf("  Offset 0x04: [ %s ] (Glide forward)\n", nop_name);
    printf("  Offset 0x08: [ %s ] (Glide forward)\n", nop_name);
    printf("  Offset ....: [ ... NOP Sledding ... ]\n");
    printf("  Offset 0x20: [ ★ SHELLCODE / TARGET ENTRY ★ ] ➔ Execution succeeds!\n\n");

    printf("[+] Result: If overwritten RET lands anywhere in the sled (0x00 ~ 0x1F),\n");
    printf("    the CPU executes NOPs sequentially until hitting the shellcode.\n");
}

/* --------------------------------------------------------------------------
 * Execution Modes
 * -------------------------------------------------------------------------- */
void run_normal_mode(void)
{
    printf("\n=== [Mode 1: Normal In-Bounds Operation] ===\n");
    const char safe_msg[] = "STATUS_NORMAL_TELEMETRY_PACKET_OK";
    printf("[+] Sending safe payload (%zu bytes) into %d-byte buffer.\n",
           strlen(safe_msg), BUFFER_SIZE);
    vulnerable_stack_service(safe_msg, strlen(safe_msg) + 1);
    printf("[+] Normal workflow completed successfully.\n");
}

void run_stack_fp_attack_mode(void)
{
    printf("\n=== [Mode 2: Stack Buffer Overflow (Function Pointer Hijack)] ===\n");

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

    printf("[!] Delivering exploit payload into vulnerable_stack_service()...\n");
    vulnerable_stack_service(payload, payload_len);

    /* This line should never execute if control flow is hijacked */
    printf("[-] FATAL: Failed to redirect control flow.\n");
    free(payload);
}

int main(int argc, char *argv[])
{
    printf("============================================================\n");
#if defined(__aarch64__)
    printf(" Classic Buffer Overflow & Control Flow Hijack [AArch64]\n");
#elif defined(__x86_64__)
    printf(" Classic Buffer Overflow & Control Flow Hijack [x86_64]\n");
#else
    printf(" Classic Buffer Overflow & Control Flow Hijack\n");
#endif
    printf("============================================================\n");
    printf("[*] unreachable_admin_shell Address : %p\n", (void *)unreachable_admin_shell);
    printf("[*] normal_worker Address           : %p\n", (void *)normal_worker);
    printf("[*] main() Function Address         : %p\n", (void *)main);

    if (argc > 1 && (strcmp(argv[1], "--attack") == 0 || strcmp(argv[1], "--stack-fp") == 0)) {
        run_stack_fp_attack_mode();
    } else if (argc > 1 && strcmp(argv[1], "--heap-bof") == 0) {
        run_heap_bof_demo();
    } else if (argc > 1 && strcmp(argv[1], "--nop-sled") == 0) {
        run_nop_sled_simulation();
    } else {
        run_normal_mode();
        printf("\n[i] Available simulation options:\n");
        printf("    './bof_demo --stack-fp'   (or make run-attack)   : Stack FP hijacking\n");
        printf("    './bof_demo --heap-bof'   (or make run-heap)     : Heap buffer overflow\n");
        printf("    './bof_demo --nop-sled'   (or make run-nop-sled) : NOP sled simulation\n");
    }

    return 0;
}
