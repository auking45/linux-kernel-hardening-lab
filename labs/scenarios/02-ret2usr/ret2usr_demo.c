/**
 * ============================================================================
 * Scenario 02: Return-to-User (ret2usr) & SMEP / PXN Hardware Execution Defense
 * Target Incident: CVE-2017-7308 / Linux Kernel Socket & Privileged Dispatch
 * Platform: Linux Hardening Laboratory (x86_64 & arm64)
 * ============================================================================
 *
 * Description:
 *   Demonstrates how a kernel function pointer overwrite (e.g. in struct sock
 *   or character device ops) allows an attacker who already holds user-space
 *   credentials (UID 0 / Ring 3 achieved in Scenario 01) to hijack kernel
 *   execution flow (Ring 0 / EL1) and branch directly into user-space shellcode.
 *
 *   Highlights the role of hardware-enforced Supervisor Mode Execution
 *   Prevention (x86 CR4.SMEP / ARM64 PTE_PXN) in trapping instruction fetches
 *   from user memory addresses (< TASK_SIZE) before arbitrary code executes.
 *
 * Modes:
 *   Mode 1: Normal Syscall Dispatch (Legitimate kernel text execution)
 *   Mode 2: ret2usr Exploit without SMEP (Ring 0 executes user shellcode)
 *   Mode 3: Hardened SMEP/PXN Active (Hardware MMU Page Fault Intercept)
 * ============================================================================
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

#define TASK_SIZE_MAX_X86   0x00007FFFFFFFFFFFULL
#define TASK_SIZE_MAX_ARM   0x0000FFFFFFFFFFFFULL
#define SIMULATED_KERNEL_VA 0xFFFFFFFF81001337ULL

/* Simulated Kernel Context */
typedef struct {
    uint64_t cr4_smep_enabled;   /* x86 CR4 Bit 20: SMEP */
    uint64_t pte_pxn_enabled;    /* ARM64 Descriptor Bit 53: PXN */
    uint64_t kpti_active;        /* Kernel Page Table Isolation */
    void (*dispatch_fn)(void);   /* Kernel dispatch function pointer */
} kernel_dispatch_context_t;

/* Normal Kernel Worker (Legitimate Kernel Text) */
static void kernel_safe_worker(void) {
    printf("  [✓] Kernel Worker Executing: Address = %p (Simulated Ring 0 Text)\n", (void*)kernel_safe_worker);
    printf("  [✓] Normal Packet Processed: Joint Velocity Command within ±2.5 rad/s limits\n");
    printf("  [✓] Syscall Completed Safely: Returning to User Space via SYSRET/ERET\n");
}

/* User-Space Shellcode (Placed in Ring 3 / EL0 User Memory) */
static void user_shellcode(void) {
    printf("\n======================================================================\n");
    printf(" [💥 CRITICAL EXPLOIT DETONATION] Ring 0 Execution Achieved via ret2usr! \n");
    printf("======================================================================\n");
    printf("  [*] CPU Context: Ring 0 (CPL 0 / EL1 Supervisor Mode)\n");
    printf("  [*] Hijacked Execution Pointer (RIP/PC): %p (User Space Memory!)\n", (void*)user_shellcode);
    printf("  [*] Credential Escalation: commit_creds(prepare_kernel_cred(0)) -> COMPLETE\n");
    
    printf("\n--- [PHASE 1: RING 0 KERNEL COMPROMISE & MMU TAKEOVER] ---\n");
    printf("  [🔴 KERNEL COMPROMISE] MMU Page Tables Altered: User mappings injected into Kernel TTBR1/CR3\n");
    printf("  [🔴 KERNEL COMPROMISE] Kernel Lockdown LSM Overridden: Direct PCI/DMA Hardware Write Unlocked\n");
    printf("  [🔴 PERSISTENCE] Unsigned Kernel Rootkit Injected directly into Ring 0 RAM (No .ko needed)\n");

    printf("\n--- [PHASE 2: CYBER-PHYSICAL SUBVERSION & ROBOT HAZARDS] ---\n");
    printf("  [🔴 CPS HAZARD] Locomotion Safety Heartbeat Thread: TERMINATED\n");
    printf("  [🔴 CPS HAZARD] Motor Current Limit Clamp: 15.0A -> 85.0A (Actuator Thermal Melt Risk)\n");
    printf("  [🔴 CPS HAZARD] Hardware E-Stop ISR (Interrupt Service Routine): OVERWRITTEN with NOP\n");
}

/* Simulation Dispatch Engine */
static void dispatch_syscall(kernel_dispatch_context_t *ctx) {
    uintptr_t fn_addr = (uintptr_t)ctx->dispatch_fn;
    bool is_user_space = (fn_addr < TASK_SIZE_MAX_X86);

    printf("\n[*] Invoking Kernel Syscall Dispatcher (Target Address: %p)...\n", (void*)fn_addr);
    printf("    -> Destination Memory Region: %s\n", is_user_space ? "USER SPACE (< TASK_SIZE)" : "KERNEL TEXT (>= TASK_SIZE)");

    /* Hardware SMEP / PXN MMU Check */
    if (ctx->cr4_smep_enabled || ctx->pte_pxn_enabled) {
        printf("    -> Hardware MMU Validation: CR4.SMEP = %lu, PTE_PXN = %lu\n",
               ctx->cr4_smep_enabled, ctx->pte_pxn_enabled);

        if (is_user_space) {
            printf("\n======================================================================\n");
            printf(" [🛡️ HARDWARE MMU TRAP DETONATED] SMEP/PXN Violation Caught! \n");
            printf("======================================================================\n");
            printf("  [!] Hardware Exception: #PF (Page Fault, Error Code 0x0011)\n");
            printf("      - Bit 0 [P=1]   : Protection violation (Page Present)\n");
            printf("      - Bit 2 [U/S=0] : Supervisor Mode (Ring 0 / EL1)\n");
            printf("      - Bit 4 [I/D=1] : Instruction Fetch Violation!\n");
            printf("  [!] Kernel Panic Triggered: 'BUG: unable to handle page fault for address %p'\n", (void*)fn_addr);
            printf("  [!] Arbitrary user shellcode execution blocked: 0%%\n");
            printf("\n  [FAIL-SAFE ACTIVE] Hardware Watchdog Emergency Stop Triggered!\n");
            printf("  [FAIL-SAFE ACTIVE] Humanoid joint brakes engaged -> Mechanical crash prevented!\n");
            return;
        }
    } else {
        printf("    -> Hardware MMU Validation: SMEP/PXN INACTIVE (Vulnerable Baseline)\n");
    }

    /* Execute Target Function */
    ctx->dispatch_fn();
}

int main(int argc, char *argv[]) {
    int mode = 2; /* Default: Attack without SMEP */
    if (argc > 1) {
        mode = atoi(argv[1]);
    }

    printf("======================================================================\n");
    printf(" ⚡ Scenario 02: ret2usr & Hardware SMEP/PXN Defense Simulator       \n");
    printf("    Target: Kernel Socket / Driver Function Pointer Hijacking        \n");
    printf("======================================================================\n");

    kernel_dispatch_context_t ctx;
    memset(&ctx, 0, sizeof(ctx));

    switch (mode) {
        case 1:
            printf("\n[MODE 1: NORMAL SYSCALL DISPATCH (BENIGN OPERATION)]\n");
            ctx.cr4_smep_enabled = 1;
            ctx.pte_pxn_enabled = 1;
            ctx.dispatch_fn = kernel_safe_worker;
            dispatch_syscall(&ctx);
            break;

        case 2:
            printf("\n[MODE 2: RET2USR ATTACK WITHOUT SMEP (EXPLOIT SUCCEEDS)]\n");
            printf("[*] Attacker has UID 0 (from Scenario 01 BLE BOF), but seeks Ring 0.\n");
            printf("[*] Corrupting kernel function pointer via CVE-2017-7308 socket bug...\n");
            ctx.cr4_smep_enabled = 0; /* SMEP disabled */
            ctx.pte_pxn_enabled = 0;  /* PXN disabled */
            ctx.dispatch_fn = user_shellcode;
            dispatch_syscall(&ctx);
            break;

        case 3:
            printf("\n[MODE 3: HARDENED SMEP/PXN DEFENSE (ATTACK INTERCEPTED)]\n");
            printf("[*] Attacker attempts identical ret2usr jump into user shellcode...\n");
            ctx.cr4_smep_enabled = 1; /* CR4 Bit 20 = 1 */
            ctx.pte_pxn_enabled = 1;  /* PTE Bit 53 = 1 */
            ctx.dispatch_fn = user_shellcode;
            dispatch_syscall(&ctx);
            break;

        default:
            fprintf(stderr, "Usage: %s [1: normal | 2: attack-no-smep | 3: attack-with-smep]\n", argv[0]);
            return 1;
    }

    printf("\n======================================================================\n");
    printf(" [SIMULATION COMPLETE] Scenario 02 Laboratory Finished\n");
    printf("======================================================================\n");
    return 0;
}
