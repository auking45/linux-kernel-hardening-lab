/**
 * Linux Kernel Hardening Lab - Principles Track 2: Stack Frame & Calling Convention (ABI)
 * labs/principles/03-stack-frame/stack_frame_demo.c
 *
 * Visualizes stack frame generation, function prologue/epilogue,
 * calling conventions (registers vs stack args), Saved Frame Pointer (SFP/RBP),
 * and the exact byte distance to the Return Address (RET).
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

/* Force frame pointer generation (-fno-omit-frame-pointer) */
__attribute__((noinline))
void target_function(uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4,
                     uint64_t a5, uint64_t a6, uint64_t a7, uint64_t a8)
{
    char local_buffer[32];
    uint64_t local_var = 0xDEADBEEFCAFEBABE;

    /* Get addresses of Saved Frame Pointer and Return Address */
    void *frame_addr = __builtin_frame_address(0);
    void *ret_addr = __builtin_return_address(0);

    /* Fill local buffer */
    strncpy(local_buffer, "SYSTEM_SECURITY_PRINCIPLES", sizeof(local_buffer) - 1);
    local_buffer[sizeof(local_buffer) - 1] = '\0';

    printf("============================================================\n");
    printf(" Stack Frame Anatomical Analysis (target_function)\n");
    printf("============================================================\n");

#if defined(__x86_64__)
    printf("[ABI] Architecture: x86_64 (System V AMD64 ABI)\n");
    printf("      Register Args: a1(RDI)=0x%lx, a2(RSI)=0x%lx, a3(RDX)=0x%lx\n", a1, a2, a3);
    printf("                     a4(RCX)=0x%lx, a5(R8)=0x%lx,  a6(R9)=0x%lx\n", a4, a5, a6);
    printf("      Stack Args   : a7=%p (0x%lx), a8=%p (0x%lx)\n",
           (void *)&a7, a7, (void *)&a8, a8);
#elif defined(__aarch64__)
    printf("[ABI] Architecture: ARM64 (AAPCS64)\n");
    printf("      Register Args: a1(X0)=0x%lx, a2(X1)=0x%lx, a3(X2)=0x%lx\n", a1, a2, a3);
    printf("                     a4(X3)=0x%lx, a5(X4)=0x%lx, a6(X5)=0x%lx\n", a4, a5, a6);
    printf("                     a7(X6)=0x%lx, a8(X7)=0x%lx\n", a7, a8);
#endif

    printf("------------------------------------------------------------\n");
    printf("[Stack Frame Memory Layout from Low to High Addresses]\n");
    printf("  [Low Addr]  local_buffer[0]      : %p\n", (void *)&local_buffer[0]);
    printf("              local_buffer[31]     : %p\n", (void *)&local_buffer[31]);
    printf("              local_var            : %p (val=0x%lx)\n", (void *)&local_var, local_var);
    printf("              Saved Frame Pointer  : %p (points to caller's frame)\n", frame_addr);
    printf("  [High Addr] Return Address (RET) : %p (caller: %p)\n",
           (void *)((uintptr_t *)frame_addr + 1), ret_addr);
    printf("------------------------------------------------------------\n");

    /* Calculate byte offset from buffer start to return address */
    intptr_t offset_to_sfp = (uintptr_t)frame_addr - (uintptr_t)&local_buffer[0];
    intptr_t offset_to_ret = (uintptr_t)((uintptr_t *)frame_addr + 1) - (uintptr_t)&local_buffer[0];

    printf("[Buffer Overflow Math]\n");
    printf("  * Distance from local_buffer[0] to Saved RBP (SFP) : %ld bytes\n", offset_to_sfp);
    printf("  * Distance from local_buffer[0] to Return Address  : %ld bytes\n", offset_to_ret);
    printf("  => To smash Return Address: Provide [%ld bytes of padding] + [8 bytes of target address]\n",
           offset_to_ret);
    printf("============================================================\n");
}

int main(void)
{
    printf("[+] Calling target_function from main() (main=%p)...\n\n", (void *)main);
    target_function(0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88);
    printf("\n[+] Successfully returned to main(). Execution continues safely.\n");
    return 0;
}
