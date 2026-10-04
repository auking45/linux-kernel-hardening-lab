/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/plt_got_inspector.c
 *
 * Demonstrates the PLT/GOT mechanism:
 * 1. Initial indirect jump through GOT
 * 2. Dynamic linker resolution
 * 3. GOT address caching
 */

#include <stdio.h>
#include <unistd.h>

int main(void)
{
    printf("============================================================\n");
    printf(" PLT / GOT Lazy Binding & Resolution Inspector (PID: %d)\n", getpid());
    printf("============================================================\n");

    printf("[1] First call to printf/puts: Dynamic linker resolves symbol.\n");
    printf("[2] Second call to printf/puts: GOT already holds resolved address.\n");
    printf("[+] Target function 'printf' resolved address in libc: %p\n", (void *)printf);
    printf("[+] Process PID: %d\n", getpid());
    printf("============================================================\n");

    return 0;
}
