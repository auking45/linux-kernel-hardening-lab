/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/secvault_dyn.c
 *
 * Demonstrates:
 * 1. 1st call to verify_token(): Triggers Lazy Binding via PLT/GOT & _dl_runtime_resolve
 * 2. 2nd call to verify_token(): Direct jump using cached GOT entry
 */

#include <stdio.h>
#include <unistd.h>
#include "libsecure.h"

int main(void)
{
    printf("============================================================\n");
    printf(" PLT / GOT Lazy Binding Demonstration (PID: %d)\n", getpid());
    printf("============================================================\n");

    const char *tok = "SEC-PASS-9900";

    /* [1st Call] verify_token - Triggers dynamic linker lazy resolution */
    printf("[*] [Call 1] Invoking verify_token() for the first time...\n");
    int res1 = verify_token(tok);
    printf("[+] [Call 1 Result] %s\n", res1 ? "AUTHORIZED" : "DENIED");

    /* [2nd Call] verify_token - Directly branches via resolved GOT entry */
    printf("[*] [Call 2] Invoking verify_token() for the second time...\n");
    int res2 = verify_token(tok);
    printf("[+] [Call 2 Result] %s\n", res2 ? "AUTHORIZED" : "DENIED");

    int chk = compute_checksum(42);
    printf("[+] Checksum computation: 0x%04X\n", chk);

    printf("============================================================\n");
    return 0;
}
