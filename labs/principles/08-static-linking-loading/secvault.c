/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/secvault.c
 */

#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include "libsecure.h"

int main(void)
{
    printf("============================================================\n");
    printf(" Security Vault Service (PID: %d)\n", getpid());
    printf("============================================================\n");

    const char *tok = "SEC-TOKEN-HARDENED-9912";
    int ok = validate_security_token(tok);
    unsigned int mac = compute_mac((const unsigned char *)tok, strlen(tok));

    printf("[+] Token validation: %s\n", ok ? "PASSED" : "FAILED");
    printf("[+] Computed MAC tag: 0x%08X\n", mac);
    printf("============================================================\n");
    return 0;
}
