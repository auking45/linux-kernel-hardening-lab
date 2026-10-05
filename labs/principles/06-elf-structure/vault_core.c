/**
 * Linux Kernel Hardening Lab - Principles Track 4: Compilation & ELF Format
 * labs/principles/06-elf-structure/vault_core.c
 *
 * Demonstrates:
 * 1. Preprocessor macro expansions
 * 2. Section placement (.rodata, .data, .bss, .text)
 * 3. Compiler optimization: printf() replacement with puts()
 * 4. DWARF debugging symbols (-g)
 */

#include <stdio.h>
#include <string.h>

#define VAULT_VERSION "2.4.0-hardened"
#define MAX_BUFFER_SIZE 256

/* Initialized global variable -> placed in .data section */
int g_vault_status = 1;
const char *g_banner = "[SEC-VAULT] Hardware Security Module Initialized";

/* Uninitialized global buffer -> placed in .bss section (NOBITS) */
char g_session_token[MAX_BUFFER_SIZE];

/* Static function -> internal linkage (STB_LOCAL symbol) */
static void initialize_crypto_state(void)
{
    /* .bss memory is zero-initialized by the kernel at runtime */
    strncpy(g_session_token, "TOKEN-9872-SECURE-KEY", sizeof(g_session_token) - 1);
}

int main(int argc, char *argv[])
{
    /* String literal placed in .rodata */
    const char *msg = "=== Security Vault Service Online ===";

    /*
     * Compiler optimization test:
     * GCC/Clang replaces printf without format specifiers with puts()
     * to avoid format string evaluation overhead.
     */
    printf("%s\n", msg);
    printf("Static Banner: %s (v%s)\n", g_banner, VAULT_VERSION);

    initialize_crypto_state();

    if (argc > 1) {
        printf("[+] Arg received: %s\n", argv[1]);
    }

    printf("[+] Active Session: %s (Status=%d)\n", g_session_token, g_vault_status);
    return 0;
}
