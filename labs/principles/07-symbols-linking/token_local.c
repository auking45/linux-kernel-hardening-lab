/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/token_local.c
 *
 * Defines 'g_auth_counter' as static (LOCAL binding).
 * When auth_main.c attempts to link against extern int g_auth_counter,
 * the linker fails with: "undefined reference to 'g_auth_counter'".
 */

#include <string.h>

/* static forces STB_LOCAL binding in .symtab */
static int g_auth_counter = 0;

int verify_auth_token(const char *token)
{
    g_auth_counter++;
    if (!token) return 0;
    return (strncmp(token, "SEC-KEY", 7) == 0);
}
