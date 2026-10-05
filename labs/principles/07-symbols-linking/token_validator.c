/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/token_validator.c
 */

#include <stdio.h>
#include <string.h>

/* Global Strong Variable */
int g_auth_counter = 0;

/* Global Strong Function */
int verify_auth_token(const char *token)
{
    g_auth_counter++;
    if (!token) return 0;
    return (strncmp(token, "SEC-KEY", 7) == 0);
}

/* Weak Function: Overridable by another object without linker collisions */
__attribute__((weak))
void auth_event_logger(const char *msg)
{
    printf("[DEFAULT-WEAK-LOGGER] %s\n", msg);
}
