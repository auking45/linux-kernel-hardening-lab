/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/auth_hook.c
 *
 * Defines a STRONG version of 'auth_event_logger' to override the WEAK symbol.
 */

#include <stdio.h>

void auth_event_logger(const char *msg)
{
    printf("[HARDENED-AUDIT-LOG] [AUDIT-ACTIVE] %s\n", msg);
}
