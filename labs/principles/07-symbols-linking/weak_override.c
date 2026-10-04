/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/weak_override.c
 */

#include <stdio.h>

/* Strong version overriding the weak symbol in calc.c */
void custom_hook(void)
{
    printf("[weak_override.c] ★ STRONG hook successfully overrode the weak symbol!\n");
}
