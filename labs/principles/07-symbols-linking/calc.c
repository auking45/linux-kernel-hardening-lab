/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/calc.c
 */

#include <stdio.h>

/* Global Strong Variable */
int g_operation_count = 0;

/* Strong Function */
int calculate_add(int a, int b)
{
    g_operation_count++;
    return a + b;
}

/* Weak Function: Can be overridden by another object file without linker error */
__attribute__((weak))
void custom_hook(void)
{
    printf("[calc.c] Default WEAK hook executed (no override provided).\n");
}
