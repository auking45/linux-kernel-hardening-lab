/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/main.c
 */

#include <stdio.h>

/* External symbol declarations resolved during linking */
extern int g_operation_count;
extern int calculate_add(int a, int b);
extern void custom_hook(void);

int main(void)
{
    printf("============================================================\n");
    printf(" Symbol Resolution & Relocation Demonstration\n");
    printf("============================================================\n");

    int res = calculate_add(10, 20);
    printf("[+] calculate_add(10, 20) = %d\n", res);
    printf("[+] g_operation_count address: %p (val=%d)\n",
           (void *)&g_operation_count, g_operation_count);

    printf("[+] Calling custom_hook() at %p:\n    ", (void *)custom_hook);
    custom_hook();

    printf("============================================================\n");
    return 0;
}
