/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/app.c
 */

#include <stdio.h>
#include <unistd.h>
#include "libops.h"

int main(void)
{
    printf("============================================================\n");
    printf(" Static vs Dynamic Linking Application (PID: %d)\n", getpid());
    printf("============================================================\n");

    int mul = static_multiply(6, 7);
    int pwr = static_power(2, 8);

    printf("[+] static_multiply(6, 7) = %d\n", mul);
    printf("[+] static_power(2, 8)     = %d\n", pwr);
    printf("[+] Address of static_multiply: %p\n", (void *)static_multiply);
    printf("[+] Address of printf         : %p\n", (void *)printf);
    printf("============================================================\n");

    return 0;
}
