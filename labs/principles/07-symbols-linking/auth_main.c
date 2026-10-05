/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/auth_main.c
 */

#include <stdio.h>

/* External symbol declarations */
extern int g_auth_counter;
extern int verify_auth_token(const char *token);
extern void auth_event_logger(const char *msg);

int main(void)
{
    printf("============================================================\n");
    printf(" Symbol Resolution & Relocation Demonstration\n");
    printf("============================================================\n");

    const char *test_token = "SEC-KEY-7721";
    int valid = verify_auth_token(test_token);

    printf("[+] Token verification result : %s\n", valid ? "VALID" : "INVALID");
    printf("[+] Global counter address    : %p (val=%d)\n",
           (void *)&g_auth_counter, g_auth_counter);

    printf("[+] Calling auth_event_logger at: %p\n    ", (void *)auth_event_logger);
    auth_event_logger("Authentication cycle successfully completed");

    printf("============================================================\n");
    return 0;
}
