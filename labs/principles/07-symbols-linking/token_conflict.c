/**
 * Linux Kernel Hardening Lab - Principles Track 4: Symbols & Relocation
 * labs/principles/07-symbols-linking/token_conflict.c
 *
 * Intentionally defines a duplicate strong symbol 'verify_auth_token'
 * to demonstrate the linker collision error: "multiple definition of 'verify_auth_token'"
 */

int verify_auth_token(const char *token)
{
    (void)token;
    return 42; /* Duplicate strong definition */
}
