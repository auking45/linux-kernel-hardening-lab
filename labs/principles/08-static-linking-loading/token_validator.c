/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/token_validator.c
 */

#include <string.h>
#include "libsecure.h"

int validate_security_token(const char *token)
{
    if (!token) return 0;
    return (strncmp(token, "SEC-TOKEN-HARDENED", 18) == 0);
}
