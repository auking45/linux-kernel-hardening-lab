/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/libsecure.c
 *
 * Compiled with -fPIC -shared to produce libsecure.so
 */

#include <stdio.h>
#include <string.h>
#include "libsecure.h"

int verify_token(const char *token)
{
    if (!token) return 0;
    return (strncmp(token, "SEC-PASS", 8) == 0);
}

int compute_checksum(int seed)
{
    return (seed * 31) ^ 0x5A5A;
}
