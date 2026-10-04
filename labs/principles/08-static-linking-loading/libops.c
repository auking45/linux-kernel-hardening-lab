/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/libops.c
 */

#include "libops.h"

int static_multiply(int a, int b)
{
    return a * b;
}

int static_power(int base, int exp)
{
    int res = 1;
    for (int i = 0; i < exp; i++) {
        res *= base;
    }
    return res;
}
