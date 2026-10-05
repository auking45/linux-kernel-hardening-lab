/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/crypto_mac.c
 */

#include "libsecure.h"

unsigned int compute_mac(const unsigned char *data, size_t len)
{
    /* Simple Bernstein hash for demonstration */
    unsigned int hash = 5381;
    for (size_t i = 0; i < len; i++) {
        hash = ((hash << 5) + hash) + data[i];
    }
    return hash;
}
