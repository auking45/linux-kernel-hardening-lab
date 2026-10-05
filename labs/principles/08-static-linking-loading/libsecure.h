/**
 * Linux Kernel Hardening Lab - Principles Track 4: Static Linking & Loading
 * labs/principles/08-static-linking-loading/libsecure.h
 */

#ifndef LIBSECURE_H
#define LIBSECURE_H

#include <stddef.h>

int validate_security_token(const char *token);
unsigned int compute_mac(const unsigned char *data, size_t len);

#endif /* LIBSECURE_H */
