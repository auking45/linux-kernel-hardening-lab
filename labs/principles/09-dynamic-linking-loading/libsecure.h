/**
 * Linux Kernel Hardening Lab - Principles Track 4: Dynamic Linking & Loading
 * labs/principles/09-dynamic-linking-loading/libsecure.h
 */

#ifndef LIBSECURE_SO_H
#define LIBSECURE_SO_H

int verify_token(const char *token);
int compute_checksum(int seed);

#endif /* LIBSECURE_SO_H */
