#ifndef UTIL_NUMTOSTR_H
#define UTIL_NUMTOSTR_H

#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>
#include "macros.h"

extern const char hextab_lower[16];
extern const char hextab_upper[16];

// Encodes a byte of data as 2 hexadecimal digits
static inline char *hex_encode_byte(char *out, uint8_t byte)
{
    out[0] = hextab_lower[byte >> 4];
    out[1] = hextab_lower[byte & 0xF];
    return out;
}

// Encodes 24 bits from a uint32_t as 6 hexadecimal digits (fixed width)
static inline char *hex_encode_u24_fixed(char *out, uint32_t x)
{
    UNROLL_LOOP(6)
    for (size_t i = 0, n = 6; i < n; i++) {
        unsigned int shift = (n - i - 1) * 4;
        out[i] = hextab_lower[(x >> shift) & 0xF];
    }
    return out;
}

size_t buf_umax_to_str(uintmax_t x, char *buf) NONNULL_ARGS;
size_t buf_umax_to_hex_str(uintmax_t x, char *buf, size_t min_digits) NONNULL_ARGS;
size_t buf_uint_to_str(unsigned int x, char *buf) NONNULL_ARGS;
const char *umax_to_str(uintmax_t x) RETURNS_NONNULL;
const char *uint_to_str(unsigned int x) RETURNS_NONNULL;
const char *ulong_to_str(unsigned long x) RETURNS_NONNULL;
char *filemode_to_str(mode_t mode, char *buf) NONNULL_ARGS_AND_RETURN;

#endif
