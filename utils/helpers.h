
#ifndef HELPERS_H
#define HELPERS_H

#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>


 size_t
bits_to_bytes(
    size_t bits);

/*
 * Copy arbitrary packed bits.
 *
 * Bit numbering is LSB-first inside each byte, consistent with
 * the rest of the PRC code.
 */
 void
copy_bits(
    uint8_t *dst,
    size_t dst_bit,
    const uint8_t *src,
    size_t src_bit,
    size_t bits);


/*
 * Single-bit access in a packed byte array.
 *
 * Bits are numbered from the least significant bit of byte 0.
 */
static inline uint8_t
get_bit(
    const uint8_t *data,
    size_t index)
{
    return (uint8_t)((data[index >> 3] >> (index & 7)) & 1u);
}

static inline void
set_bit(
    uint8_t *data,
    size_t index,
    uint8_t value)
{
    const uint8_t mask = (uint8_t)(1u << (index & 7));

    if (value)
        data[index >> 3] |= mask;
    else
        data[index >> 3] &= (uint8_t)~mask;
}

/*
 * Constant-time comparison.
 */
 int
constant_time_equal(
    const uint8_t *a,
    const uint8_t *b,
    size_t len);

size_t bitwise_hamming_dist(const uint8_t *a,
    const uint8_t *b,
    size_t len);


#endif /* HELPERS_H */