#include "helpers.h"

#include <stddef.h>
#include <stdint.h>

size_t bits_to_bytes(size_t bits)
{
    return (bits + 7) / 8;
}

/*
 * Copies `bits` bits from src (starting at bit src_bit) to dst (starting at bit dst_bit),
 * bit by bit, so neither position needs to be byte aligned; bits of dst outside the
 * range are left unchanged.
 */
void copy_bits(uint8_t *dst, size_t dst_bit, const uint8_t *src, size_t src_bit, size_t bits)
{
    for (size_t i = 0; i < bits; ++i)
        set_bit(dst, dst_bit + i, get_bit(src, src_bit + i));
}

/*
 * a == b for len bytes in time independent of the contents: the XOR of all byte pairs is
 * accumulated without an early exit, so a timing observer learns nothing about where
 * the arrays differ (used when comparing values derived from secrets).
 */
int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len)
{
    uint8_t difference = 0;

    for (size_t i = 0; i < len; ++i)
        difference |= (uint8_t)(a[i] ^ b[i]);

    return difference == 0;
}

/* Hamming distance: the population count of the XOR. */
size_t hamming_distance(const uint8_t *a, const uint8_t *b, size_t len)
{
    size_t distance = 0;

    for (size_t i = 0; i < len; i++)
        distance += (size_t)__builtin_popcount((unsigned int)(a[i] ^ b[i])); //gcc compiler function

    return distance;
}
