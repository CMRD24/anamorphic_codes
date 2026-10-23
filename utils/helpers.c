
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

size_t
bits_to_bytes(
    size_t bits)
{
    return (bits + 7) / 8;
}

/*
 * Copies `bits` bits from src (starting at bit src_bit) to dst (starting at bit dst_bit),
 * bit by bit, so neither position needs to be byte aligned. Bit i of a byte array is
 * bit (i mod 8) of byte i / 8 (least significant bit first); bits outside the range
 * are left unchanged.
 */
void copy_bits(
    uint8_t *dst,
    size_t dst_bit,
    const uint8_t *src,
    size_t src_bit,
    size_t bits)
{
    for (size_t i = 0; i < bits; ++i)
    {

        size_t s =
            src_bit + i;

        size_t d =
            dst_bit + i;

        uint8_t bit =
            (uint8_t)((src[s >> 3] >> (s & 7)) & 1u);

        if (bit)
        {

            dst[d >> 3] |=
                (uint8_t)(1u << (d & 7));
        }
        else
        {

            dst[d >> 3] &=
                (uint8_t)~(1u << (d & 7));
        }
    }
}

/*
 * a == b for len bytes in time independent of the contents: the XOR of all byte pairs is
 * accumulated without an early exit, so a timing observer learns nothing about where
 * the arrays differ (used when comparing values derived from secrets).
 */
int constant_time_equal(
    const uint8_t *a,
    const uint8_t *b,
    size_t len)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < len; ++i)
        diff |= (uint8_t)(a[i] ^ b[i]);

    return diff == 0;
}

/*
 * Hamming distance of two byte arrays: the number of differing bits (population count of the XOR).
 */
size_t bitwise_hamming_dist(const uint8_t *a,
                            const uint8_t *b,
                            size_t len)
{
    size_t distance = 0;

    for (size_t i = 0; i < len; i++)
    {
        distance += __builtin_popcount((unsigned int)(a[i] ^ b[i]));
    }

    return distance;
}
