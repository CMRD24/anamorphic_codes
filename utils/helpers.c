
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>


/*
 * ================================================================
 * Helpers
 * ================================================================
 */

 size_t
bits_to_bytes(
    size_t bits)
{
    return (bits + 7) / 8;
}


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
    size_t bits)
{
    for (size_t i = 0; i < bits; ++i) {

        size_t s =
            src_bit + i;

        size_t d =
            dst_bit + i;

        uint8_t bit =
            (uint8_t)(
                (src[s >> 3] >> (s & 7)) & 1u
            );

        if (bit) {

            dst[d >> 3] |=
                (uint8_t)(1u << (d & 7));

        } else {

            dst[d >> 3] &=
                (uint8_t)~(1u << (d & 7));
        }
    }
}


/*
 * Constant-time comparison.
 */
 int
constant_time_equal(
    const uint8_t *a,
    const uint8_t *b,
    size_t len)
{
    uint8_t diff = 0;

    for (size_t i = 0; i < len; ++i)
        diff |= (uint8_t)(a[i] ^ b[i]);

    return diff == 0;
}


static size_t bitwise_hamming_dist(const uint8_t *a,
    const uint8_t *b,
    size_t len){
        size_t distance = 0;

        for (size_t i = 0; i < len; i++) {
            distance += __builtin_popcount((unsigned int)(a[i] ^ b[i]));
        }

        return distance;
    }

