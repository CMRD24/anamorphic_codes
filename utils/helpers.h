#ifndef HELPERS_H
#define HELPERS_H

/*
 * Packed bit strings: bit i is bit (i mod 8) of byte i / 8 (least significant
 * bit first), consistently in all PRC code.
 */

#include <stddef.h>
#include <stdint.h>

size_t bits_to_bytes(size_t bits);

/* copies `bits` bits from src (from bit src_bit) to dst (from bit dst_bit) */
void copy_bits(uint8_t *dst, size_t dst_bit, const uint8_t *src, size_t src_bit, size_t bits);

static inline uint8_t
get_bit(const uint8_t *data, size_t index)
{
    return (uint8_t)((data[index >> 3] >> (index & 7)) & 1u);
}

static inline void
set_bit(uint8_t *data, size_t index, uint8_t value)
{
    const uint8_t mask = (uint8_t)(1u << (index & 7));

    if (value)
        data[index >> 3] |= mask;
    else
        data[index >> 3] &= (uint8_t)~mask;
}

/* a == b for len bytes, in time independent of the contents */
int constant_time_equal(const uint8_t *a, const uint8_t *b, size_t len);

/* the number of differing bits of two byte arrays of len bytes */
size_t hamming_distance(const uint8_t *a, const uint8_t *b, size_t len);

#endif /* HELPERS_H */
