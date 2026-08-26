
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