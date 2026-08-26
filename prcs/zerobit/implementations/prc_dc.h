#ifndef PRC_DC_H
#define PRC_DC_H

#include <stddef.h>
#include <stdint.h>

#include "../zerobit_prc.h"


/*
 * ================================================================
 * DC-PRC parameters
 * ================================================================
 *
 * The DC-PRC transforms each bit of the underlying PRC encoding
 * into a T-bit slice with the same majority.
 *
 * k is an explicit parameter of the DC-PRC and denotes the number
 * of bits in the underlying PRC codeword.
 */
typedef struct {
    size_t k;
    size_t T;

    /*
     * Underlying zero-bit PRC.
     *
     * The DC-PRC delegates key generation, decoding and key
     * destruction to this PRC.
     */
    const ZBPRC *underlying;

} PRCDC_Params;


/*
 * ================================================================
 * Construction
 * ================================================================
 */

ZBPRC
prc_dc(
    const PRCDC_Params *params
);


/*
 * ================================================================
 * Utility functions
 * ================================================================
 */

size_t
prc_dc_bytes_for_bits(
    size_t n
);


uint8_t
prc_dc_majority(
    const uint8_t *bits,
    size_t bit_offset,
    size_t length
);

#endif /* PRC_DC_H */