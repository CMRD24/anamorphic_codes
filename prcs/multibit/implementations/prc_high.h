#ifndef MBPRC_HIGH_H
#define MBPRC_HIGH_H

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../../../utils/ecc.h"

/*
 * ================================================================
 * PRC^ell_high parameters
 * ================================================================
 *
 * The construction combines:
 *
 *     - an underlying PRC^lambda_low
 *     - an ECC
 *     - a seeded pseudorandom generator
 *     - a random bit permutation
 *
 * The low PRC must encode lambda seed bits into
 * low_codeword_bits bits.
 *
 * The ECC must encode a message into ecc_codeword_bits bits.
 *
 * Therefore every high-level ciphertext has
 *
 *     low_codeword_bits + ecc_codeword_bits
 *
 * bits.
 *
 * The permutation operates on these individual bits.
 * ================================================================
 */

typedef struct {

    /*
     * Underlying PRC^lambda_low.
     *
     * This object is not owned by the high-level PRC. This PRC must be able to encode exactly lambda bits
     */
    const MBPRC *low_prc;

    /*
     * Underlying error-correcting code.
     *
     * This object is not owned by the high-level PRC.
     */
    const ECC *ecc;

    /*
     * Security parameter lambda in bits.
     *
     * Must be a multiple of 8 because the PRG seed is represented
     * as a byte array. 
     */
    size_t lambda;

    /*
     * Number of bits in the prc message.
     */
    size_t message_bits;


} PRCHigh_Params;


MBPRC prc_high_create(
    const PRCHigh_Params *params
);

#endif /* MBPRC_HIGH_H */