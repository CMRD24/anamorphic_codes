#ifndef ZERO_BIT_PRC_PP_H
#define ZERO_BIT_PRC_PP_H

#include <stddef.h>
#include <stdint.h>

#include "../../../utils/random.h"
#include "../../../utils/ecc.h"
#include "../zerobit_prc.h"
#include "../zerobit_prc_rr.h"


typedef struct {

    /*
     * Underlying error-correcting code.
     */
    ECC *ecc;

    /*
     * Number of message bytes given to the ECC.
     */
    size_t message_bytes;

    /*
     * Alphabet size q.
     *
     * Symbols are represented by integers
     *
     *     0, ..., q-1.
     */
    size_t q;

    /*
     * Number of bits used to represent one alphabet symbol.
     *
     * For q = 2^m:
     *
     *     symbol_bits = m.
     *
     * For a general q this must satisfy
     *
     *     q <= 2^symbol_bits.
     */
    size_t symbol_bits;

    /*
     * Number of codeword symbols.
     *
     * The ECC output must contain exactly
     *
     *     n * symbol_bits
     *
     * bits.
     */
    size_t n;

    /*
     * Noise parameter δ.
     *
     * Encode uses substitution probability δ/2.
     */
    double delta;

} PPParams;



ZBPRC
prc_pp(
    const PPParams *params
);

ZBPRC_RR
prc_pp_rr(
    const PPParams *params
);

//utilities for anamorphism:

int
zbprc_pp_decode_ws(
    const void *vparams,
    const ZBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *seed_out
    );

 uint8_t *
zbprc_pp_encode_ws(
    const void *vparams,
    const ZBPRC_EncKey *key,
    RandomnessSource *random,
    size_t *output_bits,
    const uint8_t *seed
);

#endif /* ZERO_BIT_PRC_PP_H */