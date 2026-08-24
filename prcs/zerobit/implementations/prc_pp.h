#ifndef ZERO_BIT_PRC_PP_H
#define ZERO_BIT_PRC_PP_H

#include <stddef.h>
#include <stdint.h>

#include "../../../utils/random.h"
#include "../../../utils/ecc.h"
#include "../zerobit_prc.h"


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


#endif /* ZERO_BIT_PRC_PP_H */