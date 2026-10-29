#ifndef ZERO_BIT_PRC_PP_H
#define ZERO_BIT_PRC_PP_H

/* The permuted-puzzle zero-bit PRC PRC_pp over F_q (see prc_pp.c). */

#include <stddef.h>
#include <stdint.h>

#include "../../../utils/ecc.h"
#include "../zerobit_prc.h"
#include "../zerobit_prc_rr.h"

typedef struct {
    /* the error-correcting code C with a worst-case decoder */
    const ECC *ecc;

    /* bytes of x, the message of C; x is the seed rho recovered by the decoder */
    size_t seed_bytes;

    /* alphabet size q; symbols are the integers 0, ..., q-1 */
    size_t q;

    /* bits per symbol, q <= 2^symbol_bits (symbol_bits = m for q = 2^m) */
    size_t symbol_bits;

    /* number n of codeword symbols: the ECC output has exactly n * symbol_bits bits */
    size_t n;

    /* noise parameter delta: Encode substitutes symbols with probability delta/2 */
    double delta;
} PPParams;

ZBPRC prc_pp(const PPParams *params);

/* PRC_pp as a seed-recoverable PRC with rho = x (randomness-recovery anamorphism) */
ZBPRC_RR prc_pp_rr(const PPParams *params);

#endif /* ZERO_BIT_PRC_PP_H */
