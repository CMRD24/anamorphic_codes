#ifndef MBPRC_HIGH_H
#define MBPRC_HIGH_H

/* PRC_high: a PRC for long messages from a lambda-bit PRC and an ECC (see prc_high.c). */

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../multibit_prc_rr.h"
#include "../../../utils/ecc.h"

typedef struct {
    /* the inner lambda-bit PRC (PRC^lambda_low); not owned */
    const MBPRC *inner;

    /* the error-correcting code of the message; not owned */
    const ECC *ecc;

    /* security parameter lambda in bits, a multiple of 8: the length of the seed r */
    size_t lambda;

    /* length of the message in bits, a multiple of 8 */
    size_t message_bits;
} PRCHigh_Params;

MBPRC prc_high(const PRCHigh_Params *params);

/* PRC_high as a seed-recoverable PRC with rho = r (randomness-recovery anamorphism) */
MBPRC_RR prc_high_rr(const PRCHigh_Params *params);

#endif /* MBPRC_HIGH_H */
