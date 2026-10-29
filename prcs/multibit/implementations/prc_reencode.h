#ifndef PRC_REENCODE_H
#define PRC_REENCODE_H

/*
 * PRC_sharp and PRC_cca (see prc_reencode.c): multibit PRCs that derive the
 * coins of an inner PRC from (r, m) and check a decoding by re-encoding. They
 * differ only in the function that derives the coins.
 */

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../multibit_prc_rr.h"

typedef struct {
    /* the inner PRC; it must encode messages of lambda + message_bits + lambda bits */
    const MBPRC *inner;

    /* security parameter lambda in bits (a multiple of 8): the length of r and of R2 */
    size_t lambda;

    /* the decoder accepts re-encodings within relative Hamming distance delta */
    double delta;
} PRCReencode_Params;

/* PRC_sharp: R2 || R1 = F(sk, r || m) for a PRF F */
MBPRC prc_sharp(const PRCReencode_Params *params);
MBPRC_RR prc_sharp_rr(const PRCReencode_Params *params);

/* PRC_cca: R2 || R1 derived from H(hk, r || m) for a hash function H (random oracle) */
MBPRC prc_cca(const PRCReencode_Params *params);
MBPRC_RR prc_cca_rr(const PRCReencode_Params *params);

#endif /* PRC_REENCODE_H */
