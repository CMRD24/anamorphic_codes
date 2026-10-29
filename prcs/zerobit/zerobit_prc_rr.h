#ifndef ZERO_BIT_PRC_RR_H
#define ZERO_BIT_PRC_RR_H

/*
 * A k-seed-recoverable zero-bit PRC (definition "seed-recoverable codes" of the
 * thesis): Encode takes its uniform seed rho in F_2^k explicitly, and RecDecode
 * returns the seed together with the decision.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"
#include "zerobit_prc.h"

typedef struct {
    ZBPRC base;

    /* Encode(enc_key; rho, omega): seed = rho (k / 8 bytes), random = the further coins omega */
    uint8_t *(*encode_with_seed)(const void *params,
                                 const ZBPRC_EncKey *enc_key,
                                 RandomnessSource *random,
                                 size_t *codeword_bits,
                                 const uint8_t *seed);

    /* RecDecode: returns 1 and writes rho to seed_out if the codeword is accepted, 0 otherwise */
    int (*recover_decode)(const void *params,
                          const ZBPRC_DecKey *dec_key,
                          const uint8_t *codeword,
                          size_t codeword_bits,
                          uint8_t *seed_out);
} ZBPRC_RR;

#endif /* ZERO_BIT_PRC_RR_H */
