#ifndef MULTI_BIT_PRC_RR_H
#define MULTI_BIT_PRC_RR_H

/*
 * A k-seed-recoverable multibit PRC (definition "seed-recoverable codes" of the
 * thesis): Encode takes its uniform seed rho in F_2^k explicitly, and RecDecode
 * returns the seed together with the message.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"
#include "multibit_prc.h"

typedef struct {
    MBPRC base;

    /* Encode(enc_key, m; rho, omega): seed = rho (k / 8 bytes), random = the further coins omega */
    uint8_t *(*encode_with_seed)(const void *params,
                                 const MBPRC_EncKey *enc_key,
                                 const uint8_t *message,
                                 size_t message_bits,
                                 RandomnessSource *random,
                                 size_t *codeword_bits,
                                 const uint8_t *seed);

    /* RecDecode: returns 1, the message and rho (seed_out) on success, 0 otherwise */
    int (*recover_decode)(const void *params,
                          const MBPRC_DecKey *dec_key,
                          const uint8_t *codeword,
                          size_t codeword_bits,
                          uint8_t *message_out,
                          size_t *message_bits_out,
                          uint8_t *seed_out);
} MBPRC_RR;

#endif /* MULTI_BIT_PRC_RR_H */
