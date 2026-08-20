#ifndef PRC_LDPC_H
#define PRC_LDPC_H

#include "../zerobit_prc.h"

#include <stddef.h>

/*
 * ================================================================
 * LDPC parameters
 * ================================================================
 */

typedef struct {
    size_t n;
    size_t r;
    size_t g;
    size_t t;
    double eta;
} LDPCParams;


/*
 * ================================================================
 * LDPC implementation
 * ================================================================
 */

ZBPRC_Keys *
ldpc_keygen(
    const void *params,
    ZBPRC_Random *random
);

uint8_t *
ldpc_encode(
    const void *params,
    const ZBPRC_EncKey *key,
    ZBPRC_Random *random,
    size_t *output_bits
);

int
ldpc_decode(
    const void *params,
    const ZBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits
);

void
ldpc_free_enc_key(
    const void *params,
    ZBPRC_EncKey *key
);

void
ldpc_free_dec_key(
    const void *params,
    ZBPRC_DecKey *key
);


/*
 * ================================================================
 * LDPC PRC constructor
 * ================================================================
 */

ZBPRC
ldpc_zbprc(
    const LDPCParams *params
);

#endif /* PRC_LDPC_H */