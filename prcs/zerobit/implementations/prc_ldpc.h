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

typedef struct {
    size_t rows;
    size_t cols;
    size_t words;

    uint64_t *data;
} PackedMatrix;


typedef struct {
    size_t bits;
    size_t words;
    uint64_t *data;
} BitVector;

typedef struct {
    size_t n;
    size_t g;
    BitVector *columns;
} PackedG;

typedef struct {
    size_t r;
    size_t n;
    size_t t;

    size_t *positions;
} SparseP;

typedef struct
{
    PackedG *G_prime;
    SparseP *P_prime;
} anakey;

anakey *
ldpc_akeygen(const void *params_ptr, ZBPRC_Keys *reg_keys,
            RandomnessSource *random);

int
ldpc_adecode(const void *params_ptr,
            const ZBPRC_DecKey *key,
            const anakey *dk,
            const uint8_t *ciphertext,
            size_t ciphertext_bits);

uint8_t *
ldpc_aencode(const void *params_ptr,
            const ZBPRC_EncKey *key,
            const anakey *dk,
            RandomnessSource *random,
            size_t *output_bits);

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