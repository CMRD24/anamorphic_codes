#include "../zerobit_prc.h"
#include "prc_ldpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "../../../utils/matrix.h"
#include "../../../utils/random_utils.h"

/*
 * ================================================================
 * Constants / helpers
 * ================================================================
 */




/*
 * ================================================================
 * Packed bit vector
 * ================================================================
 */



static int sparse_row_contains(const SparseP *P,
                               size_t row,
                               size_t col)
{
    size_t base =
        row * P->t;

    for (size_t j = 0;
         j < P->t;
         ++j) {

        if (P->positions[base + j] == col)
            return 1;
    }

    return 0;
}


void sample_sparse_p(RandomnessSource *random,
                            SparseP *P)
{
    for (size_t row = 0;
         row < P->r;
         ++row) {

        size_t placed = 0;

        while (placed < P->t) {

            size_t col =
                random_bounded(random,
                               P->n);

            if (!sparse_row_contains(P,
                                     row,
                                     col)) {

                P->positions[
                    row * P->t + placed
                ] = col;

                ++placed;
            }
        }
    }
}





/*
 * ================================================================
 * Opaque key structures
 * ================================================================
 */

struct ZBPRC_EncKey {
    PackedG G;
    BitVector z;
};


struct ZBPRC_DecKey {
    SparseP P;
    BitVector z;
};


/*
 * ================================================================
 * Key destruction
 * ================================================================
 */

void ldpc_free_enc_key(const void *params, ZBPRC_EncKey *key)
{
    (void)params;
    if (key == NULL)
        return;

    packed_g_free(&key->G);
    bitvector_free(&key->z);

    free(key);
}


void ldpc_free_dec_key(const void *params, ZBPRC_DecKey *key)
{
    (void)params;
    if (key == NULL)
        return;

    sparse_p_free(&key->P);
    bitvector_free(&key->z);

    free(key);
}

size_t
ldpc_blocksize(const void *params_ptr){
    const LDPCParams *params =
        (const LDPCParams *)params_ptr;
    return params->n;
}





/*
 * ================================================================
 * KeyGen
 * ================================================================
 */

ZBPRC_Keys *
ldpc_keygen(const void *params_ptr,
            RandomnessSource *random)
{
    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    if (params == NULL ||
        random == NULL ||
        random->rng == NULL)
        return NULL;

    if (params->n == 0 ||
        params->r == 0 ||
        params->g == 0 ||
        params->t > params->n ||
        params->g > params->n)
        return NULL;

    ZBPRC_Keys *keys =
        calloc(1, sizeof(ZBPRC_Keys));

    if (keys == NULL)
        return NULL;

    keys->enc =
        calloc(1, sizeof(ZBPRC_EncKey));

    keys->dec =
        calloc(1, sizeof(ZBPRC_DecKey));

    if (keys->enc == NULL ||
    keys->dec == NULL) {

        ldpc_free_enc_key(params_ptr, keys->enc);
        ldpc_free_dec_key(params_ptr, keys->dec);
        free(keys);

        return NULL;
    }

    /*
     * Sample P.
     */
    SparseP P =
        sparse_p_alloc(params->r,
                       params->n,
                       params->t);

    sample_sparse_p(random, &P);

    /*
     * Compute ker(P).
     */
    PackedMatrix A =
        sparse_p_to_packed(&P);
    KernelBasis K =
        kernel_basis(&A);

    if (params->g > K.dimension) {

        fprintf(stderr,
                "ZBPRC-LDPC: g=%zu exceeds "
                "dim ker(P)=%zu.\n",
                params->g,
                K.dimension);

        kernel_basis_free(&K);
        sparse_p_free(&P);
        ldpc_free_enc_key(params_ptr, keys->enc);
        ldpc_free_dec_key(params_ptr, keys->dec);
        free(keys);

        return NULL;
    }

    /*
     * Sample G uniformly from ker(P).
     */
    PackedG G =
        packed_g_alloc(params->n,
                       params->g);

    for (size_t j = 0;
         j < params->g;
         ++j) {

        for (size_t k = 0;
             k < K.dimension;
             ++k) {

            if (random_bit(random)) {

                for (size_t w = 0;
                     w < G.columns[j].words;
                     ++w) {

                    G.columns[j].data[w] ^=
                        K.vectors[k].data[w];
                }
            }
        }
    }

    kernel_basis_free(&K);

    /*
     * Sample z.
     */
    BitVector z =
        bitvector_alloc(params->n);

    random_bitvector(random, &z);

    /*
     * Both keys contain the same z.
     */
    keys->enc->G = G;
    keys->enc->z =
        bitvector_alloc(params->n);

    memcpy(keys->enc->z.data,
           z.data,
           z.words * sizeof(uint64_t));

    keys->dec->P = P;
    keys->dec->z =
        bitvector_alloc(params->n);

    memcpy(keys->dec->z.data,
           z.data,
           z.words * sizeof(uint64_t));

    bitvector_free(&z);

    return keys;
}

/*
 * ================================================================
 * Encode
 * ================================================================
 */

uint8_t *
ldpc_encode(const void *params_ptr,
            const ZBPRC_EncKey *key,
            RandomnessSource *random,
            size_t *output_bits)
{
    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    if (params == NULL ||
        key == NULL ||
        random == NULL ||
        output_bits == NULL)
        return NULL;

    /*
     * s <- F_2^g
     */
    BitVector s =
        bitvector_alloc(params->g);

    random_bitvector(random, &s);

    /*
     * e <- Ber(n, eta)
     */
    BitVector e =
        bitvector_alloc(params->n);

    random_bernoulli_vector(random,
                            &e,
                            params->eta);

    /*
     * Gs.
     */
    BitVector Gs =
        bitvector_alloc(params->n);

    packed_g_mul(&key->G,
                 &s,
                 &Gs);

    /*
     * c = Gs + z + e.
     */
    BitVector c =
        bitvector_alloc(params->n);

    for (size_t w = 0;
         w < c.words;
         ++w) {

        c.data[w] =
            Gs.data[w] ^
            key->z.data[w] ^
            e.data[w];
    }

    /*
     * Convert to packed byte representation.
     */
    size_t bytes =
        (params->n + 7) / 8;

    uint8_t *result =
        calloc(bytes, 1);

    if (result == NULL) {

        bitvector_free(&s);
        bitvector_free(&e);
        bitvector_free(&Gs);
        bitvector_free(&c);

        return NULL;
    }

    for (size_t i = 0;
         i < params->n;
         ++i) {

        if (bit_get(&c, i)) {

            result[i >> 3] |=
                (uint8_t)(
                    1u << (i & 7)
                );
        }
    }

    *output_bits = params->n;

    bitvector_free(&s);
    bitvector_free(&e);
    bitvector_free(&Gs);
    bitvector_free(&c);

    return result;
}


/*
 * ================================================================
 * Decode
 * ================================================================
 */

int
ldpc_decode(const void *params_ptr,
            const ZBPRC_DecKey *key,
            const uint8_t *ciphertext,
            size_t ciphertext_bits)
{
    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    if (params == NULL ||
        key == NULL ||
        ciphertext == NULL)
        return 0;

    /*
     * size of ciphertext must have size n
     */
    if (ciphertext_bits != params->n)
        return 0;


    /*
     * Convert byte representation to BitVector.
     */
    BitVector c =
        bitvector_alloc(params->n);

    for (size_t i = 0;
         i < params->n;
         ++i) {

        if (ciphertext[i >> 3] &
            (uint8_t)(
                1u << (i & 7)
            )) {

            bit_set(&c, i, 1);
        }
    }

    /*
     * Pc.
     */
    BitVector Pc =
        bitvector_alloc(params->r);

    sparse_p_mul(&key->P,
                 &c,
                 &Pc);

    /*
     * Pz.
     */
    BitVector Pz =
        bitvector_alloc(params->r);

    sparse_p_mul(&key->P,
                 &key->z,
                 &Pz);

    /*
     * Pc + Pz.
     */
    for (size_t w = 0;
         w < Pc.words;
         ++w) {

        Pc.data[w] ^=
            Pz.data[w];
    }

    /*
     * wt(Pc + Pz)
     */
    size_t weight =
        bitvector_weight(&Pc);

    /*
     * Threshold:
     *
     *     (1/2 - r^(-1/4)) r
     */
    double threshold =
        (0.5 -
         pow((double)params->r,
             -0.25))
        * (double)params->r;

    int result =
        ((double)weight < threshold);

    bitvector_free(&c);
    bitvector_free(&Pc);
    bitvector_free(&Pz);

    return result;
}


/*
 * ================================================================
 * LDPC zero-bit PRC instantiation
 * ================================================================
 */

ZBPRC
prc_ldpc(const LDPCParams *params)
{
    ZBPRC prc = {
        .params = params,

        .blocksize = ldpc_blocksize,

        .keygen =
            ldpc_keygen,

        .encode =
            ldpc_encode,

        .decode =
            ldpc_decode,

        .free_enc_key =
            ldpc_free_enc_key,

        .free_dec_key =
            ldpc_free_dec_key
    };

    return prc;
}