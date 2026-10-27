/*
 * Zero-bit pseudorandom error-correcting code from sparse parity checks and LPN
 * (the LDPC based construction of M. Christ and S. Gunn, "Pseudorandom
 * Error-Correcting Codes", CRYPTO 2024).
 *
 * Keys. (P, G) <- LDPC[n, g, t, r]: a sparse parity-check matrix P (r x n,
 * exactly t ones per row) and a generator matrix G (n x g) whose columns are
 * independent, uniform elements of ker P, so P G = 0; a one-time pad
 * z <- F_2^n. The encoding key is (G, z), the decoding key (P, z).
 *
 * Encode: c = G s + z + e with s uniform in F_2^g and e ~ Ber(n, eta) (each
 * coordinate 1 with probability eta). Under the learning-parity-with-noise (LPN)
 * assumption for G, and a planted-XOR assumption for the sparse rows of P, c is
 * pseudorandom without the key.
 *
 * Decode: P (c + z) = P G s + P e = P e, since P G = 0. Each coordinate of P e is
 * the parity of t entries of e, which is 1 with probability well below 1/2 when e
 * is sparse. For a string that is not a codeword the syndrome is uniform, i.e. of
 * weight about r/2. The decoder accepts iff the weight is below
 * (1/2 - r^(-1/4)) r, a threshold that separates the two cases by Hoeffding's
 * inequality; a legitimate codeword is accepted also after a binary symmetric
 * channel adds noise as long as the total noise rate is a constant below 1/2.
 */

#include "prc_ldpc.h"
#include "prc_ldpc_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/matrix.h"
#include "../../../utils/random_utils.h"


static void ldpc_free_enc_key(const void *params, ZBPRC_EncKey *enc_key)
{
    (void)params;

    if (enc_key == NULL)
        return;

    column_matrix_free(&enc_key->G);
    bitvector_free(&enc_key->z);
    free(enc_key);
}

static void ldpc_free_dec_key(const void *params, ZBPRC_DecKey *dec_key)
{
    (void)params;

    if (dec_key == NULL)
        return;

    sparse_matrix_free(&dec_key->P);
    bitvector_free(&dec_key->z);
    free(dec_key);
}

static size_t ldpc_block_length(const void *params)
{
    return ((const LDPCParams *)params)->n;
}

/*
 * (P, G) <- LDPC[n, g, t, r] and z <- F_2^n: samples P, then the g columns of G
 * as independent, uniform elements of ker P (sparse_matrix_sample_kernel). Fails
 * for parameters that are not structurally valid. It does NOT assess/check the security level achievable
 * by the chosen parameters! 
 */
static ZBPRC_Keys *ldpc_keygen(const void *params_ptr, RandomnessSource *random)
{
    const LDPCParams *params = params_ptr;

    if (params == NULL || random == NULL || random->rng == NULL ||
        params->n == 0 || params->r == 0 || params->g == 0 ||
        params->t == 0 || params->t > params->n || params->g + params->r > params->n)
        return NULL;

    ZBPRC_Keys *keys = calloc(1, sizeof(*keys));

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (keys->enc == NULL || keys->dec == NULL) {
        free(keys->enc);
        free(keys->dec);
        free(keys);
        return NULL;
    }

    keys->dec->P = sparse_matrix_alloc(params->r, params->n, params->t);
    sparse_matrix_sample(&keys->dec->P, random);

    keys->enc->G = sparse_matrix_sample_kernel(&keys->dec->P, params->g, random);

    keys->enc->z = bitvector_alloc(params->n);
    random_bitvector(random, &keys->enc->z);

    keys->dec->z = bitvector_alloc(params->n);
    bitvector_add(&keys->dec->z, &keys->enc->z);

    return keys;
}

uint8_t *ldpc_encode_seed(const LDPCParams *params,
                            const ZBPRC_EncKey *enc_key,
                            const BitVector *x,
                            RandomnessSource *random,
                            size_t *codeword_bits)
{
    BitVector c = bitvector_alloc(params->n);
    BitVector e = bitvector_alloc(params->n);

    column_matrix_mul_vector(&enc_key->G, x, &c);

    random_bernoulli_vector(random, &e, params->eta);
    bitvector_add(&c, &e);
    bitvector_add(&c, &enc_key->z);

    uint8_t *codeword = bitvector_to_bytes(&c);

    if (codeword != NULL)
        *codeword_bits = params->n;

    bitvector_free(&e);
    bitvector_free(&c);

    return codeword;
}

int ldpc_syndrome_test(const SparseMatrix *P,
                       const BitVector *z,
                       const uint8_t *codeword,
                       size_t codeword_bits)
{
    if (codeword == NULL || codeword_bits != P->cols)
        return 0;

    BitVector c = bitvector_alloc(P->cols);
    BitVector syndrome = bitvector_alloc(P->rows);

    bitvector_from_bytes(&c, codeword);
    bitvector_add(&c, z);
    sparse_matrix_mul_vector(P, &c, &syndrome);

    const double rows = (double)P->rows;
    const double threshold = (0.5 - pow(rows, -0.25)) * rows;
    const int accepted = (double)bitvector_weight(&syndrome) < threshold;

    bitvector_free(&syndrome);
    bitvector_free(&c);

    return accepted;
}

/* Encodes the bit 1: c = G s + z + e with s uniform in F_2^g. */
static uint8_t *ldpc_encode(const void *params_ptr,
                            const ZBPRC_EncKey *enc_key,
                            RandomnessSource *random,
                            size_t *codeword_bits)
{
    const LDPCParams *params = params_ptr;

    if (params == NULL || enc_key == NULL || random == NULL || codeword_bits == NULL)
        return NULL;

    BitVector s = bitvector_alloc(params->g);

    random_bitvector(random, &s);

    uint8_t *codeword = ldpc_encode_seed(params, enc_key, &s, random, codeword_bits);

    bitvector_free(&s);

    return codeword;
}

/* Accepts iff wgt(P (c + z)) < (1/2 - r^(-1/4)) r; strings of a length other than n are rejected. */
static int ldpc_decode(const void *params_ptr,
                       const ZBPRC_DecKey *dec_key,
                       const uint8_t *codeword,
                       size_t codeword_bits)
{
    (void)params_ptr;
    if (dec_key == NULL)
        return 0;

    return ldpc_syndrome_test(&dec_key->P, &dec_key->z, codeword, codeword_bits);
}

ZBPRC prc_ldpc(const LDPCParams *params)
{
    return (ZBPRC){
        .params = params,
        .block_length = ldpc_block_length,
        .keygen = ldpc_keygen,
        .encode = ldpc_encode,
        .decode = ldpc_decode,
        .free_enc_key = ldpc_free_enc_key,
        .free_dec_key = ldpc_free_dec_key,
    };
}
