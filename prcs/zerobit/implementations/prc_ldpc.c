#include "../zerobit_prc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>


/*
 * ================================================================
 * LDPC-specific parameters
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
 * Constants / helpers
 * ================================================================
 */

#define WORD_BITS 64


static size_t words_for_bits(size_t bits)
{
    return (bits + WORD_BITS - 1) / WORD_BITS;
}


/*
 * ================================================================
 * Packed bit vector
 * ================================================================
 */

typedef struct {
    size_t bits;
    size_t words;
    uint64_t *data;
} BitVector;


static BitVector bitvector_alloc(size_t bits)
{
    BitVector v;

    v.bits = bits;
    v.words = words_for_bits(bits);
    v.data = calloc(v.words, sizeof(uint64_t));

    if (v.data == NULL && v.words != 0) {
        fprintf(stderr,
                "ZBPRC-LDPC: bit vector allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    return v;
}


static void bitvector_free(BitVector *v)
{
    if (v == NULL)
        return;

    free(v->data);

    v->data = NULL;
    v->bits = 0;
    v->words = 0;
}


static inline uint8_t bit_get(const BitVector *v,
                              size_t index)
{
    return (uint8_t)(
        (v->data[index >> 6] >>
         (index & 63)) & 1ULL
    );
}


static inline void bit_set(BitVector *v,
                           size_t index,
                           uint8_t value)
{
    uint64_t mask =
        1ULL << (index & 63);

    if (value)
        v->data[index >> 6] |= mask;
    else
        v->data[index >> 6] &= ~mask;
}


static void bitvector_zero(BitVector *v)
{
    memset(v->data,
           0,
           v->words * sizeof(uint64_t));
}


static size_t bitvector_weight(const BitVector *v)
{
    size_t result = 0;

    for (size_t i = 0;
         i < v->words;
         ++i) {

        result +=
            (size_t)__builtin_popcountll(
                v->data[i]);
    }

    /*
     * Remove padding bits from the final word.
     */
    if (v->bits & 63) {

        size_t valid =
            v->bits & 63;

        uint64_t mask =
            (1ULL << valid) - 1ULL;

        uint64_t invalid =
            v->data[v->words - 1] & ~mask;

        result -=
            (size_t)__builtin_popcountll(
                invalid);
    }

    return result;
}


/*
 * ================================================================
 * Randomness
 * ================================================================
 */

static void random_bytes(ZBPRC_Random *random,
                         uint8_t *out,
                         size_t len)
{
    if (random == NULL ||
        random->rng == NULL ||
        !random->rng(random->ctx, out, len)) {

        fprintf(stderr,
                "ZBPRC-LDPC: secure randomness failure.\n");

        exit(EXIT_FAILURE);
    }
}


static uint64_t random_u64(ZBPRC_Random *random)
{
    uint64_t x;

    random_bytes(random,
                 (uint8_t *)&x,
                 sizeof(x));

    return x;
}


static uint8_t random_bit(ZBPRC_Random *random)
{
    return (uint8_t)(random_u64(random) & 1ULL);
}


/*
 * ================================================================
 * Random bit vector
 * ================================================================
 */

static void random_bitvector(ZBPRC_Random *random,
                             BitVector *v)
{
    for (size_t i = 0;
         i < v->words;
         ++i) {

        v->data[i] =
            random_u64(random);
    }

    if (v->bits & 63) {

        size_t valid =
            v->bits & 63;

        uint64_t mask =
            (1ULL << valid) - 1ULL;

        v->data[v->words - 1] &= mask;
    }
}


/*
 * ================================================================
 * Bernoulli vector
 * ================================================================
 */

static void random_bernoulli_vector(
    ZBPRC_Random *random,
    BitVector *v,
    double eta)
{
    bitvector_zero(v);

    if (eta <= 0.0)
        return;

    if (eta >= 1.0) {

        for (size_t i = 0;
             i < v->words;
             ++i) {

            v->data[i] = UINT64_MAX;
        }

        if (v->bits & 63) {

            size_t valid =
                v->bits & 63;

            v->data[v->words - 1] &=
                (1ULL << valid) - 1ULL;
        }

        return;
    }

    for (size_t i = 0;
         i < v->bits;
         ++i) {

        uint64_t x =
            random_u64(random) >> 11;

        double u =
            (double)x / 9007199254740992.0;

        if (u < eta)
            bit_set(v, i, 1);
    }
}


/*
 * ================================================================
 * Sparse P
 * ================================================================
 */

typedef struct {
    size_t r;
    size_t n;
    size_t t;

    size_t *positions;
} SparseP;


static SparseP sparse_p_alloc(size_t r,
                              size_t n,
                              size_t t)
{
    SparseP P;

    P.r = r;
    P.n = n;
    P.t = t;

    P.positions =
        malloc(r * t * sizeof(size_t));

    if (P.positions == NULL &&
        r * t != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: sparse P allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    return P;
}


static void sparse_p_free(SparseP *P)
{
    if (P == NULL)
        return;

    free(P->positions);

    P->positions = NULL;
    P->r = 0;
    P->n = 0;
    P->t = 0;
}


static size_t random_bounded(ZBPRC_Random *random,
                             size_t bound)
{
    if (bound == 0)
        return 0;

    uint64_t x;

    /*
     * Rejection sampling.
     */
    uint64_t limit =
        UINT64_MAX -
        (UINT64_MAX % (uint64_t)bound);

    do {
        x = random_u64(random);
    } while (x >= limit);

    return (size_t)(x % bound);
}


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


static void sample_sparse_p(ZBPRC_Random *random,
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
 * Sparse P × vector
 * ================================================================
 */

static void sparse_p_mul(const SparseP *P,
                         const BitVector *x,
                         BitVector *y)
{
    bitvector_zero(y);

    for (size_t row = 0;
         row < P->r;
         ++row) {

        uint8_t parity = 0;

        size_t base =
            row * P->t;

        for (size_t j = 0;
             j < P->t;
             ++j) {

            size_t col =
                P->positions[base + j];

            parity ^=
                bit_get(x, col);
        }

        if (parity)
            bit_set(y, row, 1);
    }
}


/*
 * ================================================================
 * Packed matrix
 * ================================================================
 */

typedef struct {
    size_t rows;
    size_t cols;
    size_t words;

    uint64_t *data;
} PackedMatrix;


static PackedMatrix packed_matrix_alloc(size_t rows,
                                         size_t cols)
{
    PackedMatrix M;

    M.rows = rows;
    M.cols = cols;
    M.words = words_for_bits(cols);

    M.data =
        calloc(rows * M.words,
               sizeof(uint64_t));

    if (M.data == NULL &&
        rows * M.words != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: packed matrix allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    return M;
}


static void packed_matrix_free(PackedMatrix *M)
{
    free(M->data);

    M->data = NULL;
    M->rows = 0;
    M->cols = 0;
    M->words = 0;
}


static inline uint64_t *
packed_matrix_row(PackedMatrix *M,
                  size_t row)
{
    return &M->data[row * M->words];
}


static inline const uint64_t *
packed_matrix_const_row(const PackedMatrix *M,
                        size_t row)
{
    return &M->data[row * M->words];
}


static inline uint8_t packed_matrix_get(
    const PackedMatrix *M,
    size_t row,
    size_t col)
{
    const uint64_t *r =
        packed_matrix_const_row(M, row);

    return (uint8_t)(
        (r[col >> 6] >>
         (col & 63)) & 1ULL);
}


static inline void packed_matrix_set(
    PackedMatrix *M,
    size_t row,
    size_t col)
{
    uint64_t *r =
        packed_matrix_row(M, row);

    r[col >> 6] |=
        1ULL << (col & 63);
}


static inline void packed_row_xor(
    uint64_t *dst,
    const uint64_t *src,
    size_t words)
{
    for (size_t i = 0;
         i < words;
         ++i) {

        dst[i] ^= src[i];
    }
}


static PackedMatrix sparse_p_to_packed(
    const SparseP *P)
{
    PackedMatrix M =
        packed_matrix_alloc(P->r,
                            P->n);

    for (size_t row = 0;
         row < P->r;
         ++row) {

        for (size_t j = 0;
             j < P->t;
             ++j) {

            size_t col =
                P->positions[
                    row * P->t + j
                ];

            packed_matrix_set(&M,
                              row,
                              col);
        }
    }

    return M;
}


/*
 * ================================================================
 * Kernel basis
 * ================================================================
 */

typedef struct {
    size_t dimension;
    BitVector *vectors;
} KernelBasis;


static void kernel_basis_free(KernelBasis *K)
{
    if (K == NULL)
        return;

    if (K->vectors != NULL) {

        for (size_t i = 0;
             i < K->dimension;
             ++i) {

            bitvector_free(
                &K->vectors[i]);
        }

        free(K->vectors);
    }

    K->vectors = NULL;
    K->dimension = 0;
}


static KernelBasis kernel_basis(const SparseP *P)
{
    PackedMatrix A =
        sparse_p_to_packed(P);

    size_t *pivot_column =
        malloc(P->r * sizeof(size_t));

    if (pivot_column == NULL &&
        P->r != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    size_t rank = 0;

    /*
     * Gauss-Jordan elimination over F_2.
     */
    for (size_t col = 0;
         col < P->n && rank < P->r;
         ++col) {

        size_t pivot = SIZE_MAX;

        for (size_t row = rank;
             row < P->r;
             ++row) {

            if (packed_matrix_get(&A,
                                  row,
                                  col)) {

                pivot = row;
                break;
            }
        }

        if (pivot == SIZE_MAX)
            continue;

        if (pivot != rank) {

            uint64_t *a =
                packed_matrix_row(&A,
                                  rank);

            uint64_t *b =
                packed_matrix_row(&A,
                                  pivot);

            for (size_t w = 0;
                 w < A.words;
                 ++w) {

                uint64_t tmp = a[w];
                a[w] = b[w];
                b[w] = tmp;
            }
        }

        pivot_column[rank] = col;

        const uint64_t *pivot_row =
            packed_matrix_const_row(
                &A,
                rank);

        for (size_t row = 0;
             row < P->r;
             ++row) {

            if (row == rank)
                continue;

            if (packed_matrix_get(&A,
                                  row,
                                  col)) {

                uint64_t *current =
                    packed_matrix_row(
                        &A,
                        row);

                packed_row_xor(
                    current,
                    pivot_row,
                    A.words);
            }
        }

        ++rank;
    }

    size_t dimension =
        P->n - rank;

    KernelBasis K;

    K.dimension = dimension;

    K.vectors =
        calloc(dimension,
               sizeof(BitVector));

    if (K.vectors == NULL &&
        dimension != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    uint8_t *is_pivot =
        calloc(P->n, sizeof(uint8_t));

    if (is_pivot == NULL &&
        P->n != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    for (size_t i = 0;
         i < rank;
         ++i) {

        is_pivot[pivot_column[i]] = 1;
    }

    size_t kernel_index = 0;

    for (size_t free_col = 0;
         free_col < P->n;
         ++free_col) {

        if (is_pivot[free_col])
            continue;

        BitVector v =
            bitvector_alloc(P->n);

        bit_set(&v,
                free_col,
                1);

        for (size_t row = 0;
             row < rank;
             ++row) {

            size_t pivot =
                pivot_column[row];

            if (packed_matrix_get(
                    &A,
                    row,
                    free_col)) {

                bit_set(&v,
                        pivot,
                        1);
            }
        }

        K.vectors[kernel_index++] =
            v;
    }

    free(is_pivot);
    free(pivot_column);

    packed_matrix_free(&A);

    return K;
}


/*
 * ================================================================
 * G
 * ================================================================
 */

typedef struct {
    size_t n;
    size_t g;
    BitVector *columns;
} PackedG;


static PackedG packed_g_alloc(size_t n,
                              size_t g)
{
    PackedG G;

    G.n = n;
    G.g = g;

    G.columns =
        calloc(g,
               sizeof(BitVector));

    if (G.columns == NULL &&
        g != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: G allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    for (size_t j = 0;
         j < g;
         ++j) {

        G.columns[j] =
            bitvector_alloc(n);
    }

    return G;
}


static void packed_g_free(PackedG *G)
{
    if (G == NULL)
        return;

    for (size_t j = 0;
         j < G->g;
         ++j) {

        bitvector_free(
            &G->columns[j]);
    }

    free(G->columns);

    G->columns = NULL;
    G->n = 0;
    G->g = 0;
}


static void packed_g_mul(
    const PackedG *G,
    const BitVector *s,
    BitVector *result)
{
    bitvector_zero(result);

    for (size_t j = 0;
         j < G->g;
         ++j) {

        if (bit_get(s, j)) {

            for (size_t w = 0;
                 w < result->words;
                 ++w) {

                result->data[w] ^=
                    G->columns[j].data[w];
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
    if (key == NULL)
        return;

    packed_g_free(&key->G);
    bitvector_free(&key->z);

    free(key);
}


void ldpc_free_dec_key(const void *params, ZBPRC_DecKey *key)
{
    if (key == NULL)
        return;

    sparse_p_free(&key->P);
    bitvector_free(&key->z);

    free(key);
}


/*
 * ================================================================
 * KeyGen
 * ================================================================
 */

ZBPRC_Keys *
ldpc_keygen(const void *params_ptr,
            ZBPRC_Random *random)
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
    KernelBasis K =
        kernel_basis(&P);

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
            ZBPRC_Random *random,
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
     * This PRC produces exactly n bits.
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
ldpc_zbprc(const LDPCParams *params)
{
    ZBPRC prc = {
        .params = params,

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