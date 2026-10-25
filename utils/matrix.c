/*
 * Linear algebra over F_2 for the LDPC based PRCs.
 *
 * Representations (bit i of a vector is bit i mod 64 of word i / 64):
 *   BitVector    a vector in F_2^bits.
 *   PackedG      an n x g matrix stored column by column (g vectors of F_2^n):
 *                the generator matrix G of the LDPC PRC, whose columns lie in
 *                ker P.
 *   SparseP      an r x n matrix with exactly t ones per row, stored as the
 *                column indices of the ones: the sparse parity-check matrix P.
 *
 * Addition in F_2 is XOR and multiplication is AND, so sums of vectors are XORs
 * of whole words. The sparse products are computed here directly; the dense
 * operations (kernels by elimination, products of dense matrices) use the M4RI
 * library (M. Albrecht, G. Bard, "The M4RI Library", https://github.com/malb/m4ri),
 * which implements PLUQ decomposition with the "Method of the Four Russians"
 * and Strassen-Winograd multiplication (M. Albrecht, G. Bard, W. Hart,
 * "Algorithm 898: Efficient multiplication of dense matrices over GF(2)", ACM
 * TOMS 37(1), 2010). M4RI stores rows as arrays of 64-bit words with the same
 * bit order, so rows and BitVectors are copied word by word.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <m4ri/m4ri.h>

#include "matrix.h"
#include "random_utils.h"


#define WORD_BITS 64


static size_t words_for_bits(size_t bits)
{
    return (bits + WORD_BITS - 1) / WORD_BITS;
}

static void *checked_calloc(size_t count, size_t size)
{
    void *p = calloc(count ? count : 1, size);

    if (p == NULL) {
        fprintf(stderr, "matrix: allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    return p;
}


/* ------------------------------------------------------------------------
 * Sparse matrices and vectors
 * ------------------------------------------------------------------------ */

/*
 * Allocates the position array of an r x n matrix with t ones per row (uninitialised;
 * fill it with sample_sparse_p). Exits on allocation failure.
 */
SparseP sparse_p_alloc(size_t r, size_t n, size_t t)
{
    SparseP P = {.r = r, .n = n, .t = t};

    P.positions = checked_calloc(r * t, sizeof(size_t));

    return P;
}

void sparse_p_free(SparseP *P)
{
    if (P == NULL)
        return;

    free(P->positions);
    *P = (SparseP){0};
}

/* Allocates the zero vector of F_2^bits. */
BitVector bitvector_alloc(size_t bits)
{
    BitVector v = {.bits = bits, .words = words_for_bits(bits)};

    v.data = checked_calloc(v.words, sizeof(uint64_t));

    return v;
}

void bitvector_free(BitVector *v)
{
    if (v == NULL)
        return;

    free(v->data);
    *v = (BitVector){0};
}

uint8_t bit_get(const BitVector *v, size_t index)
{
    return (uint8_t)((v->data[index >> 6] >> (index & 63)) & 1ULL);
}

void bit_set(BitVector *v, size_t index, uint8_t value)
{
    const uint64_t mask = 1ULL << (index & 63);

    if (value)
        v->data[index >> 6] |= mask;
    else
        v->data[index >> 6] &= ~mask;
}

void bitvector_zero(BitVector *v)
{
    memset(v->data, 0, v->words * sizeof(uint64_t));
}

/*
 * Hamming weight wgt(v): the number of ones, computed as the sum of the population
 * counts of the words (the padding bits above `bits` are ignored).
 */
size_t bitvector_weight(const BitVector *v)
{
    size_t result = 0;

    for (size_t i = 0; i < v->words; ++i)
        result += (size_t)__builtin_popcountll(v->data[i]);

    if (v->bits & 63) {
        const uint64_t invalid = v->data[v->words - 1] & ~((1ULL << (v->bits & 63)) - 1ULL);

        result -= (size_t)__builtin_popcountll(invalid);
    }

    return result;
}

/*
 * y = P x over F_2 for a sparse P: y_i is the parity (XOR) of the t bits of x selected
 * by row i of P. Cost O(r t) instead of O(r n).
 */
void sparse_p_mul(const SparseP *P, const BitVector *x, BitVector *y)
{
    bitvector_zero(y);

    for (size_t row = 0; row < P->r; ++row) {
        uint8_t parity = 0;

        for (size_t j = 0; j < P->t; ++j)
            parity ^= bit_get(x, P->positions[row * P->t + j]);

        if (parity)
            bit_set(y, row, 1);
    }
}


/* ------------------------------------------------------------------------
 * Column matrices
 * ------------------------------------------------------------------------ */

/* Allocates the zero n x g matrix as g column vectors of F_2^n. */
PackedG packed_g_alloc(size_t n, size_t g)
{
    PackedG G = {.n = n, .g = g};

    G.columns = checked_calloc(g, sizeof(BitVector));

    for (size_t j = 0; j < g; ++j)
        G.columns[j] = bitvector_alloc(n);

    return G;
}

void packed_g_free(PackedG *G)
{
    if (G == NULL)
        return;

    for (size_t j = 0; j < G->g; ++j)
        bitvector_free(&G->columns[j]);

    free(G->columns);
    *G = (PackedG){0};
}

/*
 * result = G s over F_2: the XOR of the columns j of G with s_j = 1 (a linear
 * combination of the columns, cost O(g n / 64)).
 */
void packed_g_mul(const PackedG *G, const BitVector *s, BitVector *result)
{
    bitvector_zero(result);

    for (size_t j = 0; j < G->g; ++j) {
        if (!bit_get(s, j))
            continue;

        for (size_t w = 0; w < result->words; ++w)
            result->data[w] ^= G->columns[j].data[w];
    }
}

/* Returns the r x g matrix P G, computed column by column: (P G)[:, j] = P G[:, j]. */
PackedG sparse_p_mul_packed_g(const SparseP *P, const PackedG *G)
{
    if (P == NULL || G == NULL || P->n != G->n)
        return (PackedG){0};

    PackedG result = packed_g_alloc(P->r, G->g);

    for (size_t j = 0; j < G->g; j++)
        sparse_p_mul(P, &G->columns[j], &result.columns[j]);

    return result;
}


/* ------------------------------------------------------------------------
 * Dense operations (M4RI)
 * ------------------------------------------------------------------------ */

/* Copies the words of vector v into row `row` of M (M has v->bits columns). */
static void row_from_vector(mzd_t *M, rci_t row, const BitVector *v)
{
    memcpy(mzd_row(M, row), v->data, v->words * sizeof(uint64_t));
}

static void vector_from_row(BitVector *v, const mzd_t *M, rci_t row)
{
    memcpy(v->data, mzd_row(M, row), v->words * sizeof(uint64_t));

    if (v->bits & 63)
        v->data[v->words - 1] &= (1ULL << (v->bits & 63)) - 1ULL;
}

/*
 * Basis of ker A for A in F_2^(rows x cols) (A is overwritten): M4RI computes a PLUQ
 * decomposition A = P L U Q and returns the cols x (cols - rank) matrix X with
 * A X = 0 whose columns are independent (rank-nullity). The basis vectors are the
 * columns of X, read as the rows of its transpose.
 */
static KernelBasis kernel_of(mzd_t *A)
{
    KernelBasis K = {0};
    const size_t cols = (size_t)A->ncols;
    mzd_t *X = mzd_kernel_left_pluq(A, 0);

    if (X == NULL)
        return K;     /* trivial kernel */

    mzd_t *Xt = mzd_transpose(NULL, X);

    K.dimension = (size_t)X->ncols;
    K.vectors = checked_calloc(K.dimension, sizeof(BitVector));

    for (size_t i = 0; i < K.dimension; ++i) {
        K.vectors[i] = bitvector_alloc(cols);
        vector_from_row(&K.vectors[i], Xt, (rci_t)i);
    }

    mzd_free(Xt);
    mzd_free(X);

    return K;
}

/* ker P = { x in F_2^n : P x = 0 } for the sparse parity-check matrix P. */
KernelBasis sparse_p_kernel(const SparseP *P)
{
    mzd_t *A = mzd_init((rci_t)P->r, (rci_t)P->n);

    for (size_t row = 0; row < P->r; ++row) {
        for (size_t j = 0; j < P->t; ++j)
            mzd_write_bit(A, (rci_t)row, (rci_t)P->positions[row * P->t + j], 1);
    }

    KernelBasis K = kernel_of(A);
    mzd_free(A);

    return K;
}

/*
 * ker M = { s in F_2^g : M s = 0 } for the n x g matrix M given by its columns
 * (sum_j s_j M[:, j] = 0). The columns are the rows of M^T, so M^T is filled
 * row by row and transposed.
 */
KernelBasis packed_g_kernel(const PackedG *M)
{
    mzd_t *Mt = mzd_init((rci_t)M->g, (rci_t)M->n);

    for (size_t j = 0; j < M->g; ++j)
        row_from_vector(Mt, (rci_t)j, &M->columns[j]);

    mzd_t *A = mzd_transpose(NULL, Mt);
    KernelBasis K = kernel_of(A);

    mzd_free(A);
    mzd_free(Mt);

    return K;
}

/*
 * Returns an n x count matrix whose columns are statistically independent, uniform elements of
 * the span of K (vectors of F_2^n): column j = sum_k R[j][k] K_k with a uniform
 * count x dim matrix R. As a matrix product G^T = R B^T, with the basis B^T as
 * the rows of a dim x n matrix; the product is computed by M4RI (Method of the Four
 * Russians, Strassen-Winograd for large sizes). R is drawn from `random`, so a
 * deterministic source gives a reproducible result.
 */
PackedG kernel_random_span(const KernelBasis *K, size_t n, size_t count,
                           RandomnessSource *random)
{
    PackedG G = packed_g_alloc(n, count);

    if (K->dimension == 0 || count == 0)
        return G;

    mzd_t *Bt = mzd_init((rci_t)K->dimension, (rci_t)n);
    mzd_t *R = mzd_init((rci_t)count, (rci_t)K->dimension);
    BitVector r = bitvector_alloc(K->dimension);

    for (size_t k = 0; k < K->dimension; ++k)
        row_from_vector(Bt, (rci_t)k, &K->vectors[k]);

    for (size_t j = 0; j < count; ++j) {
        random_bitvector(random, &r);
        row_from_vector(R, (rci_t)j, &r);
    }

    mzd_t *Gt = mzd_mul(NULL, R, Bt, 0);

    for (size_t j = 0; j < count; ++j)
        vector_from_row(&G.columns[j], Gt, (rci_t)j);

    mzd_free(Gt);
    mzd_free(R);
    mzd_free(Bt);
    bitvector_free(&r);

    return G;
}

void kernel_basis_free(KernelBasis *K)
{
    if (K == NULL)
        return;

    for (size_t i = 0; K->vectors != NULL && i < K->dimension; ++i)
        bitvector_free(&K->vectors[i]);

    free(K->vectors);
    *K = (KernelBasis){0};
}

/* Turns a kernel basis (vectors of F_2^n) into the columns of an n x dim matrix. */
PackedG kernel_basis_to_packed_g(const KernelBasis *K, size_t n)
{
    PackedG G = packed_g_alloc(n, K->dimension);

    for (size_t j = 0; j < K->dimension; ++j) {
        if (K->vectors[j].bits < n)
            abort();

        memcpy(G.columns[j].data, K->vectors[j].data, G.columns[j].words * sizeof(uint64_t));

        /* bits above n in the last word must be zero */
        if (n % 64 != 0)
            G.columns[j].data[G.columns[j].words - 1] &= (UINT64_C(1) << (n % 64)) - 1;
    }

    return G;
}
