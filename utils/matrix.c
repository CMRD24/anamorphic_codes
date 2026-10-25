/*
 * Linear algebra over F_2 for the LDPC based PRCs.
 *
 * Representations (bit i of a vector is bit i mod 64 of word i / 64):
 *   BitVector     a vector in F_2^bits.
 *   ColumnMatrix  a dense matrix stored column by column, e.g. the generator
 *                 matrix G of the LDPC PRC (n x g, columns in ker P).
 *   SparseMatrix  a matrix with exactly t ones per row, stored as the column
 *                 indices of the ones, e.g. the parity-check matrices P and P'.
 *
 * Addition in F_2 is XOR and multiplication is AND, so sums of vectors are XORs
 * of whole words. The sparse products are computed here directly; the dense
 * eliminations use the M4RI library (M. Albrecht, G. Bard, "The M4RI Library",
 * https://github.com/malb/m4ri), which implements Gaussian elimination and PLUQ
 * decomposition with the "Method of the Four Russians" (M. Albrecht, G. Bard,
 * C. Pernet, "Efficient dense Gaussian elimination over the finite field with two
 * elements", arXiv:1111.6549, 2011). M4RI stores rows as arrays of 64-bit words
 * with the same bit order, so rows and BitVectors are copied word by word.
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

/* clears the bits above v->bits in the last word */
static void clear_padding(BitVector *v)
{
    if (v->bits % WORD_BITS != 0)
        v->data[v->words - 1] &= (UINT64_C(1) << (v->bits % WORD_BITS)) - 1;
}


/* ------------------------------------------------------------------------
 * Vectors
 * ------------------------------------------------------------------------ */

/* Allocates the zero vector of F_2^bits. Exits on allocation failure. */
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

void bitvector_set_bit(BitVector *v, size_t index, uint8_t value)
{
    const uint64_t mask = UINT64_C(1) << (index % WORD_BITS);

    if (value)
        v->data[index / WORD_BITS] |= mask;
    else
        v->data[index / WORD_BITS] &= ~mask;
}

static uint8_t bitvector_get_bit(const BitVector *v, size_t index)
{
    return (uint8_t)((v->data[index / WORD_BITS] >> (index % WORD_BITS)) & 1);
}

/* Hamming weight wgt(v): the sum of the population counts of the words. */
size_t bitvector_weight(const BitVector *v)
{
    size_t weight = 0;

    for (size_t i = 0; i < v->words; ++i)
        weight += (size_t)__builtin_popcountll(v->data[i]);

    return weight;
}

void bitvector_add(BitVector *dst, const BitVector *src)
{
    for (size_t i = 0; i < dst->words; ++i)
        dst->data[i] ^= src->data[i];
}

/* bytes holds (v->bits + 7) / 8 bytes; bits above v->bits in the last byte are ignored */
void bitvector_from_bytes(BitVector *v, const uint8_t *bytes)
{
    memset(v->data, 0, v->words * sizeof(uint64_t));

    for (size_t i = 0; i < (v->bits + 7) / 8; ++i)
        v->data[i / 8] |= (uint64_t)bytes[i] << (8 * (i % 8));

    clear_padding(v);
}

/* Returns (v->bits + 7) / 8 newly allocated bytes, NULL on allocation failure. */
uint8_t *bitvector_to_bytes(const BitVector *v)
{
    const size_t byte_count = (v->bits + 7) / 8;
    uint8_t *bytes = malloc(byte_count ? byte_count : 1);

    if (bytes == NULL)
        return NULL;

    for (size_t i = 0; i < byte_count; ++i)
        bytes[i] = (uint8_t)(v->data[i / 8] >> (8 * (i % 8)));

    return bytes;
}


/* ------------------------------------------------------------------------
 * Sparse matrices
 * ------------------------------------------------------------------------ */

/* Allocates the position array (zero; fill it with sparse_matrix_sample). */
SparseMatrix sparse_matrix_alloc(size_t rows, size_t cols, size_t row_weight)
{
    SparseMatrix M = {.rows = rows, .cols = cols, .row_weight = row_weight};

    M.positions = checked_calloc(rows * row_weight, sizeof(size_t));

    return M;
}

void sparse_matrix_free(SparseMatrix *M)
{
    if (M == NULL)
        return;

    free(M->positions);
    *M = (SparseMatrix){0};
}

/*
 * Every row independently: row_weight distinct column positions, drawn uniformly
 * by rejecting repeats, i.e. a uniform vector of weight row_weight.
 */
void sparse_matrix_sample(SparseMatrix *M, RandomnessSource *random)
{
    for (size_t row = 0; row < M->rows; ++row) {
        size_t *positions = M->positions + row * M->row_weight;
        size_t placed = 0;

        while (placed < M->row_weight) {
            const size_t col = random_bounded(random, M->cols);
            int repeated = 0;

            for (size_t j = 0; j < placed && !repeated; ++j)
                repeated = positions[j] == col;

            if (!repeated)
                positions[placed++] = col;
        }
    }
}

/*
 * y = M x: y_i is the parity (XOR) of the row_weight bits of x selected by row i.
 * Cost O(rows * row_weight) instead of O(rows * cols).
 */
void sparse_matrix_mul_vector(const SparseMatrix *M, const BitVector *x, BitVector *y)
{
    memset(y->data, 0, y->words * sizeof(uint64_t));

    for (size_t row = 0; row < M->rows; ++row) {
        const size_t *positions = M->positions + row * M->row_weight;
        uint8_t parity = 0;

        for (size_t j = 0; j < M->row_weight; ++j)
            parity ^= bitvector_get_bit(x, positions[j]);

        bitvector_set_bit(y, row, parity);
    }
}


/* ------------------------------------------------------------------------
 * Column matrices
 * ------------------------------------------------------------------------ */

/* Allocates the zero rows x cols matrix. Exits on allocation failure. */
ColumnMatrix column_matrix_alloc(size_t rows, size_t cols)
{
    ColumnMatrix M = {.rows = rows, .cols = cols};

    M.columns = checked_calloc(cols, sizeof(BitVector));

    for (size_t j = 0; j < cols; ++j)
        M.columns[j] = bitvector_alloc(rows);

    return M;
}

void column_matrix_free(ColumnMatrix *M)
{
    if (M == NULL)
        return;

    for (size_t j = 0; M->columns != NULL && j < M->cols; ++j)
        bitvector_free(&M->columns[j]);

    free(M->columns);
    *M = (ColumnMatrix){0};
}

/* y = M x: the XOR of the columns j with x_j = 1 (cost O(rows * cols / 64)). */
void column_matrix_mul_vector(const ColumnMatrix *M, const BitVector *x, BitVector *y)
{
    memset(y->data, 0, y->words * sizeof(uint64_t));

    for (size_t j = 0; j < M->cols; ++j) {
        if (bitvector_get_bit(x, j))
            bitvector_add(y, &M->columns[j]);
    }
}

/* P M, computed column by column: (P M)[:, j] = P M[:, j]. */
ColumnMatrix sparse_matrix_mul_column_matrix(const SparseMatrix *P, const ColumnMatrix *M)
{
    ColumnMatrix product = column_matrix_alloc(P->rows, M->cols);

    for (size_t j = 0; j < M->cols; j++)
        sparse_matrix_mul_vector(P, &M->columns[j], &product.columns[j]);

    return product;
}

/*
 * ker M via M4RI: the PLUQ decomposition of M gives the M.cols x (M.cols - rank)
 * matrix X with M X = 0 and independent columns (rank-nullity), which is the
 * basis. M4RI works on rows, so M is built from its transpose (whose rows are the
 * columns of M) and X is read through its transpose.
 */
ColumnMatrix column_matrix_kernel(const ColumnMatrix *M)
{
    mzd_t *Mt = mzd_init((rci_t)M->cols, (rci_t)M->rows);

    for (size_t j = 0; j < M->cols; ++j)
        memcpy(mzd_row(Mt, (rci_t)j), M->columns[j].data, M->columns[j].words * sizeof(uint64_t));

    mzd_t *A = mzd_transpose(NULL, Mt);
    mzd_t *X = mzd_kernel_left_pluq(A, 0);       /* NULL: trivial kernel */
    ColumnMatrix basis = column_matrix_alloc(M->cols, X != NULL ? (size_t)X->ncols : 0);

    if (X != NULL) {
        mzd_t *Xt = mzd_transpose(NULL, X);

        for (size_t j = 0; j < basis.cols; ++j) {
            memcpy(basis.columns[j].data, mzd_row(Xt, (rci_t)j),
                   basis.columns[j].words * sizeof(uint64_t));
            clear_padding(&basis.columns[j]);
        }

        mzd_free(Xt);
        mzd_free(X);
    }

    mzd_free(A);
    mzd_free(Mt);

    return basis;
}

/*
 * Uniform elements of ker P without a basis of ker P (which would be a dense
 * (n - r) x n matrix). Gauss-Jordan elimination (M4RI) brings P to reduced row
 * echelon form R with the same kernel: row i of R has a 1 in its pivot column p_i
 * and 0 in the other pivot columns. Hence x is in ker P iff
 *     x_{p_i} = sum of the free coordinates x_j (j not a pivot) with R_ij = 1
 * for every row i. Each column is therefore sampled by drawing the free
 * coordinates uniformly and solving for the pivot coordinates; this is a bijection
 * between F_2^(n - rank) and ker P, so the columns are uniform and independent.
 * Cost O(count * rank * n / 64).
 */
ColumnMatrix sparse_matrix_sample_kernel(const SparseMatrix *P, size_t count,
                                         RandomnessSource *random)
{
    ColumnMatrix samples = column_matrix_alloc(P->cols, count);
    mzd_t *R = mzd_init((rci_t)P->rows, (rci_t)P->cols);

    for (size_t row = 0; row < P->rows; ++row) {
        for (size_t j = 0; j < P->row_weight; ++j)
            mzd_write_bit(R, (rci_t)row, (rci_t)P->positions[row * P->row_weight + j], 1);
    }

    const size_t rank = (size_t)mzd_echelonize_m4ri(R, 1, 0);
    size_t *pivots = checked_calloc(rank, sizeof(size_t));

    for (size_t i = 0; i < rank; ++i) {
        const word *row = mzd_row(R, (rci_t)i);
        size_t w = 0;

        while (row[w] == 0)
            ++w;

        pivots[i] = w * WORD_BITS + (size_t)__builtin_ctzll(row[w]);
    }

    for (size_t j = 0; j < count; ++j) {
        BitVector *x = &samples.columns[j];

        random_bitvector(random, x);

        for (size_t i = 0; i < rank; ++i)
            bitvector_set_bit(x, pivots[i], 0);

        /* the pivot coordinates do not enter any row's sum, so the order does not matter */
        for (size_t i = 0; i < rank; ++i) {
            const word *row = mzd_row(R, (rci_t)i);
            uint64_t parity = 0;

            for (size_t w = 0; w < x->words; ++w)
                parity ^= row[w] & x->data[w];

            bitvector_set_bit(x, pivots[i], (uint8_t)(__builtin_popcountll(parity) & 1));
        }
    }

    free(pivots);
    mzd_free(R);

    return samples;
}
