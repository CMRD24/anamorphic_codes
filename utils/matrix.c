
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "matrix.h"


#define WORD_BITS 64


static size_t words_for_bits(size_t bits)
{
    return (bits + WORD_BITS - 1) / WORD_BITS;
}


 SparseP sparse_p_alloc(size_t r,
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


 void sparse_p_free(SparseP *P)
{
    if (P == NULL)
        return;

    free(P->positions);

    P->positions = NULL;
    P->r = 0;
    P->n = 0;
    P->t = 0;
}


 BitVector bitvector_alloc(size_t bits)
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

 PackedMatrix packed_matrix_alloc(size_t rows,
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


 void packed_matrix_free(PackedMatrix *M)
{
    free(M->data);

    M->data = NULL;
    M->rows = 0;
    M->cols = 0;
    M->words = 0;
}




static inline uint64_t *
packed_matrix_row(const PackedMatrix *M,
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


 PackedMatrix sparse_p_to_packed(
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


 void bitvector_free(BitVector *v)
{
    if (v == NULL)
        return;

    free(v->data);

    v->data = NULL;
    v->bits = 0;
    v->words = 0;
}


uint8_t bit_get(const BitVector *v,
                              size_t index)
{
    return (uint8_t)(
        (v->data[index >> 6] >>
         (index & 63)) & 1ULL
    );
}


void bit_set(BitVector *v,
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


void bitvector_zero(BitVector *v)
{
    memset(v->data,
           0,
           v->words * sizeof(uint64_t));
}


size_t bitvector_weight(const BitVector *v)
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
 * Sparse P × vector
 * ================================================================
 */

 void sparse_p_mul(const SparseP *P,
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



 PackedMatrix
concat_g_matrices(
    const PackedG *G,
    const PackedG *Gprime)
{
    if (G->n != Gprime->n)
        abort();

    PackedMatrix M =
        packed_matrix_alloc(
            G->n,
            G->g + Gprime->g
        );

    for (size_t row = 0;
         row < G->n;
         ++row) {

        for (size_t col = 0;
             col < G->g;
             ++col) {

            if (bit_get(&G->columns[col], row))
                packed_matrix_set(&M, row, col);
        }

        for (size_t col = 0;
             col < Gprime->g;
             ++col) {

            if (bit_get(&Gprime->columns[col], row))

                packed_matrix_set(
                    &M,
                    row,
                    G->g + col
                );
        }
    }

    return M;
}








 void kernel_basis_free(KernelBasis *K)
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


 KernelBasis kernel_basis(const PackedMatrix *A)
{
    


    size_t *pivot_column =
        malloc(A->rows * sizeof(size_t));

    if (pivot_column == NULL &&
        A->rows != 0) {

        fprintf(stderr,
                "ZBPRC-LDPC: allocation failed.\n");

        exit(EXIT_FAILURE);
    }

    size_t rank = 0;

    /*
     * Gauss-Jordan elimination over F_2.
     */
    for (size_t col = 0;
         col < A->cols && rank < A->rows;
         ++col) {

        size_t pivot = SIZE_MAX;

        for (size_t row = rank;
             row < A->rows;
             ++row) {

            if (packed_matrix_get(A,
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
                packed_matrix_row(A,
                                  rank);

            uint64_t *b =
                packed_matrix_row(A,
                                  pivot);

            for (size_t w = 0;
                 w < A->words;
                 ++w) {

                uint64_t tmp = a[w];
                a[w] = b[w];
                b[w] = tmp;
            }
        }

        pivot_column[rank] = col;

        const uint64_t *pivot_row =
            packed_matrix_const_row(
                A,
                rank);

        for (size_t row = 0;
             row < A->rows;
             ++row) {

            if (row == rank)
                continue;

            if (packed_matrix_get(A,
                                  row,
                                  col)) {

                uint64_t *current =
                    packed_matrix_row(
                        A,
                        row);

                packed_row_xor(
                    current,
                    pivot_row,
                    A->words);
            }
        }

        ++rank;
    }

    size_t dimension =
        A->cols - rank;

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
        calloc(A->cols, sizeof(uint8_t));

    if (is_pivot == NULL &&
        A->cols != 0) {

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
         free_col < A->cols;
         ++free_col) {

        if (is_pivot[free_col])
            continue;

        BitVector v =
            bitvector_alloc(A->cols);

        bit_set(&v,
                free_col,
                1);

        for (size_t row = 0;
             row < rank;
             ++row) {

            size_t pivot =
                pivot_column[row];

            if (packed_matrix_get(
                    A,
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

    //packed_matrix_free(A);

    return K;
}






 PackedG packed_g_alloc(size_t n,
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


 void packed_g_free(PackedG *G)
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

 PackedG
kernel_basis_to_packed_g(
    const KernelBasis *K,
    size_t n)
{
    if (K == NULL)
        abort();

    PackedG G =
        packed_g_alloc(
            n,
            K->dimension
        );

    size_t words =
        (n + 63) / 64;

    for (size_t j = 0;
         j < K->dimension;
         ++j) {

        if (K->vectors[j].bits < n) {
            packed_g_free(&G);
            abort();
        }

        memcpy(
            G.columns[j].data,
            K->vectors[j].data,
            words * sizeof(uint64_t)
        );

        /*
         * Clear unused bits in the last word.
         */
        if (n % 64 != 0) {
            G.columns[j].data[words - 1] &=
                ((UINT64_C(1) << (n % 64)) - 1);
        }
    }

    return G;
}


 void packed_g_mul(
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


 PackedMatrix
packed_g_to_matrix(const PackedG *G)
{
    if (G == NULL)
        return (PackedMatrix){0};

    PackedMatrix M =
        packed_matrix_alloc(G->n, G->g);

    for (size_t col = 0;
         col < G->g;
         ++col) {

        for (size_t row = 0;
             row < G->n;
             ++row) {

            if (bit_get(&G->columns[col], row)) {

                packed_matrix_set(
                    &M,
                    row,
                    col);
            }
        }
    }

    return M;
}

PackedG
sparse_p_mul_packed_g(
    const SparseP *P,
    const PackedG *G)
{
    if (P == NULL || G == NULL)
        return (PackedG){0};

    /* P is r × n, G is n × g */
    if (P->n != G->n)
        return (PackedG){0};

    PackedG result = packed_g_alloc(P->r, G->g);

    for (size_t j = 0; j < G->g; j++) {
        /*
         * G->columns[j] is the j-th column of G,
         * so compute:
         *
         * result[:, j] = P * G[:, j]
         */
        sparse_p_mul(
            P,
            &G->columns[j],
            &result.columns[j]);
    }

    return result;
}

