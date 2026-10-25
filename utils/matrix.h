#ifndef MATRIX_H
#define MATRIX_H

/* Linear algebra over F_2 (see matrix.c). */

#include <stddef.h>
#include <stdint.h>

#include "random.h"

/* a vector in F_2^bits, bit i = bit i % 64 of data[i / 64]; bits above `bits` are zero */
typedef struct {
    size_t bits;
    size_t words;
    uint64_t *data;
} BitVector;

/* a rows x cols matrix, stored as its cols column vectors (each of F_2^rows) */
typedef struct {
    size_t rows;
    size_t cols;
    BitVector *columns;
} ColumnMatrix;

/* a rows x cols matrix with exactly row_weight ones per row, stored as their column indices */
typedef struct {
    size_t rows;
    size_t cols;
    size_t row_weight;
    size_t *positions;    /* row i: positions[i * row_weight .. (i + 1) * row_weight) */
} SparseMatrix;

BitVector bitvector_alloc(size_t bits);
void bitvector_free(BitVector *v);
size_t bitvector_weight(const BitVector *v);
void bitvector_set_bit(BitVector *v, size_t index, uint8_t value);

/* dst += src (dst and src have the same length) */
void bitvector_add(BitVector *dst, const BitVector *src);

/* conversion from and to packed bytes (bit i = bit i % 8 of byte i / 8) */
void bitvector_from_bytes(BitVector *v, const uint8_t *bytes);
uint8_t *bitvector_to_bytes(const BitVector *v);

SparseMatrix sparse_matrix_alloc(size_t rows, size_t cols, size_t row_weight);
void sparse_matrix_free(SparseMatrix *M);

/* Samples every row uniformly among the vectors of weight row_weight (the set S_{t,rows,cols}). */
void sparse_matrix_sample(SparseMatrix *M, RandomnessSource *random);

/* y = M x */
void sparse_matrix_mul_vector(const SparseMatrix *M, const BitVector *x, BitVector *y);

ColumnMatrix column_matrix_alloc(size_t rows, size_t cols);
void column_matrix_free(ColumnMatrix *M);

/* y = M x */
void column_matrix_mul_vector(const ColumnMatrix *M, const BitVector *x, BitVector *y);

/* the product P M of a sparse and a column matrix */
ColumnMatrix sparse_matrix_mul_column_matrix(const SparseMatrix *P, const ColumnMatrix *M);

/* a basis of ker M = { x : M x = 0 } as the columns of a M.cols x dim ker M matrix */
ColumnMatrix column_matrix_kernel(const ColumnMatrix *M);

/* P.cols x count matrix whose columns are independent, uniform elements of ker P */
ColumnMatrix sparse_matrix_sample_kernel(const SparseMatrix *P, size_t count,
                                         RandomnessSource *random);

#endif /* MATRIX_H */
