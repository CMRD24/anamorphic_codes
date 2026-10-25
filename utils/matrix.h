#ifndef MATRIX_H
#define MATRIX_H

/* Linear algebra over F_2 (see matrix.c). */

#include <stddef.h>
#include <stdint.h>

#include "random.h"

/* a vector in F_2^bits, bit i = bit i % 64 of data[i / 64] */
typedef struct {
    size_t bits;
    size_t words;
    uint64_t *data;
} BitVector;

/* an n x g matrix, stored as its g columns */
typedef struct {
    size_t n;
    size_t g;
    BitVector *columns;
} PackedG;

/* an r x n matrix with exactly t ones per row (their column indices) */
typedef struct {
    size_t r;
    size_t n;
    size_t t;
    size_t *positions;
} SparseP;

/* a basis of a subspace */
typedef struct {
    size_t dimension;
    BitVector *vectors;
} KernelBasis;

SparseP sparse_p_alloc(size_t r, size_t n, size_t t);
void sparse_p_free(SparseP *P);

BitVector bitvector_alloc(size_t bits);
void bitvector_free(BitVector *v);
void bitvector_zero(BitVector *v);
size_t bitvector_weight(const BitVector *v);
uint8_t bit_get(const BitVector *v, size_t index);
void bit_set(BitVector *v, size_t index, uint8_t value);

/* y = P x */
void sparse_p_mul(const SparseP *P, const BitVector *x, BitVector *y);

PackedG packed_g_alloc(size_t n, size_t g);
void packed_g_free(PackedG *G);

/* result = G s */
void packed_g_mul(const PackedG *G, const BitVector *s, BitVector *result);

/* P G */
PackedG sparse_p_mul_packed_g(const SparseP *P, const PackedG *G);

/* basis of ker P */
KernelBasis sparse_p_kernel(const SparseP *P);

/* basis of ker M = { s : M s = 0 } for M given by its columns */
KernelBasis packed_g_kernel(const PackedG *M);

/* n x count matrix of independent, uniformly random elements of span(K) */
PackedG kernel_random_span(const KernelBasis *K, size_t n, size_t count,
                           RandomnessSource *random);

void kernel_basis_free(KernelBasis *K);

/* the basis vectors (of F_2^n) as the columns of a matrix */
PackedG kernel_basis_to_packed_g(const KernelBasis *K, size_t n);

#endif /* MATRIX_H */
