
#ifndef MATRIX_H
#define MATRIX_H

#include <stddef.h>


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


typedef struct {
    size_t dimension;
    BitVector *vectors;
} KernelBasis;

 SparseP sparse_p_alloc(size_t r,
                              size_t n,
                              size_t t);

 void sparse_p_free(SparseP *P);

 BitVector bitvector_alloc(size_t bits);

 PackedMatrix packed_matrix_alloc(size_t rows,
                                         size_t cols);

 void packed_matrix_free(PackedMatrix *M);


 PackedMatrix sparse_p_to_packed(
    const SparseP *P);

 void bitvector_free(BitVector *v);

 void bitvector_zero(BitVector *v);

 size_t bitvector_weight(const BitVector *v);

 void sparse_p_mul(const SparseP *P,
                         const BitVector *x,
                         BitVector *y);


 PackedMatrix
concat_g_matrices(
    const PackedG *G,
    const PackedG *Gprime);


 void kernel_basis_free(KernelBasis *K);

 KernelBasis kernel_basis(const PackedMatrix *A);

 PackedG packed_g_alloc(size_t n,
                              size_t g);

uint8_t bit_get(const BitVector *v,
                              size_t index);

void bit_set(BitVector *v,
                           size_t index,
                           uint8_t value);


 void packed_g_free(PackedG *G);

 PackedG
kernel_basis_to_packed_g(
    const KernelBasis *K,
    size_t n);


 void packed_g_mul(
    const PackedG *G,
    const BitVector *s,
    BitVector *result);

 PackedMatrix
packed_g_to_matrix(const PackedG *G);

#endif /* MATRIX_H */