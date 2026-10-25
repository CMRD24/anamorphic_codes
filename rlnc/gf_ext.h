#ifndef GF_EXT_H
#define GF_EXT_H

#include <stddef.h>
#include <stdint.h>

/*
 * Arithmetic in the binary extension field E = GF(2^N), N <= GF_MAX_BITS.
 *
 * Elements are bit vectors of N bits. Addition is XOR, so an element can be
 * read as a vector of N/m symbols of GF(2^m): symbol i occupies bits
 * [i*m, (i+1)*m). This is the identification E = F_q^{K-a} used by aRLNC.
 *
 * The defining polynomial of degree N is taken from a fixed table of low-weight
 * irreducible polynomials (gf_irreducible.h), so encoder and decoder agree on it.
 */

#define GF_MAX_BITS 1024
#define GF_WORDS (GF_MAX_BITS / 64 + 1)

typedef struct {
    uint64_t w[GF_WORDS];
} gf_elem_t;

typedef struct {
    unsigned n;          /* extension degree over GF(2) */
    unsigned words;         /* words in use */
    gf_elem_t f_low;     /* defining polynomial without the x^N term */
} gf_field_t;

/* returns 0 on success, -1 if n is out of range [2, GF_MAX_BITS] */
int gf_field_init(gf_field_t *field, unsigned n);

void gf_zero(gf_elem_t *a);
int gf_is_zero(const gf_elem_t *a);
void gf_add(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b);
void gf_mul(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b);
void gf_inv(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a);
int gf_equal(const gf_field_t *field, const gf_elem_t *a, const gf_elem_t *b);

/* symbol access (m bits per symbol) */
uint32_t gf_get_symbol(const gf_elem_t *a, size_t i, unsigned m);
void gf_set_symbol(gf_elem_t *a, size_t i, unsigned m, uint32_t v);

/*
 * Reed-Solomon over E: polynomial P = sum_{i<k} coeffs[i] X^i.
 */
void gf_poly_eval(const gf_field_t *field, gf_elem_t *r,
                  const gf_elem_t *coeffs, size_t k, const gf_elem_t *x);

/*
 * Interpolate the unique polynomial of degree < k through k points with
 * pairwise distinct xs. Returns 0, or -1 on allocation failure / repeated x.
 */
int gf_poly_interpolate(const gf_field_t *field, gf_elem_t *coeffs,
                        const gf_elem_t *xs, const gf_elem_t *ys, size_t k);

#endif /* GF_EXT_H */
