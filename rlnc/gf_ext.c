#include "gf_ext.h"

#include <stdlib.h>
#include <string.h>

/* -------------------------------------------------------------------------
 * Raw bit-vector polynomial helpers over GF(2) (degree <= GF_MAX_BITS)
 * ------------------------------------------------------------------------- */

static int bit_get(const gf_elem_t *a, unsigned i)
{
    return (int)((a->w[i / 64] >> (i % 64)) & 1u);
}

static void bit_flip(gf_elem_t *a, unsigned i)
{
    a->w[i / 64] ^= (uint64_t)1 << (i % 64);
}

static void bit_clear(gf_elem_t *a, unsigned i)
{
    a->w[i / 64] &= ~((uint64_t)1 << (i % 64));
}

static int poly_deg(const gf_elem_t *a)
{
    for (int i = GF_WORDS - 1; i >= 0; --i) {
        if (a->w[i] != 0) {
            int b = 63;
            while (!((a->w[i] >> b) & 1u))
                --b;
            return i * 64 + b;
        }
    }
    return -1;
}

static void poly_shl1(gf_elem_t *a)
{
    for (int i = GF_WORDS - 1; i > 0; --i)
        a->w[i] = (a->w[i] << 1) | (a->w[i - 1] >> 63);
    a->w[0] <<= 1;
}

/* a ^= b << s */
static void poly_xor_shifted(gf_elem_t *a, const gf_elem_t *b, unsigned s)
{
    const unsigned ws = s / 64, bs = s % 64;

    for (int i = GF_WORDS - 1; i >= (int)ws; --i) {
        uint64_t v = b->w[i - ws] << bs;

        if (bs != 0 && i - (int)ws - 1 >= 0)
            v |= b->w[i - ws - 1] >> (64 - bs);

        a->w[i] ^= v;
    }
}

static void poly_mod(gf_elem_t *a, const gf_elem_t *b)
{
    const int db = poly_deg(b);
    int da;

    while ((da = poly_deg(a)) >= db)
        poly_xor_shifted(a, b, (unsigned)(da - db));
}

static int poly_gcd_degree(gf_elem_t a, gf_elem_t b)
{
    while (poly_deg(&b) >= 0) {
        poly_mod(&a, &b);
        gf_elem_t t = a;
        a = b;
        b = t;
    }
    return poly_deg(&a);
}


/* -------------------------------------------------------------------------
 * Field
 * ------------------------------------------------------------------------- */

void gf_zero(gf_elem_t *a)
{
    memset(a, 0, sizeof(*a));
}

int gf_is_zero(const gf_elem_t *a)
{
    return poly_deg(a) < 0;
}

void gf_add(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    (void)F;
    for (int i = 0; i < GF_WORDS; ++i)
        r->w[i] = a->w[i] ^ b->w[i];
}

int gf_equal(const gf_field_t *F, const gf_elem_t *a, const gf_elem_t *b)
{
    (void)F;
    return memcmp(a, b, sizeof(*a)) == 0;
}

void gf_mul(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    gf_elem_t res;
    gf_zero(&res);

    for (int i = (int)F->n - 1; i >= 0; --i) {
        const int carry = bit_get(&res, F->n - 1);

        poly_shl1(&res);
        bit_clear(&res, F->n);

        if (carry)
            gf_add(F, &res, &res, &F->f_low);

        if (bit_get(b, (unsigned)i))
            gf_add(F, &res, &res, a);
    }

    *r = res;
}

/* a^(2^n - 2) */
void gf_inv(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a)
{
    gf_elem_t acc = *a;

    /* acc = a^(2^(n-1) - 1) */
    for (unsigned i = 1; i + 1 < F->n; ++i) {
        gf_mul(F, &acc, &acc, &acc);
        gf_mul(F, &acc, &acc, a);
    }

    gf_mul(F, r, &acc, &acc);
}

/* x^n + f_low is irreducible over GF(2)? (Ben-Or) */
static int is_irreducible(const gf_field_t *F)
{
    gf_elem_t f = F->f_low;
    bit_flip(&f, F->n);

    gf_elem_t x, h;
    gf_zero(&x);
    bit_flip(&x, 1);
    h = x;

    for (unsigned i = 1; i <= F->n / 2; ++i) {
        gf_mul(F, &h, &h, &h);

        gf_elem_t g;
        gf_add(F, &g, &h, &x);

        if (poly_gcd_degree(f, g) > 0)
            return 0;
    }

    return 1;
}

int gf_field_init(gf_field_t *F, unsigned n)
{
    if (F == NULL || n < 2 || n > GF_MAX_BITS)
        return -1;

    F->n = n;
    F->nw = n / 64 + 1;

    /* trinomials x^n + x^k + 1 */
    for (unsigned k = 1; k < n; ++k) {
        gf_zero(&F->f_low);
        bit_flip(&F->f_low, k);
        bit_flip(&F->f_low, 0);

        if (is_irreducible(F))
            return 0;
    }

    /* pentanomials x^n + x^c + x^b + x^a + 1 */
    for (unsigned c = 3; c < n; ++c)
        for (unsigned b = 2; b < c; ++b)
            for (unsigned a = 1; a < b; ++a) {
                gf_zero(&F->f_low);
                bit_flip(&F->f_low, c);
                bit_flip(&F->f_low, b);
                bit_flip(&F->f_low, a);
                bit_flip(&F->f_low, 0);

                if (is_irreducible(F))
                    return 0;
            }

    return -1;
}

uint32_t gf_get_symbol(const gf_elem_t *a, size_t i, unsigned m)
{
    uint32_t v = 0;
    for (unsigned j = 0; j < m; ++j)
        v |= (uint32_t)bit_get(a, (unsigned)(i * m + j)) << j;
    return v;
}

void gf_set_symbol(gf_elem_t *a, size_t i, unsigned m, uint32_t v)
{
    for (unsigned j = 0; j < m; ++j) {
        const unsigned pos = (unsigned)(i * m + j);
        bit_clear(a, pos);
        if ((v >> j) & 1u)
            bit_flip(a, pos);
    }
}


/* -------------------------------------------------------------------------
 * Polynomials over E
 * ------------------------------------------------------------------------- */

void gf_poly_eval(const gf_field_t *F, gf_elem_t *r,
                  const gf_elem_t *coeffs, size_t k, const gf_elem_t *x)
{
    gf_elem_t acc;
    gf_zero(&acc);

    for (size_t i = k; i-- > 0;) {
        gf_mul(F, &acc, &acc, x);
        gf_add(F, &acc, &acc, &coeffs[i]);
    }

    *r = acc;
}

int gf_poly_interpolate(const gf_field_t *F, gf_elem_t *coeffs,
                        const gf_elem_t *xs, const gf_elem_t *ys, size_t k)
{
    if (k == 0)
        return 0;

    gf_elem_t *M = calloc(k + 1, sizeof(gf_elem_t));
    gf_elem_t *Q = calloc(k, sizeof(gf_elem_t));
    int rc = -1;

    if (M == NULL || Q == NULL)
        goto done;

    /* M = prod (X - x_i) (characteristic 2: X + x_i) */
    M[0].w[0] = 1;
    for (size_t i = 0; i < k; ++i) {
        for (size_t j = i + 1; j > 0; --j) {
            gf_elem_t t;
            gf_mul(F, &t, &M[j], &xs[i]);
            gf_add(F, &M[j], &M[j - 1], &t);
        }
        gf_mul(F, &M[0], &M[0], &xs[i]);
    }

    for (size_t j = 0; j < k; ++j)
        gf_zero(&coeffs[j]);

    for (size_t i = 0; i < k; ++i) {
        /* Q = M / (X - x_i) by synthetic division */
        Q[k - 1] = M[k];
        for (size_t j = k - 1; j > 0; --j) {
            gf_elem_t t;
            gf_mul(F, &t, &xs[i], &Q[j]);
            gf_add(F, &Q[j - 1], &M[j], &t);
        }

        gf_elem_t d, f, inv;
        gf_poly_eval(F, &d, Q, k, &xs[i]);

        if (gf_is_zero(&d))
            goto done; /* repeated x */

        gf_inv(F, &inv, &d);
        gf_mul(F, &f, &ys[i], &inv);

        for (size_t j = 0; j < k; ++j) {
            gf_elem_t t;
            gf_mul(F, &t, &f, &Q[j]);
            gf_add(F, &coeffs[j], &coeffs[j], &t);
        }
    }

    rc = 0;

done:
    free(M);
    free(Q);
    return rc;
}
