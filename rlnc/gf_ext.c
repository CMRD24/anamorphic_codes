#include "gf_ext.h"

#include <stdlib.h>
#include <string.h>

/*
 * Arithmetic in the binary extension field E = GF(2^N).
 *
 * E is represented in a polynomial basis: GF(2)[x] / (f), where f is an
 * irreducible polynomial of degree N over GF(2). An element is a polynomial of
 * degree < N, stored as a bit vector (bit i = coefficient of x^i). Addition is
 * the XOR of the vectors, multiplication is polynomial multiplication reduced
 * modulo f. See D. Hankerson, A. Menezes, S. Vanstone, "Guide to Elliptic Curve
 * Cryptography", section 2.3 (binary field arithmetic).
 *
 * Invariant: all words of an element above the field's words are zero.
 */

/* -------------------------------------------------------------------------
 * Polynomials over GF(2) as bit vectors (any degree <= GF_MAX_BITS); used to
 * test irreducibility of the field polynomial
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

/*
 * Degree of the polynomial a; -1 for the zero polynomial.
 */
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

/* a *= x (shift of the bit vector by one position) on the lowest nw words */
static void poly_shl1(gf_elem_t *a, unsigned nw)
{
    for (unsigned i = nw - 1; i > 0; --i)
        a->w[i] = (a->w[i] << 1) | (a->w[i - 1] >> 63);
    a->w[0] <<= 1;
}

/*
 * a += x^s * b over GF(2): the XOR of b shifted left by s bits (one step of the polynomial long division).
 */
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

/*
 * a = a mod b over GF(2) by schoolbook long division: while deg a >= deg b, subtract
 * (= XOR) the shifted divisor x^(deg a - deg b) * b, which cancels the leading term.
 */
static void poly_mod(gf_elem_t *a, const gf_elem_t *b)
{
    const int db = poly_deg(b);
    int da;

    while ((da = poly_deg(a)) >= db)
        poly_xor_shifted(a, b, (unsigned)(da - db));
}

/*
 * Degree of gcd(a, b) over GF(2), by the Euclidean algorithm (gcd(a, b) = gcd(b, a mod b)).
 * The arguments are taken by value because the algorithm overwrites them.
 */
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
 * Field elements
 * ------------------------------------------------------------------------- */

void gf_zero(gf_elem_t *a)
{
    memset(a, 0, sizeof(*a));
}

/*
 * a == 0
 */
int gf_is_zero(const gf_elem_t *a)
{
    return poly_deg(a) < 0;
}

/* a += b over GF(2) (XOR) on the lowest nw words */
static void xor_into(gf_elem_t *a, const gf_elem_t *b, unsigned nw)
{
    for (unsigned i = 0; i < nw; ++i)
        a->w[i] ^= b->w[i];
}

void gf_add(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    unsigned i;

    for (i = 0; i < F->nw; ++i)
        r->w[i] = a->w[i] ^ b->w[i];

    /* keep the invariant that the words above the field are zero */
    for (; i < GF_WORDS; ++i)
        r->w[i] = 0;
}

/*
 * a == b. A bytewise comparison is sufficient because the words above the field are always zero.
 */
int gf_equal(const gf_field_t *F, const gf_elem_t *a, const gf_elem_t *b)
{
    (void)F;
    return memcmp(a, b, sizeof(*a)) == 0;
}

/*
 * r = a * b in E: polynomial multiplication reduced modulo f.
 *
 * Shift-and-add (Horner) multiplication processing b from its most significant bit:
 *    res <- res * x mod f;  if b_i = 1 then res <- res + a.
 * Multiplying by x shifts the bit vector by one position; if the shifted-out
 * coefficient of x^(N-1) was 1, x^N is replaced by f_low (the field polynomial
 * without its leading term), because x^N = f_low in characteristic 2. Cost O(N)
 * operations on nw = N/64 + 1 words; r may alias a or b.
 */
void gf_mul(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    gf_elem_t res;
    int top = (int)F->nw - 1;

    /* leading zero bits of b would only shift the zero accumulator */
    while (top >= 0 && b->w[top] == 0)
        --top;

    if (top < 0) {
        gf_zero(r);
        return;
    }

    gf_zero(&res);
    top = top * 64 + 63;
    while (!bit_get(b, (unsigned)top))
        --top;

    for (int i = top; i >= 0; --i) {
        const int carry = bit_get(&res, F->n - 1);

        poly_shl1(&res, F->nw);
        bit_clear(&res, F->n);

        if (carry)
            xor_into(&res, &F->f_low, F->nw);

        if (bit_get(b, (unsigned)i))
            xor_into(&res, a, F->nw);
    }

    *r = res;
}

/*
 * r = a^(-1) for a != 0, by Fermat's little theorem in the multiplicative group of E
 * (of order 2^N - 1): a^(-1) = a^(2^N - 2). The exponent 2^N - 2 = 2 (2^(N-1) - 1) is
 * reached by the square-and-multiply chain a^(2^(i+1) - 1) = (a^(2^i - 1))^2 * a.
 * Cost 2N multiplications, so callers that need many inversions use batch
 * inversion (see gf_poly_interpolate).
 */
void gf_inv(const gf_field_t *F, gf_elem_t *r, const gf_elem_t *a)
{
    gf_elem_t acc = *a;

    /* after the i-th round acc = a^(2^(i+1) - 1); the loop ends at 2^(n-1) - 1 */
    for (unsigned i = 1; i + 1 < F->n; ++i) {
        gf_mul(F, &acc, &acc, &acc);
        gf_mul(F, &acc, &acc, a);
    }

    gf_mul(F, r, &acc, &acc);
}

/*
 * Is f = x^N + f_low irreducible over GF(2)? Ben-Or's test (M. Ben-Or, "Probabilistic
 * algorithms in finite fields", FOCS 1981; see J. von zur Gathen, J. Gerhard, "Modern
 * Computer Algebra", chapter 14): f of degree N is irreducible iff
 * gcd(f, x^(2^i) - x) = 1 for all 1 <= i <= N/2, because an irreducible factor of
 * degree d divides x^(2^d) - x. h is updated by squaring modulo f: h = x^(2^i) mod f.
 */
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

/*
 * Finds the field polynomial of degree n. The candidates are tried in a fixed order
 * (trinomials, then pentanomials, in lexicographic order of the exponents), so that
 * every party that calls this with the same n obtains the same field. Irreducible
 * trinomials or pentanomials exist for all degrees that occur in practice
 * (Hankerson et al., table of irreducible polynomials); the search fails (-1) if
 * there is none.
 */
static int gf_field_search(gf_field_t *F, unsigned n)
{
    F->n = n;
    F->nw = n / 64 + 1;

    /* trinomials x^n + x^k + 1 first (cheapest to reduce by) */
    for (unsigned k = 1; k < n; ++k) {
        gf_zero(&F->f_low);
        bit_flip(&F->f_low, k);
        bit_flip(&F->f_low, 0);

        if (is_irreducible(F))
            return 0;
    }

    /* then pentanomials x^n + x^c + x^b + x^a + 1 */
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

/*
 * Sets up GF(2^n), 2 <= n <= GF_MAX_BITS. The search for the polynomial costs far more
 * than the arithmetic in the field (about 1 ms at n = 64, 30 ms at n = 256), so the
 * result of the last call is cached per thread.
 */
int gf_field_init(gf_field_t *F, unsigned n)
{
    static _Thread_local gf_field_t cached;
    static _Thread_local int have_cached;

    if (F == NULL || n < 2 || n > GF_MAX_BITS)
        return -1;

    if (!have_cached || cached.n != n) {
        if (gf_field_search(&cached, n) != 0) {
            have_cached = 0;
            return -1;
        }
        have_cached = 1;
    }

    *F = cached;

    return 0;
}

/*
 * Symbol i of the element, read as a vector of GF(2^m) symbols: bits [i*m, (i+1)*m).
 * Addition is componentwise on these symbols, so E is identified with F_q^(N/m).
 */
uint32_t gf_get_symbol(const gf_elem_t *a, size_t i, unsigned m)
{
    uint32_t v = 0;
    for (unsigned j = 0; j < m; ++j)
        v |= (uint32_t)bit_get(a, (unsigned)(i * m + j)) << j;
    return v;
}

/*
 * Writes symbol i (bits [i*m, (i+1)*m)) of the element.
 */
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

/*
 * r = P(x) for P = sum_{i<k} coeffs[i] X^i, by Horner's rule
 * P(x) = (...((c_{k-1} x + c_{k-2}) x + c_{k-3}) ...) x + c_0: k-1 multiplications.
 */
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

/*
 * Coefficients of the unique polynomial P of degree < k with P(xs[i]) = ys[i], for
 * pairwise distinct xs (-1 if two coincide).
 *
 * Lagrange interpolation (e.g. von zur Gathen, Gerhard, "Modern Computer Algebra",
 * chapter 5):
 *    P(X) = sum_i  y_i * L_i(X),   L_i(X) = prod_{j != i} (X - x_j) / (x_i - x_j).
 * With the master polynomial M(X) = prod_j (X - x_j) the numerator is the quotient
 * Q_i = M / (X - x_i) (synthetic division, i.e. Horner / Ruffini, O(k)), and the
 * denominator is d_i = prod_{j != i} (x_i - x_j) = M'(x_i). All k inverses of the d_i
 * are obtained with one inversion by Montgomery's trick (P. L. Montgomery, "Speeding
 * the Pollard and elliptic curve methods of factorization", Math. Comp. 44, 1985):
 * invert the prefix product d_0 ... d_{k-1} once and recover 1/d_i from it going
 * backwards. Total cost O(k^2) multiplications and one inversion; in characteristic 2
 * subtraction is addition.
 */
int gf_poly_interpolate(const gf_field_t *F, gf_elem_t *coeffs,
                        const gf_elem_t *xs, const gf_elem_t *ys, size_t k)
{
    if (k == 0)
        return 0;

    gf_elem_t *M = calloc(k + 1, sizeof(gf_elem_t));
    gf_elem_t *Q = calloc(k, sizeof(gf_elem_t));
    gf_elem_t *inv_d = calloc(k, sizeof(gf_elem_t));   /* 1 / prod_{j != i} (x_i - x_j) */
    gf_elem_t *prefix = calloc(k, sizeof(gf_elem_t));
    int rc = -1;

    if (M == NULL || Q == NULL || inv_d == NULL || prefix == NULL)
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

    /*
     * Denominators d_i = M'(x_i) = prod_{j != i} (x_i + x_j). They are inverted
     * together (Montgomery's trick): one inversion and 3 (k - 1) multiplications
     * instead of k inversions.
     */
    for (size_t i = 0; i < k; ++i) {
        gf_elem_t d;

        d.w[0] = 1;
        for (unsigned w = 1; w < GF_WORDS; ++w)
            d.w[w] = 0;

        for (size_t j = 0; j < k; ++j) {
            gf_elem_t diff;

            if (j == i)
                continue;

            gf_add(F, &diff, &xs[i], &xs[j]);
            gf_mul(F, &d, &d, &diff);
        }

        if (gf_is_zero(&d))
            goto done; /* repeated x */

        inv_d[i] = d;
        if (i == 0)
            prefix[0] = d;
        else
            gf_mul(F, &prefix[i], &prefix[i - 1], &d);
    }

    {
        gf_elem_t total;

        gf_inv(F, &total, &prefix[k - 1]);

        for (size_t i = k; i-- > 0;) {
            gf_elem_t d = inv_d[i];

            if (i == 0)
                inv_d[0] = total;
            else
                gf_mul(F, &inv_d[i], &total, &prefix[i - 1]);

            gf_mul(F, &total, &total, &d);
        }
    }

    for (size_t j = 0; j < k; ++j)
        gf_zero(&coeffs[j]);

    for (size_t i = 0; i < k; ++i) {
        gf_elem_t f;

        /* Q = M / (X - x_i) by synthetic division */
        Q[k - 1] = M[k];
        for (size_t j = k - 1; j > 0; --j) {
            gf_elem_t t;
            gf_mul(F, &t, &Q[j], &xs[i]);
            gf_add(F, &Q[j - 1], &M[j], &t);
        }

        gf_mul(F, &f, &ys[i], &inv_d[i]);

        for (size_t j = 0; j < k; ++j) {
            gf_elem_t t;
            gf_mul(F, &t, &Q[j], &f);
            gf_add(F, &coeffs[j], &coeffs[j], &t);
        }
    }

    rc = 0;

done:
    free(M);
    free(Q);
    free(inv_d);
    free(prefix);
    return rc;
}
