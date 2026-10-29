#include "gf_ext.h"
#include "gf_irreducible.h"

#include <stdlib.h>
#include <string.h>

/*
 * Arithmetic in the binary extension field E = GF(2^N).
 *
 * E is represented in a polynomial basis: GF(2)[x] / (f), where f is an
 * irreducible polynomial of degree N over GF(2). An element is a polynomial of
 * degree < N, stored as a bit vector (bit i = coefficient of x^i). Addition is
 * the XOR of the vectors, multiplication is polynomial multiplication reduced
 * modulo f.
 *
 * Invariant: all words of an element above the field's words are zero.
 */

/* -------------------------------------------------------------------------
 * Bits of an element
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

/* a *= x (shift of the bit vector by one position) on the lowest `words` words */
static void poly_shl1(gf_elem_t *a, unsigned words)
{
    for (unsigned i = words - 1; i > 0; --i)
        a->w[i] = (a->w[i] << 1) | (a->w[i - 1] >> 63); //lowest bit of the shifted word is highest bit of the next lower word
    a->w[0] <<= 1;
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
    for (unsigned i = 0; i < GF_WORDS; ++i) {
        if (a->w[i] != 0)
            return 0;
    }

    return 1;
}

/* a += b over GF(2) (XOR) on the lowest `words` words */
static void xor_into(gf_elem_t *a, const gf_elem_t *b, unsigned words)
{
    for (unsigned i = 0; i < words; ++i)
        a->w[i] ^= b->w[i];
}

void gf_add(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    unsigned i;

    for (i = 0; i < field->words; ++i)
        r->w[i] = a->w[i] ^ b->w[i];

    /* keep the invariant that the words above the field are zero */
    for (; i < GF_WORDS; ++i)
        r->w[i] = 0;
}

/*
 * a == b. A bytewise comparison is sufficient because the words above the field are always zero.
 */
int gf_equal(const gf_field_t *field, const gf_elem_t *a, const gf_elem_t *b)
{
    (void)field;
    return memcmp(a, b, sizeof(*a)) == 0;
}

/*
 * r = a * b in E: polynomial multiplication reduced modulo f.
 *
 * Shift-and-add (Horner) multiplication processing b from its most significant bit:
 *    product <- product * x mod f;  if b_i = 1 then product <- product + a.
 * Multiplying by x shifts the bit vector by one position; if the shifted-out
 * coefficient of x^(N-1) was 1, x^N is replaced by f_low (the field polynomial
 * without its leading term), because x^N = f_low in characteristic 2; r may alias a or b.
 */
void gf_mul(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a, const gf_elem_t *b)
{
    gf_elem_t product;
    int top_bit = (int)field->words - 1;

    /* leading zero bits of b would only shift the zero accumulator */
    while (top_bit >= 0 && b->w[top_bit] == 0)
        --top_bit;

    if (top_bit < 0) {
        gf_zero(r);
        return;
    }

    gf_zero(&product);
    top_bit = top_bit * 64 + 63; //before it was "top_word" -> convert to bit
    while (!bit_get(b, (unsigned)top_bit))
        --top_bit;

    //now b:=top_bit is highest non-zero bit
    //ab = a(b_d x^d + … + b_1x + b_0) = ( ... ((b_da)x + b_{d−1}a)x + ... )x + b_0
    for (int i = top_bit; i >= 0; --i) {
        const int carry = bit_get(&product, field->n - 1);

        poly_shl1(&product, field->words); //product <- product * x mod f
        bit_clear(&product, field->n); //only relevant if carry=1

        if (carry)
            xor_into(&product, &field->f_low, field->words); //because in characteristic 2 and f=0: x^n = -f_low = f_low. So adding it back compensates the removed x^n (but keeps the highest bit 0)

        if (bit_get(b, (unsigned)i))
            xor_into(&product, a, field->words); //if b_i=1, add a to the product so the loops result is product <- product*x +b_i*a
    }

    *r = product;
}

/*
 * r = a^(-1) for a != 0, by Fermat's little theorem in the multiplicative group of E
 * (of order 2^N - 1): a^(-1) = a^(2^N - 2). The exponent 2^N - 2 = 2 (2^(N-1) - 1) is
 * reached by the square-and-multiply chain a^(2^(i+1) - 1) = (a^(2^i - 1))^2 * a.
 * Cost 2N multiplications, so callers that need many inversions use batch
 * inversion (see gf_poly_interpolate).
 */
void gf_inv(const gf_field_t *field, gf_elem_t *r, const gf_elem_t *a)
{
    gf_elem_t power = *a;

    /* after the i-th round power = a^(2^(i+1) - 1); the loop ends at 2^(n-1) - 1 */
    for (unsigned i = 1; i + 1 < field->n; ++i) {
        gf_mul(field, &power, &power, &power);//square
        gf_mul(field, &power, &power, a);//multiply, leading to (a^(2^i - 1))^2 * a
    }
    //now power = a^(2^(n-1) - 1)
    gf_mul(field, r, &power, &power); //a^(2^(n-1) - 1)^2 = a^(2^N - 2) = a^-1
}

/*
 * Sets up GF(2^n), 2 <= n <= GF_MAX_BITS. The field polynomial f = x^n + f_low is
 * looked up in a table of low-weight irreducible polynomials (gf_irreducible.h),
 * so every party that uses the same n works in the same field. Finding such a
 * polynomial by search costs far more than the arithmetic in the field (about 1 ms
 * at n = 64 and 30 ms at n = 256, with an irreducibility test such as Ben-Or's), 
 * which is why the table was generated once and checked offline.
 */
int gf_field_init(gf_field_t *field, unsigned n)
{
    if (field == NULL || n < 2 || n > GF_MAX_BITS)
        return -1;

    const gf_irreducible_t *t = &gf_irreducible[n];

    field->n = n;
    field->words = n / 64 + 1;
    gf_zero(&field->f_low);

    //setup f_low s.t. f = x^n + f_low
    bit_flip(&field->f_low, 0);
    bit_flip(&field->f_low, t->a);
    if (t->b != 0) {
        bit_flip(&field->f_low, t->b);
        bit_flip(&field->f_low, t->c);
    }

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
        if ((v >> j) & 1u) //if value bit at the j-th position is 1 set to 1 in a
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
void gf_poly_eval(const gf_field_t *field, gf_elem_t *r,
                  const gf_elem_t *coeffs, size_t k, const gf_elem_t *x)
{
    gf_elem_t value;
    gf_zero(&value);

    for (size_t i = k; i-- > 0;) {
        gf_mul(field, &value, &value, x);
        gf_add(field, &value, &value, &coeffs[i]);
    }

    *r = value;
}

/*
 * Coefficients of the unique polynomial P of degree < k with P(xs[i]) = ys[i], for
 * pairwise distinct xs (-1 if two coincide).
 *
 * Lagrange interpolation (e.g. von zur Gathen, Gerhard, "Modern Computer Algebra",
 * chapter 5 p. 93 (http://lib.ysu.am/disciplines_bk/8daf5ccde25503ca099cd564bc4018f2.pdf), 
 * https://en.wikipedia.org/wiki/Lagrange_polynomial):
 *    P(X) = sum_i  y_i * L_i(X),   L_i(X) = prod_{j != i} (X - x_j) / (x_i - x_j).
 * With the master polynomial M(X) = prod_j (X - x_j) the numerator is the quotient
 * Q_i = M / (X - x_i) (synthetic division, i.e. Horner / Ruffini, O(k)), and the
 * denominator is d_i = prod_{j != i} (x_i - x_j) = M'(x_i). All k inverses of the d_i
 * are obtained with one inversion by Montgomery's trick 
 * (https://www.johndcook.com/blog/2026/01/14/montgomerys-trick/):
 * invert the prefix product d_0 ... d_{k-1} once and recover 1/d_i from it going
 * backwards. Total cost O(k^2) multiplications and one inversion; in characteristic 2
 * subtraction is addition.
 */
int gf_poly_interpolate(const gf_field_t *field, gf_elem_t *coeffs,
                        const gf_elem_t *xs, const gf_elem_t *ys, size_t k)
{
    if (k == 0)
        return 0;

    gf_elem_t *M = calloc(k + 1, sizeof(gf_elem_t));
    gf_elem_t *Q = calloc(k, sizeof(gf_elem_t));
    gf_elem_t *inv_d = calloc(k, sizeof(gf_elem_t));   /* 1 / prod_{j != i} (x_i - x_j) */
    gf_elem_t *prefix = calloc(k, sizeof(gf_elem_t));
    int result = -1;

    if (M == NULL || Q == NULL || inv_d == NULL || prefix == NULL)
        goto done;

    /* M = prod (X - x_i) (characteristic 2: X + x_i) */
    //compute coefficients of the master polynomial M
    M[0].w[0] = 1;
    for (size_t i = 0; i < k; ++i) {//build up degree of M (multiply in one linear factor at a time)
        for (size_t j = i + 1; j > 0; --j) {//iterate over all coefficients of M so far
            gf_elem_t term;
            gf_mul(field, &term, &M[j], &xs[i]); //at j=i+1 M[j]=0 and becomes 1 with the addition (increases degree by 1). For lower monomials, 
            gf_add(field, &M[j], &M[j - 1], &term); //add the old value (now shifted by one position to the left because of the multiplication with X)
        }
        gf_mul(field, &M[0], &M[0], &xs[i]); //j=0 case (nothing to add because the old M shifted to the left is 0 here (lowest position))
    }

    /*
     * Denominators d_i = M'(x_i) = prod_{j != i} (x_i + x_j). They are inverted
     * together (Montgomery's trick): one inversion and 3 (k - 1) multiplications
     * instead of k inversions.
     */
    for (size_t i = 0; i < k; ++i) {
        //building d the same way as M except that the i-th factor is left out
        gf_elem_t d;

        d.w[0] = 1;
        for (unsigned w = 1; w < GF_WORDS; ++w)
            d.w[w] = 0;

        for (size_t j = 0; j < k; ++j) {
            gf_elem_t diff;

            if (j == i)
                continue;

            gf_add(field, &diff, &xs[i], &xs[j]);
            gf_mul(field, &d, &d, &diff);
        }

        if (gf_is_zero(&d))
            goto done; /* repeated x */

        
        inv_d[i] = d;
        //build the prefix products for the later inversion: 
        if (i == 0)
            prefix[0] = d;
        else
            gf_mul(field, &prefix[i], &prefix[i - 1], &d);
    }

    //(seperate scope for total): applying montgomery's trick
    {
        gf_elem_t total;

        gf_inv(field, &total, &prefix[k - 1]); //i.e. total = (d_(k-1)...d_0)^-1

        for (size_t i = k; i-- > 0;) {
            gf_elem_t d = inv_d[i];

            if (i == 0)
                inv_d[0] = total; //only the inverse of a single factor left which is d_0^-1
            else
                gf_mul(field, &inv_d[i], &total, &prefix[i - 1]); //e.g. (abc)^-1 * ab = c

            gf_mul(field, &total, &total, &d); //remove d_i from the total inverse
        }
    }

    //make sure the coefficients are zeroed
    for (size_t j = 0; j < k; ++j)
        gf_zero(&coeffs[j]);

    for (size_t i = 0; i < k; ++i) {
        gf_elem_t weight;

        /* Q = M / (X - x_i) by synthetic division */
        Q[k - 1] = M[k]; //bring down first coefficient
        for (size_t j = k - 1; j > 0; --j) {
            gf_elem_t term;
            gf_mul(field, &term, &Q[j], &xs[i]); //multiply coefficient by x_i
            gf_add(field, &Q[j - 1], &M[j], &term); //add to next lower coefficient
        }

        
        gf_mul(field, &weight, &ys[i], &inv_d[i]); // weight = y_i/d_i = y_i / prod_{j != i} (x_i + x_j)

        //y_i*ell_i (as defined in wiki) = weight * Q (multiply each coefficient by weight). The polynomial coefficients are now all y_i*ell_i summed up. Therefore, for each i,j<k: coefficients[j] += (y_i*ell_i)[j]
        for (size_t j = 0; j < k; ++j) {
            gf_elem_t term;
            gf_mul(field, &term, &Q[j], &weight); 
            gf_add(field, &coeffs[j], &coeffs[j], &term);
        }
    }

    result = 0;

done:
    free(M);
    free(Q);
    free(inv_d);
    free(prefix);
    return result;
}
