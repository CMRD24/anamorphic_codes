#include "folded_rs.h"

#include "prc_dc.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

/*
 * Primitive polynomials for GF(2^m), represented with the x^m term
 * included. The low m bits represent the lower-degree terms.
 *
 * These are standard primitive choices for the supported small fields.
 */
static uint32_t default_primitive_polynomial(unsigned m)
{
    switch (m) {
    case 2:  return 0x7u;       /* x^2 + x + 1 */
    case 3:  return 0xBu;       /* x^3 + x + 1 */
    case 4:  return 0x13u;      /* x^4 + x + 1 */
    case 5:  return 0x25u;      /* x^5 + x^2 + 1 */
    case 6:  return 0x43u;      /* x^6 + x + 1 */
    case 7:  return 0x83u;      /* x^7 + x + 1 */
    case 8:  return 0x11Du;     /* x^8 + x^4 + x^3 + x^2 + 1 */
    case 9:  return 0x211u;     /* x^9 + x^4 + 1 */
    case 10: return 0x409u;     /* x^10 + x^3 + 1 */
    case 11: return 0x805u;     /* x^11 + x^2 + 1 */
    case 12: return 0x1053u;    /* x^12 + x^6 + x^4 + x + 1 */
    case 13: return 0x201Bu;    /* x^13 + x^4 + x^3 + x + 1 */
    case 14: return 0x4443u;    /* x^14 + x^10 + x^6 + x + 1 */
    case 15: return 0x8003u;    /* x^15 + x + 1 */
    case 16: return 0x1100Bu;   /* x^16 + x^12 + x^3 + x + 1 */
    default: return 0;
    }
}

static int is_power_of_two_u64(uint64_t x)
{
    return x != 0 && (x & (x - 1u)) == 0;
}

static uint64_t field_size(unsigned w)
{
    if (w >= 64)
        return 0;
    return UINT64_C(1) << w;
}

uint64_t folded_rs_alphabet_size(const FoldedRSParams *params)
{
    if (params == NULL ||
        params->field_bits == 0 ||
        params->folding_factor == 0 ||
        params->field_bits > 63)
        return 0;

    const unsigned w = params->field_bits;

    if ((size_t)w > SIZE_MAX / params->folding_factor)
        return 0;

    const size_t total_bits =
        (size_t)w * params->folding_factor;

    if (total_bits >= 64)
        return 0;

    return UINT64_C(1) << total_bits;
}

int folded_rs_validate(const FoldedRSParams *params)
{
    if (params == NULL)
        return 0;

    if (params->field_bits < 2 ||
        params->field_bits > 16)
        return 0;

    if (params->folding_factor == 0 ||
        params->n == 0 ||
        params->k == 0)
        return 0;

    if (params->folding_factor > SIZE_MAX / params->n)
        return 0;

    if (params->k > params->n * params->folding_factor)
        return 0;

    if (!is_power_of_two_u64((uint64_t)params->n))
        return 0;

    const uint32_t primitive =
        params->primitive_polynomial != 0
            ? params->primitive_polynomial
            : default_primitive_polynomial(params->field_bits);

    if (primitive == 0)
        return 0;

    const uint64_t Q =
        field_size(params->field_bits);

    if (Q == 0)
        return 0;

    /* q = Q^folding_factor must fit into uint64_t. */
    if (params->field_bits >
        63u / params->folding_factor)
        return 0;

    /* Need n*fold evaluation points, all nonzero and distinct. */
    if (params->folding_factor >
        SIZE_MAX / params->n)
        return 0;

    const size_t evaluations =
        params->n * params->folding_factor;

    if ((uint64_t)evaluations >= Q)
        return 0;

    /* alpha must be nonzero and below Q. */
    if (params->alpha != 0 &&
        params->alpha >= Q)
        return 0;

    return 1;
}

int folded_rs_params_init(
    FoldedRSParams *params,
    unsigned field_bits,
    size_t folding_factor,
    size_t n,
    size_t k)
{
    if (params == NULL)
        return 0;

    memset(params, 0, sizeof(*params));

    params->field_bits = field_bits;
    params->folding_factor = folding_factor;
    params->n = n;
    params->k = k;
    params->primitive_polynomial =
        default_primitive_polynomial(field_bits);
    params->alpha = 2u; /* x in GF(2^w). */

    return folded_rs_validate(params);
}

/* ----------------------------------------------------------------
 * GF(2^w) arithmetic
 * ---------------------------------------------------------------- */

typedef struct {
    unsigned w;
    uint32_t modulus;
    uint32_t mask;
} GF2m;

static GF2m make_field(const FoldedRSParams *p)
{
    GF2m f;
    f.w = p->field_bits;
    f.modulus = p->primitive_polynomial;
    f.mask = (uint32_t)((UINT32_C(1) << f.w) - 1u);
    return f;
}

static uint32_t gf_add(uint32_t a, uint32_t b)
{
    return a ^ b;
}

static uint32_t gf_mul(GF2m f, uint32_t a, uint32_t b)
{
    uint32_t result = 0;

    a &= f.mask;
    b &= f.mask;

    while (b != 0) {
        if (b & 1u)
            result ^= a;

        b >>= 1u;
        a <<= 1u;

        if (a & (UINT32_C(1) << f.w))
            a ^= f.modulus;
    }

    return result & f.mask;
}

/* ----------------------------------------------------------------
 * RNG helpers
 * ---------------------------------------------------------------- */

static PRCDC_Random *as_random(void *rng)
{
    return (PRCDC_Random *)rng;
}

static int rng_u64(
    PRCDC_Random *random,
    uint64_t *out)
{
    if (random == NULL ||
        random->rng == NULL ||
        out == NULL)
        return 0;

    return random->rng(
        random->ctx,
        (uint8_t *)out,
        sizeof(*out));
}

static int rng_bounded(
    PRCDC_Random *random,
    uint64_t bound,
    uint64_t *out)
{
    if (bound == 0 || out == NULL)
        return 0;

    if ((bound & (bound - 1u)) == 0) {
        uint64_t x;
        if (!rng_u64(random, &x))
            return 0;

        *out = x & (bound - 1u);
        return 1;
    }

    /*
     * Rejection sampling. Use the largest multiple of bound that
     * fits in the uint64_t domain.
     */
    const uint64_t limit =
        UINT64_MAX - (UINT64_MAX % bound);

    uint64_t x;
    do {
        if (!rng_u64(random, &x))
            return 0;
    } while (x >= limit);

    *out = x % bound;
    return 1;
}

static int rng_bernoulli(
    PRCDC_Random *random,
    double p)
{
    if (p <= 0.0)
        return 0;
    if (p >= 1.0)
        return 1;

    uint64_t raw;
    if (!rng_u64(random, &raw))
        return 0;

    const uint64_t x = raw >> 11u;
    const double u =
        (double)x * (1.0 / 9007199254740992.0);

    return u < p;
}

/* ----------------------------------------------------------------
 * Folded symbol packing
 * ---------------------------------------------------------------- */

static uint64_t pack_folded(
    const uint32_t *values,
    size_t fold,
    unsigned w)
{
    uint64_t result = 0;

    for (size_t j = 0; j < fold; ++j)
        result |=
            ((uint64_t)values[j]) << (j * w);

    return result;
}

/* ----------------------------------------------------------------
 * Polynomial evaluation
 * ---------------------------------------------------------------- */

static uint32_t eval_poly(
    GF2m f,
    const uint32_t *coeff,
    size_t k,
    uint32_t x)
{
    uint32_t y = 0;

    for (size_t i = k; i > 0; --i)
        y = gf_add(
            gf_mul(f, y, x),
            coeff[i - 1]);

    return y;
}

/* ----------------------------------------------------------------
 * Codeword sampling
 * ---------------------------------------------------------------- */

static uint64_t *frs_sample(
    void *opaque,
    size_t n,
    uint64_t q,
    void *rng)
{
    FoldedRSParams *p = (FoldedRSParams *)opaque;

    if (p == NULL ||
        !folded_rs_validate(p) ||
        n != p->n ||
        q != folded_rs_alphabet_size(p))
        return NULL;

    const GF2m f = make_field(p);
    const size_t total =
        p->n * p->folding_factor;

    uint32_t *coeff =
        malloc(p->k * sizeof(*coeff));

    uint64_t *word =
        malloc(p->n * sizeof(*word));

    if ((coeff == NULL && p->k != 0) ||
        (word == NULL && p->n != 0)) {
        free(coeff);
        free(word);
        return NULL;
    }

    PRCDC_Random *random = as_random(rng);
    const uint64_t Q = field_size(p->field_bits);

    for (size_t i = 0; i < p->k; ++i) {
        uint64_t x;
        if (!rng_bounded(random, Q, &x)) {
            free(coeff);
            free(word);
            return NULL;
        }
        coeff[i] = (uint32_t)x;
    }

    uint32_t *values =
        malloc(total * sizeof(*values));

    if (values == NULL && total != 0) {
        free(coeff);
        free(word);
        return NULL;
    }

    uint32_t point = 1u;

    for (size_t j = 0; j < total; ++j) {
        values[j] = eval_poly(f, coeff, p->k, point);
        point = gf_mul(f, point,
                       p->alpha != 0 ? p->alpha : 2u);
    }

    for (size_t i = 0; i < p->n; ++i)
        word[i] = pack_folded(
            values + i * p->folding_factor,
            p->folding_factor,
            p->field_bits);

    free(values);
    free(coeff);

    return word;
}

/* ----------------------------------------------------------------
 * Substitution channel
 * ---------------------------------------------------------------- */

static uint64_t *frs_substitute(
    void *opaque,
    const uint64_t *word,
    size_t n,
    uint64_t q,
    double eta,
    void *rng)
{
    FoldedRSParams *p = (FoldedRSParams *)opaque;

    if (p == NULL ||
        word == NULL ||
        !folded_rs_validate(p) ||
        n != p->n ||
        q != folded_rs_alphabet_size(p) ||
        eta < 0.0 || eta > 1.0)
        return NULL;

    uint64_t *out =
        malloc(n * sizeof(*out));

    if (out == NULL && n != 0)
        return NULL;

    PRCDC_Random *random = as_random(rng);

    for (size_t i = 0; i < n; ++i) {
        out[i] = word[i];

        if (!rng_bernoulli(random, eta))
            continue;

        uint64_t replacement;
        if (q == 1) {
            replacement = 0;
        } else {
            uint64_t r;
            if (!rng_bounded(random, q - 1u, &r)) {
                free(out);
                return NULL;
            }

            replacement =
                r >= word[i] ? r + 1u : r;
        }

        out[i] = replacement;
    }

    return out;
}

/* ----------------------------------------------------------------
 * List recovery
 * ---------------------------------------------------------------- */

typedef struct {
    const FoldedRSParams *p;
    GF2m field;
    const uint64_t *const *lists;
    const size_t *lengths;
    size_t t_rec;
    size_t L_max;
    uint32_t *coeff;
    uint32_t *values;
    int found;
} LRSearch;

static int list_contains(
    const uint64_t *list,
    size_t length,
    uint64_t value)
{
    for (size_t i = 0; i < length; ++i)
        if (list[i] == value)
            return 1;

    return 0;
}

static int evaluate_agreement(LRSearch *s)
{
    const FoldedRSParams *p = s->p;
    const size_t total =
        p->n * p->folding_factor;

    uint32_t point = 1u;

    size_t agreement = 0;

    for (size_t i = 0; i < p->n; ++i) {
        uint64_t packed = 0;

        for (size_t j = 0;
             j < p->folding_factor;
             ++j) {
            s->values[i * p->folding_factor + j] =
                eval_poly(
                    s->field,
                    s->coeff,
                    p->k,
                    point);

            point = gf_mul(
                s->field,
                point,
                p->alpha != 0 ? p->alpha : 2u);
        }

        packed = pack_folded(
            s->values + i * p->folding_factor,
            p->folding_factor,
            p->field_bits);

        if (list_contains(
                s->lists[i],
                s->lengths[i],
                packed)) {
            ++agreement;

            if (agreement >= s->t_rec)
                return 1;
        }

        /*
         * Remaining coordinates cannot reach t_rec.
         */
        const size_t remaining =
            p->n - i - 1u;

        if (agreement + remaining < s->t_rec)
            return 0;
    }

    (void)total;
    return agreement >= s->t_rec;
}

/*
 * Enumerate all Q^k coefficient vectors. The recursion stops at the
 * first codeword meeting the agreement threshold.
 */
static int enumerate_coefficients(
    LRSearch *s,
    size_t depth,
    uint64_t Q)
{
    if (depth == s->p->k)
        return evaluate_agreement(s);

    for (uint64_t a = 0; a < Q; ++a) {
        s->coeff[depth] = (uint32_t)a;

        if (enumerate_coefficients(
                s,
                depth + 1u,
                Q))
            return 1;
    }

    return 0;
}

static int frs_list_recovery(
    void *opaque,
    size_t n,
    uint64_t q,
    size_t t_rec,
    const uint64_t *const *lists,
    const size_t *list_lengths,
    size_t L_max)
{
    FoldedRSParams *p = (FoldedRSParams *)opaque;

    if (p == NULL ||
        !folded_rs_validate(p) ||
        n != p->n ||
        q != folded_rs_alphabet_size(p) ||
        lists == NULL ||
        list_lengths == NULL ||
        t_rec > n ||
        t_rec == 0 ||
        L_max == 0)
        return 0;

    for (size_t i = 0; i < n; ++i) {
        if (list_lengths[i] > L_max)
            return 0;
    }

    const size_t total =
        p->n * p->folding_factor;

    LRSearch s;
    memset(&s, 0, sizeof(s));

    s.p = p;
    s.field = make_field(p);
    s.lists = lists;
    s.lengths = list_lengths;
    s.t_rec = t_rec;
    s.L_max = L_max;

    s.coeff =
        calloc(p->k, sizeof(*s.coeff));

    s.values =
        malloc(total * sizeof(*s.values));

    if ((s.coeff == NULL && p->k != 0) ||
        (s.values == NULL && total != 0)) {
        free(s.coeff);
        free(s.values);
        return 0;
    }

    const uint64_t Q =
        field_size(p->field_bits);

    const int result =
        enumerate_coefficients(&s, 0, Q);

    free(s.coeff);
    free(s.values);

    return result;
}

/* ----------------------------------------------------------------
 * Public interface
 * ---------------------------------------------------------------- */

int folded_rs_init(
    FoldedRSParams *params,
    PRCCode *code)
{
    if (params == NULL ||
        code == NULL ||
        !folded_rs_validate(params))
        return 0;

    memset(code, 0, sizeof(*code));

    code->n = params->n;
    code->q = folded_rs_alphabet_size(params);
    code->code_ctx = params;
    code->sample = frs_sample;
    code->substitute = frs_substitute;
    code->list_recovery = frs_list_recovery;

    return code->q != 0;
}
