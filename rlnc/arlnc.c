/*
 * Anamorphic RLNC (aRLNC): Reed-Solomon points hidden in the headers.
 *
 * A symbol's header gamma in F_q^K is split as gamma = (alpha, y) with a label
 * alpha in F_q^a (uniform) and y in E = GF(q^(K-a)) (identified with F_q^(K-a),
 * see gf_ext.c). The anamorphic message m_a = (mu_0, ..., mu_{S-2}) in E^(S-1) is
 * the coefficient vector of a polynomial P of degree <= S-2 over E (a
 * Reed-Solomon codeword: the evaluations of P at distinct points), and
 *
 *     y = P(pad0(alpha)) + PRF(s, alpha),
 *
 * where pad0 embeds the label into E. Without the PRF key s the mask makes y
 * uniform, so the header is a uniform vector as in regular RLNC. The payload is
 * u = gamma^T W, so the regular message is unaffected.
 *
 * The receiver removes the masks and obtains S points (pad0(alpha_i), P(...)) of
 * P. Any S-1 distinct points determine P (Lagrange interpolation, gf_ext.c); the
 * last point is a check that rejects headers that do not come from aRLNC.
 */
#include "rlnc.h"
#include "gf_ext.h"

#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../utils/random_utils.h"

typedef struct {
    gf_field_t F;
    unsigned m;      /* bits per GF(q) symbol */
    size_t a;        /* label length in symbols */
    size_t d;        /* K - a: extension degree of E over F_q */
} arlnc_params_t;

/*
 * log2 q: the number of bits of a GF(q) symbol (q is a power of two).
 */
static unsigned symbol_bits(uint32_t q)
{
    unsigned m = 0;
    while ((1u << m) < q)
        ++m;
    return m;
}

/*
 * Derives the parameters of the construction: label length a = ceil(lambda / log2 q)
 * (so that q^a >= 2^lambda labels), the extension degree d = K - a of E over F_q and
 * the field E = GF(2^(m d)). Requires K >= 2a and S >= K.
 */
static int params_init(const rlnc_config_t *cfg,
                       const rlnc_aconfig_t *acfg,
                       arlnc_params_t *p)
{
    if (!rlnc_config_valid(cfg) || acfg == NULL || p == NULL)
        return -1;

    p->m = symbol_bits(cfg->q);
    p->a = (acfg->lambda + p->m - 1) / p->m;

    /* K >= 2a, S >= K */
    if (acfg->lambda == 0 ||
        cfg->generation_size < 2 * p->a ||
        acfg->received < cfg->generation_size ||
        p->a > 256 - 4)
        return -1;

    p->d = cfg->generation_size - p->a;

    return gf_field_init(&p->F, (unsigned)(p->m * p->d));
}

/*
 * Length of the anamorphic message in GF(q) symbols: (S - 1) coefficients of d symbols each; 0 if the parameters are invalid.
 */
size_t rlnc_amsg_len(const rlnc_config_t *cfg, const rlnc_aconfig_t *acfg)
{
    arlnc_params_t p;

    if (params_init(cfg, acfg, &p) != 0)
        return 0;

    return (acfg->received - 1) * p.d;
}

uint8_t *rlnc_akeygen(void)
{
    if (sodium_init() < 0)
        return NULL;

    uint8_t *akey = malloc(crypto_generichash_KEYBYTES);

    if (akey != NULL)
        crypto_generichash_keygen(akey);

    return akey;
}

void rlnc_akey_free(uint8_t *akey)
{
    if (akey == NULL)
        return;

    sodium_memzero(akey, crypto_generichash_KEYBYTES);
    free(akey);
}

/*
 * F(s, alpha) in E: a keyed hash (BLAKE2b, libsodium crypto_generichash) of the label and
 * a block counter, used as a PRF. Its output is expanded in counter mode to d symbols
 * of GF(q) (one byte each, reduced to log2 q bits).
 */
/* F(s, alpha) in E, a keyed hash in counter mode */
static void prf_mask(const arlnc_params_t *p,
                     const rlnc_config_t *cfg,
                     const uint8_t *akey,
                     const uint8_t *alpha,
                     gf_elem_t *out)
{
    uint8_t in[256];
    uint8_t block[32];

    memcpy(in, alpha, p->a);
    gf_zero(out);

    for (size_t i = 0; i < p->d; ++i) {
        if (i % sizeof(block) == 0) {
            const uint32_t ctr = (uint32_t)(i / sizeof(block));

            in[p->a + 0] = (uint8_t)ctr;
            in[p->a + 1] = (uint8_t)(ctr >> 8);
            in[p->a + 2] = (uint8_t)(ctr >> 16);
            in[p->a + 3] = (uint8_t)(ctr >> 24);

            crypto_generichash(block, sizeof(block), in, p->a + 4,
                               akey, crypto_generichash_KEYBYTES);
        }

        gf_set_symbol(out, i, p->m, block[i % sizeof(block)] & (cfg->q - 1));
    }
}

/*
 * pad0(alpha): the label as an element of E (its a symbols followed by zeros).
 */
static void pad0(const arlnc_params_t *p, const uint8_t *alpha, gf_elem_t *out)
{
    gf_zero(out);

    for (size_t i = 0; i < p->a; ++i)
        gf_set_symbol(out, i, p->m, alpha[i]);
}

/*
 * Creates out_count >= S symbols for the generation `source`, hiding amessage:
 * for each symbol sample a fresh label alpha (resampled if it repeats, so all labels
 * are distinct), set y = P(pad0(alpha)) + F(s, alpha) with P from the coefficients of
 * amessage (Horner evaluation in E), and combine the source packets with
 * gamma = (alpha, y) as local vector. Returns 0, or -1 on invalid parameters.
 */
int rlnc_aencode(
    const rlnc_config_t *cfg,
    const rlnc_aconfig_t *acfg,
    const rlnc_packet_t *source,
    rlnc_packet_t *out,
    size_t out_count,
    RandomnessSource *rng,
    const uint8_t *akey,
    const uint8_t *amessage)
{
    arlnc_params_t p;

    if (source == NULL || out == NULL || rng == NULL ||
        akey == NULL || amessage == NULL)
        return -1;

    if (params_init(cfg, acfg, &p) != 0)
        return -1;

    /* T >= S, and enough distinct labels exist */
    if (out_count < acfg->received)
        return -1;

    if (p.a * p.m < 32 && ((uint64_t)1 << (p.a * p.m)) < out_count)
        return -1;

    const size_t K = cfg->generation_size;
    const size_t k = acfg->received - 1;
    int rc = -1;

    gf_elem_t *coeffs = calloc(k, sizeof(gf_elem_t));
    uint8_t *labels = malloc(out_count * p.a);
    uint8_t *gamma = malloc(K);

    if (coeffs == NULL || labels == NULL || gamma == NULL)
        goto done;

    /* m_a = (mu_0, ..., mu_{S-2}) in E^{S-1}, mu_i given as d symbols */
    for (size_t i = 0; i < k; ++i)
        for (size_t s = 0; s < p.d; ++s)
            gf_set_symbol(&coeffs[i], s, p.m,
                          amessage[i * p.d + s] & (cfg->q - 1));

    for (size_t j = 0; j < out_count; ++j) {
        uint8_t *alpha = labels + j * p.a;
        int fresh;

        /* uniform label, resampled on the (negligible) event of a repeat */
        do {
            fresh = 1;

            for (size_t i = 0; i < p.a; ++i)
                alpha[i] = (uint8_t)random_bounded(rng, cfg->q);

            for (size_t l = 0; l < j && fresh; ++l)
                if (memcmp(alpha, labels + l * p.a, p.a) == 0)
                    fresh = 0;
        } while (!fresh);

        gf_elem_t x, y, mask;

        pad0(&p, alpha, &x);
        gf_poly_eval(&p.F, &y, coeffs, k, &x);
        prf_mask(&p, cfg, akey, alpha, &mask);
        gf_add(&p.F, &y, &y, &mask);

        memcpy(gamma, alpha, p.a);
        for (size_t s = 0; s < p.d; ++s)
            gamma[p.a + s] = (uint8_t)gf_get_symbol(&y, s, p.m);

        /*
         * The sources carry the canonical global vectors e_i, so using gamma
         * as local vector yields global vector gamma and payload gamma^T W.
         */
        if (rlnc_encode_with_vector(cfg, source, K, gamma, &out[j]) != 0)
            goto done;
    }

    rc = 0;

done:
    free(coeffs);
    free(labels);
    free(gamma);
    return rc;
}

/*
 * Recovers the anamorphic message from exactly S received symbols (-1 otherwise):
 * unmask z_i = y_i - F(s, alpha_i), interpolate P through the first S-1 points
 * (pad0(alpha_i), z_i), and accept iff the last point lies on P. A symbol set that
 * does not come from aRLNC under this key passes the check with probability 1/|E|.
 * Symbols with a repeated label are rejected.
 */
int rlnc_adecode(
    const rlnc_config_t *cfg,
    const rlnc_aconfig_t *acfg,
    const rlnc_packet_t *received,
    size_t received_count,
    const uint8_t *akey,
    uint8_t *amessage)
{
    arlnc_params_t p;

    if (received == NULL || akey == NULL || amessage == NULL)
        return -1;

    if (params_init(cfg, acfg, &p) != 0)
        return -1;

    /* codewords with a different number of symbols are rejected */
    if (received_count != acfg->received)
        return -1;

    const size_t k = received_count - 1;
    int rc = -1;

    gf_elem_t *xs = calloc(received_count, sizeof(gf_elem_t));
    gf_elem_t *zs = calloc(received_count, sizeof(gf_elem_t));
    gf_elem_t *coeffs = calloc(k, sizeof(gf_elem_t));

    if (xs == NULL || zs == NULL || coeffs == NULL)
        goto done;

    for (size_t i = 0; i < received_count; ++i) {
        const uint8_t *alpha = received[i].global;
        gf_elem_t y, mask;

        /* repeated labels */
        for (size_t l = 0; l < i; ++l)
            if (memcmp(alpha, received[l].global, p.a) == 0)
                goto done;

        pad0(&p, alpha, &xs[i]);

        gf_zero(&y);
        for (size_t s = 0; s < p.d; ++s)
            gf_set_symbol(&y, s, p.m, received[i].global[p.a + s] & (cfg->q - 1));

        prf_mask(&p, cfg, akey, alpha, &mask);
        gf_add(&p.F, &zs[i], &y, &mask);
    }

    if (gf_poly_interpolate(&p.F, coeffs, xs, zs, k) != 0)
        goto done;

    /* the last point is the check */
    gf_elem_t check;
    gf_poly_eval(&p.F, &check, coeffs, k, &xs[k]);

    if (!gf_equal(&p.F, &check, &zs[k]))
        goto done;

    for (size_t i = 0; i < k; ++i)
        for (size_t s = 0; s < p.d; ++s)
            amessage[i * p.d + s] = (uint8_t)gf_get_symbol(&coeffs[i], s, p.m);

    rc = 0;

done:
    free(xs);
    free(zs);
    free(coeffs);
    return rc;
}
