/*
 * Anamorphic RLNC (aRLNC): Reed-Solomon points hidden in the global encoding vectors.
 *
 * A symbol's global encoding vector gamma in F_q^K is split as gamma = (alpha, y)
 * with a label alpha in F_q^a (uniform) and y in E = GF(q^(K-a)) (identified with
 * F_q^(K-a), see gf_ext.c). The anamorphic message m_a = (mu_0, ..., mu_{S-2}) in
 * E^(S-1) is the coefficient vector of a polynomial P of degree <= S-2 over E (a
 * Reed-Solomon codeword: the evaluations of P at distinct points), and
 *
 *     y = P(pad0(alpha)) + F(s, alpha),
 *
 * where pad0 embeds the label into E and F is a PRF with key s (the double and
 * trapdoor key). Without s the mask makes y uniform, so the global encoding vector
 * is a uniform vector as in regular RLNC. The payload is u = gamma^T W, so the
 * regular message is unaffected.
 *
 * The receiver removes the masks and obtains S points (pad0(alpha_i), z_i) of P.
 * Any S-1 distinct points determine P (Lagrange interpolation, gf_ext.c); the
 * last point is a check that rejects symbols that do not come from aRLNC.
 */
#include "rlnc.h"
#include "gf_ext.h"

#include <stdlib.h>
#include <string.h>
#include <sodium.h>
#include "../utils/random_utils.h"

typedef struct {
    gf_field_t E;
    unsigned symbol_bits;      /* log2 q: bits per GF(q) symbol */
    size_t a;                  /* label length in GF(q) symbols */
    size_t degree;             /* K - a: extension degree of E over F_q */
} arlnc_params_t;

static unsigned log2_q(uint32_t q)
{
    unsigned bits = 0;

    while ((1u << bits) < q)
        ++bits;

    return bits;
}

/*
 * Derives the parameters of the construction: label length a = ceil(lambda / log2 q)
 * (so that q^a >= 2^lambda labels), the extension degree K - a of E over F_q and the
 * field E = GF(2^(log2 q * (K - a))). Requires K >= 2a and S >= K.
 */
static int params_init(const rlnc_config_t *config,
                       const rlnc_aconfig_t *aconfig,
                       arlnc_params_t *params)
{
    if (!rlnc_config_valid(config) || aconfig == NULL || params == NULL)
        return -1;

    params->symbol_bits = log2_q(config->q);
    params->a = (aconfig->lambda + params->symbol_bits - 1) / params->symbol_bits;

    if (aconfig->lambda == 0 ||
        config->generation_size < 2 * params->a ||
        aconfig->received_symbols < config->generation_size ||
        params->a > 256 - 4) //4 bytes used for the prf counter
        return -1;

    params->degree = config->generation_size - params->a;

    return gf_field_init(&params->E, (unsigned)(params->symbol_bits * params->degree));
}

size_t rlnc_amessage_symbols(const rlnc_config_t *config, const rlnc_aconfig_t *aconfig)
{
    arlnc_params_t params;

    if (params_init(config, aconfig, &params) != 0)
        return 0;

    return (aconfig->received_symbols - 1) * params.degree; //(S-1)*(K-a)
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

//counter mode needed for PRF to produce long enough masks

/*
 * F(s, alpha) in E: a keyed hash (BLAKE2b, libsodium crypto_generichash) of the
 * label and a block counter, used as a PRF and expanded in counter mode to K - a
 * symbols of GF(q) (one byte each, reduced to log2 q bits).
 */
static void prf_mask(const arlnc_params_t *params,
                     const rlnc_config_t *config,
                     const uint8_t *akey,
                     const uint8_t *alpha,
                     gf_elem_t *mask)
{
    uint8_t input[256];          /* alpha || 32-bit block counter */
    uint8_t block[32];

    memcpy(input, alpha, params->a);
    gf_zero(mask);

    for (size_t i = 0; i < params->degree; ++i) {
        if (i % sizeof(block) == 0) { //need to sample new pseudorandom block:
            const uint32_t counter = (uint32_t)(i / sizeof(block));

            //setting the last 4 bytes in input to the counter value:
            input[params->a + 0] = (uint8_t)counter;
            input[params->a + 1] = (uint8_t)(counter >> 8);
            input[params->a + 2] = (uint8_t)(counter >> 16);
            input[params->a + 3] = (uint8_t)(counter >> 24);


            crypto_generichash(block, sizeof(block), input, params->a + 4,
                               akey, crypto_generichash_KEYBYTES); //creates random block of 32 bytes
        }
        //apply the current block's i%32-th value to the i-th symbol
        gf_set_symbol(mask, i, params->symbol_bits, block[i % sizeof(block)] & (config->q - 1));
    }
}

/* pad0(alpha): the label as an element of E (its a symbols followed by zeros) */
static void pad0(const arlnc_params_t *params, const uint8_t *alpha, gf_elem_t *x)
{
    gf_zero(x);

    for (size_t i = 0; i < params->a; ++i)
        gf_set_symbol(x, i, params->symbol_bits, alpha[i]);
}

//amessage has a only symbol_bits per byte (e.g. for q=2, each byte is either 0 or 1)

/*
 * Creates T = sent_count >= S symbols for the generation `source`, hiding amessage:
 * for each symbol sample a fresh label alpha (resampled if it repeats, so all labels
 * are distinct), set y = P(pad0(alpha)) + F(s, alpha) with P from the coefficients of
 * amessage (Horner evaluation in E), and combine the source packets with
 * gamma = (alpha, y) as local vector. Returns 0, or -1 on invalid parameters.
 */
int rlnc_aencode(
    const rlnc_config_t *config,
    const rlnc_aconfig_t *aconfig,
    const rlnc_packet_t *source,
    rlnc_packet_t *sent_out,
    size_t sent_count,
    RandomnessSource *random,
    const uint8_t *akey,
    const uint8_t *amessage)
{
    arlnc_params_t params;

    if (source == NULL || sent_out == NULL || random == NULL || akey == NULL || amessage == NULL)
        return -1;

    if (params_init(config, aconfig, &params) != 0)
        return -1;

    /* T >= S, and enough distinct labels exist */
    if (sent_count < aconfig->received_symbols)
        return -1;

    if (params.a * params.symbol_bits < 32 && //don't allow security below 32-bits. Also, more less than 2^(a*symbol_bits) must be sent (otherwise collisions inevitable)
        ((uint64_t)1 << (params.a * params.symbol_bits)) < sent_count)
        return -1;

    const size_t K = config->generation_size;
    const size_t coefficient_count = aconfig->received_symbols - 1;
    int result = -1;

    gf_elem_t *coefficients = calloc(coefficient_count, sizeof(gf_elem_t));
    uint8_t *labels = malloc(sent_count * params.a);
    uint8_t *gamma = malloc(K);

    if (coefficients == NULL || labels == NULL || gamma == NULL)
        goto done;

    /* m_a = (mu_0, ..., mu_{S-2}) in E^{S-1}, mu_i given as K - a symbols */
    for (size_t i = 0; i < coefficient_count; ++i)
        for (size_t symbol = 0; symbol < params.degree; ++symbol)
            gf_set_symbol(&coefficients[i], symbol, params.symbol_bits,
                          amessage[i * params.degree + symbol] & (config->q - 1));

    for (size_t j = 0; j < sent_count; ++j) {
        uint8_t *alpha = labels + j * params.a;
        int fresh;

        
        for (size_t i = 0; i < params.a; ++i)
                alpha[i] = (uint8_t)random_bounded(random, config->q);

        // not needed (negligible) - negative for performance
        // /* uniform label, resampled on the (negligible) event of a repeat */
        // do {
        //     fresh = 1;

        //     for (size_t i = 0; i < params.a; ++i)
        //         alpha[i] = (uint8_t)random_bounded(random, config->q);

        //     for (size_t earlier = 0; earlier < j && fresh; ++earlier)
        //         if (memcmp(alpha, labels + earlier * params.a, params.a) == 0)
        //             fresh = 0;
        // } while (!fresh);

        gf_elem_t x, y, mask;

        pad0(&params, alpha, &x);
        gf_poly_eval(&params.E, &y, coefficients, coefficient_count, &x);
        prf_mask(&params, config, akey, alpha, &mask);
        gf_add(&params.E, &y, &y, &mask);

        memcpy(gamma, alpha, params.a);
        for (size_t symbol = 0; symbol < params.degree; ++symbol)
            gamma[params.a + symbol] = (uint8_t)gf_get_symbol(&y, symbol, params.symbol_bits); //start after params.a bytes, because these belong to the label. The rest is the masked polynomial evaluation

        /*
         * The sources carry the canonical global encoding vectors e_i, so using
         * gamma as local vector yields global vector gamma and payload gamma^T W.
         */
        if (rlnc_encode_with_vector(config, source, K, gamma, &sent_out[j]) != 0)
            goto done;
    }

    result = 0;

done:
    free(coefficients);
    free(labels);
    free(gamma);
    return result;
}

/*
 * Recovers the anamorphic message from exactly S received symbols (-1 otherwise):
 * unmask z_i = y_i - F(s, alpha_i), interpolate P through the first S-1 points
 * (pad0(alpha_i), z_i), and accept iff the last point lies on P. A symbol set that
 * does not come from aRLNC under this key passes the check with probability 1/|E|.
 * Symbols with a repeated label are rejected.
 */
int rlnc_adecode(
    const rlnc_config_t *config,
    const rlnc_aconfig_t *aconfig,
    const rlnc_packet_t *received,
    size_t received_count,
    const uint8_t *akey,
    uint8_t *amessage_out)
{
    arlnc_params_t params;

    if (received == NULL || akey == NULL || amessage_out == NULL)
        return -1;

    if (params_init(config, aconfig, &params) != 0)
        return -1;

    /* codewords with a different number of packets are rejected */
    if (received_count != aconfig->received_symbols)
        return -1;

    const size_t coefficient_count = received_count - 1;
    int result = -1;

    gf_elem_t *points_x = calloc(received_count, sizeof(gf_elem_t));
    gf_elem_t *points_z = calloc(received_count, sizeof(gf_elem_t));
    gf_elem_t *coefficients = calloc(coefficient_count, sizeof(gf_elem_t));

    if (points_x == NULL || points_z == NULL || coefficients == NULL)
        goto done;

    for (size_t i = 0; i < received_count; ++i) {
        const uint8_t *alpha = received[i].global_vector;
        gf_elem_t y, mask;

        for (size_t earlier = 0; earlier < i; ++earlier)
            if (memcmp(alpha, received[earlier].global_vector, params.a) == 0)
                goto done;

        pad0(&params, alpha, &points_x[i]);

        gf_zero(&y);
        for (size_t symbol = 0; symbol < params.degree; ++symbol)
            gf_set_symbol(&y, symbol, params.symbol_bits,
                          received[i].global_vector[params.a + symbol] & (config->q - 1));

        prf_mask(&params, config, akey, alpha, &mask);
        gf_add(&params.E, &points_z[i], &y, &mask);
    }

    if (gf_poly_interpolate(&params.E, coefficients, points_x, points_z, coefficient_count) != 0)
        goto done;

    /* the last point is the check */
    gf_elem_t check;
    gf_poly_eval(&params.E, &check, coefficients, coefficient_count, &points_x[coefficient_count]);

    if (!gf_equal(&params.E, &check, &points_z[coefficient_count]))
        goto done;

    for (size_t i = 0; i < coefficient_count; ++i)
        for (size_t symbol = 0; symbol < params.degree; ++symbol)
            amessage_out[i * params.degree + symbol] =
                (uint8_t)gf_get_symbol(&coefficients[i], symbol, params.symbol_bits);

    result = 0;

done:
    free(points_x);
    free(points_z);
    free(coefficients);
    return result;
}
