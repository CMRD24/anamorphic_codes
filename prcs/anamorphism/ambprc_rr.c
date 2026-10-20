#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#include "aprc_rr.h"
#include "rr_core.h"

static RRShape shape_of(const aMBPRC_RR_Params *aparams)
{
    return (RRShape){
        .seed_len = aparams->seed_len,
        .indication_len = aparams->indication_len,
        .mu = aparams->mu,
    };
}

static APRC_RR_Keys *akeygen(
    const aMBPRC_RR_Params *aparams,
    RandomnessSource *random)
{
    (void)aparams;

    return rr_akeygen(random);
}

static void akeygen_free(const void *params, const void *aparams, APRC_RR_Keys *keys)
{
    (void)params;
    (void)aparams;

    rr_akey_free(keys);
}

/*
 * Anamorphic encoding.
 *
 * reg_messages: mu regular messages of reg_message_bits bits each.
 * ana_message: rr_message_bytes() bytes.
 * output_bits: number of bits per returned codeword.
 *
 * Returns an array of mu codewords, the i-th one encoding reg_messages[i]
 * with the i-th seed from rr_build_seeds(); NULL on error.
 */
static uint8_t **aencode(
    const aMBPRC_RR_Params *aparams,
    const MBPRC_EncKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t **reg_messages,
    size_t reg_message_bits,
    const uint8_t *ana_message,
    RandomnessSource *random,
    size_t *output_bits)
{
    if (aparams == NULL || reg_messages == NULL || output_bits == NULL ||
        aparams->prc_rr == NULL || aparams->prc_rr->encode_ws == NULL)
        return NULL;

    const RRShape shape = shape_of(aparams);
    const size_t seed_bytes = rr_seed_bytes(&shape);

    uint8_t *seeds = rr_build_seeds(&shape, dkey, ana_message, random);

    if (seeds == NULL)
        return NULL;

    uint8_t **codewords = calloc(aparams->mu, sizeof(*codewords));
    size_t codeword_bits = 0;
    int ok = codewords != NULL;

    for (size_t i = 0; ok && i < aparams->mu; i++) {
        size_t current_bits = 0;

        codewords[i] = aparams->prc_rr->encode_ws(
            aparams->prc_rr->base.params,
            reg_key,
            reg_messages[i],
            reg_message_bits,
            random,
            &current_bits,
            seeds + i * seed_bytes);

        /* all codewords must have the same length */
        if (codewords[i] == NULL || (i > 0 && current_bits != codeword_bits))
            ok = 0;

        codeword_bits = current_bits;
    }

    sodium_memzero(seeds, aparams->mu * seed_bytes);
    free(seeds);

    if (!ok) {
        rr_free_codewords(codewords, aparams->mu);
        return NULL;
    }

    *output_bits = codeword_bits;

    return codewords;
}

/*
 * Returns 1 and the anamorphic message on success, 0 otherwise.
 * reg_message_bits is only needed to size the buffer for the regular
 * messages, which adecode discards.
 */
static int adecode(
    const aMBPRC_RR_Params *aparams,
    const MBPRC_DecKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *const *codewords,
    size_t ciphertext_bits,
    uint8_t *ana_message,
    size_t reg_message_bits)
{
    if (aparams == NULL || codewords == NULL ||
        aparams->prc_rr == NULL || aparams->prc_rr->decode_ws == NULL)
        return 0;

    const RRShape shape = shape_of(aparams);
    const size_t seed_bytes = rr_seed_bytes(&shape);

    if (rr_message_bytes(&shape) == 0)
        return 0;

    uint8_t *seeds = calloc(aparams->mu, seed_bytes);
    uint8_t *reg_message = calloc(1, (reg_message_bits + 7) / 8);

    int ok = seeds != NULL && reg_message != NULL;

    /* recover r_i from every regular codeword */
    for (size_t i = 0; ok && i < aparams->mu; i++) {
        size_t reg_bits_out = 0;

        ok = aparams->prc_rr->decode_ws(
            aparams->prc_rr->base.params,
            reg_key,
            codewords[i],
            ciphertext_bits,
            reg_message,
            &reg_bits_out,
            seeds + i * seed_bytes);
    }

    ok = ok && rr_open_seeds(&shape, dkey, seeds, ana_message) == 0;

    if (seeds != NULL)
        sodium_memzero(seeds, aparams->mu * seed_bytes);
    free(seeds);
    free(reg_message);

    return ok;
}

aMBPRC_RR aMBPRC_RR_init(const aMBPRC_RR_Params *aparams)
{
    aMBPRC_RR result = {
        .adecode = adecode,
        .aencode = aencode,
        .akeygen = akeygen,
        .free_akey = akeygen_free,
        .aparams = aparams
    };
    return result;
}
