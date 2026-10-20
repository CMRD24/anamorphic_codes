#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>

#include "aprc_rr.h"
#include "rr_core.h"

static RRShape shape_of(const aZBPRC_RR_Params *aparams)
{
    return (RRShape){
        .seed_len = aparams->seed_len,
        .indication_len = aparams->indication_len,
        .mu = aparams->mu,
    };
}

static APRC_RR_Keys *akeygen(
    const aZBPRC_RR_Params *aparams,
    RandomnessSource *random)
{
    (void)aparams;
    (void)random;

    return rr_akeygen();
}

static void akeygen_free(const aZBPRC_RR_Params *aparams, APRC_RR_Keys *keys)
{
    (void)aparams;

    rr_akey_free(keys);
}

/*
 * Anamorphic encoding.
 *
 * ana_message: rr_message_bytes() bytes.
 * output_bits: number of bits per returned codeword.
 *
 * Returns an array of mu codewords, each encoding the bit 1 with one of the
 * seeds from rr_build_seeds(); NULL on error.
 */
static uint8_t **aencode(
    const aZBPRC_RR_Params *aparams,
    const ZBPRC_EncKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *ana_message,
    RandomnessSource *random,
    size_t *output_bits)
{
    if (aparams == NULL || output_bits == NULL ||
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

/* Returns 1 and the anamorphic message on success, 0 otherwise. */
static int adecode(
    const aZBPRC_RR_Params *aparams,
    const ZBPRC_DecKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *const *codewords,
    size_t ciphertext_bits,
    uint8_t *ana_message)
{
    if (aparams == NULL || codewords == NULL ||
        aparams->prc_rr == NULL || aparams->prc_rr->decode_ws == NULL)
        return 0;

    const RRShape shape = shape_of(aparams);
    const size_t seed_bytes = rr_seed_bytes(&shape);

    if (rr_message_bytes(&shape) == 0)
        return 0;

    uint8_t *seeds = calloc(aparams->mu, seed_bytes);

    if (seeds == NULL)
        return 0;

    int ok = 1;

    /* recover r_i from every regular codeword */
    for (size_t i = 0; ok && i < aparams->mu; i++) {
        ok = aparams->prc_rr->decode_ws(
            aparams->prc_rr->base.params,
            reg_key,
            codewords[i],
            ciphertext_bits,
            seeds + i * seed_bytes);
    }

    ok = ok && rr_open_seeds(&shape, dkey, seeds, ana_message) == 0;

    sodium_memzero(seeds, aparams->mu * seed_bytes);
    free(seeds);

    return ok;
}

aZBPRC_RR aZBPRC_RR_init(const aZBPRC_RR_Params *aparams)
{
    aZBPRC_RR result = {
        .adecode = adecode,
        .aencode = aencode,
        .akeygen = akeygen,
        .free_akey = akeygen_free,
        .aparams = aparams
    };
    return result;
}
