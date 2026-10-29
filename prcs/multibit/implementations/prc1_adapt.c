/*
 * PRC^1_adapt: a one-bit PRC from two independent instances of a zero-bit PRC
 *
 * Encode(m): encode 1 with instance m. Decode: run the zero-bit decoder of both
 * instances; exactly one must accept and its index is the bit. Each instance
 * alone sees a pseudorandom word, and a word accepted by no or by both
 * instances is rejected.
 */

#include "prc1_adapt.h"

#include <stdlib.h>
#include <string.h>

#define INSTANCES 2      /* J */

struct MBPRC_EncKey {
    ZBPRC_EncKey *instance[INSTANCES];
};

struct MBPRC_DecKey {
    ZBPRC_DecKey *instance[INSTANCES];
};


static size_t adapt_block_length(const void *params_ptr)
{
    const PRC1AdaptParams *params = params_ptr;

    return zbprc_block_length(params->underlying_prc);
}

static void adapt_free_enc_key(const void *params_ptr, MBPRC_EncKey *enc_key)
{
    const PRC1AdaptParams *params = params_ptr;

    if (enc_key == NULL)
        return;

    for (int j = 0; j < INSTANCES; ++j) {
        if (enc_key->instance[j] != NULL)
            zbprc_free_enc_key(params->underlying_prc, enc_key->instance[j]);
    }

    free(enc_key);
}

static void adapt_free_dec_key(const void *params_ptr, MBPRC_DecKey *dec_key)
{
    const PRC1AdaptParams *params = params_ptr;

    if (dec_key == NULL)
        return;

    for (int j = 0; j < INSTANCES; ++j) {
        if (dec_key->instance[j] != NULL)
            zbprc_free_dec_key(params->underlying_prc, dec_key->instance[j]);
    }

    free(dec_key);
}

/* two independent key pairs of the underlying PRC */
static MBPRC_Keys *adapt_keygen(const void *params_ptr, RandomnessSource *random)
{
    const PRC1AdaptParams *params = params_ptr;

    if (params == NULL || params->underlying_prc == NULL || random == NULL ||
        random->rng == NULL)
        return NULL;

    MBPRC_Keys *keys = calloc(1, sizeof(*keys));

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    for (int j = 0; keys->enc != NULL && keys->dec != NULL && j < INSTANCES; ++j) {
        ZBPRC_Keys *instance_keys = zbprc_keygen(params->underlying_prc, random);

        if (instance_keys == NULL)
            break;

        keys->enc->instance[j] = instance_keys->enc;
        keys->dec->instance[j] = instance_keys->dec;
        free(instance_keys);
    }

    if (keys->enc == NULL || keys->dec == NULL ||
        keys->enc->instance[INSTANCES - 1] == NULL) {
        adapt_free_enc_key(params, keys->enc);
        adapt_free_dec_key(params, keys->dec);
        free(keys);
        return NULL;
    }

    return keys;
}

/* the message is one bit m; the codeword is an encoding of 1 under instance m */
static uint8_t *adapt_encode(const void *params_ptr,
                             const MBPRC_EncKey *enc_key,
                             const uint8_t *message,
                             size_t message_bits,
                             RandomnessSource *random,
                             size_t *codeword_bits)
{
    const PRC1AdaptParams *params = params_ptr;

    if (params == NULL || params->underlying_prc == NULL || enc_key == NULL ||
        message == NULL || message_bits != 1 || random == NULL || codeword_bits == NULL)
        return NULL;

    return zbprc_encode(params->underlying_prc, enc_key->instance[message[0] & 1u], random,
                        codeword_bits);
}


static int adapt_decode(const void *params_ptr,
                        const MBPRC_DecKey *dec_key,
                        const uint8_t *codeword,
                        size_t codeword_bits,
                        uint8_t *message_out,
                        size_t *message_bits_out)
{
    const PRC1AdaptParams *params = params_ptr;

    if (params == NULL || params->underlying_prc == NULL || dec_key == NULL ||
        codeword == NULL || message_out == NULL || message_bits_out == NULL)
        return 0;

    const int accepted0 = zbprc_decode(params->underlying_prc, dec_key->instance[0],
                                       codeword, codeword_bits) == 1;
    const int accepted1 = zbprc_decode(params->underlying_prc, dec_key->instance[1],
                                       codeword, codeword_bits) == 1;

    /* exactly one instance must accept */
    if (accepted0 == accepted1)
        return 0;

    message_out[0] = (uint8_t)accepted1;
    *message_bits_out = 1;

    return 1;
}

MBPRC prc1_adapt(const PRC1AdaptParams *params)
{
    return (MBPRC){
        .params = params,
        .block_length = adapt_block_length,
        .keygen = adapt_keygen,
        .encode = adapt_encode,
        .decode = adapt_decode,
        .free_enc_key = adapt_free_enc_key,
        .free_dec_key = adapt_free_dec_key,
    };
}


/*
 * Anamorphic mode (anamorphic lifting).
 *
 * PRC^1_adapt is a nested PRC with one block (gamma = 1) and J = 2 instances of
 * the underlying zero-bit PRC: Plan(m) = ((m, 1), -), i.e. the block is an
 * encoding of 1 under instance m. The block is never uniform, so the extra
 * instance `sub` of the lifting construction is only used by the decoder.
 *
 * The anamorphic message space is {1}: the all-bottom message is excluded.
 */

struct AMBPRC_DoubleKey {
    AZBPRC_DoubleKey *instance[INSTANCES];   /* dk_j */
    ZBPRC_EncKey *sub;                       /* enc_key^sub */
};

struct AMBPRC_TrapdoorKey {
    AZBPRC_TrapdoorKey *instance[INSTANCES]; /* tk_j */
    ZBPRC_DecKey *sub;                       /* dec_key^sub */
};

static size_t aadapt_amessage_bits(const void *params, const void *aparams)
{
    (void)params;
    (void)aparams;

    return 1;
}

static void aadapt_free_double_key(const void *params_ptr, const void *aparams_ptr,
                                   AMBPRC_DoubleKey *double_key)
{
    const PRC1AdaptParams *params = params_ptr;
    const APRC1AdaptParams *aparams = aparams_ptr;

    if (double_key == NULL)
        return;

    for (int j = 0; j < INSTANCES; ++j)
        zbprc_free_double_key(params->underlying_prc, aparams->underlying_aprc,
                              double_key->instance[j]);

    if (double_key->sub != NULL)
        zbprc_free_enc_key(params->underlying_prc, double_key->sub);

    free(double_key);
}

static void aadapt_free_trapdoor_key(const void *params_ptr, const void *aparams_ptr,
                                     AMBPRC_TrapdoorKey *trapdoor_key)
{
    const PRC1AdaptParams *params = params_ptr;
    const APRC1AdaptParams *aparams = aparams_ptr;

    if (trapdoor_key == NULL)
        return;

    for (int j = 0; j < INSTANCES; ++j)
        zbprc_free_trapdoor_key(params->underlying_prc, aparams->underlying_aprc,
                                trapdoor_key->instance[j]);

    if (trapdoor_key->sub != NULL)
        zbprc_free_dec_key(params->underlying_prc, trapdoor_key->sub);

    free(trapdoor_key);
}

/* aKeyGen: a fresh instance `sub` and (dk_j, tk_j) <- aKeyGen^0 for both instances */
static AMBPRC_Keys *aadapt_akeygen(const void *params_ptr, const void *aparams_ptr,
                                   MBPRC_Keys *regular_keys, RandomnessSource *random)
{
    const PRC1AdaptParams *params = params_ptr;
    const APRC1AdaptParams *aparams = aparams_ptr;

    if (params == NULL || aparams == NULL || params->underlying_prc == NULL ||
        aparams->underlying_aprc == NULL || regular_keys == NULL || random == NULL)
        return NULL;

    AMBPRC_Keys *akeys = calloc(1, sizeof(*akeys));
    ZBPRC_Keys *sub_keys = NULL;

    if (akeys == NULL)
        return NULL;

    akeys->double_key = calloc(1, sizeof(*akeys->double_key));
    akeys->trapdoor_key = calloc(1, sizeof(*akeys->trapdoor_key));

    if (akeys->double_key == NULL || akeys->trapdoor_key == NULL)
        goto fail;

    sub_keys = zbprc_keygen(params->underlying_prc, random);

    if (sub_keys == NULL)
        goto fail;

    akeys->double_key->sub = sub_keys->enc;
    akeys->trapdoor_key->sub = sub_keys->dec;
    free(sub_keys);

    for (int j = 0; j < INSTANCES; ++j) {
        ZBPRC_Keys instance_keys = {
            .enc = regular_keys->enc->instance[j],
            .dec = regular_keys->dec->instance[j],
        };
        AZBPRC_Keys *instance_akeys = zbprc_akeygen(params->underlying_prc,
                                                    aparams->underlying_aprc,
                                                    &instance_keys, random);

        if (instance_akeys == NULL)
            goto fail;

        akeys->double_key->instance[j] = instance_akeys->double_key;
        akeys->trapdoor_key->instance[j] = instance_akeys->trapdoor_key;
        free(instance_akeys);
    }

    return akeys;

fail:
    aadapt_free_double_key(params, aparams, akeys->double_key);
    aadapt_free_trapdoor_key(params, aparams, akeys->trapdoor_key);
    free(akeys);

    return NULL;
}

/* aEncode^0 under instance m; the anamorphic message must be 1 */
static uint8_t *aadapt_aencode(const void *params_ptr,
                               const void *aparams_ptr,
                               const MBPRC_EncKey *enc_key,
                               const AMBPRC_DoubleKey *double_key,
                               const uint8_t *message,
                               size_t message_bits,
                               const uint8_t *amessage,
                               RandomnessSource *random,
                               size_t *codeword_bits)
{
    const PRC1AdaptParams *params = params_ptr;
    const APRC1AdaptParams *aparams = aparams_ptr;

    if (params == NULL || aparams == NULL || enc_key == NULL || double_key == NULL ||
        message == NULL || message_bits != 1 || amessage == NULL || (amessage[0] & 1u) == 0 ||
        random == NULL || codeword_bits == NULL)
        return NULL;

    const int j = message[0] & 1u;

    return zbprc_aencode(params->underlying_prc, aparams->underlying_aprc,
                         enc_key->instance[j], double_key->instance[j], random,
                         codeword_bits);
}

/* aDecode: aDecode^0 of both instances, then Decode^0 with dec_key^sub */
static int aadapt_adecode(const void *params_ptr,
                          const void *aparams_ptr,
                          const MBPRC_DecKey *dec_key,
                          const AMBPRC_TrapdoorKey *trapdoor_key,
                          const uint8_t *codeword,
                          size_t codeword_bits,
                          uint8_t *amessage_out)
{
    const PRC1AdaptParams *params = params_ptr;
    const APRC1AdaptParams *aparams = aparams_ptr;
    int present = 0;

    if (params == NULL || aparams == NULL || dec_key == NULL || trapdoor_key == NULL ||
        codeword == NULL || amessage_out == NULL)
        return 0;

    for (int j = 0; j < INSTANCES && !present; ++j)
        present = zbprc_adecode(params->underlying_prc, aparams->underlying_aprc,
                                dec_key->instance[j], trapdoor_key->instance[j],
                                codeword, codeword_bits) == 1;

    present = present ||
        zbprc_decode(params->underlying_prc, trapdoor_key->sub, codeword, codeword_bits) == 1;

    if (present)
        amessage_out[0] = 1;

    return present;
}

aMBPRC aprc1_adapt(const APRC1AdaptParams *aparams)
{
    return (aMBPRC){
        .aparams = aparams,
        .amessage_bits = aadapt_amessage_bits,
        .akeygen = aadapt_akeygen,
        .aencode = aadapt_aencode,
        .adecode = aadapt_adecode,
        .free_double_key = aadapt_free_double_key,
        .free_trapdoor_key = aadapt_free_trapdoor_key,
    };
}
