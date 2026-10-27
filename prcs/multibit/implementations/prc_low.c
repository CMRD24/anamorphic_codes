/*
 * PRC^ell_low: a PRC for messages of ell bits from a zero-bit PRC (the multi-bit
 * extension of Christ and Gunn, "Pseudorandom Error-Correcting Codes", CRYPTO
 * 2024, with one block per message bit).
 *
 * Encode(m): block i < ell is an encoding of the zero-bit PRC if m_i = 1 and a
 * uniform string if m_i = 0; block ell is always an encoding (the soundness
 * check). All gamma = ell + 1 blocks are concatenated and the bits are permuted
 * with a secret permutation. A uniform block is indistinguishable from an
 * encoding without the key, so the codeword is pseudorandom.
 *
 * Decode: undo the permutation, run the zero-bit decoder on every block (accepted
 * = bit 1) and require that the last block is accepted. The permutation is
 * harmless on a binary symmetric channel, which is permutation invariant.
 */

#include "prc_low.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/helpers.h"
#include "../../../utils/random_utils.h"


struct MBPRC_EncKey {
    ZBPRC_EncKey *underlying_key;
    size_t *permutation;           /* permutation[input position] = output position */
};

struct MBPRC_DecKey {
    ZBPRC_DecKey *underlying_key;
    size_t *inverse_permutation;   /* inverse_permutation[output position] = input position */
};


static size_t underlying_block_length(const PRCLow_Params *params)
{
    return zbprc_block_length(params->underlying);
}

/* gamma = ell + 1 blocks of the underlying PRC */
static size_t low_block_length(const void *params_ptr)
{
    const PRCLow_Params *params = params_ptr;

    return (params->ell + 1) * underlying_block_length(params);
}

static int valid_params(const PRCLow_Params *params)
{
    return params != NULL && params->underlying != NULL &&
           params->underlying->block_length != NULL && params->ell < SIZE_MAX &&
           underlying_block_length(params) <= SIZE_MAX / (params->ell + 1);
}

static void low_free_enc_key(const void *params_ptr, MBPRC_EncKey *enc_key)
{
    const PRCLow_Params *params = params_ptr;

    if (enc_key == NULL)
        return;

    if (enc_key->underlying_key != NULL)
        zbprc_free_enc_key(params->underlying, enc_key->underlying_key);

    free(enc_key->permutation);
    free(enc_key);
}

static void low_free_dec_key(const void *params_ptr, MBPRC_DecKey *dec_key)
{
    const PRCLow_Params *params = params_ptr;

    if (dec_key == NULL)
        return;

    if (dec_key->underlying_key != NULL)
        zbprc_free_dec_key(params->underlying, dec_key->underlying_key);

    free(dec_key->inverse_permutation);
    free(dec_key);
}

/* a key pair of the underlying PRC and a uniform permutation of the codeword bits */
static MBPRC_Keys *low_keygen(const void *params_ptr, RandomnessSource *random)
{
    const PRCLow_Params *params = params_ptr;

    if (!valid_params(params) || random == NULL || random->rng == NULL)
        return NULL;

    const size_t codeword_bits = low_block_length(params);
    MBPRC_Keys *keys = calloc(1, sizeof(*keys));
    ZBPRC_Keys *underlying_keys = NULL;

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (keys->enc == NULL || keys->dec == NULL)
        goto fail;

    underlying_keys = zbprc_keygen(params->underlying, random);

    if (underlying_keys == NULL)
        goto fail;

    keys->enc->underlying_key = underlying_keys->enc;
    keys->dec->underlying_key = underlying_keys->dec;
    free(underlying_keys);

    keys->enc->permutation = malloc(codeword_bits * sizeof(size_t));
    keys->dec->inverse_permutation = malloc(codeword_bits * sizeof(size_t));

    if (keys->enc->permutation == NULL || keys->dec->inverse_permutation == NULL)
        goto fail;

    random_permutation(random, keys->enc->permutation, codeword_bits);

    for (size_t i = 0; i < codeword_bits; ++i)
        keys->dec->inverse_permutation[keys->enc->permutation[i]] = i;

    return keys;

fail:
    low_free_enc_key(params, keys->enc);
    low_free_dec_key(params, keys->dec);
    free(keys);

    return NULL;
}


/*
 * The anamorphic part of an encoding (anamorphic lifting): the double key dk of
 * the regular instance, the encoding key of the extra instance sub, and the
 * anamorphic message (one bit a_i per block).
 */
typedef struct {
    const aZBPRC *aprc;
    const AZBPRC_DoubleKey *double_key;
    const ZBPRC_EncKey *sub_key;
    const uint8_t *amessage;
} LowAnamorphicPart;

/*
 * Block i of an encoding (table "lifting cases" of the thesis), where
 * x_i = 1 is an encoding of 1 under the regular instance and a_i = 1 an
 * embedded anamorphic message:
 *
 *               a_i = 0             a_i = 1
 *   x_i = 0     uniform             Encode(enc_key^sub)
 *   x_i = 1     Encode(enc_key)     aEncode(enc_key, dk)
 *
 * Returns a newly allocated block of block_bits bits, NULL on error.
 */
static uint8_t *encode_block(const PRCLow_Params *params,
                             const MBPRC_EncKey *enc_key,
                             const LowAnamorphicPart *anamorphic,
                             int x_i,
                             int a_i,
                             size_t block_bits,
                             RandomnessSource *random)
{
    uint8_t *block = NULL;
    size_t bits = 0;

    if (!x_i && !a_i) {
        block = malloc(bits_to_bytes(block_bits));

        if (block != NULL)
            random_bytes(random, block, bits_to_bytes(block_bits));

        return block;
    }

    if (x_i && a_i)
        block = zbprc_aencode(params->underlying, anamorphic->aprc, enc_key->underlying_key,
                              anamorphic->double_key, random, &bits);
    else if (a_i)
        block = zbprc_encode(params->underlying, anamorphic->sub_key, random, &bits);
    else
        block = zbprc_encode(params->underlying, enc_key->underlying_key, random, &bits);

    if (block != NULL && bits != block_bits) {
        free(block);
        return NULL;
    }

    return block;
}

/* Encodes the message, regularly (anamorphic == NULL) or with the anamorphic part. */
static uint8_t *encode(const PRCLow_Params *params,
                       const MBPRC_EncKey *enc_key,
                       const uint8_t *message,
                       size_t message_bits,
                       const LowAnamorphicPart *anamorphic,
                       RandomnessSource *random,
                       size_t *codeword_bits)
{
    if (!valid_params(params) || enc_key == NULL || message == NULL ||
        message_bits != params->ell || random == NULL || random->rng == NULL ||
        codeword_bits == NULL)
        return NULL;

    const size_t block_bits = underlying_block_length(params);
    const size_t total_bits = low_block_length(params);
    uint8_t *blocks = calloc(bits_to_bytes(total_bits), 1);
    uint8_t *codeword = calloc(bits_to_bytes(total_bits), 1);

    if (blocks == NULL || codeword == NULL)
        goto fail;

    for (size_t i = 0; i <= params->ell; ++i) {
        /* the last block is the soundness check: always an encoding of 1 */
        const int x_i = i == params->ell || get_bit(message, i) == 1;
        const int a_i = anamorphic != NULL && get_bit(anamorphic->amessage, i) == 1;
        uint8_t *block = encode_block(params, enc_key, anamorphic, x_i, a_i, block_bits,
                                      random);

        if (block == NULL)
            goto fail;

        copy_bits(blocks, i * block_bits, block, 0, block_bits);
        free(block);
    }

    for (size_t i = 0; i < total_bits; ++i)
        set_bit(codeword, enc_key->permutation[i], get_bit(blocks, i));

    free(blocks);
    *codeword_bits = total_bits;

    return codeword;

fail:
    free(blocks);
    free(codeword);

    return NULL;
}

static uint8_t *low_encode(const void *params_ptr,
                           const MBPRC_EncKey *enc_key,
                           const uint8_t *message,
                           size_t message_bits,
                           RandomnessSource *random,
                           size_t *codeword_bits)
{
    return encode(params_ptr, enc_key, message, message_bits, NULL, random, codeword_bits);
}

/*
 * Unnest: checks the length and undoes the permutation. Returns the gamma
 * concatenated blocks (newly allocated), NULL on error.
 */
static uint8_t *unnest(const PRCLow_Params *params,
                       const MBPRC_DecKey *dec_key,
                       const uint8_t *codeword,
                       size_t codeword_bits)
{
    if (!valid_params(params) || dec_key == NULL || codeword == NULL ||
        codeword_bits != low_block_length(params))
        return NULL;

    uint8_t *blocks = calloc(bits_to_bytes(codeword_bits), 1);

    if (blocks == NULL)
        return NULL;

    for (size_t i = 0; i < codeword_bits; ++i)
        set_bit(blocks, dec_key->inverse_permutation[i], get_bit(codeword, i));

    return blocks;
}

/*
 * Runs decide_block on every block i (copied to a buffer of its own) and writes
 * the answer as bit i of bits_out. Returns the number of blocks decided 1, or
 * -1 on error.
 */
typedef int (*BlockDecision)(const void *context, const uint8_t *block, size_t block_bits);

static long decide_blocks(const PRCLow_Params *params, const MBPRC_DecKey *dec_key,
                          const uint8_t *codeword, size_t codeword_bits,
                          BlockDecision decide_block, const void *context,
                          uint8_t *bits_out)
{
    const size_t block_bits = valid_params(params) ? underlying_block_length(params) : 0;
    uint8_t *blocks = unnest(params, dec_key, codeword, codeword_bits);
    uint8_t *block = calloc(bits_to_bytes(block_bits) + 1, 1);
    long ones = 0;

    if (blocks == NULL || block == NULL) {
        free(blocks);
        free(block);
        return -1;
    }

    for (size_t i = 0; i <= params->ell; ++i) {
        copy_bits(block, 0, blocks, i * block_bits, block_bits);

        const int bit = decide_block(context, block, block_bits) == 1;

        set_bit(bits_out, i, (uint8_t)bit);
        ones += bit;
    }

    free(block);
    free(blocks);

    return ones;
}

typedef struct {
    const PRCLow_Params *params;
    const MBPRC_DecKey *dec_key;
} RegularDecision;

static int regular_block_decision(const void *context, const uint8_t *block,
                                  size_t block_bits)
{
    const RegularDecision *decision = context;

    return zbprc_decode(decision->params->underlying, decision->dec_key->underlying_key,
                        block, block_bits);
}

/* blocks 0..ell-1 carry the message, the last one (block ell) must be accepted */
static int low_decode(const void *params_ptr,
                      const MBPRC_DecKey *dec_key,
                      const uint8_t *codeword,
                      size_t codeword_bits,
                      uint8_t *message_out,
                      size_t *message_bits_out)
{
    const PRCLow_Params *params = params_ptr;

    if (params == NULL || message_out == NULL || message_bits_out == NULL)
        return 0;

    const RegularDecision decision = {.params = params, .dec_key = dec_key};
    uint8_t *decoded = calloc(bits_to_bytes(params->ell + 1), 1);

    if (decoded == NULL)
        return 0;

    const int ok = decide_blocks(params, dec_key, codeword, codeword_bits,
                                 regular_block_decision, &decision, decoded) >= 0 &&
                   get_bit(decoded, params->ell) == 1;

    if (ok) {
        copy_bits(message_out, 0, decoded, 0, params->ell);
        *message_bits_out = params->ell;
    }

    free(decoded);

    return ok;
}

MBPRC prc_low(const PRCLow_Params *params)
{
    return (MBPRC){
        .params = params,
        .block_length = low_block_length,
        .keygen = low_keygen,
        .encode = low_encode,
        .decode = low_decode,
        .free_enc_key = low_free_enc_key,
        .free_dec_key = low_free_dec_key,
    };
}


/*
 * Anamorphic mode (anamorphic lifting).
 *
 * PRC^ell_low is a nested PRC with gamma = ell + 1 blocks and J = 1 instance of
 * the underlying zero-bit PRC. The anamorphic message has one bit per block
 * (ell + 1 bits); the all-zero message is excluded.
 */

struct AMBPRC_DoubleKey {
    AZBPRC_DoubleKey *double_key;       /* dk of the regular instance */
    ZBPRC_EncKey *sub;                  /* enc_key^sub */
};

struct AMBPRC_TrapdoorKey {
    AZBPRC_TrapdoorKey *trapdoor_key;   /* tk of the regular instance */
    ZBPRC_DecKey *sub;                  /* dec_key^sub */
};

static size_t alow_amessage_bits(const void *params_ptr, const void *aparams)
{
    const PRCLow_Params *params = params_ptr;

    (void)aparams;

    return params->ell + 1;
}

static void alow_free_double_key(const void *params_ptr, const void *aparams_ptr,
                                 AMBPRC_DoubleKey *double_key)
{
    const PRCLow_Params *params = params_ptr;
    const APRCLow_Params *aparams = aparams_ptr;

    if (double_key == NULL)
        return;

    zbprc_free_double_key(params->underlying, aparams->underlying_aprc, double_key->double_key);

    if (double_key->sub != NULL)
        zbprc_free_enc_key(params->underlying, double_key->sub);

    free(double_key);
}

static void alow_free_trapdoor_key(const void *params_ptr, const void *aparams_ptr,
                                   AMBPRC_TrapdoorKey *trapdoor_key)
{
    const PRCLow_Params *params = params_ptr;
    const APRCLow_Params *aparams = aparams_ptr;

    if (trapdoor_key == NULL)
        return;

    zbprc_free_trapdoor_key(params->underlying, aparams->underlying_aprc,
                            trapdoor_key->trapdoor_key);

    if (trapdoor_key->sub != NULL)
        zbprc_free_dec_key(params->underlying, trapdoor_key->sub);

    free(trapdoor_key);
}

/* aKeyGen: a fresh instance sub and (dk, tk) <- aKeyGen^0 for the regular instance */
static AMBPRC_Keys *alow_akeygen(const void *params_ptr, const void *aparams_ptr,
                                 MBPRC_Keys *regular_keys, RandomnessSource *random)
{
    const PRCLow_Params *params = params_ptr;
    const APRCLow_Params *aparams = aparams_ptr;

    if (!valid_params(params) || aparams == NULL || aparams->underlying_aprc == NULL ||
        regular_keys == NULL || random == NULL)
        return NULL;

    AMBPRC_Keys *akeys = calloc(1, sizeof(*akeys));
    ZBPRC_Keys *sub_keys = NULL;
    AZBPRC_Keys *underlying_akeys = NULL;

    if (akeys == NULL)
        return NULL;

    akeys->double_key = calloc(1, sizeof(*akeys->double_key));
    akeys->trapdoor_key = calloc(1, sizeof(*akeys->trapdoor_key));

    if (akeys->double_key == NULL || akeys->trapdoor_key == NULL)
        goto fail;

    sub_keys = zbprc_keygen(params->underlying, random);

    if (sub_keys == NULL)
        goto fail;

    akeys->double_key->sub = sub_keys->enc;
    akeys->trapdoor_key->sub = sub_keys->dec;
    free(sub_keys);

    ZBPRC_Keys underlying_keys = {
        .enc = regular_keys->enc->underlying_key,
        .dec = regular_keys->dec->underlying_key,
    };

    underlying_akeys = zbprc_akeygen(params->underlying, aparams->underlying_aprc,
                                     &underlying_keys, random);

    if (underlying_akeys == NULL)
        goto fail;

    akeys->double_key->double_key = underlying_akeys->double_key;
    akeys->trapdoor_key->trapdoor_key = underlying_akeys->trapdoor_key;
    free(underlying_akeys);//ok, because underlying_akeys does not own dk & tk

    return akeys;

fail:
    alow_free_double_key(params, aparams, akeys->double_key);
    alow_free_trapdoor_key(params, aparams, akeys->trapdoor_key);
    free(akeys);

    return NULL;
}

static uint8_t *alow_aencode(const void *params_ptr,
                             const void *aparams_ptr,
                             const MBPRC_EncKey *enc_key,
                             const AMBPRC_DoubleKey *double_key,
                             const uint8_t *message,
                             size_t message_bits,
                             const uint8_t *amessage,
                             RandomnessSource *random,
                             size_t *codeword_bits)
{
    const PRCLow_Params *params = params_ptr;
    const APRCLow_Params *aparams = aparams_ptr;
    int nonzero = 0;

    if (params == NULL || aparams == NULL || double_key == NULL || amessage == NULL)
        return NULL;

    for (size_t i = 0; i <= params->ell; ++i)
        nonzero |= get_bit(amessage, i);//bitwise xor to check if at least one "1" in anamorphic message

    /* the all-zero message means "no anamorphic message" */
    if (!nonzero)
        return NULL;

    const LowAnamorphicPart anamorphic = {
        .aprc = aparams->underlying_aprc,
        .double_key = double_key->double_key,
        .sub_key = double_key->sub,
        .amessage = amessage,
    };

    return encode(params, enc_key, message, message_bits, &anamorphic, random,
                  codeword_bits);
}

typedef struct {
    const PRCLow_Params *params;
    const APRCLow_Params *aparams;
    const MBPRC_DecKey *dec_key;
    const AMBPRC_TrapdoorKey *trapdoor_key;
} AnamorphicDecision;

/* r_i = 1 iff aDecode^0 of the regular instance or Decode^0 of sub accepts */
static int anamorphic_block_decision(const void *context, const uint8_t *block,
                                     size_t block_bits)
{
    const AnamorphicDecision *decision = context;
    const ZBPRC *underlying = decision->params->underlying;

    return zbprc_adecode(underlying, decision->aparams->underlying_aprc,
                         decision->dec_key->underlying_key,
                         decision->trapdoor_key->trapdoor_key, block, block_bits) == 1 ||
           zbprc_decode(underlying, decision->trapdoor_key->sub, block, block_bits) == 1;
}

static int alow_adecode(const void *params_ptr,
                        const void *aparams_ptr,
                        const MBPRC_DecKey *dec_key,
                        const AMBPRC_TrapdoorKey *trapdoor_key,
                        const uint8_t *codeword,
                        size_t codeword_bits,
                        uint8_t *amessage_out)
{
    const AnamorphicDecision decision = {
        .params = params_ptr,
        .aparams = aparams_ptr,
        .dec_key = dec_key,
        .trapdoor_key = trapdoor_key,
    };

    if (decision.params == NULL || decision.aparams == NULL || trapdoor_key == NULL ||
        amessage_out == NULL)
        return 0;

    /* the all-zero result means "no anamorphic message" */
    return decide_blocks(decision.params, dec_key, codeword, codeword_bits,
                         anamorphic_block_decision, &decision, amessage_out) > 0;
}

aMBPRC aprc_low(const APRCLow_Params *aparams)
{
    return (aMBPRC){
        .aparams = aparams,
        .amessage_bits = alow_amessage_bits,
        .akeygen = alow_akeygen,
        .aencode = alow_aencode,
        .adecode = alow_adecode,
        .free_double_key = alow_free_double_key,
        .free_trapdoor_key = alow_free_trapdoor_key,
    };
}
