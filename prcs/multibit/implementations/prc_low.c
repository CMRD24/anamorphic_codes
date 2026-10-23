/*
 * PRC_low: a PRC for messages of ell bits from a zero-bit PRC (the multi-bit
 * extension of Christ and Gunn, "Pseudorandom Error-Correcting Codes", CRYPTO
 * 2024, with one block per message bit).
 *
 * Encode(m): block i < ell is an encoding of the zero-bit PRC if m_i = 1 and a
 * uniform string if m_i = 0; block ell is always an encoding (the soundness
 * check). All ell + 1 blocks are concatenated and the bits are permuted with a
 * secret permutation. A uniform block is indistinguishable from an encoding
 * without the key, so the codeword is pseudorandom.
 *
 * Decode: undo the permutation, run the zero-bit decoder on every block (accepted
 * = bit 1) and require that the last block is accepted. The permutation is
 * harmless on a binary symmetric channel, which is permutation invariant.
 */

#include "prc_low.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include "../../../utils/random_utils.h"
#include "../../../utils/helpers.h"


/*
 * ================================================================
 * Concrete key types
 * ================================================================
 */

struct PRCLow_EncKey {

    ZBPRC_EncKey *underlying_key;

    /*
     * pi[i] gives the output position of input bit i.
     *
     * Both arrays contain positions in [0, total_bits).
     */
    size_t *pi;

    size_t total_bits;
};


struct PRCLow_DecKey {

    ZBPRC_DecKey *underlying_key;

    /*
     * Inverse permutation.
     *
     * pi_inv[j] is the input bit that appears at output position j.
     */
    size_t *pi_inv;

    size_t total_bits;
};


static size_t *
invert_permutation(
    const size_t *pi,
    size_t n)
{
    size_t *pi_inv =
        malloc(n * sizeof(*pi_inv));

    if (!pi_inv)
        return NULL;

    for (size_t i = 0;
         i < n;
         ++i)
    {
        if (pi[i] >= n) {

            free(pi_inv);
            return NULL;
        }

        pi_inv[pi[i]] = i;
    }

    return pi_inv;
}


/*
 * ================================================================
 * Random bits
 * ================================================================
 */

static int
fill_random_bits(
    RandomnessSource *random,
    uint8_t *out,
    size_t bits)
{
    size_t bytes =
        bits_to_bytes(bits);

    if (!random ||
        !random->rng ||
        !out)
    {
        return 0;
    }

    if (!random->rng(
            random->ctx,
            out,
            bytes))
    {
        return 0;
    }

    /*
     * Clear unused trailing bits.
     */
    if (bits % 8 != 0) {

        uint8_t mask =
            (uint8_t)((1u << (bits % 8)) - 1u);

        out[bytes - 1] &= mask;
    }

    return 1;
}


size_t prc_low_blocklength(const void *void_params)
{
    const PRCLow_Params *params =
        void_params;

    return (params->ell + 1)* params->underlying->blocksize(params->underlying->params);
}


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static MBPRC_Keys *
prc_low_keygen(
    const void *void_params,
    RandomnessSource *random)
{
    const PRCLow_Params *params =
        void_params;


    if (!params ||
        !params->underlying ||
        !params->underlying->keygen ||
        !params->underlying->free_enc_key ||
        !params->underlying->free_dec_key ||
        !random ||
        !random->rng ||
        !params->underlying->blocksize ||
        params->ell == SIZE_MAX)
    {
        return NULL;
    }

    size_t blocksize_bits = params->underlying->blocksize(params->underlying->params);

    size_t blocks =
        params->ell + 1;

    if (blocksize_bits >
        SIZE_MAX / blocks)
    {
        return NULL;
    }

    size_t total_bits =
        blocksize_bits * blocks;


    ZBPRC_Keys *underlying_keys =
        zbprc_keygen(
            params->underlying,
            random
        );

    if (!underlying_keys)
        return NULL;

    PRCLow_EncKey *enc =
        calloc(1, sizeof(*enc));

    PRCLow_DecKey *dec =
        calloc(1, sizeof(*dec));

    if (!enc || !dec) {

        free(enc);
        free(dec);

        zbprc_free_keys(
            params->underlying,
            underlying_keys
        );

        return NULL;
    }

    enc->underlying_key =
        underlying_keys->enc;

    dec->underlying_key =
        underlying_keys->dec;

    /*
     * Ownership of the individual keys was transferred.
     */
    underlying_keys->enc = NULL;
    underlying_keys->dec = NULL;

    free(underlying_keys);

    enc->pi =
        malloc(total_bits * sizeof(*enc->pi));

    if (!enc->pi)
        goto failure;

    random_permutation(
            random,
            enc->pi,
            total_bits);

    dec->pi_inv =
        invert_permutation(
            enc->pi,
            total_bits);

    if (!dec->pi_inv)
        goto failure;

    enc->total_bits =
        total_bits;

    dec->total_bits =
        total_bits;

    MBPRC_Keys *keys =
        malloc(sizeof(*keys));

    if (!keys)
        goto failure;

    keys->enc =
        (MBPRC_EncKey *)enc;

    keys->dec =
        (MBPRC_DecKey *)dec;

    return keys;


failure:

    if (enc) {

        free(enc->pi);

        if (enc->underlying_key) {
            zbprc_free_enc_key(
                params->underlying,
                enc->underlying_key
            );
        }

        free(enc);
    }

    if (dec) {

        free(dec->pi_inv);

        if (dec->underlying_key) {
            zbprc_free_dec_key(
                params->underlying,
                dec->underlying_key
            );
        }

        free(dec);
    }

    return NULL;
}


/*
 * ================================================================
 * Block layout
 * ================================================================
 *
 * The codeword consists of ell + 1 blocks of the underlying zero-bit PRC:
 * block i < ell encodes the message bit i (an encoding of 1 if the bit is 1,
 * a uniform string if it is 0), the last block is an encoding of 1 that serves
 * as soundness check. The blocks are concatenated and permuted bitwise.
 */

typedef struct {
    const aZBPRC *aprc;
    const APRC_EncKey *dk;       /* anamorphic key of the regular instance */
    const ZBPRC_EncKey *sub;     /* key of the independent instance */
    const uint8_t *amessage;    /* ell + 1 bits, LSB first */
} LowAnamorphicEncoding;

/*
 * Block i of an encoding. `regular_one` is x_i = 1 (an encoding of 1 under the
 * regular key), `hidden` is a_i = 1 (anamorphic message embedded):
 *
 *               not hidden          hidden
 *   x_i = 0     uniform             Encode(sub key, 1)
 *   x_i = 1     Encode(key, 1)      aEncode(key, dk, 1, 1)
 *
 * Returns a newly allocated block of block_bits bits, NULL on error.
 */
static uint8_t *
low_encode_block(
    const PRCLow_Params *params,
    const PRCLow_EncKey *key,
    const LowAnamorphicEncoding *ana,
    int regular_one,
    int hidden,
    size_t block_bits,
    RandomnessSource *random)
{
    uint8_t *block = NULL;
    size_t bits = 0;

    if (!regular_one && !hidden) {
        block = calloc(bits_to_bytes(block_bits), 1);

        if (block && !fill_random_bits(random, block, block_bits)) {
            free(block);
            return NULL;
        }

        return block;
    }

    if (regular_one && hidden) {
        block = zbprc_aencode(params->underlying, ana->aprc,
                              key->underlying_key, ana->dk,
                              random, &bits);
    } else if (hidden) {
        block = zbprc_encode(params->underlying, ana->sub, random, &bits);
    } else {
        block = zbprc_encode(params->underlying, key->underlying_key, random, &bits);
    }

    if (block && bits != block_bits) {
        free(block);
        return NULL;
    }

    return block;
}

/*
 * Encodes the message (ana == NULL: regularly; otherwise with the anamorphic
 * message embedded).
 */
static uint8_t *
low_encode(
    const PRCLow_Params *params,
    const PRCLow_EncKey *key,
    const uint8_t *message,
    size_t message_bits,
    const LowAnamorphicEncoding *ana,
    RandomnessSource *random,
    size_t *output_bits)
{
    if (!params || !key || !message || !random || !random->rng || !output_bits)
        return NULL;

    if (message_bits != params->ell)
        return NULL;

    if (!params->underlying || !params->underlying->encode)
        return NULL;

    const size_t block_bits =
        params->underlying->blocksize(params->underlying->params);
    const size_t blocks = params->ell + 1;
    const size_t total_bits = key->total_bits;

    if (total_bits != block_bits * blocks)
        return NULL;

    const size_t total_bytes = bits_to_bytes(total_bits);
    uint8_t *unpermuted = calloc(total_bytes, 1);
    uint8_t *ciphertext = calloc(total_bytes, 1);

    if (!unpermuted || !ciphertext)
        goto failure;

    for (size_t i = 0; i < blocks; ++i) {
        /* the last block is the soundness check: always an encoding of 1 */
        const int regular_one = i == params->ell || get_bit(message, i) == 1;
        const int hidden = ana && get_bit(ana->amessage, i) == 1;
        uint8_t *block = low_encode_block(params, key, ana, regular_one,
                                          hidden, block_bits, random);

        if (!block)
            goto failure;

        copy_bits(unpermuted, i * block_bits, block, 0, block_bits);
        free(block);
    }

    /* pi[input_position] = output_position */
    for (size_t i = 0; i < total_bits; ++i)
        set_bit(ciphertext, key->pi[i], get_bit(unpermuted, i));

    free(unpermuted);
    *output_bits = total_bits;

    return ciphertext;

failure:
    free(unpermuted);
    free(ciphertext);
    return NULL;
}

static uint8_t *
prc_low_encode(
    const void *void_params,
    const MBPRC_EncKey *void_key,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits)
{
    return low_encode(void_params, (const PRCLow_EncKey *)void_key, message,
                      message_bits, NULL, random, output_bits);
}


/*
 * ================================================================
 * Decoding
 * ================================================================
 */

/*
 * Checks the length and undoes the permutation. Returns the ell + 1
 * concatenated blocks (newly allocated) and the block size, NULL on error.
 */
static uint8_t *
low_unpermute(
    const PRCLow_Params *params,
    const PRCLow_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    size_t *block_bits_out)
{
    if (!params || !key || !ciphertext ||
        !params->underlying || !params->underlying->decode ||
        params->ell == SIZE_MAX)
        return NULL;

    const size_t block_bits =
        params->underlying->blocksize(params->underlying->params);
    const size_t blocks = params->ell + 1;

    if (block_bits > SIZE_MAX / blocks)
        return NULL;

    /* PRC^ell_low expects exactly block_bits * (ell + 1) bits */
    if (ciphertext_bits != block_bits * blocks ||
        key->total_bits != ciphertext_bits)
        return NULL;

    uint8_t *unpermuted = calloc(bits_to_bytes(ciphertext_bits), 1);

    if (!unpermuted)
        return NULL;

    /* pi_inv[output_position] = input_position */
    for (size_t output_pos = 0; output_pos < ciphertext_bits; ++output_pos) {
        set_bit(unpermuted, key->pi_inv[output_pos],
                get_bit(ciphertext, output_pos));
    }

    *block_bits_out = block_bits;

    return unpermuted;
}

static int
prc_low_decode(
    const void *void_params,
    const MBPRC_DecKey *void_key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out)
{
    const PRCLow_Params *params = void_params;
    const PRCLow_DecKey *key = (const PRCLow_DecKey *)void_key;
    size_t block_bits = 0;
    uint8_t *unpermuted, *block;
    int sound = 0;

    if (!message_out || !message_bits_out)
        return 0;

    unpermuted = low_unpermute(params, key, ciphertext, ciphertext_bits, &block_bits);
    if (!unpermuted)
        return 0;

    block = calloc(bits_to_bytes(block_bits), 1);
    if (!block) {
        free(unpermuted);
        return 0;
    }

    /* blocks 0..ell-1 carry the message, the last one is the soundness check */
    for (size_t i = 0; i <= params->ell; ++i) {
        int accepted;

        memset(block, 0, bits_to_bytes(block_bits));
        copy_bits(block, 0, unpermuted, i * block_bits, block_bits);

        accepted = zbprc_decode(params->underlying, key->underlying_key,
                                block, block_bits) == 1;

        if (i < params->ell)
            set_bit(message_out, i, accepted ? 1 : 0);
        else
            sound = accepted;
    }

    free(block);
    free(unpermuted);

    if (!sound)
        return 0;

    /* PRC^ell_low always outputs exactly ell bits */
    *message_bits_out = params->ell;

    return 1;
}


/*
 * ================================================================
 * Key destruction
 * ================================================================
 */

static void
prc_low_free_enc_key(
    const void *void_params,
    MBPRC_EncKey *void_key)
{
    const PRCLow_Params *params =
        void_params;

    PRCLow_EncKey *key =
        (PRCLow_EncKey *)void_key;

    if (!key)
        return;

    free(key->pi);

    if (key->underlying_key &&
        params &&
        params->underlying)
    {
        zbprc_free_enc_key(
            params->underlying,
            key->underlying_key
        );
    }

    free(key);
}


static void
prc_low_free_dec_key(
    const void *void_params,
    MBPRC_DecKey *void_key)
{
    const PRCLow_Params *params =
        void_params;

    PRCLow_DecKey *key =
        (PRCLow_DecKey *)void_key;

    if (!key)
        return;

    free(key->pi_inv);

    if (key->underlying_key &&
        params &&
        params->underlying)
    {
        zbprc_free_dec_key(
            params->underlying,
            key->underlying_key
        );
    }

    free(key);
}


/*
 * ================================================================
 * Construction / destruction
 * ================================================================
 */

MBPRC
prc_low(
    const PRCLow_Params *params)
{

    return (MBPRC) {
        .params = params,

        .blocksize = prc_low_blocklength,

        .keygen =
            prc_low_keygen,

        .encode =
            prc_low_encode,

        .decode =
            prc_low_decode,

        .free_enc_key =
            prc_low_free_enc_key,

        .free_dec_key =
            prc_low_free_dec_key
    };

}


/*
 * ================================================================
 * Anamorphic mode (anamorphic lifting)
 * ================================================================
 *
 * PRC^ell_low is a nested PRC with gamma = ell + 1 blocks and J = 1 instance
 * of the underlying zero-bit PRC. The anamorphic message has one bit per block
 * (ell + 1 bits); the all-zero message is excluded.
 */

struct AMBPRC_EncKey {
    APRC_EncKey *dk;
    ZBPRC_EncKey *sub;
};

struct AMBPRC_DecKey {
    APRC_DecKey *tk;
    ZBPRC_DecKey *sub;
};

static size_t
aprc_low_amessage_bits(
    const void *params,
    const void *aparams)
{
    const PRCLow_Params *p = params;

    (void)aparams;

    return p->ell + 1;
}

static void
aprc_low_free_aenc_key(
    const void *params,
    const void *aparams,
    AMBPRC_EncKey *key)
{
    const PRCLow_Params *p = params;
    const APRCLow_Params *ap = aparams;

    if (!key)
        return;

    if (key->dk)
        zbprc_free_enc_akey(p->underlying, ap->underlying_aprc, key->dk);
    if (key->sub)
        zbprc_free_enc_key(p->underlying, key->sub);

    free(key);
}

static void
aprc_low_free_adec_key(
    const void *params,
    const void *aparams,
    AMBPRC_DecKey *key)
{
    const PRCLow_Params *p = params;
    const APRCLow_Params *ap = aparams;

    if (!key)
        return;

    if (key->tk)
        zbprc_free_dec_akey(p->underlying, ap->underlying_aprc, key->tk);
    if (key->sub)
        zbprc_free_dec_key(p->underlying, key->sub);

    free(key);
}

static AMBPRC_Keys *
aprc_low_akeygen(
    const void *params,
    const void *aparams,
    MBPRC_Keys *reg_keys,
    RandomnessSource *random)
{
    const PRCLow_Params *p = params;
    const APRCLow_Params *ap = aparams;
    AMBPRC_Keys *keys = calloc(1, sizeof(*keys));
    ZBPRC_Keys *sub = NULL;
    APRC_Keys *ak = NULL;

    if (!p || !ap || !p->underlying || !ap->underlying_aprc ||
        !reg_keys || !random || !keys)
        goto fail;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (!keys->enc || !keys->dec)
        goto fail;

    /* independent instance for blocks that are uniform in the regular code */
    sub = zbprc_keygen(p->underlying, random);
    if (!sub)
        goto fail;

    keys->enc->sub = sub->enc;
    keys->dec->sub = sub->dec;
    free(sub);

    {
        const PRCLow_EncKey *enc = (const PRCLow_EncKey *)reg_keys->enc;
        const PRCLow_DecKey *dec = (const PRCLow_DecKey *)reg_keys->dec;
        ZBPRC_Keys regular = {
            .enc = enc->underlying_key,
            .dec = dec->underlying_key,
        };

        ak = zbprc_akeygen(p->underlying, ap->underlying_aprc, &regular, random);
    }

    if (!ak)
        goto fail;

    keys->enc->dk = ak->enc;
    keys->dec->tk = ak->dec;
    free(ak);

    return keys;

fail:
    if (keys) {
        aprc_low_free_aenc_key(params, aparams, keys->enc);
        aprc_low_free_adec_key(params, aparams, keys->dec);
        free(keys);
    }

    return NULL;
}

static uint8_t *
aprc_low_aencode(
    const void *params,
    const void *aparams,
    const MBPRC_EncKey *reg_key,
    const AMBPRC_EncKey *dkey,
    const uint8_t *message,
    size_t message_bits,
    const uint8_t *amessage,
    RandomnessSource *random,
    size_t *output_bits)
{
    const PRCLow_Params *p = params;
    const APRCLow_Params *ap = aparams;
    int any = 0;

    if (!p || !ap || !reg_key || !dkey || !amessage)
        return NULL;

    for (size_t i = 0; i <= p->ell; ++i)
        any |= get_bit(amessage, i);

    /* the all-zero message means "no anamorphic message" */
    if (!any)
        return NULL;

    const LowAnamorphicEncoding ana = {
        .aprc = ap->underlying_aprc,
        .dk = dkey->dk,
        .sub = dkey->sub,
        .amessage = amessage,
    };

    return low_encode(p, (const PRCLow_EncKey *)reg_key, message, message_bits,
                      &ana, random, output_bits);
}

static int
aprc_low_adecode(
    const void *params,
    const void *aparams,
    const MBPRC_DecKey *reg_key,
    const AMBPRC_DecKey *tkey,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *amessage_out)
{
    const PRCLow_Params *p = params;
    const APRCLow_Params *ap = aparams;
    const PRCLow_DecKey *key = (const PRCLow_DecKey *)reg_key;
    size_t block_bits = 0;
    uint8_t *unpermuted, *block;
    int any = 0;

    if (!ap || !tkey || !amessage_out)
        return 0;

    unpermuted = low_unpermute(p, key, ciphertext, ciphertext_bits, &block_bits);
    if (!unpermuted)
        return 0;

    block = calloc(bits_to_bytes(block_bits), 1);
    if (!block) {
        free(unpermuted);
        return 0;
    }

    for (size_t i = 0; i <= p->ell; ++i) {
        int hidden;

        memset(block, 0, bits_to_bytes(block_bits));
        copy_bits(block, 0, unpermuted, i * block_bits, block_bits);

        /* r_i: the instance with the regular key, else the independent one */
        hidden = zbprc_adecode(p->underlying, ap->underlying_aprc,
                               key->underlying_key, tkey->tk,
                               block, block_bits) == 1 ||
                 zbprc_decode(p->underlying, tkey->sub, block, block_bits) == 1;

        set_bit(amessage_out, i, hidden ? 1 : 0);
        any |= hidden;
    }

    free(block);
    free(unpermuted);

    return any;
}

aMBPRC
aprc_low(
    const APRCLow_Params *aparams)
{
    return (aMBPRC) {
        .aparams = aparams,
        .amessage_bits = aprc_low_amessage_bits,
        .akeygen = aprc_low_akeygen,
        .aencode = aprc_low_aencode,
        .adecode = aprc_low_adecode,
        .free_aenc_key = aprc_low_free_aenc_key,
        .free_adec_key = aprc_low_free_adec_key,
    };
}
