/*
 * PRC^1_adapt: a one-bit PRC from two independent keys of a zero-bit PRC (the
 * adaptive one-bit construction of Christ and Gunn, "Pseudorandom
 * Error-Correcting Codes", CRYPTO 2024).
 *
 * Encode(b): encode 1 with the key number b. Decode: run the zero-bit decoder with
 * both keys; exactly one must accept and its index is the bit. Each key alone
 * sees a pseudorandom word, and a word accepted under no key or both keys is
 * rejected.
 */

#include "prc1_adapt.h"

#include <stdlib.h>
#include <string.h>


/*
 * ================================================================
 * Concrete wrapper key types
 * ================================================================
 *
 * MBPRC_EncKey and MBPRC_DecKey are opaque in the generic interface.
 * This implementation defines their concrete representation.
 */

struct MBPRC_EncKey {

    ZBPRC_EncKey *key0;
    ZBPRC_EncKey *key1;

};


struct MBPRC_DecKey {

    ZBPRC_DecKey *key0;
    ZBPRC_DecKey *key1;

};


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static MBPRC_Keys *
prc1_adapt_keygen(
    const void *params,
    RandomnessSource *random)
{
    const PRC1AdaptParams *adapt_params =
        (const PRC1AdaptParams *)params;

    const ZBPRC *prc;


    ZBPRC_Keys *keys0 = NULL;
    ZBPRC_Keys *keys1 = NULL;

    MBPRC_EncKey *enc = NULL;
    MBPRC_DecKey *dec = NULL;
    MBPRC_Keys *keys = NULL;


    if (!adapt_params ||
        !adapt_params->underlying_prc ||
        !random ||
        !random->rng)
    {
        return NULL;
    }

    prc = adapt_params->underlying_prc;


    /*
     * Generate the two independent zero-bit PRC key pairs.
     */

    keys0 = zbprc_keygen(
        prc,
        random
    );

    if (!keys0)
        goto fail;


    keys1 = zbprc_keygen(
        prc,
        random
    );

    if (!keys1)
        goto fail;


    enc = malloc(sizeof(*enc));

    if (!enc)
        goto fail;


    dec = malloc(sizeof(*dec));

    if (!dec)
        goto fail;


    keys = malloc(sizeof(*keys));

    if (!keys)
        goto fail;


    enc->key0 = keys0->enc;
    enc->key1 = keys1->enc;

    dec->key0 = keys0->dec;
    dec->key1 = keys1->dec;


    /*
     * The wrapper now owns the individual keys.
     * Free only the ZBPRC_Keys containers.
     */

    free(keys0);
    free(keys1);

    keys->enc = enc;
    keys->dec = dec;

    return keys;


fail:

    if (keys)
        free(keys);

    if (dec)
        free(dec);

    if (enc)
        free(enc);

    if (keys0)
        zbprc_free_keys(
            prc,
            keys0
        );

    if (keys1)
        zbprc_free_keys(
            prc,
            keys1
        );

    return NULL;
}


/*
 * ================================================================
 * Encoding
 * ================================================================
 */

static uint8_t *
prc1_adapt_encode(
    const void *params,
    const MBPRC_EncKey *key,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits)
{
    const PRC1AdaptParams *adapt_params =
        (const PRC1AdaptParams *)params;

    const ZBPRC *prc;


    const ZBPRC_EncKey *selected_key;


    if (!adapt_params ||
        !adapt_params->underlying_prc ||
        !key ||
        !message ||
        !random ||
        !random->rng ||
        !output_bits)
    {
        return NULL;
    }

    if(message_bits!=1){
        return NULL;
    }


    prc = adapt_params->underlying_prc;


    /*
     * The message is one packed bit.
     *
     * Bit value 0 -> use key0.
     * Bit value 1 -> use key1.
     */

    if ((message[0] & 1u) == 0)
        selected_key = key->key0;
    else
        selected_key = key->key1;


    return zbprc_encode(
        prc,
        selected_key,
        random,
        output_bits
    );
}


/*
 * ================================================================
 * Decoding
 * ================================================================
 */

static int
prc1_adapt_decode(
    const void *params,
    const MBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out)
{
    const PRC1AdaptParams *adapt_params =
        (const PRC1AdaptParams *)params;

    const ZBPRC *prc;

    int m0;
    int m1;


    if (!adapt_params ||
        !adapt_params->underlying_prc ||
        !key ||
        !ciphertext ||
        !message_out ||
        !message_bits_out)
    {
        return 0;
    }


    prc = adapt_params->underlying_prc;


    /*
     * Decode under both zero-bit PRC keys.
     */

    m0 = zbprc_decode(
        prc,
        key->key0,
        ciphertext,
        ciphertext_bits
    );

    m1 = zbprc_decode(
        prc,
        key->key1,
        ciphertext,
        ciphertext_bits
    );


    /*
     * Exactly one decoder must accept.
     */

    if (m0 == 1 && m1 == 0) {

        message_out[0] = 0;
        *message_bits_out = 1;

        return 1;
    }


    if (m0 == 0 && m1 == 1) {

        message_out[0] = 1;
        *message_bits_out = 1;

        return 1;
    }


    /*
     * Both accept or both reject.
     */

    return 0;
}


/*
 * ================================================================
 * Key destruction
 * ================================================================
 */

static void
prc1_adapt_free_enc_key(
    const void *params,
    MBPRC_EncKey *key)
{
    const PRC1AdaptParams *adapt_params =
        (const PRC1AdaptParams *)params;

    if (!adapt_params ||
        !adapt_params->underlying_prc ||
        !key)
    {
        return;
    }

    const ZBPRC *prc =
        adapt_params->underlying_prc;

    if (key->key0) {
        zbprc_free_enc_key(
            prc,
            key->key0
        );
    }

    if (key->key1) {
        zbprc_free_enc_key(
            prc,
            key->key1
        );
    }

    free(key);
}


static void
prc1_adapt_free_dec_key(
    const void *params,
    MBPRC_DecKey *key)
{
    const PRC1AdaptParams *adapt_params =
        (const PRC1AdaptParams *)params;

    if (!adapt_params ||
        !adapt_params->underlying_prc ||
        !key)
    {
        return;
    }

    const ZBPRC *prc =
        adapt_params->underlying_prc;

    if (key->key0) {
        zbprc_free_dec_key(
            prc,
            key->key0
        );
    }

    if (key->key1) {
        zbprc_free_dec_key(
            prc,
            key->key1
        );
    }

    free(key);
}


MBPRC
prc1_adapt(
    const PRC1AdaptParams *params)
{
    return (MBPRC) {
        .params = params,

        .keygen =
            prc1_adapt_keygen,

        .encode =
            prc1_adapt_encode,

        .decode =
            prc1_adapt_decode,

        .free_enc_key =
            prc1_adapt_free_enc_key,

        .free_dec_key =
            prc1_adapt_free_dec_key
    };
}


/*
 * ================================================================
 * Anamorphic mode (anamorphic lifting)
 * ================================================================
 *
 * PRC^1_adapt is a nested PRC with one block (gamma = 1) and J = 2 instances
 * of the underlying zero-bit PRC: Plan(m) = ((m, 1), -). The block is never
 * uniform, so the independent instance `sub` of the lifting construction is
 * only needed by the decoder for the (unused) case x = bottom.
 *
 * The anamorphic message space is {1}: the all-bottom message is excluded.
 */

struct AMBPRC_EncKey {
    APRC_EncKey *dk[2];
    ZBPRC_EncKey *sub;
};

struct AMBPRC_DecKey {
    APRC_DecKey *tk[2];
    ZBPRC_DecKey *sub;
};

static size_t
aprc1_adapt_amessage_bits(
    const void *params,
    const void *aparams)
{
    (void)params;
    (void)aparams;

    return 1;
}

static void
aprc1_adapt_free_aenc_key(
    const void *params,
    const void *aparams,
    AMBPRC_EncKey *key)
{
    const PRC1AdaptParams *p = params;
    const APRC1AdaptParams *ap = aparams;

    if (!key)
        return;

    for (int j = 0; j < 2; ++j) {
        if (key->dk[j])
            zbprc_free_enc_akey(p->underlying_prc, ap->underlying_aprc, key->dk[j]);
    }

    if (key->sub)
        zbprc_free_enc_key(p->underlying_prc, key->sub);

    free(key);
}

static void
aprc1_adapt_free_adec_key(
    const void *params,
    const void *aparams,
    AMBPRC_DecKey *key)
{
    const PRC1AdaptParams *p = params;
    const APRC1AdaptParams *ap = aparams;

    if (!key)
        return;

    for (int j = 0; j < 2; ++j) {
        if (key->tk[j])
            zbprc_free_dec_akey(p->underlying_prc, ap->underlying_aprc, key->tk[j]);
    }

    if (key->sub)
        zbprc_free_dec_key(p->underlying_prc, key->sub);

    free(key);
}

static AMBPRC_Keys *
aprc1_adapt_akeygen(
    const void *params,
    const void *aparams,
    MBPRC_Keys *reg_keys,
    RandomnessSource *random)
{
    const PRC1AdaptParams *p = params;
    const APRC1AdaptParams *ap = aparams;
    AMBPRC_Keys *keys = calloc(1, sizeof(*keys));
    ZBPRC_Keys *sub = NULL;

    if (!p || !ap || !p->underlying_prc || !ap->underlying_aprc ||
        !reg_keys || !random || !keys)
        goto fail;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (!keys->enc || !keys->dec)
        goto fail;

    /* independent instance for blocks that are uniform in the regular code */
    sub = zbprc_keygen(p->underlying_prc, random);
    if (!sub)
        goto fail;

    keys->enc->sub = sub->enc;
    keys->dec->sub = sub->dec;
    free(sub);

    for (int j = 0; j < 2; ++j) {
        ZBPRC_Keys regular = {
            .enc = j ? reg_keys->enc->key1 : reg_keys->enc->key0,
            .dec = j ? reg_keys->dec->key1 : reg_keys->dec->key0,
        };
        APRC_Keys *ak = zbprc_akeygen(p->underlying_prc, ap->underlying_aprc,
                                      &regular, random);

        if (!ak)
            goto fail;

        keys->enc->dk[j] = ak->enc;
        keys->dec->tk[j] = ak->dec;
        free(ak);
    }

    return keys;

fail:
    if (keys) {
        aprc1_adapt_free_aenc_key(params, aparams, keys->enc);
        aprc1_adapt_free_adec_key(params, aparams, keys->dec);
        free(keys);
    }

    return NULL;
}

static uint8_t *
aprc1_adapt_aencode(
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
    const PRC1AdaptParams *p = params;
    const APRC1AdaptParams *ap = aparams;

    if (!p || !ap || !reg_key || !dkey || !message || !amessage ||
        !random || !output_bits || message_bits != 1)
        return NULL;

    /* the only valid anamorphic message is 1 */
    if ((amessage[0] & 1u) == 0)
        return NULL;

    const int j = message[0] & 1u;

    return zbprc_aencode(
        p->underlying_prc,
        ap->underlying_aprc,
        j ? reg_key->key1 : reg_key->key0,
        dkey->dk[j],
        random,
        output_bits);
}

static int
aprc1_adapt_adecode(
    const void *params,
    const void *aparams,
    const MBPRC_DecKey *reg_key,
    const AMBPRC_DecKey *tkey,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *amessage_out)
{
    const PRC1AdaptParams *p = params;
    const APRC1AdaptParams *ap = aparams;
    int present = 0;

    if (!p || !ap || !reg_key || !tkey || !ciphertext || !amessage_out)
        return 0;

    for (int j = 0; j < 2 && !present; ++j) {
        present = zbprc_adecode(
            p->underlying_prc,
            ap->underlying_aprc,
            j ? reg_key->key1 : reg_key->key0,
            tkey->tk[j],
            ciphertext,
            ciphertext_bits) == 1;
    }

    /* blocks that are uniform in the regular code would be read with `sub` */
    present = present ||
        zbprc_decode(p->underlying_prc, tkey->sub, ciphertext, ciphertext_bits) == 1;

    if (present)
        amessage_out[0] = 1;

    return present;
}

aMBPRC
aprc1_adapt(
    const APRC1AdaptParams *aparams)
{
    return (aMBPRC) {
        .aparams = aparams,
        .amessage_bits = aprc1_adapt_amessage_bits,
        .akeygen = aprc1_adapt_akeygen,
        .aencode = aprc1_adapt_aencode,
        .adecode = aprc1_adapt_adecode,
        .free_aenc_key = aprc1_adapt_free_aenc_key,
        .free_adec_key = aprc1_adapt_free_adec_key,
    };
}
