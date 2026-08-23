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
 * Randomness adapter
 * ================================================================
 *
 * RandomnessSource and RandomnessSource have the same shape, but they are
 * distinct C types. We therefore create a small adapter instead of
 * casting function pointers.
 */

typedef struct {

    RandomnessSource *random;

} RandomAdapterCtx;


static int
random_adapter(
    void *ctx,
    uint8_t *out,
    size_t len)
{
    RandomAdapterCtx *adapter =
        (RandomAdapterCtx *)ctx;

    if (!adapter ||
        !adapter->random ||
        !adapter->random->rng)
    {
        return 0;
    }

    return adapter->random->rng(
        adapter->random->ctx,
        out,
        len
    );
}




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

    RandomAdapterCtx random_ctx;
    RandomnessSource zb_random;

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
     * Adapt the multibit RNG to the zero-bit RNG interface.
     */

    random_ctx.random = random;

    zb_random.rng = random_adapter;
    zb_random.ctx = &random_ctx;


    /*
     * Generate the two independent zero-bit PRC key pairs.
     */

    keys0 = zbprc_keygen(
        prc,
        &zb_random
    );

    if (!keys0)
        goto fail;


    keys1 = zbprc_keygen(
        prc,
        &zb_random
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

    RandomAdapterCtx random_ctx;
    RandomnessSource zb_random;

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


    random_ctx.random = random;

    zb_random.rng = random_adapter;
    zb_random.ctx = &random_ctx;


    return zbprc_encode(
        prc,
        selected_key,
        &zb_random,
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
prc1_adapt_create(
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