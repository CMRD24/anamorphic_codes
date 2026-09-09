#include "prc_sharp.h"
#include "../../../utils/csprg_sodium.h"
#include "../../../utils/helpers.h"

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>




/*
 * ================================================================
 * Internal key types
 * ================================================================
 */

struct MBPRC_EncKey {

    uint8_t *prf_key;

    
    MBPRC_EncKey *underlying;
};


struct MBPRC_DecKey {

    uint8_t *prf_key;

    
    MBPRC_DecKey *underlying_dec;
    MBPRC_EncKey *underlying_enc;
};





/*
 * ================================================================
 * Blocksize
 * ================================================================
 */

static size_t
sharp_blocksize(
    const void *vparams)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    return mbprc_blocksize(
        params->prc
    );
}


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static MBPRC_Keys *
sharp_keygen(
    const void *vparams,
    RandomnessSource *random)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;


    if (!params ||
        !params->prc ||
        !random ||
        !random->rng)
        return NULL;

    /*
     * Generate the underlying PRC keys.
     */
    MBPRC_Keys *underlying =
        mbprc_keygen(
            params->prc,
            random
        );

    if (!underlying)
        return NULL;

    printf("a1\n");




    struct MBPRC_EncKey *enc =
        calloc(1, sizeof(*enc));

    struct MBPRC_DecKey *dec =
        calloc(1, sizeof(*dec));

    if (!enc || !dec) {

        free(enc);
        free(dec);

        mbprc_free_keys(
            params->prc,
            underlying
        );

        return NULL;
    }


    /*
     * Generate the PRF key.
     */
    size_t prf_key_bytes =
    bits_to_bytes(params->lambda_bits);

    enc->prf_key =
        malloc(prf_key_bytes);

    dec->prf_key =
        malloc(prf_key_bytes);

    if (!enc->prf_key || !dec->prf_key) {

        free(enc->prf_key);
        free(dec->prf_key);

        free(enc);
        free(dec);

        mbprc_free_keys(
            params->prc,
            underlying
        );

        return NULL;
    }

    if (!random->rng(
            random->ctx,
            enc->prf_key,
            prf_key_bytes)) {

        free(enc->prf_key);
        free(dec->prf_key);
        free(enc);
        free(dec);

        mbprc_free_keys(
            params->prc,
            underlying
        );

        return NULL;
    }

    printf("a2\n");


    /*
     * Both encryption and decryption use the same PRF key.
     */
    memcpy(
        dec->prf_key,
        enc->prf_key,
        prf_key_bytes
    );

    /*
     * Transfer ownership of the underlying keys.
     */
    enc->underlying =
        underlying->enc;

    dec->underlying_dec =
        underlying->dec;

    dec->underlying_enc =
        underlying->enc;

    //TODO: should copy enc key, otherwise double free when both keys are freed

    underlying->enc = NULL;
    underlying->dec = NULL;

    mbprc_free_keys(
        params->prc,
        underlying
    );


    MBPRC_Keys *keys =
        calloc(1, sizeof(*keys));

    if (!keys) {

        mbprc_free_enc_key(
            params->prc,
            (MBPRC_EncKey *)enc
        );

        mbprc_free_dec_key(
            params->prc,
            (MBPRC_DecKey *)dec
        );

        return NULL;
    }

    keys->enc =
        (MBPRC_EncKey *)enc;

    keys->dec =
        (MBPRC_DecKey *)dec;

    printf("aaaaaaaaaa\n");

    return keys;
}


/*
 * ================================================================
 * Encode
 * ================================================================
 */



static uint8_t *
sharp_encode_ws(
    const void *vparams,
    const MBPRC_EncKey *vkey,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits,
    const uint8_t *seed    
)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    const struct MBPRC_EncKey *key =
        (const struct MBPRC_EncKey *)vkey;


    if (!params ||
        !params->prc ||
        !key ||
        !message ||
        !random ||
        !output_bits||
        !seed)
        return NULL;


    size_t lambda =
        params->lambda_bits;


    size_t lambda_bytes =
        bits_to_bytes(lambda);


    /*
     * ------------------------------------------------------------
     * 2. Construct r || m
     * ------------------------------------------------------------
     */

    if (lambda >
        SIZE_MAX - message_bits) {

        return NULL;
    }

    size_t rm_bits =
        lambda + message_bits;

    size_t rm_bytes =
        bits_to_bytes(rm_bits);

    uint8_t *rm =
        calloc(1, rm_bytes);

    if (!rm) {

        return NULL;
    }

    copy_bits(
        rm,
        0,
        seed,
        0,
        lambda
    );

    copy_bits(
        rm,
        lambda,
        message,
        0,
        message_bits
    );


    /*
     * ------------------------------------------------------------
     * 3. Compute
     *
     *     F_sk(r || m) = R1 || R2 (switch order)
     *
     * 
     * R2 has lambda bits.
     * ------------------------------------------------------------
     */

    RandomnessSource pseudo = csprg_randomness(rm, rm_bytes);



    /*
     * ------------------------------------------------------------
     * 4. Construct r || m || R2
     * ------------------------------------------------------------
     */
    uint8_t* r2 = malloc(lambda_bytes);


    if(!pseudo.rng(pseudo.ctx, r2, lambda_bytes)){
        printf("r2 generation failed\n");
        return NULL;
    }

    if (rm_bits >
        SIZE_MAX - lambda)
    {
        csprg_randomness_free(&pseudo);
        free(rm);

        return NULL;
    }

    

    size_t encoded_message_bits =
        rm_bits + lambda;

    size_t encoded_message_bytes =
        bits_to_bytes(encoded_message_bits);

    uint8_t *encoded_message =
        calloc(1, encoded_message_bytes);

    if (!encoded_message) {

        csprg_randomness_free(&pseudo);
        free(rm);

        return NULL;
    }


    copy_bits(
        encoded_message,
        0,
        rm,
        0,
        rm_bits
    );

    copy_bits(
        encoded_message,
        rm_bits,
        r2,
        0,
        lambda
    );


    //pseudo now contains r1



    printf("ey!\n");


    uint8_t *ciphertext =
        params->prc->encode(
            params->prc->params,

            (const MBPRC_EncKey *)
                key->underlying,

            encoded_message,
            encoded_message_bits,

            &pseudo,

            output_bits
        );

    printf("hey!\n");


    free(encoded_message);
    csprg_randomness_free(&pseudo);
    free(r2);
    free(rm);

    return ciphertext;
}



 static uint8_t *
sharp_encode(
    const void *vparams,
    const MBPRC_EncKey *vkey,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits
){

    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    size_t lambda =
        params->lambda_bits;
/*
     * ------------------------------------------------------------
     * 1. Sample r <- {0,1}^lambda
     * ------------------------------------------------------------
     */

    size_t lambda_bytes =
        bits_to_bytes(lambda);

    uint8_t *r =
        calloc(1, lambda_bytes);

    if (!r)
        return NULL;

    if (!random->rng(
            random->ctx,
            r,
            lambda_bytes)) {

        free(r);
        return NULL;
    }

    uint8_t *encoding = sharp_encode_ws(params, 
        vkey,
        message,
        message_bits,
        random,
        output_bits,
        r
    );

    if(encoding==NULL){
        free(r);
    }

    return encoding;

}


/*
 * ================================================================
 * Decode
 * ================================================================
 */


int
sharp_decode_ws(
    const void *vparams,
    const MBPRC_DecKey *vkey,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out,
    uint8_t *seed_out)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    const struct MBPRC_DecKey *key =
        (const struct MBPRC_DecKey *)vkey;


    if (!params ||
        !params->prc ||
        !key ||
        !ciphertext ||
        !message_out ||
        !message_bits_out)
        return 0;

    printf("d1\n");


    size_t lambda =
        params->lambda_bits;


    /*
     * ------------------------------------------------------------
     * 1. Decode using the underlying PRC.
     * ------------------------------------------------------------
     *
     * The result should be:
     *
     *     r || m || R2
     */

    size_t tmp_bytes =
        bits_to_bytes(ciphertext_bits);

    uint8_t *decoded =
        calloc(1, tmp_bytes);

    if (!decoded)
        return 0;

    printf("d2\n");

    size_t decoded_bits = 0;

    int rc =
        params->prc->decode(
            params->prc->params,

            (const MBPRC_DecKey *)
                key->underlying_dec,

            ciphertext,
            ciphertext_bits,

            decoded,
            &decoded_bits
        );

    if (rc != 1) {

        free(decoded);
        return 0;
    }

    printf("d3\n");

    /*
     * Need at least:
     *
     *     r || R2
     *
     * i.e. 2 * lambda bits.
     */
    if (lambda >
        SIZE_MAX / 2) {

        free(decoded);
        return 0;
    }

    printf("d4\n");

    if (decoded_bits <
        2 * lambda) {

        free(decoded);
        return 0;
    }

    printf("d5\n");

    /*
     * ------------------------------------------------------------
     * 2. Extract:
     *
     *     r || m
     *
     * and R2.
     * ------------------------------------------------------------
     */

    size_t message_bits =
        decoded_bits - 2 * lambda;

    size_t rm_bits =
        lambda + message_bits;

    size_t rm_bytes =
        bits_to_bytes(rm_bits);

    uint8_t *rm =
        calloc(1, rm_bytes);

    if (!rm) {

        free(decoded);
        return 0;
    }

    printf("d6\n");

    copy_bits(
        rm,
        0,
        decoded,
        0,
        rm_bits
    );

    copy_bits(
        seed_out,
        0,
        rm,
        0,
        lambda
    );


    size_t r2_bytes =
        bits_to_bytes(lambda);

    uint8_t *r2 =
        calloc(1, r2_bytes);

    if (!r2) {

        free(rm);
        free(decoded);

        return 0;
    }

    printf("d7\n");

    copy_bits(
        r2,
        0,
        decoded,
        rm_bits,
        lambda
    );


    /*
     * ------------------------------------------------------------
     * 3. Recompute F_sk(r || m)
     *
     *     F_sk(r || m) = R1 || R2'
     * ------------------------------------------------------------
     */

    RandomnessSource pseudo = csprg_randomness(rm, rm_bytes);

    size_t lambda_bytes =
        bits_to_bytes(lambda);

    uint8_t* r2_tilde = malloc(lambda_bytes);


    if(!pseudo.rng(pseudo.ctx, r2_tilde, lambda_bytes)){
        printf("r2 generation failed\n");
        return 0;
    }

    if (rm_bits >
        SIZE_MAX - lambda)
    {
        csprg_randomness_free(&pseudo);
        free(r2);
        free(rm);
        free(r2_tilde);
        free(decoded);

        return 0;
    }


    printf("d8\n");



    /*
     * ------------------------------------------------------------
     * 4. Verify R2 == R2'
     * ------------------------------------------------------------
     */

    if (!constant_time_equal(
            r2,
            r2_tilde,
            r2_bytes)) {

        csprg_randomness_free(&pseudo);
        free(r2_tilde);
        free(r2);
        free(rm);
        free(decoded);

        return 0;
    }

    printf("d11\n");


    //reencode the message using pseudo

    size_t ciphertext_tilde_bits = 0;

    uint8_t *ciphertext_tilde =
        params->prc->encode(
            params->prc->params,

            (const MBPRC_EncKey *)
                key->underlying_enc,

            decoded,
            decoded_bits,

            &pseudo,
            //random,

            &ciphertext_tilde_bits
        );


    //check distance between reencoded and received:

    size_t dist = bitwise_hamming_dist(ciphertext, ciphertext_tilde, tmp_bytes);

    printf("distance: %zu\n", dist);

    if(dist > params->delta*ciphertext_bits){
        return 0;
    }


    /*
     * ------------------------------------------------------------
     * 5. Extract m.
     *
     * decoded = r || m || R2
     *
     * Therefore m starts at bit lambda.
     * ------------------------------------------------------------
     */

    size_t message_bytes =
        bits_to_bytes(message_bits);

    memset(
        message_out,
        0,
        message_bytes
    );

    copy_bits(
        message_out,
        0,
        decoded,
        lambda,
        message_bits
    );

    *message_bits_out =
        message_bits;


    

    csprg_randomness_free(&pseudo);
    free(ciphertext_tilde);
    free(r2_tilde);
    free(r2);
    free(rm);
    free(decoded);

    return 1;
}


 static int
sharp_decode(
    const void *vparams,
    const MBPRC_DecKey *vkey,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out){

const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

size_t lambda_bytes =
        bits_to_bytes(params->lambda_bits);

uint8_t* seed = calloc(1, lambda_bytes);

if(!seed){
    return 0;
}

int decoding = sharp_decode_ws(vparams, vkey, ciphertext, ciphertext_bits, message_out, message_bits_out, seed);

//regular mode doesn't make use of the seed:

free(seed);
return decoding;

}


/*
 * ================================================================
 * Key destruction
 * ================================================================
 */

static void
sharp_free_enc_key(
    const void *vparams,
    MBPRC_EncKey *vkey)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    struct MBPRC_EncKey *key =
        (struct MBPRC_EncKey *)vkey;

    if (!key)
        return;

    if (key->underlying) {

        params->prc->free_enc_key(
            params->prc->params,
            (MBPRC_EncKey *)
                key->underlying
        );
    }

    size_t prf_key_bytes =
    bits_to_bytes(params->lambda_bits);

    if (key->prf_key) {

        memset(
            key->prf_key,
            0,
            prf_key_bytes
        );

        free(key->prf_key);
    }    

    free(key);
}


static void
sharp_free_dec_key(
    const void *vparams,
    MBPRC_DecKey *vkey)
{
    const PRCSharp_Params *params =
        (const PRCSharp_Params *)vparams;

    struct MBPRC_DecKey *key =
        (struct MBPRC_DecKey *)vkey;

    if (!key)
        return;

    if (key->underlying_dec) {

        params->prc->free_dec_key(
            params->prc->params,
            (MBPRC_DecKey *)
                key->underlying_dec
        );
    }

    if (key->underlying_enc) {

        params->prc->free_enc_key(
            params->prc->params,
            (MBPRC_EncKey *)
                key->underlying_enc
        );
    }

    size_t prf_key_bytes =
    bits_to_bytes(params->lambda_bits);

    if (key->prf_key) {

        memset(
            key->prf_key,
            0,
            prf_key_bytes
        );

        free(key->prf_key);
    }

    free(key);
}


/*
 * ================================================================
 * Constructor
 * ================================================================
 */

MBPRC
prc_sharp(
    const PRCSharp_Params *params)
{
    MBPRC result = {
        .params =
            params,

        .blocksize =
            sharp_blocksize,

        .keygen =
            sharp_keygen,

        .encode =
            sharp_encode,

        .decode =
            sharp_decode,

        .free_enc_key =
            sharp_free_enc_key,

        .free_dec_key =
            sharp_free_dec_key
    };

    return result;
}

MBPRC_RR
prc_sharp_rr(
    const PRCSharp_Params *params)
{
    MBPRC_RR result = {
        .base = prc_sharp(params),
        .decode_ws = sharp_decode_ws,
        .encode_ws = sharp_encode_ws
    };

    return result;
}