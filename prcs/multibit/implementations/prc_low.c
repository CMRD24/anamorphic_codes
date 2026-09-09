#include "prc_low.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include "../../../utils/random_utils.h"


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


/*
 * ================================================================
 * Bit helpers
 * ================================================================
 *
 * Packed bit convention:
 *
 * bit 0 = MSB of byte 0
 */

static int
get_bit(
    const uint8_t *data,
    size_t bit)
{
    return (data[bit / 8] >> (7 - (bit % 8))) & 1;
}


static void
set_bit(
    uint8_t *data,
    size_t bit,
    int value)
{
    uint8_t mask =
        (uint8_t)(1u << (7 - (bit % 8)));

    if (value)
        data[bit / 8] |= mask;
    else
        data[bit / 8] &= (uint8_t)~mask;
}


static size_t
bits_to_bytes(
    size_t bits)
{
    return (bits + 7) / 8;
}





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
            (uint8_t)(
                0xFFu <<
                (8 - (bits % 8))
            );

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
 * Encoding
 * ================================================================
 */

static uint8_t *
prc_low_encode(
    const void *void_params,
    const MBPRC_EncKey *void_key,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits)
{
    const PRCLow_Params *params =
        void_params;

    const PRCLow_EncKey *key =
        (const PRCLow_EncKey *)void_key;

    if (!params ||
        !key ||
        !message ||
        !random ||
        !random->rng ||
        !output_bits)
    {
        return NULL;
    }

    if (message_bits != params->ell)
        return NULL;

    if (!params->underlying ||
        !params->underlying->encode)
    {
        return NULL;
    }

    size_t block_bits = params->underlying->blocksize(params->underlying->params);


    size_t blocks =
        params->ell + 1;

    size_t total_bits =
        key->total_bits;

    if (total_bits !=
        block_bits * blocks)
    {
        return NULL;
    }

    size_t total_bytes =
        bits_to_bytes(total_bits);

    uint8_t *unpermuted =
        calloc(total_bytes, 1);

    uint8_t *ciphertext =
        calloc(total_bytes, 1);

    if (!unpermuted ||
        !ciphertext)
    {
        free(unpermuted);
        free(ciphertext);
        return NULL;
    }


    /*
     * Encode the ell message bits.
     */
    for (size_t i = 0;
         i < params->ell;
         ++i)
    {
        size_t offset =
            i * block_bits;

        uint8_t *block =
            unpermuted +
            offset / 8;

        /*
         * Blocks need not start at byte boundaries.
         *
         * Therefore we generate each block separately and copy
         * its individual bits below.
         */
        (void)block;

        uint8_t *encoded_block =
            NULL;

        size_t encoded_bits = 0;

        if (get_bit(message, i) == 1) {

            encoded_block =
                zbprc_encode(
                    params->underlying,
                    key->underlying_key,
                    random,
                    &encoded_bits
                );

            if (!encoded_block ||
                encoded_bits != block_bits)
            {
                free(encoded_block);
                goto failure;
            }

        } else {

            //printf("there\n");
            size_t block_bytes =
                bits_to_bytes(block_bits);

            encoded_block =
                calloc(block_bytes, 1);

            if (!encoded_block)
                goto failure;

            if (!fill_random_bits(
                    random,
                    encoded_block,
                    block_bits))
            {
                free(encoded_block);
                goto failure;
            }
        }

        for (size_t j = 0;
             j < block_bits;
             ++j)
        {
            set_bit(
                unpermuted,
                offset + j,
                get_bit(encoded_block, j)
            );
        }

        free(encoded_block);
    }


    /*
     * Encode the additional soundness-check bit 1.
     */
    {
        uint8_t *check_block;

        size_t encoded_bits = 0;

        check_block =
            zbprc_encode(
                params->underlying,
                key->underlying_key,
                random,
                &encoded_bits
            );

        if (!check_block ||
            encoded_bits != block_bits)
        {
            free(check_block);
            goto failure;
        }

        size_t offset =
            params->ell * block_bits;

        for (size_t j = 0;
             j < block_bits;
             ++j)
        {
            set_bit(
                unpermuted,
                offset + j,
                get_bit(check_block, j)
            );
        }

        free(check_block);
    }


    /*
     * Apply the permutation.
     *
     * pi[input_position] = output_position.
     */
    for (size_t i = 0;
         i < total_bits;
         ++i)
    {
        set_bit(
            ciphertext,
            key->pi[i],
            get_bit(unpermuted, i)
        );
    }

    free(unpermuted);

    *output_bits =
        total_bits;

    return ciphertext;


failure:

    free(unpermuted);
    free(ciphertext);

    return NULL;
}


/*
 * ================================================================
 * Decoding
 * ================================================================
 */
static int
prc_low_decode(
    const void *void_params,
    const MBPRC_DecKey *void_key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out)
{
    const PRCLow_Params *params =
        void_params;

    const PRCLow_DecKey *key =
        (const PRCLow_DecKey *)void_key;

    if (!params ||
        !key ||
        !ciphertext ||
        !message_out ||
        !message_bits_out ||
        !params->underlying ||
        !params->underlying->decode)
    {
        return 0;
    }

    size_t block_bits = params->underlying->blocksize(params->underlying->params);

    /*
     * PRC^ell_low expects exactly
     *
     *     block_bits * (ell + 1)
     *
     * ciphertext bits.
     */
    if (params->ell == SIZE_MAX)
        return 0;

    size_t blocks =
        params->ell + 1;

    if (block_bits >
        SIZE_MAX / blocks)
    {
        return 0;
    }

    size_t expected_ciphertext_bits =
        block_bits * blocks;

    if (ciphertext_bits != expected_ciphertext_bits)
        return 0;

    if (key->total_bits != expected_ciphertext_bits)
        return 0;

    size_t total_bytes =
        bits_to_bytes(ciphertext_bits);

    uint8_t *unpermuted =
        calloc(total_bytes, 1);

    if (!unpermuted)
        return 0;


    /*
     * Undo the permutation.
     *
     * pi_inv[output_position] = input_position.
     */
    for (size_t output_pos = 0;
         output_pos < ciphertext_bits;
         ++output_pos)
    {
        size_t input_pos =
            key->pi_inv[output_pos];

        set_bit(
            unpermuted,
            input_pos,
            get_bit(ciphertext, output_pos)
        );
    }



    size_t block_bytes =
        bits_to_bytes(block_bits);

    uint8_t *block =
        calloc(block_bytes, 1);

    if (!block) {
        free(unpermuted);
        return 0;
    }


    /*
     * Decode the ell message blocks.
     */
    for (size_t i = 0;
         i < params->ell;
         ++i)
    {
        memset(
            block,
            0,
            block_bytes
        );

        size_t offset =
            i * block_bits;

        for (size_t j = 0;
             j < block_bits;
             ++j)
        {
            set_bit(
                block,
                j,
                get_bit(
                    unpermuted,
                    offset + j
                )
            );
        }

        int accepted =
            zbprc_decode(
                params->underlying,
                key->underlying_key,
                block,
                block_bits
            );

        //printf("accept? %d\n", accepted);

        set_bit(
            message_out,
            i,
            accepted ? 1 : 0
        );
    }


    /*
     * Decode the final soundness-check block.
     */
    memset(
        block,
        0,
        block_bytes
    );

    {
        size_t offset =
            params->ell * block_bits;

        for (size_t j = 0;
             j < block_bits;
             ++j)
        {
            set_bit(
                block,
                j,
                get_bit(
                    unpermuted,
                    offset + j
                )
            );
        }
    }

    int sound =
        zbprc_decode(
            params->underlying,
            key->underlying_key,
            block,
            block_bits
        );

    //printf("accept sound? %d\n", sound);

    free(block);
    free(unpermuted);

    if (!sound)
        return 0;

    /*
     * PRC^ell_low always outputs exactly ell bits.
     */
    *message_bits_out =
        params->ell;

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


