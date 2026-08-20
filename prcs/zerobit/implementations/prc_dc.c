#include "prc_dc.h"

#include <stdint.h>
#include <stdlib.h>
#include <limits.h>

#include <stdio.h>


/*
 * ================================================================
 * Concrete opaque key types
 * ================================================================
 *
 * The DC-PRC only wraps the corresponding key of the underlying
 * PRC. The underlying PRC itself is stored in PRCDC_Params.
 */

struct ZBPRC_EncKey {
    ZBPRC_EncKey *inner;
};

struct ZBPRC_DecKey {
    ZBPRC_DecKey *inner;
};


/*
 * ================================================================
 * Bit utilities
 * ================================================================
 */

size_t
prc_dc_bytes_for_bits(size_t n)
{
    return (n + 7u) / 8u;
}


static inline uint8_t
get_bit(
    const uint8_t *data,
    size_t index)
{
    return (uint8_t)(
        (data[index >> 3u] >>
         (index & 7u)) & 1u
    );
}


static inline void
set_bit_1(
    uint8_t *data,
    size_t index)
{
    data[index >> 3u] |=
        (uint8_t)(1u << (index & 7u));
}


/*
 * ================================================================
 * Majority
 * ================================================================
 *
 * Majority(z) =
 *
 *     1 if wt(z) > |z| / 2
 *     0 otherwise
 *
 * Thus, for even |z|, exactly half ones gives 0.
 */

uint8_t
prc_dc_majority(
    const uint8_t *bits,
    size_t bit_offset,
    size_t length)
{
    size_t weight = 0;

    for (size_t i = 0;
         i < length;
         ++i) {

        weight +=
            get_bit(
                bits,
                bit_offset + i
            );
    }

    return (uint8_t)(
        weight > length / 2u
    );
}


/*
 * ================================================================
 * Randomness
 * ================================================================
 */

static int
random_bytes(
    ZBPRC_Random *random,
    uint8_t *out,
    size_t len)
{
    if (random == NULL ||
        random->rng == NULL) {

        return 0;
    }

    return random->rng(
        random->ctx,
        out,
        len
    );
}


/*
 * ================================================================
 * Majority-slice sampling
 * ================================================================
 *
 * Samples uniformly from
 *
 *     { z in {0,1}^T :
 *       Majority(z) = majority }.
 *
 * Rejection sampling gives the exact uniform distribution over
 * this set.
 */

static int
sample_majority_slice(
    uint8_t *output,
    size_t output_bit_offset,
    size_t T,
    uint8_t majority,
    ZBPRC_Random *random)
{
    if (output == NULL ||
        T == 0 ||
        majority > 1u) {

        return 0;
    }

    const size_t bytes =
        prc_dc_bytes_for_bits(T);

    uint8_t *candidate =
        malloc(bytes);

    if (candidate == NULL)
        return 0;

    for (;;) {

        /*
         * Sample a uniformly random T-bit string.
         */
        if (!random_bytes(
                random,
                candidate,
                bytes)) {

            free(candidate);
            return 0;
        }

        /*
         * Clear unused padding bits.
         */
        if ((T & 7u) != 0u) {

            const uint8_t mask =
                (uint8_t)(
                    (1u << (T & 7u)) - 1u
                );

            candidate[bytes - 1u] &= mask;
        }

        /*
         * Reject if the majority is wrong.
         */
        if (prc_dc_majority(
                candidate,
                0,
                T) != majority) {

            continue;
        }

        /*
         * Copy the accepted T-bit slice.
         *
         * output is zero-initialized by the caller, so only
         * one-bits have to be written.
         */
        for (size_t i = 0;
             i < T;
             ++i) {

            if (get_bit(candidate, i)) {

                set_bit_1(
                    output,
                    output_bit_offset + i
                );
            }
        }

        free(candidate);
        return 1;
    }
}


/*
 * ================================================================
 * Parameter validation
 * ================================================================
 */

static int
prc_dc_valid_params(
    const PRCDC_Params *params)
{
    if (params == NULL)
        return 0;

    if (params->k == 0 ||
        params->T == 0) {

        return 0;
    }

    if (params->underlying == NULL)
        return 0;

    if (params->underlying->keygen == NULL ||
        params->underlying->encode == NULL ||
        params->underlying->decode == NULL ||
        params->underlying->free_enc_key == NULL ||
        params->underlying->free_dec_key == NULL) {

        return 0;
    }

    /*
     * The DC-PRC output contains k*T bits.
     */
    if (params->k >
        SIZE_MAX / params->T) {

        return 0;
    }

    return 1;
}


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static ZBPRC_Keys *
prc_dc_keygen(
    const void *params_ptr,
    ZBPRC_Random *random)
{
    const PRCDC_Params *params =
        (const PRCDC_Params *)params_ptr;

    if (!prc_dc_valid_params(params) ||
        random == NULL) {

        return NULL;
    }

    /*
     * Delegate key generation completely to the underlying PRC.
     */
    ZBPRC_Keys *inner =
        params->underlying->keygen(
            params->underlying->params,
            random
        );

    if (inner == NULL)
        return NULL;

    /*
     * Wrap the underlying encoding key.
     */
    ZBPRC_EncKey *enc =
        malloc(sizeof(*enc));

    if (enc == NULL) {

        if (inner->enc != NULL) {

            params->underlying->free_enc_key(
                params->underlying->params,
                inner->enc
            );
        }

        if (inner->dec != NULL) {

            params->underlying->free_dec_key(
                params->underlying->params,
                inner->dec
            );
        }

        free(inner);
        return NULL;
    }

    enc->inner = inner->enc;

    /*
     * Wrap the underlying decoding key.
     */
    ZBPRC_DecKey *dec =
        malloc(sizeof(*dec));

    if (dec == NULL) {

        if (enc->inner != NULL) {

            params->underlying->free_enc_key(
                params->underlying->params,
                enc->inner
            );
        }

        if (inner->dec != NULL) {

            params->underlying->free_dec_key(
                params->underlying->params,
                inner->dec
            );
        }

        free(enc);
        free(inner);

        return NULL;
    }

    dec->inner = inner->dec;

    /*
     * Ownership of inner->enc and inner->dec has been
     * transferred to the wrapper keys.
     */
    free(inner);

    /*
     * Return the generic key pair.
     */
    ZBPRC_Keys *keys =
        malloc(sizeof(*keys));

    if (keys == NULL) {

        params->underlying->free_enc_key(
            params->underlying->params,
            enc->inner
        );

        params->underlying->free_dec_key(
            params->underlying->params,
            dec->inner
        );

        free(enc);
        free(dec);

        return NULL;
    }

    keys->enc = enc;
    keys->dec = dec;

    return keys;
}


/*
 * ================================================================
 * Encoding
 * ================================================================
 */

static uint8_t *
prc_dc_encode(
    const void *params_ptr,
    const ZBPRC_EncKey *base_key,
    ZBPRC_Random *random,
    size_t *output_bits)
{
    const PRCDC_Params *params =
        (const PRCDC_Params *)params_ptr;

    const ZBPRC_EncKey *key =
        base_key;
    

    if (!prc_dc_valid_params(params) ||
        key == NULL ||
        random == NULL ||
        output_bits == NULL) {


        return NULL;
    }

    /*
     * First encode the distinguished bit 1 with the underlying
     * zero-bit PRC.
     *
     * The result must contain exactly k bits.
     */
    size_t inner_bits = 0;

    uint8_t *inner =
        params->underlying->encode(
            params->underlying->params,
            key->inner,
            random,
            &inner_bits
        );


    //temp: todo remove after testing:
    printf("Inner bits (%zu):\n", inner_bits);

    for (size_t i = 0; i < inner_bits; ++i) {
        printf("%u",
            (inner[i >> 3] >> (i & 7)) & 1u);
    }

    printf("\n");

    if (inner == NULL)
        return NULL;

    if (inner_bits != params->k) {

        printf("misconfigured number of bits\n");
        free(inner);
        return NULL;
    }

    /*
     * The DC-PRC output consists of k slices of T bits:
     *
     *     z_1 || z_2 || ... || z_k
     *
     * where
     *
     *     Majority(z_i) = inner_i.
     */
    const size_t encoded_bits =
        params->k * params->T;

    const size_t encoded_bytes =
        prc_dc_bytes_for_bits(
            encoded_bits
        );

    uint8_t *output =
        calloc(encoded_bytes, 1);

    if (output == NULL) {

        free(inner);
        return NULL;
    }

    for (size_t i = 0;
         i < params->k;
         ++i) {

        const uint8_t majority =
            get_bit(inner, i);

        if (!sample_majority_slice(
                output,
                i * params->T,
                params->T,
                majority,
                random)) {

            free(output);
            free(inner);

            return NULL;
        }
    }

    free(inner);

    *output_bits =
        encoded_bits;

    return output;
}


/*
 * ================================================================
 * Decoding
 * ================================================================
 */

static int
prc_dc_decode(
    const void *params_ptr,
    const ZBPRC_DecKey *base_key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits)
{
    const PRCDC_Params *params =
        (const PRCDC_Params *)params_ptr;

    const ZBPRC_DecKey *key =
        base_key;

    if (!prc_dc_valid_params(params) ||
        key == NULL ||
        ciphertext == NULL) {

        printf("invalid params. Decoding to 0\n");

        return 0;
    }

    const size_t k =
        params->k;

    /*
     * Every one of the k slices must contain at least one bit.
     */
    if (ciphertext_bits < k)
        return 0;

    /*
     * Partition the received ciphertext into k balanced slices.
     *
     * Let
     *
     *     q = floor(L / k)
     *     r = L mod k.
     *
     * The first r slices have q+1 bits and the remaining
     * k-r slices have q bits.
     */
    const size_t q =
        ciphertext_bits / k;

    const size_t r =
        ciphertext_bits % k;

    /*
     * Reconstruct the k-bit codeword of the underlying PRC.
     */
    const size_t inner_bytes =
        prc_dc_bytes_for_bits(k);

    uint8_t *inner =
        calloc(inner_bytes, 1);

    if (inner == NULL)
        return 0;

    size_t offset = 0;

    for (size_t i = 0;
         i < k;
         ++i) {

        const size_t slice_length =
            q + (i < r ? 1u : 0u);

        const uint8_t majority =
            prc_dc_majority(
                ciphertext,
                offset,
                slice_length
            );

        if (majority)
            set_bit_1(inner, i);

        offset += slice_length;
    }

    /*
     * Defensive sanity check.
     */
    if (offset != ciphertext_bits) {

        printf("insane!\n");

        free(inner);
        return 0;
    }

    printf("Recovered inner bits (%zu):\n", k);

    for (size_t i = 0; i < k; ++i) {
        printf("%u",
            (inner[i >> 3] >> (i & 7)) & 1u);
    }

    printf("\n");


    /*
     * Delegate decoding to the underlying PRC.
     */
    const int result =
        params->underlying->decode(
            params->underlying->params,
            key->inner,
            inner,
            k
        );

    free(inner);

    return result;
}


/*
 * ================================================================
 * Encoding-key destruction
 * ================================================================
 */

static void
prc_dc_free_enc_key(
    const void *params_ptr,
    ZBPRC_EncKey *base_key)
{
    const PRCDC_Params *params =
        (const PRCDC_Params *)params_ptr;

    if (base_key == NULL)
        return;

    if (params != NULL &&
        params->underlying != NULL) {

        if (base_key->inner != NULL) {

            params->underlying->free_enc_key(
                params->underlying->params,
                base_key->inner
            );
        }
    }

    free(base_key);
}


/*
 * ================================================================
 * Decoding-key destruction
 * ================================================================
 */

static void
prc_dc_free_dec_key(
    const void *params_ptr,
    ZBPRC_DecKey *base_key)
{
    const PRCDC_Params *params =
        (const PRCDC_Params *)params_ptr;

    if (base_key == NULL)
        return;

    if (params != NULL &&
        params->underlying != NULL) {

        if (base_key->inner != NULL) {

            params->underlying->free_dec_key(
                params->underlying->params,
                base_key->inner
            );
        }
    }

    free(base_key);
}


/*
 * ================================================================
 * DC-PRC construction
 * ================================================================
 */

ZBPRC
prc_dc_create(
    const PRCDC_Params *params)
{
    ZBPRC prc = {
        .params = params,

        .keygen =
            prc_dc_keygen,

        .encode =
            prc_dc_encode,

        .decode =
            prc_dc_decode,

        .free_enc_key =
            prc_dc_free_enc_key,

        .free_dec_key =
            prc_dc_free_dec_key
    };

    return prc;
}