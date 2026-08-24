#include "prc_pp.h"

#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <math.h>
#include <stdio.h>


/*
 * ================================================================
 * Key structures
 * ================================================================
 */

struct ZBPRC_EncKey {

    size_t n;
    size_t q;
    size_t symbol_bits;

    /*
     * sigma[i] determines the source symbol used at position i:
     *
     *     hat_c[i] = pi_i(c[sigma[i]])
     */
    size_t *sigma;

    /*
     * pi[i] is a permutation of {0,...,q-1}.
     *
     * pi[i][x] gives the image of x.
     */
    size_t **pi;

    /*
     * One-time pad, one q-ary symbol per position.
     */
    size_t *otp;
};


struct ZBPRC_DecKey {

    size_t n;
    size_t q;
    size_t symbol_bits;

    size_t *sigma;

    /*
     * Inverse permutations.
     *
     * pi_inv[i][x] = pi[i]^{-1}(x)
     */
    size_t **pi_inv;

    size_t *otp;
};


/*
 * ================================================================
 * Randomness
 * ================================================================
 */

 //1 on success
static int
random_bytes(
    RandomnessSource *random,
    uint8_t *out,
    size_t len)
{
    if (!random || !random->rng)
        return -1;

    if (len == 0)
        return 1;

    return random->rng(
        random->ctx,
        out,
        len
    );
}


/*
 * Unbiased random value in [0,bound).
 */
static int
random_bounded(
    RandomnessSource *random,
    size_t bound,
    size_t *out)
{
    if (!random || !out || bound == 0)
        return 0;

    /*
     * Use a byte-oriented rejection sampler rather than
     * assuming that size_t itself is uniformly generated.
     */
    size_t bits = 0;
    size_t x = bound - 1;

    while (x != 0) {
        bits++;
        x >>= 1;
    }

    size_t bytes = (bits + 7) / 8;

    if (bytes == 0)
        bytes = 1;

    for (;;) {

        uint8_t buf[sizeof(size_t)] = {0};

        if (bytes > sizeof(buf))
            return 0;

        if (!random_bytes(
                random,
                buf,
                bytes))
            return 0;

        x = 0;

        for (size_t i = 0; i < bytes; i++)
            x |= ((size_t)buf[i]) << (8 * i);

        /*
         * Mask unused high bits.
         */
        if (bits < sizeof(size_t) * 8)
            x &= (((size_t)1 << bits) - 1);

        if (x < bound) {
            *out = x;
            return 1;
        }
    }
}


/*
 * ================================================================
 * Permutation helpers
 * ================================================================
 */

static int
sample_permutation(
    RandomnessSource *random,
    size_t q,
    size_t *p)
{
    for (size_t i = 0; i < q; i++)
        p[i] = i;

    /*
     * Fisher-Yates.
     */
    for (size_t i = q; i > 1; i--) {

        size_t j;

        if (!random_bounded(
                random,
                i,
                &j))
            return -1;

        size_t tmp = p[i - 1];
        p[i - 1] = p[j];
        p[j] = tmp;
    }

    return 0;
}


static int
invert_permutation(
    const size_t *p,
    size_t q,
    size_t *inv)
{
    for (size_t i = 0; i < q; i++)
        inv[p[i]] = i;

    return 0;
}


static int
sample_sigma(
    RandomnessSource *random,
    size_t n,
    size_t *sigma)
{
    for (size_t i = 0; i < n; i++)
        sigma[i] = i;

    for (size_t i = n; i > 1; i--) {

        size_t j;

        if (!random_bounded(
                random,
                i,
                &j))
            return -1;

        size_t tmp = sigma[i - 1];
        sigma[i - 1] = sigma[j];
        sigma[j] = tmp;
    }

    return 0;
}


/*
 * ================================================================
 * Symbol serialization
 * ================================================================
 *
 * Symbols are packed consecutively, least-significant bit first.
 *
 * For example, for symbol_bits = 4:
 *
 *   symbols: a b c
 *
 * are represented as:
 *
 *   [a0 a1 a2 a3 | b0 b1 b2 b3 | c0 c1 c2 c3]
 *
 * q need not be a power of two. Values >= q are simply invalid.
 */


/*
 * Read one symbol.
 */
static size_t
get_symbol(
    const uint8_t *buf,
    size_t symbol_index,
    size_t symbol_bits)
{
    size_t bit_offset =
        symbol_index * symbol_bits;

    size_t value = 0;

    for (size_t j = 0; j < symbol_bits; j++) {

        size_t bit =
            bit_offset + j;

        uint8_t b =
            (uint8_t)(
                (buf[bit >> 3] >> (bit & 7)) & 1u
            );

        value |= b << j;
    }

    return value;
}


/*
 * Write one symbol.
 */
static void
set_symbol(
    uint8_t *buf,
    size_t symbol_index,
    size_t symbol_bits,
    size_t value)
{
    size_t bit_offset =
        symbol_index * symbol_bits;

    for (size_t j = 0; j < symbol_bits; j++) {

        size_t bit =
            bit_offset + j;

        uint8_t mask =
            (uint8_t)(1u << (bit & 7));

        if ((value >> j) & 1u)
            buf[bit >> 3] |= mask;
        else
            buf[bit >> 3] &= (uint8_t)~mask;
    }
}


/*
 * ================================================================
 * Size helpers
 * ================================================================
 */

static int
checked_symbol_bytes(
    size_t n,
    size_t symbol_bits,
    size_t *bytes)
{
    if (symbol_bits == 0)
        return -1;

    if (n > SIZE_MAX / symbol_bits)
        return -1;

    size_t bits =
        n * symbol_bits;

    *bytes =
        (bits + 7) / 8;

    return 0;
}


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static ZBPRC_Keys *
zbprc_pp_keygen(
    const void *vparams,
    RandomnessSource *random)
{
    const PPParams *params =
        vparams;

    if (!params ||
        !params->ecc ||
        !random ||
        params->q < 2 ||
        params->symbol_bits == 0 ||
        params->n == 0)
        return NULL;

    printf("k1\n");
    /*
     * q must fit in symbol_bits bits.
     */
    if (params->symbol_bits <
        sizeof(size_t) * 8) {

        size_t max_symbol =
            ((size_t)1 << params->symbol_bits);

        if (params->q > max_symbol)
            return NULL;
    }

    printf("k2\n");

    size_t encoded_bytes;

    if (checked_symbol_bytes(
            params->n,
            params->symbol_bits,
            &encoded_bytes) != 0)
        return NULL;

    printf("k3\n");

    /*
     * The ECC's encoded representation must have exactly
     * this many bytes.
     */
    printf("enc %zu\n", encoded_bytes);
    printf("%zu\n", ecc_encoded_size(
            params->ecc,
            params->message_bytes));

    if (ecc_encoded_size(
            params->ecc,
            params->message_bytes) != encoded_bytes)
        return NULL;

    printf("k4\n");

    /*
     * sigma.
     */
    size_t *sigma =
        malloc(params->n * sizeof(*sigma));

    if (!sigma)
        return NULL;

    printf("k5\n");

    if (sample_sigma(
            random,
            params->n,
            sigma) != 0) {

        free(sigma);
        return NULL;
    }

    printf("k6\n");

    /*
     * pi and inverse pi.
     */
    size_t **pi =
        calloc(params->n, sizeof(*pi));

    size_t **pi_inv =
        calloc(params->n, sizeof(*pi_inv));

    if (!pi || !pi_inv)
        goto fail;

    printf("k6a\n");

    for (size_t i = 0; i < params->n; i++) {

        pi[i] =
            malloc(params->q * sizeof(size_t));

        pi_inv[i] =
            malloc(params->q * sizeof(size_t));

        if (!pi[i] || !pi_inv[i])
            goto fail;

        if (sample_permutation(
                random,
                params->q,
                pi[i]) != 0)
            goto fail;

        invert_permutation(
            pi[i],
            params->q,
            pi_inv[i]
        );
    }

    printf("k7\n");

    /*
     * q-ary OTP.
     */
    size_t *otp =
        malloc(params->n * sizeof(*otp));

    if (!otp)
        goto fail;

    for (size_t i = 0; i < params->n; i++) {

        if (!random_bounded(
                random,
                params->q,
                &otp[i])) {

            free(otp);
            goto fail;
        }
    }

    /*
     * Allocate key pair.
     */
    ZBPRC_Keys *keys =
        calloc(1, sizeof(*keys));

    if (!keys)
        goto fail_otp;

    keys->enc =
        calloc(1, sizeof(*keys->enc));

    keys->dec =
        calloc(1, sizeof(*keys->dec));

    if (!keys->enc || !keys->dec) {
        free(keys->enc);
        free(keys->dec);
        free(keys);
        goto fail_otp;
    }

    /*
     * We copy sigma/pi because encryption and decryption keys
     * are independently owned.
     */
    keys->enc->n = params->n;
    keys->enc->q = params->q;
    keys->enc->symbol_bits = params->symbol_bits;

    keys->dec->n = params->n;
    keys->dec->q = params->q;
    keys->dec->symbol_bits = params->symbol_bits;

    keys->enc->sigma =
        malloc(params->n * sizeof(size_t));

    keys->dec->sigma =
        malloc(params->n * sizeof(size_t));

    keys->enc->otp =
        malloc(params->n * sizeof(size_t));

    keys->dec->otp =
        malloc(params->n * sizeof(size_t));

    if (!keys->enc->sigma ||
        !keys->dec->sigma ||
        !keys->enc->otp ||
        !keys->dec->otp)
        goto fail_keys;

    memcpy(
        keys->enc->sigma,
        sigma,
        params->n * sizeof(size_t)
    );

    memcpy(
        keys->dec->sigma,
        sigma,
        params->n * sizeof(size_t)
    );

    memcpy(
        keys->enc->otp,
        otp,
        params->n * sizeof(size_t)
    );

    memcpy(
        keys->dec->otp,
        otp,
        params->n * sizeof(size_t)
    );

    /*
     * Copy permutations.
     */
    keys->enc->pi =
        calloc(params->n, sizeof(size_t *));

    keys->dec->pi_inv =
        calloc(params->n, sizeof(size_t *));

    if (!keys->enc->pi ||
        !keys->dec->pi_inv)
        goto fail_keys;

    for (size_t i = 0; i < params->n; i++) {

        keys->enc->pi[i] =
            malloc(params->q * sizeof(size_t));

        keys->dec->pi_inv[i] =
            malloc(params->q * sizeof(size_t));

        if (!keys->enc->pi[i] ||
            !keys->dec->pi_inv[i])
            goto fail_keys;

        memcpy(
            keys->enc->pi[i],
            pi[i],
            params->q * sizeof(size_t)
        );

        memcpy(
            keys->dec->pi_inv[i],
            pi_inv[i],
            params->q * sizeof(size_t)
        );
    }

    /*
     * Clean temporary material.
     */
    free(sigma);
    free(otp);

    for (size_t i = 0; i < params->n; i++) {
        free(pi[i]);
        free(pi_inv[i]);
    }

    free(pi);
    free(pi_inv);

    return keys;


fail_keys:

    if (keys) {

        if (keys->enc) {
            free(keys->enc->sigma);
            free(keys->enc->otp);

            if (keys->enc->pi) {
                for (size_t i = 0; i < params->n; i++)
                    free(keys->enc->pi[i]);

                free(keys->enc->pi);
            }
        }

        if (keys->dec) {
            free(keys->dec->sigma);
            free(keys->dec->otp);

            if (keys->dec->pi_inv) {
                for (size_t i = 0; i < params->n; i++)
                    free(keys->dec->pi_inv[i]);

                free(keys->dec->pi_inv);
            }
        }

        free(keys->enc);
        free(keys->dec);
        free(keys);
    }

fail_otp:
    free(otp);

fail:

    if (pi) {
        for (size_t i = 0; i < params->n; i++)
            free(pi[i]);

        free(pi);
    }

    if (pi_inv) {
        for (size_t i = 0; i < params->n; i++)
            free(pi_inv[i]);

        free(pi_inv);
    }

    free(sigma);

    return NULL;
}


/*
 * ================================================================
 * Symbol substitution channel
 * ================================================================
 *
 * IMPORTANT:
 *
 * channel_edits() works on bits. It therefore cannot directly
 * implement SC_delta over F_q.
 *
 * SC_p below implements the actual q-ary substitution channel:
 *
 * with probability p:
 *
 *     x -> uniformly random y in F_q \ {x}
 *
 * otherwise:
 *
 *     x -> x
 *
 * This is the channel specified by the PRC construction.
 */

static int
sample_substituted_symbol(
    size_t x,
    size_t q,
    double probability,
    RandomnessSource *random,
    size_t *result)
{
    if (probability <= 0.0) {
        *result = x;
        return 0;
    }

    if (probability >= 1.0) {

        size_t y;

        if (!random_bounded(
                random,
                q - 1,
                &y))
            return -1;

        /*
         * Map [0,q-2] to F_q \ {x}.
         */
        *result =
            (y >= x) ? y + 1 : y;

        return 0;
    }

    /*
     * Generate a uniform random double from 53 random bits.
     */
    uint64_t r;

    if (!random_bytes(
            random,
            (uint8_t *)&r,
            sizeof(r)))
        return -1;

    double u =
        (double)(r >> 11) *
        (1.0 / 9007199254740992.0);

    if (u >= probability) {
        *result = x;
        return 0;
    }

    size_t y;

    if (!random_bounded(
            random,
            q - 1,
            &y))
        return -1;

    *result =
        (y >= x) ? y + 1 : y;

    return 0;
}


/*
 * ================================================================
 * Encode
 * ================================================================
 */

static uint8_t *
zbprc_pp_encode(
    const void *vparams,
    const ZBPRC_EncKey *key,
    RandomnessSource *random,
    size_t *output_bits)
{
    const PPParams *params =
        vparams;

    if (!params ||
        !params->ecc ||
        !key ||
        !random ||
        !output_bits)
        return NULL;

    size_t encoded_bytes;

    if (checked_symbol_bytes(
            key->n,
            key->symbol_bits,
            &encoded_bytes) != 0)
        return NULL;


    /*
     * ------------------------------------------------------------
     * 1. Sample x <- F_q^k and encode.
     * ------------------------------------------------------------
     *
     * Since the ECC interface works on bytes, the random message
     * is represented as message_bytes random bytes.
     */

    uint8_t *message =
        malloc(params->message_bytes);

    uint8_t *encoded =
        calloc(encoded_bytes, 1);

    if (!message || !encoded) {
        free(message);
        free(encoded);
        return NULL;
    }

    if (!random_bytes(
            random,
            message,
            params->message_bytes)) {

        free(message);
        free(encoded);
        return NULL;
    }

    size_t encoded_len =
        encoded_bytes;

    if (ecc_encode(
            params->ecc,
            message,
            params->message_bytes,
            encoded,
            &encoded_len) != 0 ||
        encoded_len != encoded_bytes) {

        free(message);
        free(encoded);
        return NULL;
    }

    free(message);


    /*
     * ------------------------------------------------------------
     * 2. sigma and pi_i.
     *
     *     hat_c_i = pi_i(c_{sigma(i)})
     * ------------------------------------------------------------
     */

    uint8_t *permuted =
        calloc(encoded_bytes, 1);

    if (!permuted) {
        free(encoded);
        return NULL;
    }

    for (size_t i = 0; i < key->n; i++) {

        size_t source =
            key->sigma[i];

        size_t symbol =
            get_symbol(
                encoded,
                source,
                key->symbol_bits
            );

        /*
         * The ECC serialization must only contain valid
         * F_q symbols.
         */
        if (symbol >= key->q) {
            free(encoded);
            free(permuted);
            return NULL;
        }

        symbol =
            key->pi[i][symbol];

        set_symbol(
            permuted,
            i,
            key->symbol_bits,
            symbol
        );
    }

    free(encoded);


    /*
     * ------------------------------------------------------------
     * 3. SC_{delta/2}.
     * ------------------------------------------------------------
     */

    uint8_t *noisy =
        calloc(encoded_bytes, 1);

    if (!noisy) {
        free(permuted);
        return NULL;
    }

    for (size_t i = 0; i < key->n; i++) {

        size_t symbol =
            get_symbol(
                permuted,
                i,
                key->symbol_bits
            );

        size_t noisy_symbol;

        if (sample_substituted_symbol(
                symbol,
                key->q,
                params->delta / 2.0,
                random,
                &noisy_symbol) != 0) {

            free(permuted);
            free(noisy);
            return NULL;
        }

        set_symbol(
            noisy,
            i,
            key->symbol_bits,
            noisy_symbol
        );
    }

    free(permuted);


    /*
     * ------------------------------------------------------------
     * 4. OTP:
     *
     *     c = c' + o
     *
     * over F_q.
     * ------------------------------------------------------------
     */

    uint8_t *ciphertext =
        calloc(encoded_bytes, 1);

    if (!ciphertext) {
        free(noisy);
        return NULL;
    }

    for (size_t i = 0; i < key->n; i++) {

        size_t symbol =
            get_symbol(
                noisy,
                i,
                key->symbol_bits
            );

        /*
         * Addition in F_q is NOT generally integer addition
         * modulo q.
         *
         * The PRC construction requires the actual field
         * operation here.
         *
         * Therefore this implementation assumes q-ary symbols
         * are represented by Z_q for the OTP operation.
         *
         * For GF(2^m), this must instead be field addition/XOR.
         */
        symbol =
            (symbol + key->otp[i]) %
            key->q;

        set_symbol(
            ciphertext,
            i,
            key->symbol_bits,
            symbol
        );
    }

    free(noisy);

    *output_bits =
        key->n * key->symbol_bits;

    return ciphertext;
}


/*
 * ================================================================
 * Hamming distance over F_q
 * ================================================================
 */

static size_t
symbol_hamming_distance(
    const uint8_t *a,
    const uint8_t *b,
    size_t n,
    size_t symbol_bits)
{
    size_t distance = 0;

    for (size_t i = 0; i < n; i++) {

        size_t x =
            get_symbol(
                a,
                i,
                symbol_bits
            );

        size_t y =
            get_symbol(
                b,
                i,
                symbol_bits
            );

        if (x != y)
            distance++;
    }

    return distance;
}


/*
 * ================================================================
 * Decode
 * ================================================================
 */

static int
zbprc_pp_decode(
    const void *vparams,
    const ZBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits)
{
    const PPParams *params =
        vparams;

    if (!params ||
        !params->ecc ||
        !key ||
        !ciphertext)
        return 0;

    size_t expected_bits =
        key->n * key->symbol_bits;

    if (ciphertext_bits != expected_bits)
        return 0;

    size_t encoded_bytes;

    if (checked_symbol_bytes(
            key->n,
            key->symbol_bits,
            &encoded_bytes) != 0)
        return 0;


    /*
     * ------------------------------------------------------------
     * 1. Remove OTP.
     *
     * For the Z_q representation:
     *
     *     c' = c - o mod q.
     * ------------------------------------------------------------
     */

    uint8_t *unmasked =
        calloc(encoded_bytes, 1);

    if (!unmasked)
        return 0;

    for (size_t i = 0; i < key->n; i++) {

        size_t c =
            get_symbol(
                ciphertext,
                i,
                key->symbol_bits
            );

        if (c >= key->q) {
            free(unmasked);
            return 0;
        }

        size_t symbol =
            (c + key->q - key->otp[i]) %
            key->q;

        set_symbol(
            unmasked,
            i,
            key->symbol_bits,
            symbol
        );
    }


    /*
     * ------------------------------------------------------------
     * 2. Undo sigma and pi.
     *
     * Encoding:
     *
     *     hat_c[i] = pi_i(c[sigma[i]])
     *
     * Therefore:
     *
     *     c[sigma[i]]
     *       = pi_i^{-1}(hat_c[i]).
     * ------------------------------------------------------------
     */

    uint8_t *codeword =
        calloc(encoded_bytes, 1);

    if (!codeword) {
        free(unmasked);
        return 0;
    }

    for (size_t i = 0; i < key->n; i++) {

        size_t symbol =
            get_symbol(
                unmasked,
                i,
                key->symbol_bits
            );

        if (symbol >= key->q) {
            free(unmasked);
            free(codeword);
            return 0;
        }

        symbol =
            key->pi_inv[i][symbol];

        set_symbol(
            codeword,
            key->sigma[i],
            key->symbol_bits,
            symbol
        );
    }

    free(unmasked);


    /*
     * ------------------------------------------------------------
     * 3. Decode C.
     * ------------------------------------------------------------
     */

    size_t decoded_bytes =
        ecc_decoded_size(
            params->ecc,
            encoded_bytes
        );

    if (decoded_bytes == 0) {
        free(codeword);
        return 0;
    }

    uint8_t *message =
        malloc(decoded_bytes);

    if (!message) {
        free(codeword);
        return 0;
    }

    if (ecc_decode(
            params->ecc,
            codeword,
            encoded_bytes,
            message,
            decoded_bytes) != 0) {

        free(message);
        free(codeword);
        return 0;
    }


    /*
     * ------------------------------------------------------------
     * 4. Re-encode.
     * ------------------------------------------------------------
     */

    uint8_t *reencoded =
        calloc(encoded_bytes, 1);

    if (!reencoded) {
        free(message);
        free(codeword);
        return 0;
    }

    size_t reencoded_len =
        encoded_bytes;

    if (ecc_encode(
            params->ecc,
            message,
            decoded_bytes,
            reencoded,
            &reencoded_len) != 0 ||
        reencoded_len != encoded_bytes) {

        free(message);
        free(codeword);
        free(reencoded);
        return 0;
    }

    free(message);


    /*
     * ------------------------------------------------------------
     * 5. Check
     *
     *     D_H(hat_c,c'') <= delta*n.
     * ------------------------------------------------------------
     */

    size_t distance =
        symbol_hamming_distance(
            reencoded,
            codeword,
            key->n,
            key->symbol_bits
        );

    free(codeword);
    free(reencoded);

    if ((double)distance >
        params->delta * (double)key->n)
        return 0;

    return 1;
}


/*
 * ================================================================
 * Destruction
 * ================================================================
 */

static void
zbprc_pp_free_enc_key(
    const void *vparams,
    ZBPRC_EncKey *key)
{
    (void)vparams;

    if (!key)
        return;

    free(key->sigma);
    free(key->otp);

    if (key->pi) {
        for (size_t i = 0; i < key->n; i++)
            free(key->pi[i]);

        free(key->pi);
    }

    free(key);
}


static void
zbprc_pp_free_dec_key(
    const void *vparams,
    ZBPRC_DecKey *key)
{
    (void)vparams;

    if (!key)
        return;

    free(key->sigma);
    free(key->otp);

    if (key->pi_inv) {
        for (size_t i = 0; i < key->n; i++)
            free(key->pi_inv[i]);

        free(key->pi_inv);
    }

    free(key);
}


/*
 * ================================================================
 * Blocksize
 * ================================================================
 */

static size_t
zbprc_pp_blocksize(
    const void *vparams)
{
    const PPParams *params =
        vparams;

    if (!params)
        return 0;

    if (params->n >
        SIZE_MAX / params->symbol_bits)
        return 0;

    return params->n * params->symbol_bits;
}


/*
 * ================================================================
 * Initialization
 * ================================================================
 */

ZBPRC
prc_pp(
   const PPParams *params)
{
    ZBPRC prc = {
        .params = params,

        .decode = zbprc_pp_decode,
        .encode = zbprc_pp_encode,
        .blocksize = zbprc_pp_blocksize,
        .keygen = zbprc_pp_keygen,
        .free_dec_key = zbprc_pp_free_dec_key,
        .free_enc_key = zbprc_pp_free_enc_key
    };

    return prc;

}