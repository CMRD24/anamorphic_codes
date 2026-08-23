#include "prc_high.h"

#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <stdio.h>

#include "../../../utils/csprg_sodium.h"


/*
 * ================================================================
 * Internal key structures
 * ================================================================
 */

struct MBPRC_EncKey {

    /*
     * Encoding key of the underlying PRC.
     */
    MBPRC_EncKey *low_enc_key;

    /*
     * Bit permutation.
     *
     * permutation[i] = destination position of source bit i.
     *
     * Thus encoding writes:
     *
     *     ciphertext[permutation[i]] = input[i]
     *
     * The inverse permutation is stored in the decoding key.
     */
    size_t *permutation;

    size_t permutation_length;
};


struct MBPRC_DecKey {

    /*
     * Decoding key of the underlying PRC.
     */
    MBPRC_DecKey *low_dec_key;

    /*
     * Inverse bit permutation.
     *
     * inverse_permutation[i] = source position for output bit i.
     */
    size_t *permutation;

    size_t permutation_length;
};


/*
 * ================================================================
 * Utility functions
 * ================================================================
 */


/*
 * Set a single bit in a packed byte array.
 *
 * Bits are numbered from the least significant bit of byte 0.
 */
static void
set_bit(
    uint8_t *buffer,
    size_t bit,
    uint8_t value)
{
    size_t byte_index = bit / 8;
    size_t bit_index  = bit % 8;

    if (value)
        buffer[byte_index] |= (uint8_t)(1u << bit_index);
    else
        buffer[byte_index] &= (uint8_t)~(1u << bit_index);
}


static uint8_t
get_bit(
    const uint8_t *buffer,
    size_t bit)
{
    size_t byte_index = bit / 8;
    size_t bit_index  = bit % 8;

    return (uint8_t)(
        (buffer[byte_index] >> bit_index) & 1u
    );
}


/*
 * XOR two byte arrays.
 */
static void
xor_bytes(
    uint8_t *dst,
    const uint8_t *a,
    const uint8_t *b,
    size_t len)
{
    for (size_t i = 0; i < len; ++i)
        dst[i] = a[i] ^ b[i];
}



static int
random_size_t(
    RandomnessSource *random,
    size_t *out)
{
    uint8_t bytes[sizeof(size_t)];

    if (!random ||
        !random->rng ||
        !out)
    {
        return 0;
    }

    if (!random->rng(
            random->ctx,
            bytes,
            sizeof(bytes)))
    {
        return 0;
    }

    size_t value = 0;

    for (size_t i = 0;
         i < sizeof(bytes);
         ++i)
    {
        value =
            (value << 8) |
            bytes[i];
    }

    *out = value;

    return 1;
}


/*
 * ================================================================
 * Random integer
 * ================================================================
 *
 * Returns a uniformly distributed random value in [0, bound).
 *
 * Rejection sampling is used to avoid modulo bias.
 * ================================================================
 */



/*
 * Sample an unbiased value in [0, bound).
 */
static int
random_bounded(
    RandomnessSource *random,
    size_t bound,
    size_t *out)
{
    if (bound == 0)
        return 0;

    /*
     * Rejection sampling.
     */
    size_t limit =
        SIZE_MAX - (SIZE_MAX % bound);

    size_t value;

    do {

        if (!random_size_t(
                random,
                &value))
        {
            return 0;
        }

    } while (value >= limit);

    *out = value % bound;

    return 1;
}




/*
 * ================================================================
 * Random permutation
 * ================================================================
 *
 * Fisher-Yates shuffle.
 *
 * permutation initially contains:
 *
 *     0, 1, ..., n-1
 *
 * and is then uniformly shuffled.
 * ================================================================
 */

static int
generate_permutation(
    size_t *permutation,
    size_t n,
    RandomnessSource *random)
{
    if (!permutation || !random)
        return -1;

    for (size_t i = 0; i < n; ++i)
        permutation[i] = i;

    if (n < 2)
        return 0;

    for (size_t i = n - 1; i > 0; --i) {

        size_t j;

        if (!random_bounded(
                random,
                i + 1,
                &j))
            return -1;

        size_t tmp = permutation[i];
        permutation[i] = permutation[j];
        permutation[j] = tmp;
    }

    return 0;
}



/*
 * ================================================================
 * Key generation
 * ================================================================
 */

static MBPRC_Keys *
high_keygen(
    const void *params_ptr,
    RandomnessSource *random)
{
    const PRCHigh_Params *params = params_ptr;

    if (!params ||
        !params->low_prc ||
        !params->ecc ||
        !random)
        return NULL;

    const size_t low_bits =
        params->low_prc->blocksize(params->low_prc->params);

    const size_t ecc_bits =
        params->ecc->encoded_size(params->message_bits / 8) * 8;

    if (low_bits > SIZE_MAX - ecc_bits)
        return NULL;

    const size_t total_bits = low_bits + ecc_bits;

    MBPRC_Keys *low_keys =
        mbprc_keygen(params->low_prc, random);

    if (!low_keys)
        return NULL;

    MBPRC_EncKey *enc_key = NULL;
    MBPRC_DecKey *dec_key = NULL;
    size_t *permutation = NULL;
    MBPRC_Keys *keys = NULL;

    enc_key = calloc(1, sizeof(*enc_key));
    dec_key = calloc(1, sizeof(*dec_key));
    permutation = malloc(total_bits * sizeof(*permutation));

    if (!enc_key || !dec_key || !permutation)
        goto fail;

    if (generate_permutation(
            permutation,
            total_bits,
            random) != 0)
        goto fail;

    keys = calloc(1, sizeof(*keys));

    if (!keys)
        goto fail;

    /*
     * Transfer ownership of the underlying PRC keys.
     */
    enc_key->low_enc_key = low_keys->enc;
    dec_key->low_dec_key = low_keys->dec;

    low_keys->enc = NULL;
    low_keys->dec = NULL;

    enc_key->permutation = permutation;
    enc_key->permutation_length = total_bits;

    dec_key->permutation = permutation;
    dec_key->permutation_length = total_bits;

    keys->enc = enc_key;
    keys->dec = dec_key;

    mbprc_free_keys(params->low_prc, low_keys);

    return keys;

fail:
    free(permutation);
    free(enc_key);
    free(dec_key);
    free(keys);

    mbprc_free_keys(params->low_prc, low_keys);

    return NULL;
}

/*
//remove after testing:
static int
save_codeword(const char *filename,
              const uint8_t *codeword,
              size_t bits)
{
    FILE *file =
        fopen(filename, "w");

    if (file == NULL) {
        perror("fopen");
        return 0;
    }

    for (size_t i = 0;
         i < bits;
         ++i) {

        if (fputc(
                (codeword[i >> 3] &
                 (uint8_t)(1u << (i & 7)))
                ? '1'
                : '0',
                file) == EOF) {

            fclose(file);
            return 0;
        }
    }

    if (fputc('\n', file) == EOF) {
        fclose(file);
        return 0;
    }

    fclose(file);

    return 1;
}

*/

/*
 * ================================================================
 * Encode
 * ================================================================
 */

static uint8_t *
high_encode(
    const void *params_ptr,
    const MBPRC_EncKey *key_ptr,
    const uint8_t *message,
    size_t message_bits,
    RandomnessSource *random,
    size_t *output_bits)
{
    const PRCHigh_Params *params =
        (const PRCHigh_Params *)params_ptr;

    const MBPRC_EncKey *key =
        (const MBPRC_EncKey *)key_ptr;

    if (!params ||
        !key ||
        !message ||
        !random ||
        !output_bits){
            printf("t1\n");
            return NULL;

        }
        

    
    /*
     * The ECC interface operates on whole bytes.
     */
    if (message_bits % 8 != 0){
        printf("Message bits must be devisible by 8\n");
        return NULL;
    }
    
        

    const size_t message_len =
        message_bits / 8;

    /*
     * The seed consists of lambda bits.
     */
    const size_t seed_len =
        params->lambda / 8;

    printf("t3\n");
    /*
     * Determine the ECC codeword size.
     */
    const size_t ecc_len =
        ecc_encoded_size(
            params->ecc,
            message_len
        );

    printf("t4\n");

    if (ecc_len == 0)
        return NULL;

    printf("t4a\n");

    /*
     * ------------------------------------------------------------
     * 1. Sample random seed r
     * ------------------------------------------------------------
     */

    uint8_t seed[seed_len];

    if (!random->rng(
            random->ctx,
            seed,
            seed_len))
        return NULL;

    printf("t5\n");
    /*
     * ------------------------------------------------------------
     * 2. Encode seed using low PRC
     * ------------------------------------------------------------
     */

    size_t low_codeword_bits = params->low_prc->blocksize(params->low_prc->params);

    const size_t low_capacity =
        (low_codeword_bits + 7) / 8;

    uint8_t *low_codeword =
        calloc(1, low_capacity);

    printf("t6\n");

    if (!low_codeword)
        return NULL;

    size_t low_output_bits = 0;

    if (!params->low_prc->encode) {
        free(low_codeword);
        return NULL;
    }

    uint8_t *encoded_seed =
        mbprc_encode(
            params->low_prc,
            key->low_enc_key,
            seed,
            params->lambda,
            random,
            &low_output_bits
        );

    if (!encoded_seed ||
        low_output_bits != low_codeword_bits) {

        free(encoded_seed);
        free(low_codeword);

        return NULL;
    }

    //save_codeword("test-enc.txt", encoded_seed, low_output_bits);

    free(low_codeword);


    


    /*
     * ------------------------------------------------------------
     * 3. ECC.Encode(m)
     * ------------------------------------------------------------
     */

    uint8_t *ecc_codeword =
        malloc(ecc_len);

    if (!ecc_codeword) {
        free(encoded_seed);
        return NULL;
    }

    size_t actual_ecc_len = 0;

    if (ecc_encode(
            params->ecc,
            message,
            message_len,
            ecc_codeword,
            &actual_ecc_len) != 0 ||
        actual_ecc_len != ecc_len) {

        free(encoded_seed);
        free(ecc_codeword);

        return NULL;
    }

    

    /*
     * ------------------------------------------------------------
     * 4. Generate PRG(r)
     * ------------------------------------------------------------
     */

    uint8_t *mask =
        malloc(ecc_len);

    if (!mask) {
        free(encoded_seed);
        free(ecc_codeword);
        return NULL;
    }

    //const CSPRG *csprg = csprg_sodium();
    RandomnessSource rand = csprg_randomness(seed, seed_len);
    

    if (rand.rng(rand.ctx, mask, ecc_len) != 0) {

        free(encoded_seed);
        free(ecc_codeword);
        free(mask);

        return NULL;
    }

    /*
     * ------------------------------------------------------------
     * 5. ECC(m) XOR PRG(r)
     * ------------------------------------------------------------
     */

    uint8_t *masked_ecc =
        malloc(ecc_len);

    if (!masked_ecc) {
        free(encoded_seed);
        free(ecc_codeword);
        free(mask);

        return NULL;
    }

    xor_bytes(
        masked_ecc,
        ecc_codeword,
        mask,
        ecc_len
    );

    free(ecc_codeword);
    free(mask);

    /*
     * ------------------------------------------------------------
     * 6. Concatenate
     *
     *     encoded_seed || masked_ecc
     * ------------------------------------------------------------
     */

    size_t ecc_codeword_bits = params->ecc->encoded_size(params->message_bits/8)*8;


    const size_t total_bits =
        low_codeword_bits +
        ecc_codeword_bits;

    const size_t total_bytes =
        (total_bits + 7) / 8;

    uint8_t *unpermuted =
        calloc(1, total_bytes);

    uint8_t *ciphertext =
        calloc(1, total_bytes);

    if (!unpermuted || !ciphertext) {

        free(encoded_seed);
        free(masked_ecc);
        free(unpermuted);
        free(ciphertext);

        return NULL;
    }

    /*
     * Copy low PRC codeword bits.
     */
    for (size_t i = 0;
         i < low_codeword_bits;
         ++i) {

        set_bit(
            unpermuted,
            i,
            get_bit(encoded_seed, i)
        );
    }

    /*
     * Copy masked ECC codeword bits.
     */
    for (size_t i = 0;
         i < ecc_codeword_bits;
         ++i) {

        set_bit(
            unpermuted,
            low_codeword_bits + i,
            get_bit(masked_ecc, i)
        );
    }

    free(encoded_seed);
    free(masked_ecc);

    /*
     * ------------------------------------------------------------
     * 7. Apply permutation
     * ------------------------------------------------------------
     *
     * c[pi(i)] = c_hat[i]
     */

    for (size_t i = 0;
         i < total_bits;
         ++i) {

        set_bit(
            ciphertext,
            key->permutation[i],
            get_bit(unpermuted, i)
        );
    }

    free(unpermuted);

    *output_bits = total_bits;

    return ciphertext;
}




/*
 * ================================================================
 * Decode
 * ================================================================
 */

static int
high_decode(
    const void *params_ptr,
    const MBPRC_DecKey *key_ptr,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out)
{
    const PRCHigh_Params *params =
        (const PRCHigh_Params *)params_ptr;

    const MBPRC_DecKey *key =
        (const MBPRC_DecKey *)key_ptr;

    if (!params ||
        !key ||
        !ciphertext ||
        !message_out ||
        !message_bits_out)
        return 0;

    

    size_t low_bits = params->low_prc->blocksize(params->low_prc->params);
    size_t ecc_bits = params->ecc->encoded_size(params->message_bits/8)*8;

    const size_t total_bits =
        low_bits +
        ecc_bits;

    if (ciphertext_bits != total_bits)
        return 0;

    /*
     * ------------------------------------------------------------
     * 1. Undo permutation
     *
     * y[i] = c[pi(i)]
     * ------------------------------------------------------------
     */

    const size_t total_bytes =
        (total_bits + 7) / 8;

    uint8_t *y =
        calloc(1, total_bytes);

    if (!y)
        return 0;

    // for (size_t i = 0;
    //      i < total_bits;
    //      ++i) {

    //     set_bit(
    //         y,
    //         i,
    //         get_bit(
    //             ciphertext,
    //             key->permutation_length == 0
    //                 ? i
    //                 : key->inverse_permutation[i]
    //         )
    //     );
    // }

        for (size_t i = 0; i < total_bits; ++i) {
        set_bit(
            y,
            i,
            get_bit(ciphertext, key->permutation[i])
        );
    }

    /*
     * ------------------------------------------------------------
     * 2. Split
     *
     *     y = y0 || y1
     * ------------------------------------------------------------
     */


    const size_t low_bytes =
        (low_bits + 7) / 8;

    const size_t ecc_bytes =
        (ecc_bits + 7) / 8;

    uint8_t *encoded_seed =
        calloc(1, low_bytes);

    uint8_t *y1 =
        calloc(1, ecc_bytes);

    

    if (!encoded_seed || !y1) {

        free(y);
        free(encoded_seed);
        free(y1);

        return 0;
    }

    for (size_t i = 0; i < low_bits; ++i)
        set_bit(
            encoded_seed,
            i,
            get_bit(y, i)
        );

    for (size_t i = 0; i < ecc_bits; ++i)
        set_bit(
            y1,
            i,
            get_bit(y, low_bits + i)
        );

    free(y);


    //save_codeword("test-dec.txt", encoded_seed, low_bits);
    /*
     * ------------------------------------------------------------
     * 3. Decode seed using low PRC
     * ------------------------------------------------------------
     */

    const size_t seed_len =
        params->lambda / 8;

    uint8_t *seed =
        calloc(1, seed_len);

    if (!seed) {
        free(encoded_seed);
        free(y1);
        return 0;
    }

    size_t seed_bits = 0;

    

    if (!mbprc_decode(
            params->low_prc,
            key->low_dec_key,
            encoded_seed,
            low_bits,
            seed,
            &seed_bits) ||
        seed_bits != params->lambda) {

        free(encoded_seed);
        free(y1);
        free(seed);

        return 0;
    }

    free(encoded_seed);

    /*
     * ------------------------------------------------------------
     * 4. Calculate PRG(r)
     * ------------------------------------------------------------
     */

    uint8_t *mask =
        malloc(ecc_bytes);

    if (!mask) {
        free(y1);
        free(seed);
        return 0;
    }

    //const CSPRG *csprg = csprg_sodium();
    RandomnessSource rand = csprg_randomness(seed, seed_len);

    if (rand.rng(rand.ctx, mask, ecc_bytes) != 0) {

        free(y1);
        free(seed);
        free(mask);

        return 0;
    }

    free(seed);

    /*
     * ------------------------------------------------------------
     * 5. ECC codeword =
     *
     *     y1 XOR PRG(r)
     * ------------------------------------------------------------
     */

    xor_bytes(
        y1,
        y1,
        mask,
        ecc_bytes
    );

    free(mask);

    /*
     * ------------------------------------------------------------
     * 6. Determine original message length.
     * ------------------------------------------------------------
     *
     * The ECC interface does not provide a direct way to recover
     * the original message length from an encoded buffer unless
     * decoded_size() supports it.
     */

    const size_t message_len =
        ecc_decoded_size(params->ecc, ecc_bytes);

    if (message_len == 0) {
        free(y1);
        return 0;
    }

    /*
     * ------------------------------------------------------------
     * 7. Decode ECC.
     * ------------------------------------------------------------
    */

    if (ecc_decode(
            params->ecc,
            y1,
            ecc_bytes,
            message_out,
            message_len) != 0) {

        free(y1);
        return 0;
    }

    free(y1);

    *message_bits_out =
        message_len * 8;

    return 1;
}


/*
 * ================================================================
 * Key destruction
 * ================================================================
 */

static void
high_free_enc_key(
    const void *params_ptr,
    MBPRC_EncKey *key_ptr)
{
    const PRCHigh_Params *params =
        (const PRCHigh_Params *)params_ptr;

    MBPRC_EncKey *key =
        (MBPRC_EncKey *)key_ptr;

    if (!key)
        return;

    if (key->low_enc_key) {
        mbprc_free_enc_key(
            params->low_prc,
            key->low_enc_key
        );
    }

    free(key->permutation);
    free(key);
}


static void
high_free_dec_key(
    const void *params_ptr,
    MBPRC_DecKey *key_ptr)
{
    const PRCHigh_Params *params =
        (const PRCHigh_Params *)params_ptr;

    MBPRC_DecKey *key =
        (MBPRC_DecKey *)key_ptr;

    if (!key)
        return;

    if (key->low_dec_key) {
        mbprc_free_dec_key(
            params->low_prc,
            key->low_dec_key
        );
    }

    free(key->permutation);
    free(key);
}




MBPRC
prc_high_create(
    const PRCHigh_Params *params)
{

    return (MBPRC) {
        .params = params,

        .keygen =
            high_keygen,

        .encode =
            high_encode,

        .decode =
            high_decode,

        .free_enc_key =
            high_free_enc_key,

        .free_dec_key =
            high_free_dec_key
    };

}
