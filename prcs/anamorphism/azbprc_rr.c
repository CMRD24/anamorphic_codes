
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "aprc_rr.h"

#define PRF_KEYBYTES 32




uint8_t prf_bit(const unsigned char *key,
                const unsigned char *input,
                size_t input_len)
{
    unsigned char output[crypto_generichash_BYTES];

    crypto_generichash(
        output,
        sizeof(output),
        input,
        input_len,
        key,
        crypto_generichash_KEYBYTES
    );

    return output[0] & 1;
}


/*
 * Ciphertext layout:
 *
 *   ciphertext = seed || (PRF(key, seed) XOR message)
 *
 * Ciphertext length = seed_len + max_message_length
 *
 * The unused part after message_len is zero-padded.
 * 
 * 1 on success, 0 on failure
 */
int encrypt(
    const uint8_t *key,
    size_t seed_len_bytes,
    const uint8_t *message,
    size_t message_len,
    uint8_t *ciphertext)
{
    if (key == NULL || ciphertext == NULL)
        return 0;

    if (message_len > 0 && message == NULL)
        return 0;

    /*
     * 1. Sample a uniformly random seed.
     *
     * ciphertext[0 .. seed_len-1] = seed
     */
    randombytes_buf(ciphertext, seed_len_bytes);

    /*
     * 2. Generate PRF output:
     *
     *    pad = F_k(seed)
     *
     * with exactly max_message_length bytes.
     */
    uint8_t *pad = malloc(message_len);

    if (message_len > 0 && pad == NULL)
        return 0;

    if (crypto_generichash(
            pad,
            message_len,
            ciphertext,       // seed
            seed_len_bytes,
            key,
            PRF_KEYBYTES) != 0) {
        free(pad);
        return 0;
    }

    /*
     * 3. Compute:
     *
     *    ciphertext = seed || (pad XOR message)
     */
    for (size_t i = 0; i < message_len; i++) {
        ciphertext[seed_len_bytes + i] =
            pad[i] ^ message[i];
    }


    sodium_memzero(pad, message_len);
    free(pad);

    return 1;
}


/*
 * Decrypt:
 *
 * ciphertext = seed || (PRF(key, seed) XOR message)
 *
 * message_len must be supplied separately because the ciphertext
 * does not encode the actual message length.
 */
int decrypt(
    const uint8_t *key,
    size_t seed_len_bytes,
    const uint8_t *ciphertext,
    uint8_t *message,
    size_t message_len)
{
    if (key == NULL || ciphertext == NULL)
        return 0;

    if (message_len > 0 && message == NULL)
        return 0;

    /*
     * 1. Generate the same PRF output:
     *
     *    pad = F_k(seed)
     *
     * The seed is stored in the first seed_len bytes
     * of the ciphertext.
     */
    uint8_t *pad = malloc(message_len);

    if (message_len > 0 && pad == NULL)
        return 0;

    if (crypto_generichash(
            pad,
            message_len,
            ciphertext,       // seed
            seed_len_bytes,
            key,
            PRF_KEYBYTES) != 0) {
        free(pad);
        return 0;
    }

    /*
     * 2. Recover:
     *
     *    message = ciphertext_part XOR pad
     */
    for (size_t i = 0; i < message_len; i++) {
        message[i] =
            ciphertext[seed_len_bytes + i] ^ pad[i];
    }

    sodium_memzero(pad, message_len);
    free(pad);

    return 1;
}



APRC_RR_Keys *akeygen(
        const aZBPRC_RR_Params *aparams,
        RandomnessSource *random
) {
    (void)aparams;
    (void)random;

    APRC_RR_Keys *keys = malloc(sizeof(*keys));
    if (keys == NULL) {
        return NULL;
    }

    uint8_t *prf_key = malloc(crypto_generichash_KEYBYTES);
    uint8_t *encryption_key = malloc(crypto_generichash_KEYBYTES);

    if (prf_key == NULL || encryption_key == NULL) {
        free(prf_key);
        free(encryption_key);
        free(keys);
        return NULL;
    }

    crypto_generichash_keygen(prf_key);
    crypto_generichash_keygen(encryption_key);

    keys->prf_key = prf_key;
    keys->encryption_key = encryption_key;

    return keys;
}

void akeygen_free(const aZBPRC_RR_Params *aparams, APRC_RR_Keys *keys)
{
    (void)aparams;

    if (keys == NULL) {
        return;
    }

    sodium_memzero((void *)keys->prf_key, crypto_generichash_KEYBYTES);
    sodium_memzero((void *)keys->encryption_key, crypto_generichash_KEYBYTES);

    free((void *)keys->prf_key);
    free((void *)keys->encryption_key);
    free(keys);
}



/*
 * Anamorphic encoding.
 *
 * reg_messages:
 *     mu regular zero-bit messages, represented as single bits.
 *
 * ana_message:
 *     anamorphic message, arbitrary bytes/bits depending on the SKE
 *     representation.
 *
 * output_bits:
 *     number of bits per returned codeword.
 *
 * Returns an array of mu codewords. Each codeword is represented as a
 * byte array; its individual length is determined by prc_rr->base.
 */
uint8_t **aencode(
    const aZBPRC_RR_Params *aparams,
    const ZBPRC_EncKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *ana_message,
    RandomnessSource *random,
    size_t *output_bits
)
{

    if (aparams == NULL ||
        dkey == NULL ||
        dkey->prf_key == NULL ||
        dkey->encryption_key == NULL ||
        random == NULL ||
        random->rng == NULL ||
        ana_message == NULL ||
        output_bits == NULL ||
        aparams->prc_rr == NULL ||
        aparams->prc_rr->encode_ws == NULL) {
        return NULL;
    }


    const size_t k  = aparams->seed_len;
    const size_t mu = aparams->mu;
    const size_t z  = aparams->indication_len;

    if (k == 0 || mu == 0 || z > mu)
        return NULL;

    /*
     * The construction requires the SKE ciphertext to contain
     * exactly (mu-z)*k bits.
     */
    const size_t encrypted_bits = k * (mu - z);


    const size_t ana_message_bits = encrypted_bits-k;


    /*
     * Convert the anamorphic message into the SKE ciphertext.
     *
     * The SKE interface has to provide ciphertext bits. Here `encrypt`
     * is assumed to produce exactly encrypted_bits bits.
     */
    uint8_t *encrypted = NULL;

    if (encrypted_bits > 0) {
        const size_t encrypted_bytes = (encrypted_bits + 7) / 8;


        encrypted = malloc(encrypted_bytes);
        if (encrypted == NULL)
            return NULL;

        /*
         * Replace this call with your actual SKE encryption function.
         *
         * IMPORTANT:
         * encrypted must contain exactly (mu-z)*k bits.
         */

        

        if (!encrypt(
                dkey->encryption_key,
                k/8, //use the same lambda as the seed
                ana_message,
                ana_message_bits/8,
                encrypted)) {
            free(encrypted);
            return NULL;
        }
    }


    /*
     * r_i are k-bit seeds.
     *
     * We store all seeds consecutively:
     *
     *     seeds = r_1 || ... || r_z || r_{z+1} || ... || r_mu
     *
     * The first z seeds are sampled such that PRF(s,r_i)=0.
     */
    const size_t seed_bytes = (k + 7) / 8;
    uint8_t *seeds = calloc(mu, seed_bytes);

    if (seeds == NULL) {
        free(encrypted);
        return NULL;
    }


    /*
     * Generate the indication seeds.
     */
    for (size_t i = 0; i < z; i++) {

        uint8_t *seed = seeds + i * seed_bytes;

        do {
            if (!random->rng(
                    random,
                    seed,
                    seed_bytes)) {
                free(seeds);
                free(encrypted);
                return NULL;
            }

            /*
             * If k is not a multiple of 8, clear the unused
             * high bits so the seed really represents k bits.
             */
            if (k % 8 != 0) {
                seed[seed_bytes - 1] &= (uint8_t)((1u << (k % 8)) - 1u);
            }

        } while (prf_bit(
            dkey->prf_key,
            seed,
            seed_bytes
        ) != 0);
    }


    /*
     * r_{z+1} || ... || r_mu = SKEEnc(ek,m_a)
     *
     * Copy the SKE ciphertext bit string into the remaining seeds.
     */
    if (mu > z) {
        memcpy(
            seeds + z * seed_bytes,
            encrypted,
            (encrypted_bits + 7) / 8
        );
    }

    /*
     * Encode every regular message using its corresponding seed.
     */
    uint8_t **codewords = calloc(mu, sizeof(*codewords));

    if (codewords == NULL) {
        sodium_memzero(seeds, mu * seed_bytes);
        free(seeds);
        free(encrypted);
        return NULL;
    }

    size_t codeword_bits = 0;

    for (size_t i = 0; i < mu; i++) {

        size_t current_bits = 0;


        /*
         * encode_ws() consumes the seed directly.
         */
        codewords[i] = aparams->prc_rr->encode_ws(
            aparams->prc_rr->base.params,
            reg_key,
            random,
            &current_bits,
            seeds + i * seed_bytes
        );

        if (codewords[i] == NULL) {
            /*
             * Free already-created codewords.
             *
             * The exact allocation size depends on your PRC.
             * Ideally the PRC should expose a codeword_free()
             * function.
             */
            for (size_t j = 0; j < i; j++)
                free(codewords[j]);

            free(codewords);

            sodium_memzero(seeds, mu * seed_bytes);
            free(seeds);
            free(encrypted);

            return NULL;
        }

        if (i == 0) {
            codeword_bits = current_bits;
        } else if (current_bits != codeword_bits) {
            /*
             * The construction assumes equal-size PRC codewords.
             */
            for (size_t j = 0; j <= i; j++)
                free(codewords[j]);

            free(codewords);

            sodium_memzero(seeds, mu * seed_bytes);
            free(seeds);
            free(encrypted);

            return NULL;
        }
    }


    *output_bits = codeword_bits;

    sodium_memzero(seeds, mu * seed_bytes);
    free(seeds);

    if (encrypted != NULL) {
        sodium_memzero(
            encrypted,
            (encrypted_bits + 7) / 8
        );
        free(encrypted);
    }


    return codewords;
}



int adecode(
    const aZBPRC_RR_Params *aparams,
    const ZBPRC_DecKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *const *codewords,
    size_t ciphertext_bits,
    uint8_t *ana_message
)
{

    if (aparams == NULL ||
        dkey == NULL ||
        dkey->prf_key == NULL ||
        dkey->encryption_key == NULL ||
        codewords == NULL ||
        aparams->prc_rr == NULL ||
        aparams->prc_rr->decode_ws == NULL) {
        return 0;
    }


    const size_t k  = aparams->seed_len;
    const size_t mu = aparams->mu;
    const size_t z  = aparams->indication_len;

    if (k == 0 || mu == 0 || z > mu)
        return 0;


    const size_t encrypted_bits = k * (mu - z);

    const size_t ana_message_bits = encrypted_bits-k;
    /*
     * Each recovered seed is k bits.
     */
    const size_t seed_bytes = (k + 7) / 8;

    uint8_t *seeds = calloc(mu, seed_bytes);

    if (seeds == NULL)
        return 0;


    /*
     * Recover r_i from every regular PRC codeword.
     */
    for (size_t i = 0; i < mu; i++) {


        if (!aparams->prc_rr->decode_ws(
                aparams->prc_rr->base.params,
                reg_key,
                codewords[i],
                ciphertext_bits,
                seeds + i * seed_bytes
            )) {


            sodium_memzero(seeds, mu * seed_bytes);
            free(seeds);
            return 0;
        }


    }



    /*
     * Check the indication seeds:
     *
     *     PRF(s,r_i) == 0
     *
     * for every i <= z.
     */
    for (size_t i = 0; i < z; i++) {

        uint8_t bit = prf_bit(
            dkey->prf_key,
            seeds + i * seed_bytes,
            seed_bytes
        );


        if (bit != 0) {
            sodium_memzero(seeds, mu * seed_bytes);
            free(seeds);
            return 0;
        }
    }


    /*
     * Extract
     *
     *     r_{z+1} || ... || r_mu
     *
     * which is exactly the SKE ciphertext.
     */
    const size_t encrypted_bytes = (encrypted_bits + 7) / 8;

    uint8_t *encrypted = NULL;

    if (encrypted_bytes > 0) {

        encrypted = malloc(encrypted_bytes);

        if (encrypted == NULL) {
            sodium_memzero(seeds, mu * seed_bytes);
            free(seeds);
            return 0;
        }

        memcpy(
            encrypted,
            seeds + z * seed_bytes,
            encrypted_bytes
        );

        /*
         * If the number of bits isn't byte aligned, clear
         * the unused bits.
         */
        if (encrypted_bits % 8 != 0) {
            encrypted[encrypted_bytes - 1] &=
                (uint8_t)((1u << (encrypted_bits % 8)) - 1u);
        }
    }


    /*
     * SKE.Dec(ek, r_{z+1} || ... || r_mu)
     */
    int result = decrypt(
        dkey->encryption_key,
        k/8,
        encrypted,
        ana_message,
        ana_message_bits/8
    );

    if (encrypted != NULL) {
        sodium_memzero(encrypted, encrypted_bytes);
        free(encrypted);
    }

    sodium_memzero(seeds, mu * seed_bytes);
    free(seeds);


    return result;
}



aZBPRC_RR aZBPRC_RR_init(const aZBPRC_RR_Params *aparams){
    aZBPRC_RR result = {
        .adecode = adecode,
        .aencode = aencode,
        .akeygen = akeygen,
        .free_akey = akeygen_free,
        .aparams = aparams
    };
    return result;
}
