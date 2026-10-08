

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>
#include <string.h>
#include "aprc_rr.h"

#define PRF_KEYBYTES 32






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
