/*
 * Pseudorandom symmetric encryption: a nonce-based stream cipher.
 *
 * The keystream for a nonce N is the output of the keyed hash BLAKE2b (RFC 7693,
 * libsodium crypto_generichash) on N, which is used as a PRF; the ciphertext is
 * N || (message XOR PRF_key(N)). If the nonce is uniform and never repeats, the
 * whole ciphertext is indistinguishable from a uniform string (a pseudorandom
 * ciphertext, IND$-CPA), which is what the randomness-recovery anamorphism needs.
 * With a random nonce of n bytes, repeats occur with probability about
 * q^2 / 2^(8n) after q encryptions.
 *
 * The encryption is not authenticated: a modified ciphertext decrypts to a
 * modified message, and every string of the right length decrypts to something.
 * BLAKE2b has at most 64 bytes of output, which bounds the message length.
 */

#include "ske.h"

#include <stdlib.h>
#include <sodium.h>

/*
 * out[i] = in[i] XOR PRF(key, nonce)[i]. in and out may be the same buffer.
 */
static int xor_prf_pad(
    const uint8_t *key,
    const uint8_t *nonce,
    size_t nonce_len,
    const uint8_t *in,
    uint8_t *out,
    size_t len)
{
    uint8_t *pad;

    if (key == NULL || nonce == NULL || out == NULL)
        return -1;

    if (len == 0)
        return 0;

    if (in == NULL)
        return -1;

    pad = malloc(len);
    if (pad == NULL)
        return -1;

    if (crypto_generichash(pad, len, nonce, nonce_len,
                           key, crypto_generichash_KEYBYTES) != 0) {
        free(pad);
        return -1;
    }

    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ pad[i];

    sodium_memzero(pad, len);
    free(pad);

    return 0;
}

int encrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *ciphertext)
{
    if (ciphertext == NULL)
        return -1;

    randombytes_buf(ciphertext, nonce_len);

    return xor_prf_pad(key, ciphertext, nonce_len,
                       message, ciphertext + nonce_len, message_len);
}

int decrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *ciphertext,
    uint8_t *message,
    size_t message_len)
{
    if (ciphertext == NULL)
        return -1;

    return xor_prf_pad(key, ciphertext, nonce_len,
                       ciphertext + nonce_len, message, message_len);
}

uint8_t ske_prf_bit(
    const uint8_t *key,
    const uint8_t *input,
    size_t input_len)
{
    uint8_t output[crypto_generichash_BYTES];

    crypto_generichash(output, sizeof(output), input, input_len,
                       key, crypto_generichash_KEYBYTES);

    return output[0] & 1;
}
