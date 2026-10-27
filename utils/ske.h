#ifndef SKE_H
#define SKE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Pseudorandom symmetric encryption (nonce-based stream cipher).
 *
 * Ciphertext layout:
 *   nonce || (PRF(key, nonce) XOR message)
 *
 * The ciphertext buffer must have at least nonce_len + message_len bytes, with
 * message_len <= 64 (the output length of BLAKE2b). The key is a libsodium
 * generichash key (crypto_generichash_KEYBYTES bytes). The nonce is uniform.
 *
 * Returns 0 on success, -1 on error.
 */
int ske_encrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *ciphertext
);

/*
 * Decrypt a ciphertext produced by ske_encrypt().
 *
 * message_len must be supplied separately because the ciphertext
 * does not encode the actual message length. The ciphertext buffer must
 * contain at least nonce_len + message_len bytes.
 *
 * Returns 0 on success, -1 on error.
 */
int ske_decrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *ciphertext,
    uint8_t *message,
    size_t message_len
);

/*
 * First bit of a keyed hash of input; used for the indication bits of the
 * randomness-recovery based anamorphic PRCs. (OPTIONAL: indications could be used for more efficient anamorphic decoding (receiver knows when to decrypt))
 */
uint8_t ske_prf_bit(
    const uint8_t *key,
    const uint8_t *input,
    size_t input_len
);

#endif /* SKE_H */
