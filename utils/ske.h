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
 * The ciphertext buffer must have at least
 * nonce_len + message_len bytes. The key is a libsodium generichash key
 * (crypto_generichash_KEYBYTES bytes).
 *
 * Returns 0 on success, -1 on error.
 */
int encrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *message,
    size_t message_len,
    uint8_t *ciphertext
);

/*
 * Decrypt a ciphertext produced by encrypt().
 *
 * message_len must be supplied separately because the ciphertext
 * does not encode the actual message length. The ciphertext buffer must
 * contain at least nonce_len + message_len bytes.
 *
 * Returns 0 on success, -1 on error.
 */
int decrypt(
    const uint8_t *key,
    size_t nonce_len,
    const uint8_t *ciphertext,
    uint8_t *message,
    size_t message_len
);

/*
 * First bit of a keyed hash of input; used for the indication bits of the
 * randomness-recovery based anamorphic PRCs.
 */
uint8_t ske_prf_bit(
    const uint8_t *key,
    const uint8_t *input,
    size_t input_len
);

#endif /* SKE_H */
