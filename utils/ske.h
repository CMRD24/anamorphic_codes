
#ifndef SKE_H
#define SKE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Encrypt a message.
 *
 * Ciphertext layout:
 *   seed || (PRF(key, seed) XOR message)
 *
 * The ciphertext buffer must have at least
 * seed_len_bytes + message_len bytes.
 *
 * Returns 1 on success, 0 on failure.
 */
int encrypt(
    const uint8_t *key,
    size_t seed_len_bytes,
    const uint8_t *message,
    size_t message_len,
    uint8_t *ciphertext
);

/*
 * Decrypt a message.
 *
 * message_len must be supplied separately because
 * the ciphertext does not encode the actual message length.
 *
 * The ciphertext buffer must contain at least
 * seed_len_bytes + message_len bytes.
 * The message buffer must have at least message_len bytes.
 *
 * Returns 1 on success, 0 on failure.
 */
int decrypt(
    const uint8_t *key,
    size_t seed_len_bytes,
    const uint8_t *ciphertext,
    uint8_t *message,
    size_t message_len
);

#endif /* SKE_H */