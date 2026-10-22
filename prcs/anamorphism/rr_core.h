#ifndef RR_CORE_H
#define RR_CORE_H

/*
 * Shared core of the randomness-recovery based anamorphic PRCs (zero-bit and
 * multibit): the anamorphic message is encrypted with a pseudorandom
 * encryption (nonce || PRF(key, nonce) xor message) and the ciphertext is
 * written into the seeds of the regular codewords.
 *
 * The first z of the mu codewords have indication seeds with
 * PRF(prf_key, seed) = 0 (they make the decoder reject strings that are not
 * anamorphic, at the price of z extra codewords; z = 0 is allowed). The
 * remaining mu - z seeds carry the ciphertext, which therefore has exactly
 * (mu - z) * seed_len / 8 bytes. With mu - z = 1 the ciphertext is the seed of a
 * single codeword: the nonce must then be shorter than the seed.
 *
 * Without indication seeds the decryption is not authenticated, so the
 * decoder returns a message for every codeword whose seed it can recover.
 */

#include <stddef.h>
#include <stdint.h>

#include "aprc_rr.h"

typedef struct {
    size_t seed_len;        /* k: bits per seed, a multiple of 8 */
    size_t indication_len;  /* z */
    size_t mu;
    size_t message_bytes;   /* length of the anamorphic message */
} RRShape;

/* The nonce of the encryption has at least this many bytes. */
#define RR_MIN_NONCE_BYTES 8

/*
 * Smallest number of ciphertext seeds (mu - indication_len) that can carry a
 * message of message_bytes bytes together with a nonce of RR_MIN_NONCE_BYTES.
 */
size_t rr_min_ciphertext_seeds(size_t seed_len, size_t message_bytes);

/* Bytes of one seed. */
size_t rr_seed_bytes(const RRShape *shape);

/* Length in bytes of the anamorphic message; 0 if the shape is invalid
 * (seed length not a multiple of 8, no ciphertext seed, or a nonce shorter than
 * RR_MIN_NONCE_BYTES). */
size_t rr_message_bytes(const RRShape *shape);

/* Keys are drawn from random, so a deterministic source gives reproducible keys. */
APRC_RR_Keys *rr_akeygen(RandomnessSource *random);
void rr_akey_free(APRC_RR_Keys *keys);

/*
 * Builds the mu seeds (mu * seed_bytes, consecutive) for ana_message, which
 * has rr_message_bytes() bytes. Returns NULL on error; the caller wipes and
 * frees the buffer.
 */
uint8_t *rr_build_seeds(
    const RRShape *shape,
    const APRC_RR_Keys *keys,
    const uint8_t *ana_message,
    RandomnessSource *random);

/*
 * Checks the indication seeds and decrypts the message from the recovered
 * seeds. Returns 0 on success, -1 if an indication fails or on error.
 */
int rr_open_seeds(
    const RRShape *shape,
    const APRC_RR_Keys *keys,
    const uint8_t *seeds,
    uint8_t *ana_message);

void rr_free_codewords(uint8_t **codewords, size_t count);

#endif /* RR_CORE_H */
