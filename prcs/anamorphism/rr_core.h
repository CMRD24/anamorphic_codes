#ifndef RR_CORE_H
#define RR_CORE_H

/*
 * Shared core of the randomness-recovery based anamorphic PRCs (zero-bit and
 * multibit): the anamorphic message is encrypted and spread over the seeds of
 * mu regular codewords. The first z seeds are indication seeds with
 * PRF(prf_key, seed) = 0, the remaining mu - z seeds carry the ciphertext.
 */

#include <stddef.h>
#include <stdint.h>

#include "aprc_rr.h"

typedef struct {
    size_t seed_len;        /* k: bits per seed, a multiple of 8 */
    size_t indication_len;  /* z */
    size_t mu;
} RRShape;

/* Bytes of one seed. */
size_t rr_seed_bytes(const RRShape *shape);

/* Length in bytes of the anamorphic message; 0 if the shape is invalid. */
size_t rr_message_bytes(const RRShape *shape);

APRC_RR_Keys *rr_akeygen(void);
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
