#include "rr_core.h"

#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "../../utils/random_utils.h"
#include "../../utils/ske.h"

size_t rr_seed_bytes(const RRShape *shape)
{
    return shape->seed_len / 8;
}

size_t rr_message_bytes(const RRShape *shape)
{
    if (shape->seed_len == 0 || shape->seed_len % 8 != 0 ||
        shape->mu <= shape->indication_len + 1)
        return 0;

    /* ciphertext = nonce (one seed) || masked message */
    return rr_seed_bytes(shape) * (shape->mu - shape->indication_len - 1);
}

APRC_RR_Keys *rr_akeygen(RandomnessSource *random)
{
    APRC_RR_Keys *keys = malloc(sizeof(*keys));
    uint8_t *prf_key = malloc(crypto_generichash_KEYBYTES);
    uint8_t *encryption_key = malloc(crypto_generichash_KEYBYTES);

    if (keys == NULL || prf_key == NULL || encryption_key == NULL ||
        random == NULL || random->rng == NULL) {
        free(keys);
        free(prf_key);
        free(encryption_key);
        return NULL;
    }

    random_bytes(random, prf_key, crypto_generichash_KEYBYTES);
    random_bytes(random, encryption_key, crypto_generichash_KEYBYTES);

    keys->prf_key = prf_key;
    keys->encryption_key = encryption_key;

    return keys;
}

void rr_akey_free(APRC_RR_Keys *keys)
{
    if (keys == NULL)
        return;

    sodium_memzero((void *)keys->prf_key, crypto_generichash_KEYBYTES);
    sodium_memzero((void *)keys->encryption_key, crypto_generichash_KEYBYTES);

    free((void *)keys->prf_key);
    free((void *)keys->encryption_key);
    free(keys);
}

uint8_t *rr_build_seeds(
    const RRShape *shape,
    const APRC_RR_Keys *keys,
    const uint8_t *ana_message,
    RandomnessSource *random)
{
    const size_t seed_bytes = rr_seed_bytes(shape);
    const size_t message_bytes = rr_message_bytes(shape);

    if (keys == NULL || keys->prf_key == NULL ||
        keys->encryption_key == NULL || ana_message == NULL ||
        random == NULL || random->rng == NULL || message_bytes == 0)
        return NULL;

    uint8_t *seeds = calloc(shape->mu, seed_bytes);

    if (seeds == NULL)
        return NULL;

    /* r_1 .. r_z: sampled until PRF(prf_key, r_i) = 0 */
    for (size_t i = 0; i < shape->indication_len; i++) {
        uint8_t *seed = seeds + i * seed_bytes;

        do {
            random_bytes(random, seed, seed_bytes);
        } while (ske_prf_bit(keys->prf_key, seed, seed_bytes) != 0);
    }

    /* r_(z+1) .. r_mu = Enc(encryption_key, m_a) */
    if (encrypt(keys->encryption_key, seed_bytes, ana_message, message_bytes,
                seeds + shape->indication_len * seed_bytes) != 0) {
        free(seeds);
        return NULL;
    }

    return seeds;
}

int rr_open_seeds(
    const RRShape *shape,
    const APRC_RR_Keys *keys,
    const uint8_t *seeds,
    uint8_t *ana_message)
{
    const size_t seed_bytes = rr_seed_bytes(shape);
    const size_t message_bytes = rr_message_bytes(shape);

    if (keys == NULL || keys->prf_key == NULL ||
        keys->encryption_key == NULL || seeds == NULL ||
        ana_message == NULL || message_bytes == 0)
        return -1;

    for (size_t i = 0; i < shape->indication_len; i++) {
        if (ske_prf_bit(keys->prf_key, seeds + i * seed_bytes, seed_bytes) != 0)
            return -1;
    }

    return decrypt(keys->encryption_key, seed_bytes,
                   seeds + shape->indication_len * seed_bytes,
                   ana_message, message_bytes);
}

void rr_free_codewords(uint8_t **codewords, size_t count)
{
    if (codewords == NULL)
        return;

    for (size_t i = 0; i < count; i++)
        free(codewords[i]);

    free(codewords);
}
