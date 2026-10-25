/*
 * Anamorphism from randomness recoverability for zero-bit and multibit PRCs
 * (see aprc_rr.h for the construction and the layout of the seeds).
 */

#include "aprc_rr.h"

#include <stdlib.h>
#include <string.h>
#include <sodium.h>

#include "../../utils/random_utils.h"
#include "../../utils/ske.h"

_Static_assert(RR_KEY_BYTES == crypto_generichash_KEYBYTES,
               "the keys are BLAKE2b keys");


static size_t seed_bytes_of(const RR_Shape *shape)
{
    return shape->seed_bits / 8;
}

/* ciphertext seeds mu - z */
static size_t ciphertext_seeds_of(const RR_Shape *shape)
{
    return shape->codeword_count - shape->indication_seeds;
}

/* 1 iff the seeds can hold the indication seeds, the nonce and the message */
static int shape_is_valid(const RR_Shape *shape)
{
    return shape->seed_bits > 0 && shape->seed_bits % 8 == 0 &&
           shape->codeword_count > shape->indication_seeds && shape->amessage_bytes > 0 &&
           shape->amessage_bytes + RR_MIN_NONCE_BYTES <=
               ciphertext_seeds_of(shape) * seed_bytes_of(shape);
}

size_t rr_min_ciphertext_seeds(size_t seed_bits, size_t amessage_bytes)
{
    const size_t seed_bytes = seed_bits / 8;

    if (seed_bytes == 0)
        return 0;

    return (amessage_bytes + RR_MIN_NONCE_BYTES + seed_bytes - 1) / seed_bytes;
}

RR_AKeys *rr_akeygen(RandomnessSource *random)
{
    if (random == NULL || random->rng == NULL)
        return NULL;

    RR_AKeys *akeys = malloc(sizeof(*akeys));

    if (akeys == NULL)
        return NULL;

    random_bytes(random, akeys->indication_key, sizeof(akeys->indication_key));
    random_bytes(random, akeys->encryption_key, sizeof(akeys->encryption_key));

    return akeys;
}

void rr_free_akeys(RR_AKeys *akeys)
{
    if (akeys == NULL)
        return;

    sodium_memzero(akeys, sizeof(*akeys));
    free(akeys);
}

void rr_free_codewords(uint8_t **codewords, size_t count)
{
    if (codewords == NULL)
        return;

    for (size_t i = 0; i < count; i++)
        free(codewords[i]);

    free(codewords);
}

/*
 * The mu seeds (consecutive, k / 8 bytes each): rho_1 .. rho_z sampled until
 * PRF(indication_key, rho_i) = 0, then rho_(z+1) || .. || rho_mu = Enc(sk, m_a).
 * Returns NULL on error; the caller wipes and frees the buffer.
 */
static uint8_t *build_seeds(const RR_Shape *shape, const RR_AKeys *akeys,
                            const uint8_t *amessage, RandomnessSource *random)
{
    const size_t seed_bytes = seed_bytes_of(shape);

    if (!shape_is_valid(shape) || akeys == NULL || amessage == NULL ||
        random == NULL || random->rng == NULL)
        return NULL;

    uint8_t *seeds = calloc(shape->codeword_count, seed_bytes);

    if (seeds == NULL)
        return NULL;

    for (size_t i = 0; i < shape->indication_seeds; i++) {
        uint8_t *seed = seeds + i * seed_bytes;

        do {
            random_bytes(random, seed, seed_bytes);
        } while (ske_prf_bit(akeys->indication_key, seed, seed_bytes) != 0);
    }

    const size_t nonce_bytes = ciphertext_seeds_of(shape) * seed_bytes - shape->amessage_bytes;

    if (ske_encrypt(akeys->encryption_key, nonce_bytes, amessage, shape->amessage_bytes,
                    seeds + shape->indication_seeds * seed_bytes) != 0) {
        free(seeds);
        return NULL;
    }

    return seeds;
}

/* Checks the indication seeds and decrypts m_a. Returns 0, or -1 on rejection or error. */
static int open_seeds(const RR_Shape *shape, const RR_AKeys *akeys,
                      const uint8_t *seeds, uint8_t *amessage_out)
{
    const size_t seed_bytes = seed_bytes_of(shape);

    for (size_t i = 0; i < shape->indication_seeds; i++) {
        if (ske_prf_bit(akeys->indication_key, seeds + i * seed_bytes, seed_bytes) != 0)
            return -1;
    }

    const size_t nonce_bytes = ciphertext_seeds_of(shape) * seed_bytes - shape->amessage_bytes;

    return ske_decrypt(akeys->encryption_key, nonce_bytes,
                       seeds + shape->indication_seeds * seed_bytes,
                       amessage_out, shape->amessage_bytes);
}

/* The regular encoding of codeword i with seed rho_i (zero-bit or multibit PRC). */
typedef struct {
    const aZBPRC_RR *zerobit;
    const aMBPRC_RR *multibit;
    const ZBPRC_EncKey *zerobit_key;
    const MBPRC_EncKey *multibit_key;
    const uint8_t *const *messages;
    size_t message_bits;
} SeededEncoder;

static uint8_t *encode_codeword(const SeededEncoder *encoder, size_t i, const uint8_t *seed,
                                RandomnessSource *random, size_t *codeword_bits)
{
    if (encoder->zerobit != NULL) {
        const ZBPRC_RR *prc = encoder->zerobit->prc;

        return prc->encode_with_seed(prc->base.params, encoder->zerobit_key, random,
                                     codeword_bits, seed);
    }

    const MBPRC_RR *prc = encoder->multibit->prc;

    return prc->encode_with_seed(prc->base.params, encoder->multibit_key,
                                 encoder->messages[i], encoder->message_bits, random,
                                 codeword_bits, seed);
}

/* aEncode: the mu codewords for the seeds of m_a, all of the same length. */
static uint8_t **aencode(const RR_Shape *shape, const SeededEncoder *encoder,
                         const RR_AKeys *akeys, const uint8_t *amessage,
                         RandomnessSource *random, size_t *codeword_bits)
{
    if (codeword_bits == NULL)
        return NULL;

    const size_t seed_bytes = seed_bytes_of(shape);
    uint8_t *seeds = build_seeds(shape, akeys, amessage, random);

    if (seeds == NULL)
        return NULL;

    uint8_t **codewords = calloc(shape->codeword_count, sizeof(*codewords));
    size_t first_bits = 0;
    int ok = codewords != NULL;

    for (size_t i = 0; ok && i < shape->codeword_count; i++) {
        size_t bits = 0;

        codewords[i] = encode_codeword(encoder, i, seeds + i * seed_bytes, random, &bits);

        if (i == 0)
            first_bits = bits;

        ok = codewords[i] != NULL && bits == first_bits;
    }

    sodium_memzero(seeds, shape->codeword_count * seed_bytes);
    free(seeds);

    if (!ok) {
        rr_free_codewords(codewords, shape->codeword_count);
        return NULL;
    }

    *codeword_bits = first_bits;

    return codewords;
}

uint8_t **azbprc_rr_aencode(const aZBPRC_RR *aprc,
                            const ZBPRC_EncKey *enc_key,
                            const RR_AKeys *akeys,
                            const uint8_t *amessage,
                            RandomnessSource *random,
                            size_t *codeword_bits)
{
    if (aprc == NULL || aprc->prc == NULL || aprc->prc->encode_with_seed == NULL)
        return NULL;

    const SeededEncoder encoder = {.zerobit = aprc, .zerobit_key = enc_key};

    return aencode(&aprc->shape, &encoder, akeys, amessage, random, codeword_bits);
}

uint8_t **ambprc_rr_aencode(const aMBPRC_RR *aprc,
                            const MBPRC_EncKey *enc_key,
                            const RR_AKeys *akeys,
                            const uint8_t *const *messages,
                            size_t message_bits,
                            const uint8_t *amessage,
                            RandomnessSource *random,
                            size_t *codeword_bits)
{
    if (aprc == NULL || aprc->prc == NULL || aprc->prc->encode_with_seed == NULL ||
        messages == NULL)
        return NULL;

    const SeededEncoder encoder = {
        .multibit = aprc,
        .multibit_key = enc_key,
        .messages = messages,
        .message_bits = message_bits,
    };

    return aencode(&aprc->shape, &encoder, akeys, amessage, random, codeword_bits);
}

/*
 * aDecode: RecDecode recovers rho_i from every codeword (recover_seed returns 1
 * on success), then the seeds are opened.
 */
typedef int (*RecoverSeed)(const void *context, const uint8_t *codeword,
                           size_t codeword_bits, uint8_t *seed_out);

static int adecode(const RR_Shape *shape, RecoverSeed recover_seed, const void *context,
                   const RR_AKeys *akeys, const uint8_t *const *codewords,
                   size_t codeword_bits, uint8_t *amessage_out)
{
    if (!shape_is_valid(shape) || akeys == NULL || codewords == NULL || amessage_out == NULL)
        return 0;

    const size_t seed_bytes = seed_bytes_of(shape);
    uint8_t *seeds = calloc(shape->codeword_count, seed_bytes);
    int ok = seeds != NULL;

    for (size_t i = 0; ok && i < shape->codeword_count; i++)
        ok = recover_seed(context, codewords[i], codeword_bits, seeds + i * seed_bytes) == 1;

    ok = ok && open_seeds(shape, akeys, seeds, amessage_out) == 0;

    if (seeds != NULL)
        sodium_memzero(seeds, shape->codeword_count * seed_bytes);
    free(seeds);

    return ok;
}

typedef struct {
    const ZBPRC_RR *prc;
    const ZBPRC_DecKey *dec_key;
} ZerobitRecovery;

static int zerobit_recover_seed(const void *context, const uint8_t *codeword,
                                size_t codeword_bits, uint8_t *seed_out)
{
    const ZerobitRecovery *recovery = context;

    return recovery->prc->recover_decode(recovery->prc->base.params, recovery->dec_key,
                                         codeword, codeword_bits, seed_out);
}

int azbprc_rr_adecode(const aZBPRC_RR *aprc,
                      const ZBPRC_DecKey *dec_key,
                      const RR_AKeys *akeys,
                      const uint8_t *const *codewords,
                      size_t codeword_bits,
                      uint8_t *amessage_out)
{
    if (aprc == NULL || aprc->prc == NULL || aprc->prc->recover_decode == NULL)
        return 0;

    const ZerobitRecovery recovery = {.prc = aprc->prc, .dec_key = dec_key};

    return adecode(&aprc->shape, zerobit_recover_seed, &recovery, akeys, codewords,
                   codeword_bits, amessage_out);
}

typedef struct {
    const MBPRC_RR *prc;
    const MBPRC_DecKey *dec_key;
    uint8_t *message;            /* buffer for the discarded regular messages */
} MultibitRecovery;

static int multibit_recover_seed(const void *context, const uint8_t *codeword,
                                 size_t codeword_bits, uint8_t *seed_out)
{
    const MultibitRecovery *recovery = context;
    size_t message_bits = 0;

    return recovery->prc->recover_decode(recovery->prc->base.params, recovery->dec_key,
                                         codeword, codeword_bits, recovery->message,
                                         &message_bits, seed_out);
}

int ambprc_rr_adecode(const aMBPRC_RR *aprc,
                      const MBPRC_DecKey *dec_key,
                      const RR_AKeys *akeys,
                      const uint8_t *const *codewords,
                      size_t codeword_bits,
                      size_t message_bits,
                      uint8_t *amessage_out)
{
    if (aprc == NULL || aprc->prc == NULL || aprc->prc->recover_decode == NULL)
        return 0;

    MultibitRecovery recovery = {
        .prc = aprc->prc,
        .dec_key = dec_key,
        .message = calloc(1, (message_bits + 7) / 8 + 1),
    };

    if (recovery.message == NULL)
        return 0;

    const int ok = adecode(&aprc->shape, multibit_recover_seed, &recovery, akeys,
                           codewords, codeword_bits, amessage_out);

    free(recovery.message);

    return ok;
}
