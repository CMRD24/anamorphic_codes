/*
 * PRC_sharp and PRC_cca: PRCs for messages of message_bits bits, built from an
 * inner multibit PRC (PRC_high in the demos and tests) that encodes
 * lambda + message_bits + lambda bits.
 *
 * Encode(m): sample a seed r of lambda bits and derive pseudorandom bits
 * R2 || R1 from (r, m); encode the payload r || m || R2 with the inner PRC, using
 * R1 as the coins of the inner encoder (R2 is the first lambda bits of the
 * derived stream, R1 the following ones, which the inner encoder consumes).
 *
 * Decode(c): decode the inner PRC to r || m || R2', recompute R2 || R1 from
 * (r, m), and accept iff R2' = R2 and the re-encoding of the payload with the
 * coins R1 is within relative Hamming distance delta of the received word. The
 * re-encoding check rejects words that decode but were not produced by Encode;
 *  delta must exceed the noise rate of the channel.
 *
 * The two PRCs differ in the derivation of R2 || R1 (a stream of the ChaCha20
 * generator of csprg_sodium.c):
 *   PRC_sharp  seeded with sk || r || m, i.e. a PRF F(sk, r || m) keyed with sk;
 *   PRC_cca    seeded with H(hk, r || m), the keyed BLAKE2b hash (random oracle).
 *
 * The seed r is recovered by the decoder (RecDecode) and chosen by the encoder
 * (Encode with seed), which is what the randomness-recovery anamorphism uses;
 * the coins R1 are a function of (r, m), so there are no further coins.
 */

#include "prc_reencode.h"

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/csprg_sodium.h"
#include "../../../utils/helpers.h"
#include "../../../utils/random_utils.h"

#define KEY_BYTES crypto_generichash_KEYBYTES

typedef enum {
    COINS_FROM_PRF,       /* PRC_sharp */
    COINS_FROM_HASH,      /* PRC_cca */
} CoinDerivation;

/*
 * The decoding key keeps the inner encoding key to re-encode. Both keys share it
 * through a reference count, so they can be freed in any order.
 */
typedef struct {
    MBPRC_EncKey *key;
    int references;
} SharedInnerEncKey;

struct MBPRC_EncKey {
    CoinDerivation derivation;
    uint8_t key[KEY_BYTES];                 /* sk (PRF key) or hk (hash key) */
    SharedInnerEncKey *inner_enc_key;
};

struct MBPRC_DecKey {
    CoinDerivation derivation;
    uint8_t key[KEY_BYTES];
    SharedInnerEncKey *inner_enc_key;
    MBPRC_DecKey *inner_dec_key;
};


static void release_inner_enc_key(const PRCReencode_Params *params, SharedInnerEncKey *shared)
{
    if (shared == NULL || --shared->references > 0)
        return;

    mbprc_free_enc_key(params->inner, shared->key);
    free(shared);
}

static void reencode_free_enc_key(const void *params, MBPRC_EncKey *enc_key)
{
    if (enc_key == NULL)
        return;

    release_inner_enc_key(params, enc_key->inner_enc_key);
    sodium_memzero(enc_key, sizeof(*enc_key));
    free(enc_key);
}

static void reencode_free_dec_key(const void *params_ptr, MBPRC_DecKey *dec_key)
{
    const PRCReencode_Params *params = params_ptr;

    if (dec_key == NULL)
        return;

    mbprc_free_dec_key(params->inner, dec_key->inner_dec_key);
    release_inner_enc_key(params, dec_key->inner_enc_key);
    sodium_memzero(dec_key, sizeof(*dec_key));
    free(dec_key);
}

static int valid_params(const PRCReencode_Params *params)
{
    return params != NULL && params->inner != NULL && params->lambda > 0 &&
           params->lambda % 8 == 0;
}

static size_t reencode_block_length(const void *params_ptr)
{
    const PRCReencode_Params *params = params_ptr;

    return mbprc_block_length(params->inner);
}

/* the inner key pair and the key sk or hk */
static MBPRC_Keys *keygen(const PRCReencode_Params *params, CoinDerivation derivation,
                          RandomnessSource *random)
{
    if (!valid_params(params) || random == NULL || random->rng == NULL)
        return NULL;

    MBPRC_Keys *keys = calloc(1, sizeof(*keys));
    MBPRC_Keys *inner_keys = NULL;

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));
    SharedInnerEncKey *shared = calloc(1, sizeof(*shared));

    if (keys->enc == NULL || keys->dec == NULL || shared == NULL ||
        (inner_keys = mbprc_keygen(params->inner, random)) == NULL) {
        free(shared);
        free(keys->enc);
        free(keys->dec);
        free(keys);
        return NULL;
    }

    shared->key = inner_keys->enc;
    shared->references = 2; //encoder and decoder

    keys->enc->derivation = derivation;
    keys->enc->inner_enc_key = shared;
    random_bytes(random, keys->enc->key, KEY_BYTES);

    keys->dec->derivation = derivation;
    keys->dec->inner_enc_key = shared;
    keys->dec->inner_dec_key = inner_keys->dec;
    memcpy(keys->dec->key, keys->enc->key, KEY_BYTES);

    free(inner_keys);

    return keys;
}

static MBPRC_Keys *sharp_keygen(const void *params, RandomnessSource *random)
{
    return keygen(params, COINS_FROM_PRF, random);
}

static MBPRC_Keys *cca_keygen(const void *params, RandomnessSource *random)
{
    return keygen(params, COINS_FROM_HASH, random);
}

/* the generator of R2 || R1 for r || m (lambda + message_bits bits) */
static RandomnessSource derive_coins(CoinDerivation derivation, const uint8_t key[KEY_BYTES],
                                     const uint8_t *r_and_m, size_t bits)
{
    const size_t bytes = bits_to_bytes(bits);

    if (derivation == COINS_FROM_HASH) {
        uint8_t digest[crypto_generichash_BYTES_MAX];

        crypto_generichash(digest, sizeof(digest), r_and_m, bytes, key, KEY_BYTES);//keyed hash function (blake2b) - digest is result

        RandomnessSource coins = csprg_randomness(digest, sizeof(digest));

        sodium_memzero(digest, sizeof(digest));//coins does not own digest
        return coins;
    }

    //else if from PRF with seed r||m -> concatenate with prf key:

    uint8_t *seed = malloc(KEY_BYTES + bytes);

    if (seed == NULL)
        return (RandomnessSource){.ctx = NULL, .rng = NULL}; //leads to randomness failure -> handled higher up

    memcpy(seed, key, KEY_BYTES);
    memcpy(seed + KEY_BYTES, r_and_m, bytes);

    RandomnessSource coins = csprg_randomness(seed, KEY_BYTES + bytes);

    sodium_memzero(seed, KEY_BYTES + bytes);
    free(seed);

    return coins;
}

/*
 * The payload r || m || R2 (lambda + message_bits + lambda bits) for r || m;
 * coins is the generator of R2 || R1, which afterwards yields R1. Returns
 * NULL on error.
 */
static uint8_t *payload_of(const PRCReencode_Params *params, const uint8_t *r_and_m,
                           size_t message_bits, RandomnessSource *coins)
{
    const size_t r_and_m_bits = params->lambda + message_bits;
    uint8_t *payload = calloc(bits_to_bytes(r_and_m_bits + params->lambda), 1);
    uint8_t *R2 = malloc(params->lambda / 8);

    if (payload != NULL && R2 != NULL && coins->rng != NULL &&
        coins->rng(coins->ctx, R2, params->lambda / 8)) { //generate R2 (second output of PRF) first
        copy_bits(payload, 0, r_and_m, 0, r_and_m_bits);
        copy_bits(payload, r_and_m_bits, R2, 0, params->lambda);
    } else {
        free(payload);
        payload = NULL;
    }

    free(R2);

    return payload;
}

/* Encode(enc_key, m; rho = r): seed holds the lambda bits of r */
static uint8_t *reencode_encode_with_seed(const void *params_ptr,
                                          const MBPRC_EncKey *enc_key,
                                          const uint8_t *message,
                                          size_t message_bits,
                                          RandomnessSource *random,
                                          size_t *codeword_bits,
                                          const uint8_t *seed)
{
    const PRCReencode_Params *params = params_ptr;

    (void)random;   /* all coins are derived from (r, m) */

    if (!valid_params(params) || enc_key == NULL || message == NULL ||
        codeword_bits == NULL || seed == NULL || message_bits > SIZE_MAX - 2 * params->lambda)
        return NULL;

    const size_t r_and_m_bits = params->lambda + message_bits;
    uint8_t *r_and_m = calloc(bits_to_bytes(r_and_m_bits), 1);

    if (r_and_m == NULL)
        return NULL;

    copy_bits(r_and_m, 0, seed, 0, params->lambda);
    copy_bits(r_and_m, params->lambda, message, 0, message_bits);

    RandomnessSource coins = derive_coins(enc_key->derivation, enc_key->key, r_and_m,
                                          r_and_m_bits);
    uint8_t *payload = payload_of(params, r_and_m, message_bits, &coins);
    uint8_t *codeword = NULL;

    /* what remains of the stream is R1, the coins of the inner encoder */
    if (payload != NULL)
        codeword = mbprc_encode(params->inner, enc_key->inner_enc_key->key, payload,
                                r_and_m_bits + params->lambda, &coins, codeword_bits);

    csprg_randomness_free(&coins);
    free(payload);
    free(r_and_m);

    return codeword;
}

static uint8_t *reencode_encode(const void *params_ptr,
                                const MBPRC_EncKey *enc_key,
                                const uint8_t *message,
                                size_t message_bits,
                                RandomnessSource *random,
                                size_t *codeword_bits)
{
    const PRCReencode_Params *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    uint8_t *r = malloc(params->lambda / 8);

    if (r == NULL)
        return NULL;

    random_bytes(random, r, params->lambda / 8);

    uint8_t *codeword = reencode_encode_with_seed(params, enc_key, message, message_bits,
                                                  random, codeword_bits, r);

    free(r);

    return codeword;
}

/* RecDecode: m (message_out) and r (seed_out, lambda bits) */
static int reencode_recover_decode(const void *params_ptr,
                                   const MBPRC_DecKey *dec_key,
                                   const uint8_t *codeword,
                                   size_t codeword_bits,
                                   uint8_t *message_out,
                                   size_t *message_bits_out,
                                   uint8_t *seed_out)
{
    const PRCReencode_Params *params = params_ptr;

    if (!valid_params(params) || dec_key == NULL || codeword == NULL ||
        message_out == NULL || message_bits_out == NULL || seed_out == NULL)
        return 0;

    /* the payload r || m || R2' is never longer than the codeword */
    uint8_t *decoded = calloc(bits_to_bytes(codeword_bits) + 1, 1);
    uint8_t *payload = NULL;
    uint8_t *reencoded = NULL;
    RandomnessSource coins = {0};
    size_t decoded_bits = 0;
    size_t reencoded_bits = 0;
    int accepted = 0;

    if (decoded == NULL ||
        mbprc_decode(params->inner, dec_key->inner_dec_key, codeword, codeword_bits,
                     decoded, &decoded_bits) != 1 ||
        decoded_bits < 2 * params->lambda)
        goto done;

    if (decoded_bits % 8 != 0)
        decoded[decoded_bits / 8] &= (uint8_t)((1u << (decoded_bits % 8)) - 1); //remove bits (set to 0) that are not part of the decoded message

    const size_t message_bits = decoded_bits - 2 * params->lambda;
    const size_t r_and_m_bits = params->lambda + message_bits;

    /* decoded = r || m || R2': recompute R2 || R1 from its first r_and_m_bits bits */
    coins = derive_coins(dec_key->derivation, dec_key->key, decoded, r_and_m_bits);
    payload = payload_of(params, decoded, message_bits, &coins);

    if (payload == NULL ||
        !constant_time_equal(payload, decoded, bits_to_bytes(decoded_bits)))
        goto done;

    /* the re-encoding with R1 must be close to the received word (the channel flips bits) */
    reencoded = mbprc_encode(params->inner, dec_key->inner_enc_key->key, payload,
                             decoded_bits, &coins, &reencoded_bits);

    if (reencoded == NULL || reencoded_bits != codeword_bits ||
        (double)hamming_distance(codeword, reencoded, bits_to_bytes(codeword_bits)) >
            params->delta * (double)codeword_bits)
        goto done;

    copy_bits(seed_out, 0, decoded, 0, params->lambda);
    memset(message_out, 0, bits_to_bytes(message_bits)); //makes sure the last (potentially unused) bits are zero (not crucial tho)
    copy_bits(message_out, 0, decoded, params->lambda, message_bits);
    *message_bits_out = message_bits;
    accepted = 1;

done:
    csprg_randomness_free(&coins);
    free(reencoded);
    free(payload);
    free(decoded);

    return accepted;
}

static int reencode_decode(const void *params_ptr,
                           const MBPRC_DecKey *dec_key,
                           const uint8_t *codeword,
                           size_t codeword_bits,
                           uint8_t *message_out,
                           size_t *message_bits_out)
{
    const PRCReencode_Params *params = params_ptr;

    if (!valid_params(params))
        return 0;

    uint8_t *r = malloc(params->lambda / 8);

    if (r == NULL)
        return 0;

    /* the regular decoder discards r */
    const int accepted = reencode_recover_decode(params, dec_key, codeword, codeword_bits,
                                                 message_out, message_bits_out, r);

    free(r);

    return accepted;
}

static MBPRC reencode_prc(const PRCReencode_Params *params,
                          MBPRC_Keys *(*keygen_function)(const void *, RandomnessSource *))
{
    return (MBPRC){
        .params = params,
        .block_length = reencode_block_length,
        .keygen = keygen_function,
        .encode = reencode_encode,
        .decode = reencode_decode,
        .free_enc_key = reencode_free_enc_key,
        .free_dec_key = reencode_free_dec_key,
    };
}

MBPRC prc_sharp(const PRCReencode_Params *params)
{
    return reencode_prc(params, sharp_keygen);
}

MBPRC prc_cca(const PRCReencode_Params *params)
{
    return reencode_prc(params, cca_keygen);
}

MBPRC_RR prc_sharp_rr(const PRCReencode_Params *params)
{
    return (MBPRC_RR){
        .base = prc_sharp(params),
        .encode_with_seed = reencode_encode_with_seed,
        .recover_decode = reencode_recover_decode,
    };
}

MBPRC_RR prc_cca_rr(const PRCReencode_Params *params)
{
    return (MBPRC_RR){
        .base = prc_cca(params),
        .encode_with_seed = reencode_encode_with_seed,
        .recover_decode = reencode_recover_decode,
    };
}
