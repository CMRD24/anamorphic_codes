/*
 * PRC_high: a PRC for longer messages of message_bits bits (the construction of
 * Christ and Gunn, "Pseudorandom Error-Correcting Codes", CRYPTO 2024, that
 * encodes the message with an ordinary error-correcting code and hides it
 * with a pseudorandom pad).
 *
 * Encode(m): sample a seed r of lambda bits; encode r with the inner PRC (PRC_low);
 * output the concatenation Enc_inner(r) || tau with tau = ECC(m) XOR PRG(r), with a
 * secret permutation of all bit positions. PRG is a pseudorandom generator (the
 * ChaCha20 generator of csprg_sodium.c). The pad PRG(r) makes tau look uniform,
 * the inner PRC makes the first part look uniform.
 *
 * Decode: undo the permutation, decode r from the inner PRC, recompute PRG(r),
 * unmask tau and decode the ECC. The error-correction of the message is that of
 * the ECC; the seed r is the value the anamorphic mode controls (rho = r).
 */

#include "prc_high.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/csprg_sodium.h"
#include "../../../utils/helpers.h"
#include "../../../utils/random_utils.h"


struct MBPRC_EncKey {
    MBPRC_EncKey *inner_key;
    size_t *permutation;     /* codeword[permutation[i]] = unpermuted[i] */
};

struct MBPRC_DecKey {
    MBPRC_DecKey *inner_key;
    size_t *permutation;     /* unpermuted[i] = codeword[permutation[i]] */
};


static size_t inner_bits_of(const PRCHigh_Params *params)
{
    return mbprc_block_length(params->inner);
}

/* bytes of ECC(m), the length of tau */
static size_t tau_bytes_of(const PRCHigh_Params *params)
{
    return ecc_encoded_size(params->ecc, params->message_bits / 8);
}

static size_t high_block_length(const void *params_ptr)
{
    const PRCHigh_Params *params = params_ptr;

    return inner_bits_of(params) + 8 * tau_bytes_of(params);
}

static int valid_params(const PRCHigh_Params *params)
{
    return params != NULL && params->inner != NULL && params->ecc != NULL &&
           params->lambda > 0 && params->lambda % 8 == 0 && params->message_bits % 8 == 0 &&
           tau_bytes_of(params) > 0;
}

static void high_free_enc_key(const void *params_ptr, MBPRC_EncKey *enc_key)
{
    const PRCHigh_Params *params = params_ptr;

    if (enc_key == NULL)
        return;

    mbprc_free_enc_key(params->inner, enc_key->inner_key);
    free(enc_key->permutation);
    free(enc_key);
}

static void high_free_dec_key(const void *params_ptr, MBPRC_DecKey *dec_key)
{
    const PRCHigh_Params *params = params_ptr;

    if (dec_key == NULL)
        return;

    mbprc_free_dec_key(params->inner, dec_key->inner_key);
    free(dec_key->permutation);
    free(dec_key);
}

/* the inner key pair and a uniform permutation of the codeword bits */
static MBPRC_Keys *high_keygen(const void *params_ptr, RandomnessSource *random)
{
    const PRCHigh_Params *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    const size_t codeword_bits = high_block_length(params);
    MBPRC_Keys *keys = calloc(1, sizeof(*keys));
    MBPRC_Keys *inner_keys = NULL;

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (keys->enc == NULL || keys->dec == NULL ||
        (inner_keys = mbprc_keygen(params->inner, random)) == NULL)
        goto fail;

    keys->enc->inner_key = inner_keys->enc;
    keys->dec->inner_key = inner_keys->dec;
    free(inner_keys);

    keys->enc->permutation = malloc(codeword_bits * sizeof(size_t));
    keys->dec->permutation = malloc(codeword_bits * sizeof(size_t));

    if (keys->enc->permutation == NULL || keys->dec->permutation == NULL)
        goto fail;

    random_permutation(random, keys->enc->permutation, codeword_bits);
    memcpy(keys->dec->permutation, keys->enc->permutation, codeword_bits * sizeof(size_t));

    return keys;

fail:
    high_free_enc_key(params, keys->enc);
    high_free_dec_key(params, keys->dec);
    free(keys);

    return NULL;
}

/* data XOR= PRG(r) for len bytes; returns 0 on failure */
static int xor_prg(uint8_t *data, size_t len, const uint8_t *r, size_t r_bytes)
{
    RandomnessSource prg = csprg_randomness(r, r_bytes);
    uint8_t *pad = malloc(len);
    int ok = pad != NULL && prg.rng != NULL && prg.rng(prg.ctx, pad, len);

    for (size_t i = 0; ok && i < len; ++i)
        data[i] ^= pad[i];

    free(pad);
    csprg_randomness_free(&prg);

    return ok;
}

/* Encode(enc_key, m; rho = r, omega): seed holds the lambda bits of r */
static uint8_t *high_encode_with_seed(const void *params_ptr,
                                      const MBPRC_EncKey *enc_key,
                                      const uint8_t *message,
                                      size_t message_bits,
                                      RandomnessSource *random,
                                      size_t *codeword_bits,
                                      const uint8_t *seed)
{
    const PRCHigh_Params *params = params_ptr;

    if (!valid_params(params) || enc_key == NULL || message == NULL || random == NULL ||
        codeword_bits == NULL || seed == NULL || message_bits != params->message_bits)
        return NULL;

    const size_t inner_bits = inner_bits_of(params);
    const size_t tau_bytes = tau_bytes_of(params);
    const size_t total_bits = high_block_length(params);
    size_t encoded_seed_bits = 0;
    size_t ecc_bytes = 0;
    uint8_t *encoded_seed = mbprc_encode(params->inner, enc_key->inner_key, seed,
                                         params->lambda, random, &encoded_seed_bits);
    uint8_t *tau = malloc(tau_bytes);
    uint8_t *unpermuted = calloc(bits_to_bytes(total_bits), 1);
    uint8_t *codeword = calloc(bits_to_bytes(total_bits), 1);
    int ok = encoded_seed != NULL && encoded_seed_bits == inner_bits && tau != NULL &&
             unpermuted != NULL && codeword != NULL;

    /* tau = ECC(m) XOR PRG(r) */
    ok = ok && ecc_encode(params->ecc, message, message_bits / 8, tau, &ecc_bytes) == 0 &&
         ecc_bytes == tau_bytes && xor_prg(tau, tau_bytes, seed, params->lambda / 8);

    if (ok) {
        copy_bits(unpermuted, 0, encoded_seed, 0, inner_bits);
        copy_bits(unpermuted, inner_bits, tau, 0, 8 * tau_bytes);

        for (size_t i = 0; i < total_bits; ++i)
            set_bit(codeword, enc_key->permutation[i], get_bit(unpermuted, i));

        *codeword_bits = total_bits;
    } else {
        free(codeword);
        codeword = NULL;
    }

    free(encoded_seed);
    free(tau);
    free(unpermuted);

    return codeword;
}

static uint8_t *high_encode(const void *params_ptr,
                            const MBPRC_EncKey *enc_key,
                            const uint8_t *message,
                            size_t message_bits,
                            RandomnessSource *random,
                            size_t *codeword_bits)
{
    const PRCHigh_Params *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    uint8_t *r = malloc(params->lambda / 8);

    if (r == NULL)
        return NULL;

    random_bytes(random, r, params->lambda / 8);

    uint8_t *codeword = high_encode_with_seed(params, enc_key, message, message_bits, random,
                                              codeword_bits, r);

    free(r);

    return codeword;
}

/* RecDecode: m (message_out) and r (seed_out, lambda bits) */
static int high_recover_decode(const void *params_ptr,
                               const MBPRC_DecKey *dec_key,
                               const uint8_t *codeword,
                               size_t codeword_bits,
                               uint8_t *message_out,
                               size_t *message_bits_out,
                               uint8_t *seed_out)
{
    const PRCHigh_Params *params = params_ptr;

    if (!valid_params(params) || dec_key == NULL || codeword == NULL ||
        message_out == NULL || message_bits_out == NULL || seed_out == NULL ||
        codeword_bits != high_block_length(params))
        return 0;

    const size_t inner_bits = inner_bits_of(params);
    const size_t tau_bytes = tau_bytes_of(params);
    const size_t message_bytes = ecc_decoded_size(params->ecc, tau_bytes);
    uint8_t *unpermuted = calloc(bits_to_bytes(codeword_bits), 1);
    uint8_t *encoded_seed = calloc(bits_to_bytes(inner_bits), 1);
    uint8_t *tau = calloc(tau_bytes, 1);
    size_t seed_bits = 0;
    int ok = unpermuted != NULL && encoded_seed != NULL && tau != NULL && message_bytes > 0;

    if (ok) {
        for (size_t i = 0; i < codeword_bits; ++i)
            set_bit(unpermuted, i, get_bit(codeword, dec_key->permutation[i]));

        copy_bits(encoded_seed, 0, unpermuted, 0, inner_bits);
        copy_bits(tau, 0, unpermuted, inner_bits, 8 * tau_bytes);
    }

    /* r from the inner PRC, then ECC(m) = tau XOR PRG(r) */
    ok = ok &&
         mbprc_decode(params->inner, dec_key->inner_key, encoded_seed, inner_bits, seed_out,
                      &seed_bits) == 1 &&
         seed_bits == params->lambda &&
         xor_prg(tau, tau_bytes, seed_out, params->lambda / 8) &&
         ecc_decode(params->ecc, tau, tau_bytes, message_out, message_bytes) == 0;

    if (ok)
        *message_bits_out = 8 * message_bytes;

    free(unpermuted);
    free(encoded_seed);
    free(tau);

    return ok;
}

static int high_decode(const void *params_ptr,
                       const MBPRC_DecKey *dec_key,
                       const uint8_t *codeword,
                       size_t codeword_bits,
                       uint8_t *message_out,
                       size_t *message_bits_out)
{
    const PRCHigh_Params *params = params_ptr;

    if (!valid_params(params))
        return 0;

    uint8_t *r = malloc(params->lambda / 8);

    if (r == NULL)
        return 0;

    /* the regular decoder discards r */
    const int accepted = high_recover_decode(params, dec_key, codeword, codeword_bits,
                                             message_out, message_bits_out, r);

    free(r);

    return accepted;
}

MBPRC prc_high(const PRCHigh_Params *params)
{
    return (MBPRC){
        .params = params,
        .block_length = high_block_length,
        .keygen = high_keygen,
        .encode = high_encode,
        .decode = high_decode,
        .free_enc_key = high_free_enc_key,
        .free_dec_key = high_free_dec_key,
    };
}

MBPRC_RR prc_high_rr(const PRCHigh_Params *params)
{
    return (MBPRC_RR){
        .base = prc_high(params),
        .encode_with_seed = high_encode_with_seed,
        .recover_decode = high_recover_decode,
    };
}
