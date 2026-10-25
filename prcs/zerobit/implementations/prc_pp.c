/*
 * Zero-bit PRC from a "permuted puzzle" over a q-ary alphabet (the
 * error-correcting-code based construction of Christ and Gunn, "Pseudorandom
 * Error-Correcting Codes", CRYPTO 2024).
 *
 * Let C be an error-correcting code with a worst-case decoder, encoding x in F_q^k
 * to a word of F_q^n.
 *
 * Key: a random permutation sigma of the positions (sigma(i) is the position of
 * the source symbol used at output position i), permutations pi_i of F_q for
 * every position i, and a one-time pad o in F_q^n.
 *
 * Encode: x uniform, c = C(x); hat_c_i = pi_i(c_sigma(i)) (permute and relabel
 * symbols); pass hat_c through the q-ary substitution channel with probability
 * delta/2 (each symbol replaced by a different uniform one); output
 * hat_c + o. Without the key the output is uniform because of the pad.
 *
 * Decode: subtract o, undo pi_i and sigma to obtain a noisy word of C, decode it
 * with the decoder of C, re-encode and compare with the received word: accept iff
 * the Hamming distance is at most delta n. A random word is far from every
 * codeword when C has a sparse enough set of codewords.
 *
 * The message x is the seed rho recovered by the decoder (and the substitution
 * noise the further coins omega), so the randomness-recovery anamorphism can
 * choose it freely (encode_with_seed).
 */

#include "prc_pp.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "../../../utils/random_utils.h"


struct ZBPRC_EncKey {
    size_t *sigma;     /* hat_c[i] = pi[i][c[sigma[i]]] */
    size_t **pi;       /* n permutations of {0, ..., q-1} */
    size_t *pad;       /* the one-time pad o, one symbol per position */
};

struct ZBPRC_DecKey {
    size_t *sigma;
    size_t **pi_inverse;   /* pi_inverse[i] = pi[i]^-1 */
    size_t *pad;
};


/*
 * Symbols are packed consecutively, least significant bit first: for
 * symbol_bits = 4 the symbols a b c are [a0 a1 a2 a3 | b0 b1 b2 b3 | c0 c1 c2 c3].
 * q need not be a power of two; values >= q are invalid.
 */
static size_t get_symbol(const uint8_t *buf, size_t index, size_t symbol_bits)
{
    const size_t first_bit = index * symbol_bits;
    size_t value = 0;

    for (size_t j = 0; j < symbol_bits; j++) {
        const size_t bit = first_bit + j;

        value |= (size_t)((buf[bit >> 3] >> (bit & 7)) & 1u) << j;
    }

    return value;
}

static void set_symbol(uint8_t *buf, size_t index, size_t symbol_bits, size_t value)
{
    const size_t first_bit = index * symbol_bits;

    for (size_t j = 0; j < symbol_bits; j++) {
        const size_t bit = first_bit + j;
        const uint8_t mask = (uint8_t)(1u << (bit & 7));

        if ((value >> j) & 1u)
            buf[bit >> 3] |= mask;
        else
            buf[bit >> 3] &= (uint8_t)~mask;
    }
}

/* bytes of a word of n symbols */
static size_t word_bytes(const PPParams *params)
{
    return (params->n * params->symbol_bits + 7) / 8;
}

static int valid_params(const PPParams *params)
{
    return params != NULL && params->ecc != NULL && params->q >= 2 && params->n > 0 &&
           params->symbol_bits > 0 && params->symbol_bits < 8 * sizeof(size_t) &&
           params->q <= ((size_t)1 << params->symbol_bits) &&
           params->n <= SIZE_MAX / params->symbol_bits &&
           ecc_encoded_size(params->ecc, params->seed_bytes) == word_bytes(params);
}

static size_t *copy_array(const size_t *array, size_t length)
{
    size_t *copy = malloc(length * sizeof(*copy));

    if (copy != NULL)
        memcpy(copy, array, length * sizeof(*copy));

    return copy;
}

static void free_permutations(size_t **permutations, size_t n)
{
    if (permutations == NULL)
        return;

    for (size_t i = 0; i < n; i++)
        free(permutations[i]);

    free(permutations);
}

static void pp_free_enc_key(const void *params_ptr, ZBPRC_EncKey *enc_key)
{
    const PPParams *params = params_ptr;

    if (enc_key == NULL)
        return;

    free(enc_key->sigma);
    free(enc_key->pad);
    free_permutations(enc_key->pi, params->n);
    free(enc_key);
}

static void pp_free_dec_key(const void *params_ptr, ZBPRC_DecKey *dec_key)
{
    const PPParams *params = params_ptr;

    if (dec_key == NULL)
        return;

    free(dec_key->sigma);
    free(dec_key->pad);
    free_permutations(dec_key->pi_inverse, params->n);
    free(dec_key);
}

/* sigma, the pi_i and the pad o; the decoding key holds the inverses pi_i^-1 */
static ZBPRC_Keys *pp_keygen(const void *params_ptr, RandomnessSource *random)
{
    const PPParams *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    const size_t n = params->n;
    const size_t q = params->q;
    ZBPRC_Keys *keys = calloc(1, sizeof(*keys));

    if (keys == NULL)
        return NULL;

    keys->enc = calloc(1, sizeof(*keys->enc));
    keys->dec = calloc(1, sizeof(*keys->dec));

    if (keys->enc == NULL || keys->dec == NULL)
        goto fail;

    keys->enc->sigma = malloc(n * sizeof(size_t));
    keys->enc->pad = malloc(n * sizeof(size_t));
    keys->enc->pi = calloc(n, sizeof(size_t *));
    keys->dec->pi_inverse = calloc(n, sizeof(size_t *));

    if (keys->enc->sigma == NULL || keys->enc->pad == NULL ||
        keys->enc->pi == NULL || keys->dec->pi_inverse == NULL)
        goto fail;

    random_permutation(random, keys->enc->sigma, n);

    for (size_t i = 0; i < n; i++) {
        keys->enc->pi[i] = malloc(q * sizeof(size_t));
        keys->dec->pi_inverse[i] = malloc(q * sizeof(size_t));

        if (keys->enc->pi[i] == NULL || keys->dec->pi_inverse[i] == NULL)
            goto fail;

        random_permutation(random, keys->enc->pi[i], q);

        for (size_t symbol = 0; symbol < q; symbol++)
            keys->dec->pi_inverse[i][keys->enc->pi[i][symbol]] = symbol;
    }

    for (size_t i = 0; i < n; i++)
        keys->enc->pad[i] = random_bounded(random, q);

    keys->dec->sigma = copy_array(keys->enc->sigma, n);
    keys->dec->pad = copy_array(keys->enc->pad, n);

    if (keys->dec->sigma == NULL || keys->dec->pad == NULL)
        goto fail;

    return keys;

fail:
    pp_free_enc_key(params, keys->enc);
    pp_free_dec_key(params, keys->dec);
    free(keys);

    return NULL;
}

/*
 * The q-ary substitution channel SC_p on one symbol: with probability p the
 * symbol is replaced by a uniform different symbol (a uniform value of [0, q-2]
 * mapped to F_q \ {symbol}), otherwise it is kept. The uniform double in [0, 1)
 * is formed from 53 random bits.
 */
static size_t substitute_symbol(size_t symbol, size_t q, double probability,
                                RandomnessSource *random)
{
    if (probability <= 0.0)
        return symbol;

    const double uniform = (double)(random_u64(random) >> 11) / 9007199254740992.0;

    if (uniform >= probability)
        return symbol;

    const size_t other = random_bounded(random, q - 1);

    return other >= symbol ? other + 1 : other;
}

/* Encode(enc_key; rho = x, omega): x is the seed of seed_bytes bytes */
static uint8_t *pp_encode_with_seed(const void *params_ptr,
                                    const ZBPRC_EncKey *enc_key,
                                    RandomnessSource *random,
                                    size_t *codeword_bits,
                                    const uint8_t *seed)
{
    const PPParams *params = params_ptr;

    if (!valid_params(params) || enc_key == NULL || random == NULL ||
        codeword_bits == NULL || seed == NULL)
        return NULL;

    const size_t bytes = word_bytes(params);
    uint8_t *ecc_codeword = calloc(bytes, 1);
    uint8_t *codeword = calloc(bytes, 1);
    size_t ecc_codeword_bytes = bytes;

    if (ecc_codeword == NULL || codeword == NULL ||
        ecc_encode(params->ecc, seed, params->seed_bytes, ecc_codeword,
                   &ecc_codeword_bytes) != 0 ||
        ecc_codeword_bytes != bytes)
        goto fail;

    for (size_t i = 0; i < params->n; i++) {
        size_t symbol = get_symbol(ecc_codeword, enc_key->sigma[i], params->symbol_bits);

        /* the ECC output must only contain symbols of F_q */
        if (symbol >= params->q)
            goto fail;

        /* hat_c_i = pi_i(c_sigma(i)), then SC_{delta/2}, then + o_i */
        symbol = enc_key->pi[i][symbol];
        symbol = substitute_symbol(symbol, params->q, params->delta / 2.0, random);
        symbol = (symbol + enc_key->pad[i]) % params->q;

        set_symbol(codeword, i, params->symbol_bits, symbol);
    }

    free(ecc_codeword);
    *codeword_bits = params->n * params->symbol_bits;

    return codeword;

fail:
    free(ecc_codeword);
    free(codeword);

    return NULL;
}

static uint8_t *pp_encode(const void *params_ptr,
                          const ZBPRC_EncKey *enc_key,
                          RandomnessSource *random,
                          size_t *codeword_bits)
{
    const PPParams *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    uint8_t *x = malloc(params->seed_bytes ? params->seed_bytes : 1);

    if (x == NULL)
        return NULL;

    random_bytes(random, x, params->seed_bytes);

    uint8_t *codeword = pp_encode_with_seed(params, enc_key, random, codeword_bits, x);

    free(x);

    return codeword;
}

/*
 * RecDecode: removes the pad, undoes pi_i and sigma, decodes C to x (seed_out,
 * seed_bytes bytes), re-encodes x and accepts iff the re-encoding differs from
 * the received word of C in at most delta n symbols.
 */
static int pp_recover_decode(const void *params_ptr,
                             const ZBPRC_DecKey *dec_key,
                             const uint8_t *codeword,
                             size_t codeword_bits,
                             uint8_t *seed_out)
{
    const PPParams *params = params_ptr;

    if (!valid_params(params) || dec_key == NULL || codeword == NULL || seed_out == NULL ||
        codeword_bits != params->n * params->symbol_bits)
        return 0;

    const size_t bytes = word_bytes(params);
    uint8_t *received = calloc(bytes, 1);       /* the noisy word of C */
    uint8_t *reencoded = calloc(bytes, 1);
    size_t reencoded_bytes = bytes;
    int accepted = 0;

    if (received == NULL || reencoded == NULL)
        goto done;

    for (size_t i = 0; i < params->n; i++) {
        size_t symbol = get_symbol(codeword, i, params->symbol_bits);

        if (symbol >= params->q)
            goto done;

        /* c[sigma[i]] = pi_i^-1(hat_c[i] - o_i) */
        symbol = (symbol + params->q - dec_key->pad[i]) % params->q;
        set_symbol(received, dec_key->sigma[i], params->symbol_bits,
                   dec_key->pi_inverse[i][symbol]);
    }

    if (ecc_decode(params->ecc, received, bytes, seed_out, params->seed_bytes) != 0 ||
        ecc_encode(params->ecc, seed_out, params->seed_bytes, reencoded,
                   &reencoded_bytes) != 0 ||
        reencoded_bytes != bytes)
        goto done;

    size_t distance = 0;

    for (size_t i = 0; i < params->n; i++)
        distance += get_symbol(received, i, params->symbol_bits) !=
                    get_symbol(reencoded, i, params->symbol_bits);

    accepted = (double)distance <= params->delta * (double)params->n;

done:
    free(received);
    free(reencoded);

    return accepted;
}

/* the regular decoder discards the recovered x */
static int pp_decode(const void *params_ptr,
                     const ZBPRC_DecKey *dec_key,
                     const uint8_t *codeword,
                     size_t codeword_bits)
{
    const PPParams *params = params_ptr;

    if (!valid_params(params))
        return 0;

    uint8_t *x = malloc(params->seed_bytes ? params->seed_bytes : 1);

    if (x == NULL)
        return 0;

    const int accepted = pp_recover_decode(params, dec_key, codeword, codeword_bits, x);

    free(x);

    return accepted;
}

static size_t pp_block_length(const void *params_ptr)
{
    const PPParams *params = params_ptr;

    return params->n * params->symbol_bits;
}

ZBPRC prc_pp(const PPParams *params)
{
    return (ZBPRC){
        .params = params,
        .block_length = pp_block_length,
        .keygen = pp_keygen,
        .encode = pp_encode,
        .decode = pp_decode,
        .free_enc_key = pp_free_enc_key,
        .free_dec_key = pp_free_dec_key,
    };
}

ZBPRC_RR prc_pp_rr(const PPParams *params)
{
    return (ZBPRC_RR){
        .base = prc_pp(params),
        .encode_with_seed = pp_encode_with_seed,
        .recover_decode = pp_recover_decode,
    };
}
