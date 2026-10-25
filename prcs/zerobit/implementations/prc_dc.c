/*
 * Zero-bit PRC for channels with deletions and insertions (substitutions), built
 * on any zero-bit PRC with codewords of k bits: each codeword bit is expanded into
 * a slice of T bits with the same majority, in the spirit of the constructions for
 * indel channels in Christ and Gunn, "Pseudorandom Error-Correcting Codes",
 * CRYPTO 2024.
 *
 * Encode: every bit b_i of a codeword of the underlying PRC is replaced by a
 * uniform T-bit string z_i whose majority is b_i; the output is z_1 || ... || z_k
 * (k T bits). Because each z_i is uniform among strings with that majority and
 * the underlying codeword is pseudorandom, the output is pseudorandom.
 *
 * Decode: cut the received word into k consecutive slices of nearly equal length
 * (the first (L mod k) slices have one extra bit, L = received length), take the
 * majority of every slice and decode the resulting k bits with the underlying
 * PRC. Isolated deletions and insertions only move slice boundaries slightly, so
 * the majorities mostly stay correct.
 *
 * The keys are those of the underlying PRC.
 */

#include "prc_dc.h"

#include <stdint.h>
#include <stdlib.h>

#include "../../../utils/helpers.h"
#include "../../../utils/random_utils.h"


/* 1 if more than half of the bits [offset, offset + length) are 1 (a tie gives 0) */
static uint8_t majority(const uint8_t *bits, size_t offset, size_t length)
{
    size_t weight = 0;

    for (size_t i = 0; i < length; ++i)
        weight += get_bit(bits, offset + i);

    return (uint8_t)(weight > length / 2);
}

/*
 * Writes a uniform element of { z in {0,1}^slice_bits : majority(z) = bit } to
 * the (zeroed) bits [offset, offset + slice_bits) of output, by rejection
 * sampling of uniform strings (exactly uniform on that set). Returns 0 on
 * allocation failure.
 */
static int sample_majority_slice(uint8_t *output, size_t offset, size_t slice_bits,
                                 uint8_t bit, RandomnessSource *random)
{
    const size_t slice_bytes = bits_to_bytes(slice_bits);
    uint8_t *candidate = malloc(slice_bytes);

    if (candidate == NULL)
        return 0;

    do {
        random_bytes(random, candidate, slice_bytes);
    } while (majority(candidate, 0, slice_bits) != bit);

    copy_bits(output, offset, candidate, 0, slice_bits);
    free(candidate);

    return 1;
}

static int valid_params(const PRCDC_Params *params)
{
    return params != NULL && params->slice_bits > 0 && params->underlying != NULL &&
           params->underlying->block_length != NULL &&
           zbprc_block_length(params->underlying) <= SIZE_MAX / params->slice_bits;
}

static size_t dc_block_length(const void *params_ptr)
{
    const PRCDC_Params *params = params_ptr;

    return zbprc_block_length(params->underlying) * params->slice_bits;
}

static ZBPRC_Keys *dc_keygen(const void *params_ptr, RandomnessSource *random)
{
    const PRCDC_Params *params = params_ptr;

    if (!valid_params(params) || random == NULL)
        return NULL;

    return zbprc_keygen(params->underlying, random);
}

static uint8_t *dc_encode(const void *params_ptr,
                          const ZBPRC_EncKey *enc_key,
                          RandomnessSource *random,
                          size_t *codeword_bits)
{
    const PRCDC_Params *params = params_ptr;

    if (!valid_params(params) || enc_key == NULL || random == NULL || codeword_bits == NULL)
        return NULL;

    size_t underlying_bits = 0;
    uint8_t *underlying_codeword = zbprc_encode(params->underlying, enc_key, random,
                                                &underlying_bits);

    if (underlying_codeword == NULL)
        return NULL;

    uint8_t *codeword = calloc(bits_to_bytes(underlying_bits * params->slice_bits) + 1, 1);
    int ok = codeword != NULL;

    for (size_t i = 0; ok && i < underlying_bits; ++i)
        ok = sample_majority_slice(codeword, i * params->slice_bits, params->slice_bits,
                                   get_bit(underlying_codeword, i), random);

    free(underlying_codeword);

    if (!ok) {
        free(codeword);
        return NULL;
    }

    *codeword_bits = underlying_bits * params->slice_bits;

    return codeword;
}

static int dc_decode(const void *params_ptr,
                     const ZBPRC_DecKey *dec_key,
                     const uint8_t *codeword,
                     size_t codeword_bits)
{
    const PRCDC_Params *params = params_ptr;

    if (!valid_params(params) || dec_key == NULL || codeword == NULL)
        return 0;

    const size_t underlying_bits = zbprc_block_length(params->underlying);

    /* every slice must contain at least one bit */
    if (codeword_bits < underlying_bits)
        return 0;

    /* L = short_length k + remainder: the first `remainder` slices have one bit more */
    const size_t short_length = codeword_bits / underlying_bits;
    const size_t remainder = codeword_bits % underlying_bits;
    uint8_t *underlying_codeword = calloc(bits_to_bytes(underlying_bits), 1);
    size_t offset = 0;

    if (underlying_codeword == NULL)
        return 0;

    for (size_t i = 0; i < underlying_bits; ++i) {
        const size_t slice_length = short_length + (i < remainder ? 1 : 0);

        set_bit(underlying_codeword, i, majority(codeword, offset, slice_length));
        offset += slice_length;
    }

    const int accepted = zbprc_decode(params->underlying, dec_key, underlying_codeword,
                                      underlying_bits);

    free(underlying_codeword);

    return accepted;
}

static void dc_free_enc_key(const void *params_ptr, ZBPRC_EncKey *enc_key)
{
    const PRCDC_Params *params = params_ptr;

    if (enc_key != NULL)
        zbprc_free_enc_key(params->underlying, enc_key);
}

static void dc_free_dec_key(const void *params_ptr, ZBPRC_DecKey *dec_key)
{
    const PRCDC_Params *params = params_ptr;

    if (dec_key != NULL)
        zbprc_free_dec_key(params->underlying, dec_key);
}

ZBPRC prc_dc(const PRCDC_Params *params)
{
    return (ZBPRC){
        .params = params,
        .block_length = dc_block_length,
        .keygen = dc_keygen,
        .encode = dc_encode,
        .decode = dc_decode,
        .free_enc_key = dc_free_enc_key,
        .free_dec_key = dc_free_dec_key,
    };
}
