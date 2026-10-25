#ifndef ZERO_BIT_PRC_H
#define ZERO_BIT_PRC_H

/*
 * Zero-bit PRC: the message space is {1}, i.e. a codeword only tells the decoder
 * that it is not random.
 *
 *     KeyGen() -> (enc_key, dec_key)
 *     Encode(enc_key) -> c
 *     Decode(dec_key, c) -> 1 (accept) or 0 (reject)
 *
 * Every implementation defines its own struct ZBPRC_EncKey / ZBPRC_DecKey.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"

typedef struct ZBPRC_EncKey ZBPRC_EncKey;
typedef struct ZBPRC_DecKey ZBPRC_DecKey;

typedef struct {
    ZBPRC_EncKey *enc;
    ZBPRC_DecKey *dec;
} ZBPRC_Keys;

typedef struct {
    /* implementation-specific parameters */
    const void *params;

    /* number of bits of a codeword */
    size_t (*block_length)(const void *params);

    /* generates the encoding and the decoding key, NULL on error */
    ZBPRC_Keys *(*keygen)(const void *params, RandomnessSource *random);

    /*
     * Encodes the bit 1. Returns a newly allocated packed bit string (LSB first)
     * of *codeword_bits bits, NULL on error.
     */
    uint8_t *(*encode)(const void *params,
                       const ZBPRC_EncKey *enc_key,
                       RandomnessSource *random,
                       size_t *codeword_bits);

    /* 1 = accept, 0 = reject */
    int (*decode)(const void *params,
                  const ZBPRC_DecKey *dec_key,
                  const uint8_t *codeword,
                  size_t codeword_bits);

    void (*free_enc_key)(const void *params, ZBPRC_EncKey *enc_key);
    void (*free_dec_key)(const void *params, ZBPRC_DecKey *dec_key);
} ZBPRC;


static inline size_t
zbprc_block_length(const ZBPRC *prc)
{
    return prc->block_length(prc->params);
}

static inline ZBPRC_Keys *
zbprc_keygen(const ZBPRC *prc, RandomnessSource *random)
{
    return prc->keygen(prc->params, random);
}

static inline uint8_t *
zbprc_encode(const ZBPRC *prc, const ZBPRC_EncKey *enc_key,
             RandomnessSource *random, size_t *codeword_bits)
{
    return prc->encode(prc->params, enc_key, random, codeword_bits);
}

static inline int
zbprc_decode(const ZBPRC *prc, const ZBPRC_DecKey *dec_key,
             const uint8_t *codeword, size_t codeword_bits)
{
    return prc->decode(prc->params, dec_key, codeword, codeword_bits);
}

static inline void
zbprc_free_enc_key(const ZBPRC *prc, ZBPRC_EncKey *enc_key)
{
    prc->free_enc_key(prc->params, enc_key);
}

static inline void
zbprc_free_dec_key(const ZBPRC *prc, ZBPRC_DecKey *dec_key)
{
    prc->free_dec_key(prc->params, dec_key);
}

static inline void
zbprc_free_keys(const ZBPRC *prc, ZBPRC_Keys *keys)
{
    if (keys == NULL)
        return;

    if (keys->enc != NULL)
        prc->free_enc_key(prc->params, keys->enc);

    if (keys->dec != NULL)
        prc->free_dec_key(prc->params, keys->dec);

    free(keys);
}

#endif /* ZERO_BIT_PRC_H */
