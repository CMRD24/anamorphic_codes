#ifndef MULTIBIT_PRC_H
#define MULTIBIT_PRC_H

/*
 * Multibit PRC:
 *
 *     KeyGen() -> (enc_key, dec_key)
 *     Encode(enc_key, m) -> c
 *     Decode(dec_key, c) -> m or failure
 *
 * Messages and codewords are packed bit strings (LSB first). Every
 * implementation defines its own struct MBPRC_EncKey / MBPRC_DecKey.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"

typedef struct MBPRC_EncKey MBPRC_EncKey;
typedef struct MBPRC_DecKey MBPRC_DecKey;

typedef struct {
    MBPRC_EncKey *enc;
    MBPRC_DecKey *dec;
} MBPRC_Keys;

typedef struct {
    /* implementation-specific parameters */
    const void *params;

    /* number of bits of a codeword */
    size_t (*block_length)(const void *params);

    /* generates the encoding and the decoding key, NULL on error */
    MBPRC_Keys *(*keygen)(const void *params, RandomnessSource *random);

    /*
     * Encodes a message of message_bits bits. Returns a newly allocated codeword
     * of *codeword_bits bits, NULL on error.
     */
    uint8_t *(*encode)(const void *params,
                       const MBPRC_EncKey *enc_key,
                       const uint8_t *message,
                       size_t message_bits,
                       RandomnessSource *random,
                       size_t *codeword_bits);

    /*
     * Returns 1 and writes the message to message_out (its length in bits to
     * message_bits_out) on success, 0 on a decoding failure.
     */
    int (*decode)(const void *params,
                  const MBPRC_DecKey *dec_key,
                  const uint8_t *codeword,
                  size_t codeword_bits,
                  uint8_t *message_out,
                  size_t *message_bits_out);

    void (*free_enc_key)(const void *params, MBPRC_EncKey *enc_key);
    void (*free_dec_key)(const void *params, MBPRC_DecKey *dec_key);
} MBPRC;


static inline size_t
mbprc_block_length(const MBPRC *prc)
{
    return prc->block_length(prc->params);
}

static inline MBPRC_Keys *
mbprc_keygen(const MBPRC *prc, RandomnessSource *random)
{
    return prc->keygen(prc->params, random);
}

static inline uint8_t *
mbprc_encode(const MBPRC *prc, const MBPRC_EncKey *enc_key, const uint8_t *message,
             size_t message_bits, RandomnessSource *random, size_t *codeword_bits)
{
    return prc->encode(prc->params, enc_key, message, message_bits, random, codeword_bits);
}

static inline int
mbprc_decode(const MBPRC *prc, const MBPRC_DecKey *dec_key, const uint8_t *codeword,
             size_t codeword_bits, uint8_t *message_out, size_t *message_bits_out)
{
    return prc->decode(prc->params, dec_key, codeword, codeword_bits, message_out,
                       message_bits_out);
}

static inline void
mbprc_free_enc_key(const MBPRC *prc, MBPRC_EncKey *enc_key)
{
    if (enc_key != NULL)
        prc->free_enc_key(prc->params, enc_key);
}

static inline void
mbprc_free_dec_key(const MBPRC *prc, MBPRC_DecKey *dec_key)
{
    if (dec_key != NULL)
        prc->free_dec_key(prc->params, dec_key);
}

static inline void
mbprc_free_keys(const MBPRC *prc, MBPRC_Keys *keys)
{
    if (keys == NULL)
        return;

    mbprc_free_enc_key(prc, keys->enc);
    mbprc_free_dec_key(prc, keys->dec);
    free(keys);
}

#endif /* MULTIBIT_PRC_H */
