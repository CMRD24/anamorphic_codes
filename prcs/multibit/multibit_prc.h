#ifndef MULTIBIT_PRC_H
#define MULTIBIT_PRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>

/*
 * ================================================================
 * Randomness
 * ================================================================
 */

typedef int (*MBPRC_Rng)(
    void *ctx,
    uint8_t *out,
    size_t len
);

typedef struct {
    MBPRC_Rng rng;
    void *ctx;
} MBPRC_Random;


/*
 * ================================================================
 * Opaque key types
 * ================================================================
 */

typedef struct MBPRC_EncKey MBPRC_EncKey;
typedef struct MBPRC_DecKey MBPRC_DecKey;


/*
 * ================================================================
 * Key pair
 * ================================================================
 *
 * KeyGen generates both keys simultaneously.
 */

typedef struct {
    MBPRC_EncKey *enc;
    MBPRC_DecKey *dec;
} MBPRC_Keys;


/*
 * ================================================================
 * Multibit PRC interface
 * ================================================================
 *
 * A multibit PRC provides:
 *
 *     KeyGen() -> (ek, dk)
 *     Encode(ek, m) -> c
 *     Decode(dk, c) -> m
 *
 * The concrete key types and parameters are hidden behind
 * this interface.
 * ================================================================
 */

typedef struct {

    /*
     * Implementation-specific parameters.
     *
     * The generic interface does not interpret this pointer.
     */
    const void *params;



    size_t (*blocksize)(
        const void *params
    );

    /*
     * ------------------------------------------------------------
     * Key generation
     * ------------------------------------------------------------
     *
     * Generates both the encoding and decoding keys.
     */
    MBPRC_Keys *(*keygen)(
        const void *params,
        MBPRC_Random *random
    );


    /*
     * ------------------------------------------------------------
     * Encoding
     * ------------------------------------------------------------
     *
     * Encodes a message.
     *
     * Returns a newly allocated packed ciphertext.
     *
     * The number of valid ciphertext bits is written to
     * output_bits.
     *
     * The caller owns the returned buffer.
     */
    uint8_t *(*encode)(
        const void *params,
        const MBPRC_EncKey *key,
        const uint8_t *message,
        size_t message_bits,
        MBPRC_Random *random,
        size_t *output_bits
    );


    /*
     * ------------------------------------------------------------
     * Decoding
     * ------------------------------------------------------------
     *
     * Decodes a ciphertext.
     *
     * Returns:
     *
     *     1 = successfully decoded
     *     0 = decoding failure
     *
     * On success, the decoded message is written to message_out.
     *
     */
    int (*decode)(
        const void *params,
        const MBPRC_DecKey *key,
        const uint8_t *ciphertext,
        size_t ciphertext_bits,
        uint8_t *message_out,
        size_t *message_bits_out
    );


    /*
     * ------------------------------------------------------------
     * Key destruction
     * ------------------------------------------------------------
     */

    void (*free_enc_key)(
        const void *params,
        MBPRC_EncKey *key
    );

    void (*free_dec_key)(
        const void *params,
        MBPRC_DecKey *key
    );

} MBPRC;


/*
 * ================================================================
 * Convenience functions
 * ================================================================
 */

static inline size_t
mbprc_blocksize(
    const MBPRC *prc)
{
    return prc->blocksize(
        prc->params
    );
}

static inline MBPRC_Keys *
mbprc_keygen(
    const MBPRC *prc,
    MBPRC_Random *random)
{
    return prc->keygen(
        prc->params,
        random
    );
}


static inline uint8_t *
mbprc_encode(
    const MBPRC *prc,
    const MBPRC_EncKey *key,
    const uint8_t *message,
    size_t message_bits,
    MBPRC_Random *random,
    size_t *output_bits)
{
    printf("mm1\n");
    return prc->encode(
        prc->params,
        key,
        message,
        message_bits,
        random,
        output_bits
    );
}


static inline int
mbprc_decode(
    const MBPRC *prc,
    const MBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits,
    uint8_t *message_out,
    size_t *message_bits_out)
{
    return prc->decode(
        prc->params,
        key,
        ciphertext,
        ciphertext_bits,
        message_out,
        message_bits_out
    );
}


static inline void
mbprc_free_enc_key(
    const MBPRC *prc,
    MBPRC_EncKey *key)
{
    prc->free_enc_key(prc->params, key);
}


static inline void
mbprc_free_dec_key(
    const MBPRC *prc,
    MBPRC_DecKey *key)
{
    prc->free_dec_key(prc->params, key);
}


static inline void
mbprc_free_keys(
    const MBPRC *prc,
    MBPRC_Keys *keys)
{
    if (!keys)
        return;

    if (keys->enc)
        prc->free_enc_key(prc->params, keys->enc);

    if (keys->dec)
        prc->free_dec_key(prc->params, keys->dec);

    free(keys);
}

#endif /* MULTIBIT_PRC_H */