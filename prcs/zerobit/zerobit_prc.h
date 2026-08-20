#ifndef ZERO_BIT_PRC_H
#define ZERO_BIT_PRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

/*
 * ================================================================
 * Randomness
 * ================================================================
 */

typedef int (*ZBPRC_Rng)(
    void *ctx,
    uint8_t *out,
    size_t len
);

typedef struct {
    ZBPRC_Rng rng;
    void *ctx;
} ZBPRC_Random;


/*
 * ================================================================
 * Opaque key types
 * ================================================================
 */

typedef struct ZBPRC_EncKey ZBPRC_EncKey;
typedef struct ZBPRC_DecKey ZBPRC_DecKey;


/*
 * ================================================================
 * Key pair
 * ================================================================
 */

typedef struct {
    ZBPRC_EncKey *enc;
    ZBPRC_DecKey *dec;
} ZBPRC_Keys;


/*
 * ================================================================
 * Zero-bit PRC interface
 * ================================================================
 */

typedef struct {

    /*
     * Implementation-specific parameters.
     */
    const void *params;


    /*
     * ------------------------------------------------------------
     * Key generation
     * ------------------------------------------------------------
     *
     * Generates both the encoding and decoding keys.
     */
    ZBPRC_Keys *(*keygen)(
        const void *params,
        ZBPRC_Random *random
    );


    /*
     * ------------------------------------------------------------
     * Encoding
     * ------------------------------------------------------------
     *
     * Encodes the distinguished bit 1.
     *
     * Returns a newly allocated packed bit string.
     * The caller owns the returned buffer.
     */
    uint8_t *(*encode)(
        const void *params,
        const ZBPRC_EncKey *key,
        ZBPRC_Random *random,
        size_t *output_bits
    );


    /*
     * ------------------------------------------------------------
     * Decoding
     * ------------------------------------------------------------
     *
     * Returns:
     *
     *     1 = accept
     *     0 = reject
     */
    int (*decode)(
        const void *params,
        const ZBPRC_DecKey *key,
        const uint8_t *ciphertext,
        size_t ciphertext_bits
    );


    /*
     * ------------------------------------------------------------
     * Key destruction
     * ------------------------------------------------------------
     */

    void (*free_enc_key)(
        const void *params,
        ZBPRC_EncKey *key
    );

    void (*free_dec_key)(
        const void *params,
        ZBPRC_DecKey *key
    );

    

} ZBPRC;


/*
 * ================================================================
 * Convenience functions
 * ================================================================
 */

static inline ZBPRC_Keys *
zbprc_keygen(
    const ZBPRC *prc,
    ZBPRC_Random *random)
{
    return prc->keygen(
        prc->params,
        random
    );
}

static inline uint8_t *
zbprc_encode(
    const ZBPRC *prc,
    const ZBPRC_EncKey *key,
    ZBPRC_Random *random,
    size_t *output_bits)
{
    return prc->encode(
        prc->params,
        key,
        random,
        output_bits
    );
}


static inline int
zbprc_decode(
    const ZBPRC *prc,
    const ZBPRC_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits)
{
    return prc->decode(
        prc->params,
        key,
        ciphertext,
        ciphertext_bits
    );
}


static inline void
zbprc_free_enc_key(
    const ZBPRC *prc,
    ZBPRC_EncKey *key)
{
    prc->free_enc_key(prc->params,key);
}


static inline void
zbprc_free_dec_key(
    const ZBPRC *prc,
    ZBPRC_DecKey *key)
{
    prc->free_dec_key(prc->params,key);
}


static inline void
zbprc_free_keys(
    const ZBPRC *prc,
    ZBPRC_Keys *keys)
{
    if (!keys)
        return;

    if (keys->enc)
        prc->free_enc_key(prc->params,keys->enc);

    if (keys->dec)
        prc->free_dec_key(prc->params,keys->dec);

    free(keys);
}

#endif /* ZERO_BIT_PRC_H */