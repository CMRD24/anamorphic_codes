#ifndef ZERO_BIT_PRC_H
#define ZERO_BIT_PRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../../utils/random.h"
#include "../../zerobit/zerobit_prc.h"

/*
 * ================================================================
 * Randomness
 * ================================================================
 */

// typedef int (*ZBPRC_Rng)(
//     void *ctx,
//     uint8_t *out,
//     size_t len
// );

// typedef struct {
//     ZBPRC_Rng rng;
//     void *ctx;
// } ZBPRC_Random;


/*
 * ================================================================
 * Opaque key types
 * ================================================================
 */

typedef struct APRC_EncKey APRC_EncKey;
typedef struct APRC_DecKey APRC_DecKey;


/*
 * ================================================================
 * Key pair
 * ================================================================
 */

typedef struct {
    APRC_EncKey *enc;
    APRC_DecKey *dec;
} APRC_Keys;


/*
 * ================================================================
 * anamorphic PRC interface
 * ================================================================
 */

typedef struct {

    
    APRC_Keys *(*akeygen)(
        const void *params,
        ZBPRC_Keys *reg_keys,
        RandomnessSource *random
    );


    uint8_t *(*aencode)(
        const void *params,
        const ZBPRC_EncKey *reg_key,
        const APRC_EncKey *dkey,
        RandomnessSource *random,
        size_t *output_bits
    );


    /*
     * ------------------------------------------------------------
     * anamoprhic Decoding
     * ------------------------------------------------------------
     *
     * Returns:
     *     2 = anamorphic accept (both 1)
     *     1 = regular accept
     *     0 = reject
     */
    int (*adecode)(
        const void *params,
        const ZBPRC_DecKey *reg_key,
        const APRC_DecKey tkey,
        const uint8_t *ciphertext,
        size_t ciphertext_bits
    );


    /*
     * ------------------------------------------------------------
     * Key destruction
     * ------------------------------------------------------------
     */

    void (*free_aenc_key)(
        const void *params,
        APRC_EncKey *key
    );

    void (*free_adec_key)(
        const void *params,
        APRC_DecKey *key
    );

    

} aZBPRC;


/*
 * ================================================================
 * Convenience functions
 * ================================================================
 */





static inline ZBPRC_Keys *
a_zbprc_keygen(
    const ZBPRC *prc,
    RandomnessSource *random)
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
    RandomnessSource *random,
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