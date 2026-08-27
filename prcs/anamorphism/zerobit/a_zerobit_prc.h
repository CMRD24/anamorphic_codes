#ifndef AZERO_BIT_PRC_H
#define AZERO_BIT_PRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../../utils/random.h"
#include "../../zerobit/zerobit_prc.h"



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



    const void *aparams;

    
    APRC_Keys *(*akeygen)(
        const void *params,
        const void *aparams,
        ZBPRC_Keys *reg_keys,
        RandomnessSource *random
    );


    uint8_t *(*aencode)(
        const void *params,
        const void *aparams,
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
     *     1 = anamorphic accept
     *     0 = reject
     */
    int (*adecode)(
        const void *params,
        const void *aparams,
        const ZBPRC_DecKey *reg_key,
        const APRC_DecKey *tkey,
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
        const void *aparams,
        APRC_EncKey *key
    );

    void (*free_adec_key)(
        const void *params,
        const void *aparams,
        APRC_DecKey *key
    );

    

} aZBPRC;


/*
 * ================================================================
 * Convenience functions
 * ================================================================
 */





static inline APRC_Keys *
zbprc_akeygen(
    const ZBPRC *prc,
    const aZBPRC *aprc,
    ZBPRC_Keys *keys,
    RandomnessSource *random)
{
    return aprc->akeygen(
        prc->params,
        aprc->aparams,
        keys,
        random
    );
}

static inline uint8_t *
zbprc_aencode(
    const ZBPRC *prc,
    const aZBPRC *aprc,
    const ZBPRC_EncKey *key,
    const APRC_EncKey *dkey,
    RandomnessSource *random,
    size_t *output_bits)
{
    return aprc->aencode(
        prc->params,
        aprc->aparams,
        key,
        dkey,
        random,
        output_bits
    );
}


static inline int
zbprc_adecode(
    const ZBPRC *prc,
    const aZBPRC *aprc,
    const ZBPRC_DecKey *key,
    const APRC_DecKey *tkey,
    const uint8_t *ciphertext,
    size_t ciphertext_bits)
{
    return aprc->adecode(
        prc->params,
        aprc->aparams,
        key,
        tkey,
        ciphertext,
        ciphertext_bits
    );
}


static inline void
zbprc_free_enc_akey(
    const ZBPRC *prc,
    const aZBPRC *aprc,
    APRC_EncKey *key)
{
    aprc->free_aenc_key(prc->params, aprc->aparams,key);
}


static inline void
zbprc_free_dec_akey(
    const ZBPRC *prc,
    const aZBPRC *aprc,
    APRC_DecKey *key)
{
    aprc->free_adec_key(prc->params, aprc->aparams,key);
}





#endif /* AZERO_BIT_PRC_H */