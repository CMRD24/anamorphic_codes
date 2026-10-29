#ifndef AZERO_BIT_PRC_H
#define AZERO_BIT_PRC_H

/*
 * Anamorphic mode of a zero-bit PRC with M_A = {1} (definition "anamorphic code"
 * of the thesis):
 *
 *     aKeyGen(enc_key, dec_key) -> (dk, tk)   double key and trapdoor key
 *     aEncode(enc_key, dk) -> c
 *     aDecode(dec_key, tk, c) -> 1 (anamorphic message present) or 0
 *
 * Every implementation defines its own struct AZBPRC_DoubleKey / AZBPRC_TrapdoorKey.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../../utils/random.h"
#include "../../zerobit/zerobit_prc.h"

typedef struct AZBPRC_DoubleKey AZBPRC_DoubleKey;
typedef struct AZBPRC_TrapdoorKey AZBPRC_TrapdoorKey;

typedef struct {
    AZBPRC_DoubleKey *double_key;
    AZBPRC_TrapdoorKey *trapdoor_key;
} AZBPRC_Keys;

typedef struct {
    /* implementation-specific anamorphic parameters */
    const void *aparams;

    /* NULL on error */
    AZBPRC_Keys *(*akeygen)(const void *params,
                            const void *aparams,
                            ZBPRC_Keys *regular_keys,
                            RandomnessSource *random);

    /* as ZBPRC.encode */
    uint8_t *(*aencode)(const void *params,
                        const void *aparams,
                        const ZBPRC_EncKey *enc_key,
                        const AZBPRC_DoubleKey *double_key,
                        RandomnessSource *random,
                        size_t *codeword_bits);

    /* 1 = anamorphic message present, 0 = reject */
    int (*adecode)(const void *params,
                   const void *aparams,
                   const ZBPRC_DecKey *dec_key,
                   const AZBPRC_TrapdoorKey *trapdoor_key,
                   const uint8_t *codeword,
                   size_t codeword_bits);

    void (*free_double_key)(const void *params, const void *aparams,
                            AZBPRC_DoubleKey *double_key);
    void (*free_trapdoor_key)(const void *params, const void *aparams,
                              AZBPRC_TrapdoorKey *trapdoor_key);
} aZBPRC;


static inline AZBPRC_Keys *
zbprc_akeygen(const ZBPRC *prc, const aZBPRC *aprc, ZBPRC_Keys *regular_keys,
              RandomnessSource *random)
{
    return aprc->akeygen(prc->params, aprc->aparams, regular_keys, random);
}

static inline uint8_t *
zbprc_aencode(const ZBPRC *prc, const aZBPRC *aprc, const ZBPRC_EncKey *enc_key,
              const AZBPRC_DoubleKey *double_key, RandomnessSource *random,
              size_t *codeword_bits)
{
    return aprc->aencode(prc->params, aprc->aparams, enc_key, double_key, random,
                         codeword_bits);
}

static inline int
zbprc_adecode(const ZBPRC *prc, const aZBPRC *aprc, const ZBPRC_DecKey *dec_key,
              const AZBPRC_TrapdoorKey *trapdoor_key, const uint8_t *codeword,
              size_t codeword_bits)
{
    return aprc->adecode(prc->params, aprc->aparams, dec_key, trapdoor_key, codeword,
                         codeword_bits);
}

static inline void
zbprc_free_double_key(const ZBPRC *prc, const aZBPRC *aprc, AZBPRC_DoubleKey *double_key)
{
    if (double_key != NULL)
        aprc->free_double_key(prc->params, aprc->aparams, double_key);
}

static inline void
zbprc_free_trapdoor_key(const ZBPRC *prc, const aZBPRC *aprc,
                        AZBPRC_TrapdoorKey *trapdoor_key)
{
    if (trapdoor_key != NULL)
        aprc->free_trapdoor_key(prc->params, aprc->aparams, trapdoor_key);
}

static inline void
zbprc_free_akeys(const ZBPRC *prc, const aZBPRC *aprc, AZBPRC_Keys *akeys)
{
    if (akeys == NULL)
        return;

    zbprc_free_double_key(prc, aprc, akeys->double_key);
    zbprc_free_trapdoor_key(prc, aprc, akeys->trapdoor_key);
    free(akeys);
}

#endif /* AZERO_BIT_PRC_H */
