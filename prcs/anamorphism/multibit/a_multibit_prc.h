#ifndef A_MULTIBIT_PRC_H
#define A_MULTIBIT_PRC_H

/*
 * Anamorphic multibit PRC obtained by lifting the anamorphic mode of an
 * underlying zero-bit PRC (anamorphic lifting construction).
 *
 * A nested multibit PRC encodes its regular message into gamma blocks, each an
 * encoding of the underlying zero-bit PRC (or uniform). The anamorphic message
 * has one bit per block: bit i = 1 hides the zero-bit anamorphic message in
 * block i, bit i = 0 leaves the block regular. The all-zero message means "no
 * anamorphic message" and is not a valid anamorphic message.
 *
 * Every implementation defines its own struct AMBPRC_DoubleKey / AMBPRC_TrapdoorKey.
 */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../../utils/random.h"
#include "../../multibit/multibit_prc.h"

typedef struct AMBPRC_DoubleKey AMBPRC_DoubleKey;
typedef struct AMBPRC_TrapdoorKey AMBPRC_TrapdoorKey;

typedef struct {
    AMBPRC_DoubleKey *double_key;
    AMBPRC_TrapdoorKey *trapdoor_key;
} AMBPRC_Keys;

typedef struct {
    /* implementation-specific anamorphic parameters */
    const void *aparams;

    /* gamma: number of bits of the anamorphic message */
    size_t (*amessage_bits)(const void *params, const void *aparams);

    /* needs the regular keys of the PRC; NULL on error */
    AMBPRC_Keys *(*akeygen)(const void *params,
                            const void *aparams,
                            MBPRC_Keys *regular_keys,
                            RandomnessSource *random);

    /*
     * Encodes `message` and hides `amessage` (packed bits, LSB first,
     * amessage_bits() bits, not all zero). Returns a newly allocated codeword,
     * NULL on error.
     */
    uint8_t *(*aencode)(const void *params,
                        const void *aparams,
                        const MBPRC_EncKey *enc_key,
                        const AMBPRC_DoubleKey *double_key,
                        const uint8_t *message,
                        size_t message_bits,
                        const uint8_t *amessage,
                        RandomnessSource *random,
                        size_t *codeword_bits);

    /*
     * Returns 1 and writes amessage_bits() bits to amessage_out if an
     * anamorphic message is present, 0 otherwise.
     */
    int (*adecode)(const void *params,
                   const void *aparams,
                   const MBPRC_DecKey *dec_key,
                   const AMBPRC_TrapdoorKey *trapdoor_key,
                   const uint8_t *codeword,
                   size_t codeword_bits,
                   uint8_t *amessage_out);

    void (*free_double_key)(const void *params, const void *aparams,
                            AMBPRC_DoubleKey *double_key);
    void (*free_trapdoor_key)(const void *params, const void *aparams,
                              AMBPRC_TrapdoorKey *trapdoor_key);
} aMBPRC;


static inline size_t
mbprc_amessage_bits(const MBPRC *prc, const aMBPRC *aprc)
{
    return aprc->amessage_bits(prc->params, aprc->aparams);
}

static inline AMBPRC_Keys *
mbprc_akeygen(const MBPRC *prc, const aMBPRC *aprc, MBPRC_Keys *regular_keys,
              RandomnessSource *random)
{
    return aprc->akeygen(prc->params, aprc->aparams, regular_keys, random);
}

static inline uint8_t *
mbprc_aencode(const MBPRC *prc, const aMBPRC *aprc, const MBPRC_EncKey *enc_key,
              const AMBPRC_DoubleKey *double_key, const uint8_t *message,
              size_t message_bits, const uint8_t *amessage,
              RandomnessSource *random, size_t *codeword_bits)
{
    return aprc->aencode(prc->params, aprc->aparams, enc_key, double_key, message,
                         message_bits, amessage, random, codeword_bits);
}

static inline int
mbprc_adecode(const MBPRC *prc, const aMBPRC *aprc, const MBPRC_DecKey *dec_key,
              const AMBPRC_TrapdoorKey *trapdoor_key, const uint8_t *codeword,
              size_t codeword_bits, uint8_t *amessage_out)
{
    return aprc->adecode(prc->params, aprc->aparams, dec_key, trapdoor_key, codeword,
                         codeword_bits, amessage_out);
}

static inline void
mbprc_free_akeys(const MBPRC *prc, const aMBPRC *aprc, AMBPRC_Keys *akeys)
{
    if (akeys == NULL)
        return;

    if (akeys->double_key != NULL)
        aprc->free_double_key(prc->params, aprc->aparams, akeys->double_key);

    if (akeys->trapdoor_key != NULL)
        aprc->free_trapdoor_key(prc->params, aprc->aparams, akeys->trapdoor_key);

    free(akeys);
}

#endif /* A_MULTIBIT_PRC_H */
