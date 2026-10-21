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
 */

#include <stddef.h>
#include <stdint.h>

#include "../../../utils/random.h"
#include "../../multibit/multibit_prc.h"

typedef struct AMBPRC_EncKey AMBPRC_EncKey;
typedef struct AMBPRC_DecKey AMBPRC_DecKey;

typedef struct {
    AMBPRC_EncKey *enc;   /* double key */
    AMBPRC_DecKey *dec;   /* trapdoor key */
} AMBPRC_Keys;

typedef struct {
    const void *aparams;

    /* gamma: number of bits of the anamorphic message */
    size_t (*amessage_bits)(
        const void *params,
        const void *aparams
    );

    /* Needs the regular keys of the PRC. */
    AMBPRC_Keys *(*akeygen)(
        const void *params,
        const void *aparams,
        MBPRC_Keys *reg_keys,
        RandomnessSource *random
    );

    /*
     * Encodes `message` and hides `amessage` (packed bits, LSB first,
     * amessage_bits() bits, not all zero). Returns a newly allocated codeword,
     * NULL on error.
     */
    uint8_t *(*aencode)(
        const void *params,
        const void *aparams,
        const MBPRC_EncKey *reg_key,
        const AMBPRC_EncKey *dkey,
        const uint8_t *message,
        size_t message_bits,
        const uint8_t *amessage,
        RandomnessSource *random,
        size_t *output_bits
    );

    /*
     * Returns 1 and writes amessage_bits() bits to amessage_out if an
     * anamorphic message is present, 0 otherwise.
     */
    int (*adecode)(
        const void *params,
        const void *aparams,
        const MBPRC_DecKey *reg_key,
        const AMBPRC_DecKey *tkey,
        const uint8_t *ciphertext,
        size_t ciphertext_bits,
        uint8_t *amessage_out
    );

    void (*free_aenc_key)(
        const void *params,
        const void *aparams,
        AMBPRC_EncKey *key
    );

    void (*free_adec_key)(
        const void *params,
        const void *aparams,
        AMBPRC_DecKey *key
    );
} aMBPRC;


static inline size_t
mbprc_amessage_bits(const MBPRC *prc, const aMBPRC *aprc)
{
    return aprc->amessage_bits(prc->params, aprc->aparams);
}

static inline AMBPRC_Keys *
mbprc_akeygen(const MBPRC *prc, const aMBPRC *aprc, MBPRC_Keys *keys,
              RandomnessSource *random)
{
    return aprc->akeygen(prc->params, aprc->aparams, keys, random);
}

static inline uint8_t *
mbprc_aencode(const MBPRC *prc, const aMBPRC *aprc, const MBPRC_EncKey *key,
              const AMBPRC_EncKey *dkey, const uint8_t *message,
              size_t message_bits, const uint8_t *amessage,
              RandomnessSource *random, size_t *output_bits)
{
    return aprc->aencode(prc->params, aprc->aparams, key, dkey, message,
                         message_bits, amessage, random, output_bits);
}

static inline int
mbprc_adecode(const MBPRC *prc, const aMBPRC *aprc, const MBPRC_DecKey *key,
              const AMBPRC_DecKey *tkey, const uint8_t *ciphertext,
              size_t ciphertext_bits, uint8_t *amessage_out)
{
    return aprc->adecode(prc->params, aprc->aparams, key, tkey, ciphertext,
                         ciphertext_bits, amessage_out);
}

static inline void
mbprc_free_aenc_key(const MBPRC *prc, const aMBPRC *aprc, AMBPRC_EncKey *key)
{
    aprc->free_aenc_key(prc->params, aprc->aparams, key);
}

static inline void
mbprc_free_adec_key(const MBPRC *prc, const aMBPRC *aprc, AMBPRC_DecKey *key)
{
    aprc->free_adec_key(prc->params, aprc->aparams, key);
}

#endif /* A_MULTIBIT_PRC_H */
