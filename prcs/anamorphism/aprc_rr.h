#ifndef AZERO_BIT_PRC_H
#define AZERO_BIT_PRC_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

//#include "../../utils/random.h"
#include "../zerobit/zerobit_prc_rr.h"
#include "../multibit/multibit_prc_rr.h"



typedef struct {

    //number of seed bits
    const size_t seed_len;

    //number of indication bits
    const size_t indication_len;

    //number of regular messages for one anamorphic message
    const size_t mu;

    //the regular PRC

    const ZBPRC_RR *prc_rr;

} aZBPRC_RR_Params;

typedef struct {

    const size_t seed_len;

    //number of indication bits
    const size_t indication_len;

    //number of regular messages for one anamorphic message
    const size_t mu;

    //the regular PRC

    const MBPRC_RR *prc_rr;

} aMBPRC_RR_Params;


typedef struct {
    const uint8_t *prf_key;
    const uint8_t  *encryption_key;

} APRC_RR_Keys;




/*
 * ================================================================
 * anamorphic zerobit PRC interface for PRCs with randomness recoverability
 * ================================================================
 */

typedef struct {



    const aZBPRC_RR_Params *aparams;

    
    APRC_RR_Keys *(*akeygen)(
        const aZBPRC_RR_Params *aparams,
        RandomnessSource *random
    );


    //for zerobit prcs the regular messages are single bits and the array of bits is represented as a uint8_t*
    //returns an array of codewords
    uint8_t **(*aencode)(
        const aZBPRC_RR_Params *aparams,
        const ZBPRC_EncKey *reg_key,
        const APRC_RR_Keys *dkey,
        const uint8_t *ana_message,
        RandomnessSource *random,
        size_t *output_bits
    );


    //returns 1 on success 0 on failure
    int (*adecode)(
        const aZBPRC_RR_Params *aparams,
        const ZBPRC_DecKey *reg_key,
        const APRC_RR_Keys *dkey,
        const uint8_t *const *codewords,
        size_t ciphertext_bits,
        uint8_t *ana_message
    );


    /*
     * ------------------------------------------------------------
     * Key destruction
     * ------------------------------------------------------------
     */

    void (*free_akey)(
        const aZBPRC_RR_Params *aparams,
        APRC_RR_Keys *key
    );

    

} aZBPRC_RR;





/*
 * ================================================================
 * anamorphic multibit PRC interface for PRCs with randomness recoverability
 * ================================================================
 */

typedef struct {



    const aMBPRC_RR_Params *aparams;

    
    APRC_RR_Keys *(*akeygen)(
        const aMBPRC_RR_Params *aparams,
        RandomnessSource *random
    );


    //returns an array of codewords
    uint8_t **(*aencode)(
        const aMBPRC_RR_Params *aparams,
        const MBPRC_EncKey *reg_key,
        const APRC_RR_Keys *dkey,
        const uint8_t **reg_messages,
        size_t reg_message_bits,
        const uint8_t *ana_message,
        RandomnessSource *random,
        size_t *output_bits
    );


    int (*adecode)(
        const aMBPRC_RR_Params *aparams,
    const MBPRC_DecKey *reg_key,
    const APRC_RR_Keys *dkey,
    const uint8_t *const *codewords,
    size_t ciphertext_bits,
    uint8_t *ana_message,
    size_t reg_message_bits //only needed to allocate right amount
    );


    /*
     * ------------------------------------------------------------
     * Key destruction
     * ------------------------------------------------------------
     */

    void (*free_akey)(
        const void *params,
        const void *aparams,
        APRC_RR_Keys *key
    );

    

} aMBPRC_RR;


aZBPRC_RR aZBPRC_RR_init(const aZBPRC_RR_Params *aparams);

aMBPRC_RR aMBPRC_RR_init(const aMBPRC_RR_Params *aparams);


#endif /* AZERO_BIT_PRC_H */