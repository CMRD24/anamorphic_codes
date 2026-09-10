#ifndef MULTI_BIT_PRC_RR_H
#define MULTI_BIT_PRC_RR_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"
#include "multibit_prc.h"



typedef struct {

    MBPRC base;


    uint8_t *(*encode_ws)(
        const void *params_ptr,
        const MBPRC_EncKey *key_ptr,
        const uint8_t *message,
        size_t message_bits,
        RandomnessSource *random,
        size_t *output_bits,
        const uint8_t *seed
    );


    int (*decode_ws)(
        const void *params_ptr,
        const MBPRC_DecKey *key_ptr,
        const uint8_t *ciphertext,
        size_t ciphertext_bits,
        uint8_t *message_out,
        size_t *message_bits_out,
        uint8_t *seed_out
    );
    

} MBPRC_RR;




#endif /* MULTI_BIT_PRC_RR_H */