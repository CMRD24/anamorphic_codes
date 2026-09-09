#ifndef ZERO_BIT_PRC_RR_H
#define ZERO_BIT_PRC_RR_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#include "../../utils/random.h"
#include "zerobit_prc.h"



typedef struct {

    ZBPRC base;


    uint8_t *(*encode_ws)(
        const void *params,
        const ZBPRC_EncKey *key,
        RandomnessSource *random,
        size_t *output_bits,
        const uint8_t *seed
    );


    int (*decode_ws)(
        const void *params,
        const ZBPRC_DecKey *key,
        const uint8_t *ciphertext,
        size_t ciphertext_bits,
        uint8_t *seed_out
    );
    

} ZBPRC_RR;




#endif /* ZERO_BIT_PRC_RR_H */