#ifndef APRC_PP_H
#define APRC_PP_H

#include "a_zerobit_prc.h"
#include "../../../utils/matrix.h"

#include <stddef.h>

/*
 * ================================================================
 * LDPC parameters
 * ================================================================
 */

typedef struct {
    //seed supplier e.g. encryption function
    //must encsure that the right seed length is returned
    uint8_t *supplier(uint8_t * amsg);

    //seed post-processing (e.g. decryption function)
    uint8_t *deconstructor(uint8_t * seed);

} A_PPParams;



aZBPRC
aprc_ldpc(const A_PPParams *aparams);

#endif /* APRC_LDPC_H */