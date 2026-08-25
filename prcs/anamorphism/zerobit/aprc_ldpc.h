#ifndef APRC_LDPC_H
#define APRC_LDPC_H

#include "a_zerobit_prc.h"
#include "../../../utils/matrix.h"

#include <stddef.h>

/*
 * ================================================================
 * LDPC parameters
 * ================================================================
 */

typedef struct {
    size_t g_prime;
} A_LDPCParams;



aZBPRC
aprc_ldpc(const A_LDPCParams *aparams);

#endif /* APRC_LDPC_H */