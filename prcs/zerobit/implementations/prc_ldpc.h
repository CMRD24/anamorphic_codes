#ifndef PRC_LDPC_H
#define PRC_LDPC_H

#include "../zerobit_prc.h"
#include "../../../utils/matrix.h"

#include <stddef.h>

/*
 * ================================================================
 * LDPC parameters
 * ================================================================
 */

typedef struct {
    size_t n;
    size_t r;
    size_t g;
    size_t t;
    double eta;
} LDPCParams;



void sample_sparse_p(RandomnessSource *random,
                            SparseP *P);


/*
 * ================================================================
 * LDPC PRC constructor
 * ================================================================
 */

ZBPRC
ldpc_zbprc(
    const LDPCParams *params
);

#endif /* PRC_LDPC_H */