#ifndef PRC_SHARP_H
#define PRC_SHARP_H

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../multibit_prc_rr.h"


typedef struct {

    /*
     * Underlying multibit PRC.
     *
     * Must remain alive while this interface is used.
     */
    const MBPRC *prc;

    /*
     * Security parameter λ in bits.
     *
     * r has λ bits and R2 has λ bits.
     */
    size_t lambda_bits;



    double delta;


} PRCSharp_Params;


MBPRC
prc_sharp(
    const PRCSharp_Params *params
);

MBPRC_RR
prc_sharp_rr(
    const PRCSharp_Params *params
);

#endif /* PRC_SHARP_H */