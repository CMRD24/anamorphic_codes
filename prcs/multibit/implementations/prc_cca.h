#ifndef PRC_SHARP_H
#define PRC_SHARP_H

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"



typedef struct {

    /*
     * Underlying multibit PRC.
     *
     * Must remain alive while this interface is used.
     */
    const MBPRC *prc;

    

    /*
     * Security parameter lambda in bits.
     *
     * r has lambda bits and R2 has lambda bits.
     */
    size_t lambda_bits;



    double delta;


} PRC_CCA_Params;


MBPRC
prc_cca(
    const PRC_CCA_Params *params
);

#endif /* PRC_SHARP_H */