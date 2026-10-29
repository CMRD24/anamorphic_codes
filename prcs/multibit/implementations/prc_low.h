#ifndef PRC_LOW_H
#define PRC_LOW_H

/* PRC^ell_low: an ell-bit PRC from a zero-bit PRC (see prc_low.c). */

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../../zerobit/zerobit_prc.h"
#include "../../anamorphism/multibit/a_multibit_prc.h"
#include "../../anamorphism/zerobit/a_zerobit_prc.h"

typedef struct {
    /* the underlying zero-bit PRC (not owned; must outlive the PRC^ell_low instance) */
    const ZBPRC *underlying;

    /* message length ell in bits */
    size_t ell;
} PRCLow_Params;

MBPRC prc_low(const PRCLow_Params *params);

/*
 * Anamorphic mode by anamorphic lifting (gamma = ell + 1, J = 1). Needs a robust
 * anamorphic zero-bit PRC for the same underlying PRC (for example aprc_ldpc).
 * The anamorphic message has ell + 1 bits, one per block; it must not be all zero.
 */
typedef struct {
    const aZBPRC *underlying_aprc;
} APRCLow_Params;

aMBPRC aprc_low(const APRCLow_Params *aparams);

#endif /* PRC_LOW_H */
