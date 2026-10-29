#ifndef PRC_1_ADAPT_H
#define PRC_1_ADAPT_H

/* PRC^1_adapt: a one-bit PRC from two instances of a zero-bit PRC (see prc1_adapt.c). */

#include "../multibit_prc.h"
#include "../../zerobit/zerobit_prc.h"
#include "../../anamorphism/multibit/a_multibit_prc.h"
#include "../../anamorphism/zerobit/a_zerobit_prc.h"

typedef struct {
    /* the underlying zero-bit PRC (not owned; must outlive the PRC^1_adapt instance) */
    const ZBPRC *underlying_prc;
} PRC1AdaptParams;

MBPRC prc1_adapt(const PRC1AdaptParams *params);

/*
 * Anamorphic mode by anamorphic lifting (gamma = 1, J = 2). Needs a robust
 * anamorphic zero-bit PRC for the same underlying PRC (for example aprc_ldpc).
 * The anamorphic message is the single bit 1.
 */
typedef struct {
    const aZBPRC *underlying_aprc;
} APRC1AdaptParams;

aMBPRC aprc1_adapt(const APRC1AdaptParams *aparams);

#endif /* PRC_1_ADAPT_H */
