#ifndef PRC_LOW_H
#define PRC_LOW_H

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../../zerobit/zerobit_prc.h"
#include "../../anamorphism/multibit/a_multibit_prc.h"
#include "../../anamorphism/zerobit/a_zerobit_prc.h"


/*
 * Parameters for PRC^ell_low.
 *
 * The underlying zero-bit PRC is not owned by this structure.
 * The caller must ensure that `underlying` and `underlying->params`
 * remain valid while this PRC is used.
 */
typedef struct {

    /*
     * The underlying zero-bit PRC PRC^0_*.
     */
    const ZBPRC *underlying;

    /*
     * Message length ell, in bits.
     */
    size_t ell;

} PRCLow_Params;


/*
 * Opaque concrete key types.
 */
typedef struct PRCLow_EncKey PRCLow_EncKey;
typedef struct PRCLow_DecKey PRCLow_DecKey;


MBPRC prc_low(
    const PRCLow_Params *params
);


/*
 * ================================================================
 * Anamorphic mode (anamorphic lifting, gamma = ell + 1, J = 1)
 * ================================================================
 *
 * Needs a robust anamorphic zero-bit PRC for the same underlying PRC
 * (for example aprc_ldpc). The anamorphic message has ell + 1 bits, one per
 * block; it must not be all zero.
 */
typedef struct {
    const aZBPRC *underlying_aprc;
} APRCLow_Params;

aMBPRC aprc_low(
    const APRCLow_Params *aparams
);

#endif /* PRC_LOW_H */