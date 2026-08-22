#ifndef PRC_LOW_H
#define PRC_LOW_H

#include <stddef.h>
#include <stdint.h>

#include "../multibit_prc.h"
#include "../../zerobit/zerobit_prc.h"


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


/*
 * Create a PRC^ell_low instance.
 *
 */
MBPRC prc_low_create(
    const PRCLow_Params *params
);


/*
 * Destroy the PRC wrapper created by prc_low_create().
 *
 * Does not free params or the underlying PRC.
 */
void prc_low_destroy(
    MBPRC *prc
);

#endif /* PRC_LOW_H */