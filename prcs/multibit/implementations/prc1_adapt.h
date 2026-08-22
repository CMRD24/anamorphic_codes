#ifndef PRC_1_ADAPT_H
#define PRC_1_ADAPT_H

#include "../multibit_prc.h"
#include "../../zerobit/zerobit_prc.h"


/*
 * ================================================================
 * Parameters
 * ================================================================
 *
 * The underlying zero-bit PRC is configurable.
 *
 * The PRC object itself is not owned by this wrapper.
 * The caller must ensure that it remains valid for as long as the
 * PRC^1_adapt instance is used.
 */

typedef struct {

    const ZBPRC *underlying_prc;

} PRC1AdaptParams;


/*
 * ================================================================
 * Construction
 * ================================================================
 *
 * Returns an MBPRC implementing PRC^1_adapt using the supplied
 * zero-bit PRC.
 *
 * The returned MBPRC stores params as its implementation-specific
 * parameter pointer.
 */

MBPRC prc1_adapt_create(
    const PRC1AdaptParams *params
);

#endif /* PRC_1_ADAPT_H */