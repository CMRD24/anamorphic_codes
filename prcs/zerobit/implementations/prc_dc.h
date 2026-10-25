#ifndef PRC_DC_H
#define PRC_DC_H

/*
 * Zero-bit PRC for channels with deletions and insertions on top of a zero-bit
 * PRC (see prc_dc.c).
 */

#include <stddef.h>
#include <stdint.h>

#include "../zerobit_prc.h"

typedef struct {
    /* every bit of the underlying codeword becomes a slice of this many bits */
    size_t slice_bits;

    /* the underlying zero-bit PRC, whose keys are used unchanged */
    const ZBPRC *underlying;
} PRCDC_Params;

/* The deletion-channel PRC (the parameters must outlive it). */
ZBPRC prc_dc(const PRCDC_Params *params);

#endif /* PRC_DC_H */
