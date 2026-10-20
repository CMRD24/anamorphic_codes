#ifndef SHARED_ENC_KEY_H
#define SHARED_ENC_KEY_H

#include <stdlib.h>

#include "../multibit_prc.h"

/*
 * The decoding keys of the CCA-style PRCs keep a handle on the underlying
 * encoding key (to re-encode while decoding). Encoding and decoding key share
 * it through a reference count, so they can be freed in any order.
 */
static inline void
mbprc_release_shared_enc_key(
    const MBPRC *prc,
    MBPRC_EncKey *key,
    int *refs)
{
    if (!key)
        return;

    if (refs && --*refs > 0)
        return;

    prc->free_enc_key(prc->params, key);
    free(refs);
}

#endif /* SHARED_ENC_KEY_H */
