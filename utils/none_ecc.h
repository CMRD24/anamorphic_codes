#ifndef NONE_ECC_H
#define NONE_ECC_H

#include "ecc.h"

/*
 * No-error-correction ECC.
 *
 * Encoding and decoding are identity operations:
 *
 *     encoded = input
 *     decoded = input
 *
 * This is useful for testing constructions without
 * introducing redundancy or error correction.
 */

extern const ECC NONE_ECC;

#endif /* NONE_ECC_H */