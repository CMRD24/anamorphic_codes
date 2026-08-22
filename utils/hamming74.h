#ifndef HAMMING74_H
#define HAMMING74_H

#include "ecc.h"

/*
 * Returns a CSPRG implementation backed by libsodium.
 */
ECC hamming74_ecc(void);

#endif /* HAMMING74_H */