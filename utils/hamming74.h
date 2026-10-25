#ifndef HAMMING74_H
#define HAMMING74_H

#include "ecc.h"

/*
 * The Hamming(7,4) code on bytes (see hamming74.c): every nibble becomes a 7-bit
 * codeword in a byte, so the output has twice the length of the input.
 */
ECC hamming74_ecc(void);

#endif /* HAMMING74_H */