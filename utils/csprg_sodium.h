#ifndef CSPRG_SODIUM_H
#define CSPRG_SODIUM_H

#include "csprg.h"

/*
 * Returns a CSPRG implementation backed by libsodium.
 */
const CSPRG *csprg_sodium(void);

#endif /* CSPRG_SODIUM_H */