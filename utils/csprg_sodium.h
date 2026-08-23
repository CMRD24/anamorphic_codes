#ifndef CSPRG_SODIUM_H
#define CSPRG_SODIUM_H

#include "random.h"

RandomnessSource
csprg_randomness(
    const uint8_t *seed,
    size_t seed_length);

void
csprg_randomness_free(
    RandomnessSource *random);

#endif /* CSPRG_SODIUM_H */