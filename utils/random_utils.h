#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"

 void random_bytes(RandomnessSource *random,
                         uint8_t *out,
                         size_t len);


 uint64_t random_u64(RandomnessSource *random);

 uint8_t random_bit(RandomnessSource *random);

 void random_bitvector(RandomnessSource *random,
                             BitVector *v);

 void random_bernoulli_vector(
    RandomnessSource *random,
    BitVector *v,
    double eta);

 size_t random_bounded(RandomnessSource *random,
                             size_t bound);
    
void
random_permutation(
    RandomnessSource *random,
    size_t *pi,
    size_t n);

#endif /* RANDOM_UTILS_H */