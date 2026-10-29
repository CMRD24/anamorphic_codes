#ifndef RANDOM_UTILS_H
#define RANDOM_UTILS_H

/* Sampling from a RandomnessSource; every function aborts if the source fails. */

#include <stddef.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"

void random_bytes(RandomnessSource *random, uint8_t *out, size_t len);

uint64_t random_u64(RandomnessSource *random);

/* a uniform vector of F_2^v->bits */
void random_bitvector(RandomnessSource *random, BitVector *v);

/* independent bits that are 1 with the given probability (e <- Ber(n, probability)) */
void random_bernoulli_vector(RandomnessSource *random, BitVector *v, double probability);

/* a uniform integer in [0, bound) */
size_t random_bounded(RandomnessSource *random, size_t bound);

/* a uniform permutation of {0, ..., length - 1} */
void random_permutation(RandomnessSource *random, size_t *permutation, size_t length);

#endif /* RANDOM_UTILS_H */
