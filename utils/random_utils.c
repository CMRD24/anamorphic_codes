


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"



/*
 * ================================================================
 * Randomness
 * ================================================================
 */

 void random_bytes(RandomnessSource *random,
                         uint8_t *out,
                         size_t len)
{
    if (random == NULL ||
        random->rng == NULL ||
        !random->rng(random->ctx, out, len)) {

        fprintf(stderr,
                "ZBPRC-LDPC: secure randomness failure.\n");

        exit(EXIT_FAILURE);
    }
}


 uint64_t random_u64(RandomnessSource *random)
{
    uint64_t x;

    random_bytes(random,
                 (uint8_t *)&x,
                 sizeof(x));

    return x;
}


 uint8_t random_bit(RandomnessSource *random)
{
    return (uint8_t)(random_u64(random) & 1ULL);
}


/*
 * ================================================================
 * Random bit vector
 * ================================================================
 */

 void random_bitvector(RandomnessSource *random,
                             BitVector *v)
{
    for (size_t i = 0;
         i < v->words;
         ++i) {

        v->data[i] =
            random_u64(random);
    }

    if (v->bits & 63) {

        size_t valid =
            v->bits & 63;

        uint64_t mask =
            (1ULL << valid) - 1ULL;

        v->data[v->words - 1] &= mask;
    }
}


/*
 * ================================================================
 * Bernoulli vector
 * ================================================================
 */

 void random_bernoulli_vector(
    RandomnessSource *random,
    BitVector *v,
    double eta)
{
    bitvector_zero(v);

    if (eta <= 0.0)
        return;

    if (eta >= 1.0) {

        for (size_t i = 0;
             i < v->words;
             ++i) {

            v->data[i] = UINT64_MAX;
        }

        if (v->bits & 63) {

            size_t valid =
                v->bits & 63;

            v->data[v->words - 1] &=
                (1ULL << valid) - 1ULL;
        }

        return;
    }

    for (size_t i = 0;
         i < v->bits;
         ++i) {

        uint64_t x =
            random_u64(random) >> 11;

        double u =
            (double)x / 9007199254740992.0;

        if (u < eta)
            bit_set(v, i, 1);
    }
}




 size_t random_bounded(RandomnessSource *random,
                             size_t bound)
{
    if (bound == 0)
        return 0;

    uint64_t x;

    /*
     * Rejection sampling.
     */
    uint64_t limit =
        UINT64_MAX -
        (UINT64_MAX % (uint64_t)bound);

    do {
        x = random_u64(random);
    } while (x >= limit);

    return (size_t)(x % bound);
}
