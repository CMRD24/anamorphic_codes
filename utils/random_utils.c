


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"


static inline void error(){
    fprintf(stderr,
                "secure randomness failure.\n");

        exit(EXIT_FAILURE);
        
}

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

        error();
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






size_t
random_bounded(
    RandomnessSource *random,
    size_t bound)
{
    if (random == NULL || bound == 0){
        error();
    }

    uint64_t x;
    uint64_t threshold = -((uint64_t)bound) % (uint64_t)bound;

    do {
        x = random_u64(random);
    } while (x < threshold);

    return (size_t)(x % bound);
}


/*
 * Fisher-Yates permutation.
 *
 * pi[input_position] = output_position.
 */
void
random_permutation(
    RandomnessSource *random,
    size_t *pi,
    size_t n)
{
    if (!random || !pi){
        error();
    }

    for (size_t i = 0;
         i < n;
         ++i)
    {
        pi[i] = i;
    }

    if (n <= 1)
        return;

    for (size_t i = n - 1;
         i > 0;
         --i)
    {
        size_t j = random_bounded(
                random,
                i + 1);

        size_t tmp = pi[i];
        pi[i] = pi[j];
        pi[j] = tmp;
    }

}
