


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"


/*
 * The randomness source failed: a key or codeword built from it would be insecure, so abort.
 */
static inline void error(){
    fprintf(stderr,
                "secure randomness failure.\n");

        exit(EXIT_FAILURE);

}

/*
 * Fills out with len random bytes from the source; aborts if the source fails.
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


/*
 * A uniform 64-bit word.
 */
 uint64_t random_u64(RandomnessSource *random)
{
    uint64_t x;

    random_bytes(random,
                 (uint8_t *)&x,
                 sizeof(x));

    return x;
}


/*
 * A uniform bit.
 */
 uint8_t random_bit(RandomnessSource *random)
{
    return (uint8_t)(random_u64(random) & 1ULL);
}


/*
 * A uniform vector of F_2^bits (random words, padding bits cleared).
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
 * A vector of independent Bernoulli(eta) bits, i.e. each coordinate is 1 with
 * probability eta (the error vector e <- Ber(n, eta) of the noise models). A uniform
 * double in [0, 1) is formed from 53 random bits (the precision of a double) and
 * compared with eta.
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


/*
 * A uniform integer in [0, bound) by rejection sampling: x % bound is biased unless x is
 * uniform on a multiple of bound, so the first 2^64 mod bound values (threshold) are
 * rejected and the rest reduced (the "debiased modulo" method also used by OpenBSD's
 * arc4random_uniform). The expected number of draws is below 2.
 */
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
 * A uniform random permutation pi of {0, ..., n-1} (pi[input_position] = output_position)
 * by the Fisher-Yates shuffle in Durstenfeld's form (R. Durstenfeld, CACM 7(7), 1964;
 * D. E. Knuth, TAOCP vol. 2, section 3.4.2, algorithm P): for i = n-1 down to 1 swap
 * pi[i] with pi[j], j uniform in [0, i]. Every permutation has probability 1/n!.
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
