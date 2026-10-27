#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include "matrix.h"
#include "random.h"
#include "random_utils.h"


/*
 * The randomness source failed: a key or codeword built from it would be insecure, so abort.
 */
static void randomness_failure(void)
{
    fprintf(stderr, "secure randomness failure.\n");
    exit(EXIT_FAILURE);
}

/*
 * Fills out with len random bytes from the source.
 */
void random_bytes(RandomnessSource *random, uint8_t *out, size_t len)
{
    if (random == NULL || random->rng == NULL || !random->rng(random->ctx, out, len))
        randomness_failure();
}

/*
 * A uniform 64-bit word.
 */
uint64_t random_u64(RandomnessSource *random)
{
    uint64_t x;

    random_bytes(random, (uint8_t *)&x, sizeof(x));

    return x;
}

/*
 * A uniform vector of F_2^bits (random words, padding bits cleared).
 */
void random_bitvector(RandomnessSource *random, BitVector *v)
{
    random_bytes(random, (uint8_t *)v->data, v->words * sizeof(uint64_t));

    if (v->bits % 64 != 0)
        v->data[v->words - 1] &= (UINT64_C(1) << (v->bits % 64)) - 1; //clears the higher bits
}

/*
 * Independent Bernoulli bits, i.e. each coordinate is 1 with the given probability
 * (the error vector e <- Ber(n, eta) of the noise models). A uniform double in
 * [0, 1) is formed from 53 random bits (the precision of a double) and compared
 * with the probability.
 */
void random_bernoulli_vector(RandomnessSource *random, BitVector *v, double probability)
{
    memset(v->data, 0, v->words * sizeof(uint64_t));

    if (probability <= 0.0)
        return;

    for (size_t i = 0; i < v->bits; ++i) {
        const double uniform = (double)(random_u64(random) >> 11) / 9007199254740992.0; //53 bits of the double's precision are used (that is why >> 11 is necessary. 9007199254740992 is 2^53)

        if (uniform < probability)
            bitvector_set_bit(v, i, 1);
    }
}

/*
 * A uniform integer in [0, bound) by rejection sampling: x % bound is biased unless x is
 * uniform on a multiple of bound, so the first 2^64 mod bound values (threshold) are
 * rejected and the rest reduced (the "debiased modulo" method also used by OpenBSD's
 * arc4random_uniform: https://man.openbsd.org/arc4random). The expected number of draws is below 2.
 */
size_t random_bounded(RandomnessSource *random, size_t bound)
{
    if (random == NULL || bound == 0)
        randomness_failure();

    const uint64_t threshold = -((uint64_t)bound) % (uint64_t)bound; //mod before subtraction: leads to the largest possible multiple of bound
    uint64_t x;

    do {
        x = random_u64(random);
    } while (x < threshold);

    return (size_t)(x % bound);
}

/*
 * A uniform random permutation (permutation[input_position] = output_position)
 * by the Fisher-Yates shuffle (https://en.wikipedia.org/wiki/Fisher%E2%80%93Yates_shuffle): 
 * for i = length-1 down to 1
 * swap permutation[i] with permutation[j], j uniform in [0, i]. Every permutation has
 * probability 1/length!.
 */
void random_permutation(RandomnessSource *random, size_t *permutation, size_t length)
{
    if (random == NULL || permutation == NULL)
        randomness_failure();

    for (size_t i = 0; i < length; ++i)
        permutation[i] = i;

    for (size_t i = length; i > 1; --i) {
        const size_t j = random_bounded(random, i);
        const size_t swap = permutation[i - 1];

        permutation[i - 1] = permutation[j];
        permutation[j] = swap;
    }
}
