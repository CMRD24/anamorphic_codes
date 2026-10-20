#ifndef TEST_COMMON_H
#define TEST_COMMON_H

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "../utils/random.h"

static int tests_run = 0;
static int tests_failed = 0;

#define CHECK(cond)                                                       \
    do {                                                                  \
        ++tests_run;                                                      \
        if (!(cond)) {                                                    \
            ++tests_failed;                                               \
            printf("  FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);      \
        }                                                                 \
    } while (0)

#define CHECK_MSG(cond, ...)                                              \
    do {                                                                  \
        ++tests_run;                                                      \
        if (!(cond)) {                                                    \
            ++tests_failed;                                               \
            printf("  FAIL %s:%d: %s -- ", __FILE__, __LINE__, #cond);    \
            printf(__VA_ARGS__);                                          \
            printf("\n");                                                 \
        }                                                                 \
    } while (0)

#define RUN(test)                                                         \
    do {                                                                  \
        int before = tests_failed;                                        \
        printf("[ RUN  ] %s\n", #test);                                   \
        test();                                                           \
        printf("[ %s ] %s\n", tests_failed == before ? " OK " : "FAIL",   \
               #test);                                                    \
    } while (0)

static inline int test_summary(const char *suite)
{
    printf("%s: %d checks, %d failed\n", suite, tests_run, tests_failed);
    return tests_failed == 0 ? 0 : 1;
}

/* packed bit strings: bit i is bit (i & 7) of byte (i >> 3) */

/* flips every bit independently with probability p (BSC), in place */
static inline void test_bsc(uint8_t *bits, size_t nbits, double p,
                            RandomnessSource *rng)
{
    for (size_t i = 0; i < nbits; ++i) {
        uint8_t b[4];
        rng->rng(rng->ctx, b, sizeof b);
        uint32_t v = (uint32_t)b[0] | (uint32_t)b[1] << 8 |
                     (uint32_t)b[2] << 16 | (uint32_t)b[3] << 24;
        if ((double)v / 4294967296.0 < p)
            bits[i >> 3] ^= (uint8_t)(1u << (i & 7));
    }
}

static inline uint8_t *test_random_bits(size_t nbits, RandomnessSource *rng)
{
    size_t bytes = (nbits + 7) / 8;
    uint8_t *v = calloc(bytes ? bytes : 1, 1);
    rng->rng(rng->ctx, v, bytes);
    if (nbits % 8)
        v[bytes - 1] &= (uint8_t)((1u << (nbits % 8)) - 1u);
    return v;
}

static inline uint8_t *test_copy(const uint8_t *src, size_t bytes)
{
    uint8_t *d = malloc(bytes ? bytes : 1);
    memcpy(d, src, bytes);
    return d;
}

#endif /* TEST_COMMON_H */
