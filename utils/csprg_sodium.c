/*
 * Deterministic pseudorandom generator from a seed ("counter mode" hash DRBG).
 *
 * Output block t (64 bytes) is BLAKE2b-512(domain || bits(seed) || seed || t) with a
 * 64-bit counter t = 0, 1, 2, ... Under the assumption that BLAKE2b behaves as a
 * random oracle (or that its keyed/prefixed use is a PRF) the stream is
 * indistinguishable from random to anyone who does not know the seed. It is used
 * to derive reproducible keys and the pseudorandom coins of the PRC constructions
 * from a short seed; it is not a NIST SP 800-90A generator.
 *
 * A request that does not end on a block boundary discards the rest of the block,
 * so the stream depends on the sequence of request sizes.
 */

#include <sodium.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>

#include "random.h"

#define PRNG_BLOCK_BYTES 64

typedef struct {
    uint8_t *seed;
    size_t seed_bits;
    uint64_t counter;
} SecurePseudorandomCtx;


/* Block number `counter` of the stream (see the comment at the top of the file). */
static int
generate_block(
    const uint8_t *seed,
    size_t seed_bits,
    uint64_t counter,
    uint8_t *out)
{
    /*
     * Include the counter in the input.
     */
    uint8_t counter_bytes[8];

    for (size_t i = 0; i < 8; ++i)
        counter_bytes[i] =
            (uint8_t)(counter >> (8 * i));

    /*
     * Hash:
     *
     *     domain || seed_bits || seed || counter
     *
     * using BLAKE2b-512.
     */
    crypto_generichash_state state;

    if (crypto_generichash_init(
            &state,
            NULL,
            0,
            PRNG_BLOCK_BYTES) != 0)
        return -1;

    static const uint8_t domain[] =
        "CSPRG-SODIUM-STREAM";

    if (crypto_generichash_update(
            &state,
            domain,
            sizeof(domain) - 1) != 0)
        return -1;

    uint64_t bits = (uint64_t)seed_bits;
    uint8_t bits_bytes[8];

    for (size_t i = 0; i < 8; ++i)
        bits_bytes[i] =
            (uint8_t)(bits >> (8 * i));

    if (crypto_generichash_update(
            &state,
            bits_bytes,
            sizeof(bits_bytes)) != 0)
        return -1;

    /*
     * Seed is byte-packed, so only complete bytes
     * are passed here.
     */
    size_t seed_len =
        (seed_bits + 7) / 8;

    if (seed_len > 0) {

        if (crypto_generichash_update(
                &state,
                seed,
                seed_len) != 0)
            return -1;
    }

    if (crypto_generichash_update(
            &state,
            counter_bytes,
            sizeof(counter_bytes)) != 0)
        return -1;

    return crypto_generichash_final(
        &state,
        out,
        PRNG_BLOCK_BYTES
    );
}


int
secure_pseudorandom(
    void *ctx,
    uint8_t *out,
    size_t len)
{
    SecurePseudorandomCtx *prng =
        (SecurePseudorandomCtx *)ctx;

    if (prng == NULL)
        return 0;

    if (len > 0 && out == NULL)
        return 0;

    while (len > 0) {

        uint8_t block[PRNG_BLOCK_BYTES];

        if (generate_block(
                prng->seed,
                prng->seed_bits,
                prng->counter,
                block) != 0)
            return 0;

        size_t take = len;

        if (take > PRNG_BLOCK_BYTES)
            take = PRNG_BLOCK_BYTES;

        memcpy(out, block, take);

        out += take;
        len -= take;

        prng->counter++;
    }

    return 1;
}

void
csprg_randomness_free(
    RandomnessSource *random)
{
    if (random == NULL || random->ctx == NULL)
        return;

    SecurePseudorandomCtx *ctx =
        random->ctx;

    free(ctx->seed);
    free(ctx);

    random->ctx = NULL;
    random->rng = NULL;
}


RandomnessSource
csprg_randomness(
    const uint8_t *seed,
    size_t seed_length)
{
    SecurePseudorandomCtx *ctx =
        malloc(sizeof(*ctx));

    if (ctx == NULL)
        return (RandomnessSource) {
            .ctx = NULL,
            .rng = NULL
        };

    ctx->seed = malloc(seed_length);

    if (seed_length > 0 && ctx->seed == NULL) {
        free(ctx);
        return (RandomnessSource) {
            .ctx = NULL,
            .rng = NULL
        };
    }

    memcpy(
        ctx->seed,
        seed,
        seed_length
    );

    ctx->seed_bits = seed_length * 8;
    ctx->counter = 0;

    return (RandomnessSource) {
        .ctx = ctx,
        .rng = secure_pseudorandom
    };
}

