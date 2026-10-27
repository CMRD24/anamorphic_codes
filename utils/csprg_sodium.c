/*
 * Deterministic pseudorandom generator from a seed.
 *
 * The seed (any length) is compressed to a 256-bit key with BLAKE2b and a domain
 * separation prefix; the output is the ChaCha20 keystream under that key
 * (libsodium crypto_stream_chacha20 with a 64-bit block counter). ChaCha20 is a stream
 * cipher, so the stream is indistinguishable from random to anyone who does not
 * know the seed. It is used to derive reproducible keys and the pseudorandom
 * coins of the PRC constructions; the output is a continuous byte stream, i.e.
 * it does not depend on how the requests are split.
 */

#include <sodium.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "csprg_sodium.h"

#define BLOCK_BYTES 64           /* ChaCha20 block */
#define CHUNK_BYTES 4096         /* whole blocks generated at once */

typedef struct {
    uint8_t key[crypto_stream_chacha20_KEYBYTES];
    uint64_t position;           /* bytes of the stream already returned */
    uint8_t block[BLOCK_BYTES];  /* the block containing `position` ... */
    uint64_t block_index;        /* ... if block_valid */
    int block_valid;
} StreamCtx;

static const uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];   /* zero: one key per stream */

/* the keystream bytes [position, position + len) */
//similar implementation to random_linux
static int stream_read(void *vctx, uint8_t *out, size_t len)
{
    StreamCtx *ctx = vctx;

    if (ctx == NULL || (len > 0 && out == NULL))
        return 0;

    while (len > 0) {
        const uint64_t index = ctx->position / BLOCK_BYTES;
        const size_t offset = (size_t)(ctx->position % BLOCK_BYTES);
        size_t take;

        if (offset == 0 && len >= BLOCK_BYTES) {
            /* whole blocks directly into the output */
            take = len - len % BLOCK_BYTES;
            if (take > CHUNK_BYTES)
                take = CHUNK_BYTES;

            memset(out, 0, take);
            //https://libsodium.gitbook.io/doc/advanced/stream_ciphers/chacha20
            crypto_stream_chacha20_xor_ic(out, out, take, nonce, index, ctx->key);
        } else {
            /* a partial block: kept, so consecutive small reads generate it once */
            take = BLOCK_BYTES - offset;
            if (take > len)
                take = len;

            if (!ctx->block_valid || ctx->block_index != index) { //must generate new block
                memset(ctx->block, 0, sizeof(ctx->block));
                crypto_stream_chacha20_xor_ic(ctx->block, ctx->block, sizeof(ctx->block),
                                              nonce, index, ctx->key);
                ctx->block_index = index;
                ctx->block_valid = 1;
            }

            memcpy(out, ctx->block + offset, take);
        }

        out += take;
        len -= take;
        ctx->position += take;
    }

    return 1;
}

void csprg_randomness_free(RandomnessSource *random)
{
    if (random == NULL || random->ctx == NULL)
        return;

    sodium_memzero(random->ctx, sizeof(StreamCtx));
    free(random->ctx);

    random->ctx = NULL;
    random->rng = NULL;
}

RandomnessSource csprg_randomness(const uint8_t *seed, size_t seed_length)
{
    static const uint8_t domain[] = "CSPRG-CHACHA20";
    crypto_generichash_state state;
    StreamCtx *ctx = calloc(1, sizeof(*ctx));

    if (ctx == NULL || sodium_init() < 0) {
        free(ctx);
        return (RandomnessSource){.ctx = NULL, .rng = NULL};
    }

    /* key = BLAKE2b-256(domain || seed) */
    crypto_generichash_init(&state, NULL, 0, sizeof(ctx->key));
    crypto_generichash_update(&state, domain, sizeof(domain) - 1);//don't use the zero-terminator of the string as domain part (that is why -1)
    crypto_generichash_update(&state, seed, seed_length);
    crypto_generichash_final(&state, ctx->key, sizeof(ctx->key));

    return (RandomnessSource){.ctx = ctx, .rng = stream_read};
}
