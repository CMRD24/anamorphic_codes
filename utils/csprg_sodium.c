#include "csprg_sodium.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>


/*
 * ================================================================
 * Seed hashing
 * ================================================================
 *
 * libsodium's deterministic random generator requires a fixed-size
 * seed (randombytes_SEEDBYTES, currently 32 bytes).
 *
 * Our CSPRG interface accepts arbitrary-length seeds.
 *
 * Therefore:
 *
 *     arbitrary seed
 *          |
 *          v
 *       BLAKE2b
 *          |
 *          v
 *       256-bit seed
 *          |
 *          v
 * randombytes_buf_deterministic()
 *
 * The seed length is included in the hash input so that different
 * bit strings with different lengths cannot accidentally be treated
 * as the same seed.
 * ================================================================
 */

static int
sodium_generate(
    const uint8_t *seed,
    size_t seed_bits,
    uint8_t *output,
    size_t output_len)
{
    /*
     * Validate arguments.
     */
    if (seed_bits > 0 && seed == NULL)
        return -1;

    if (output_len > 0 && output == NULL)
        return -1;

    /*
     * libsodium must have been initialized.
     */
    if (sodium_init() < 0)
        return -1;


    /*
     * ------------------------------------------------------------
     * Calculate the number of bytes containing the seed.
     * ------------------------------------------------------------
     */

    const size_t seed_len =
        (seed_bits + 7) / 8;


    /*
     * ------------------------------------------------------------
     * Construct a canonical representation of the seed.
     * ------------------------------------------------------------
     *
     * We hash:
     *
     *     domain || seed_bits || seed
     *
     * where the unused bits of the final seed byte are zeroed.
     *
     * This ensures that, for example:
     *
     *     seed_bits = 5
     *
     * only the first five bits of seed[0] matter.
     * ------------------------------------------------------------
     */

    uint8_t *canonical_seed = NULL;

    if (seed_len > 0) {

        canonical_seed =
            malloc(seed_len);

        if (!canonical_seed)
            return -1;

        memcpy(
            canonical_seed,
            seed,
            seed_len
        );

        /*
         * Clear unused bits in the final byte.
         *
         * Bits are interpreted in the same packed representation
         * as the rest of the project:
         *
         *     bit 0 = least significant bit of byte 0.
         */
        if (seed_bits % 8 != 0) {

            const unsigned used_bits =
                (unsigned)(seed_bits % 8);

            const uint8_t mask =
                (uint8_t)((1u << used_bits) - 1u);

            canonical_seed[seed_len - 1] &= mask;
        }
    }


    /*
     * ------------------------------------------------------------
     * Hash the arbitrary-length seed into a 256-bit seed.
     * ------------------------------------------------------------
     *
     * We use BLAKE2b-256.
     *
     * The seed length is encoded explicitly as a uint64_t.
     *
     * Since this is only a domain-separation / seed-expansion
     * operation, little-endian encoding is sufficient as long as
     * it is deterministic.
     * ------------------------------------------------------------
     */

    uint8_t hash_input_prefix[16];

    /*
     * Domain separator:
     *
     * "CSPRG-SODIUM"
     *
     * followed by zero padding.
     */
    static const uint8_t domain[] = {
        'C', 'S', 'P', 'R', 'G',
        '-', 'S', 'O', 'D', 'I', 'U', 'M'
    };

    memset(
        hash_input_prefix,
        0,
        sizeof(hash_input_prefix)
    );

    memcpy(
        hash_input_prefix,
        domain,
        sizeof(domain)
    );

    /*
     * Store seed_bits as little-endian uint64_t.
     */
    uint64_t bits = (uint64_t)seed_bits;

    for (size_t i = 0; i < 8; ++i) {
        hash_input_prefix[8 + i] =
            (uint8_t)(bits >> (8 * i));
    }

    uint8_t derived_seed[randombytes_SEEDBYTES];

    /*
     * Use the streaming BLAKE2b API so that the implementation
     * does not need to construct one large contiguous buffer.
     */
    crypto_generichash_state state;

    if (crypto_generichash_init(
            &state,
            NULL,
            0,
            randombytes_SEEDBYTES) != 0) {

        free(canonical_seed);
        return -1;
    }

    if (crypto_generichash_update(
            &state,
            hash_input_prefix,
            sizeof(hash_input_prefix)) != 0) {

        free(canonical_seed);
        return -1;
    }

    if (seed_len > 0) {

        if (crypto_generichash_update(
                &state,
                canonical_seed,
                seed_len) != 0) {

            free(canonical_seed);
            return -1;
        }
    }

    if (crypto_generichash_final(
            &state,
            derived_seed,
            sizeof(derived_seed)) != 0) {

        free(canonical_seed);
        return -1;
    }

    free(canonical_seed);


    /*
     * ------------------------------------------------------------
     * Generate the pseudorandom output.
     * ------------------------------------------------------------
     */

    randombytes_buf_deterministic(
        output,
        output_len,
        derived_seed
    );

    /*
     * Clear the derived seed from memory.
     */
    sodium_memzero(
        derived_seed,
        sizeof(derived_seed)
    );

    return 0;
}


/*
 * ================================================================
 * CSPRG implementation
 * ================================================================
 */

static const CSPRG sodium_csprg = {
    .generate = sodium_generate
};


/*
 * ================================================================
 * Public interface
 * ================================================================
 */

const CSPRG *
csprg_sodium(void)
{
    return &sodium_csprg;
}