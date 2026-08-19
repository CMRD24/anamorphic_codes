#include "prc_dc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * ================================================================
 * Bit utilities
 * ================================================================
 */

size_t prc_dc_bytes_for_bits(size_t n)
{
    return (n + 7) / 8;
}


static inline uint8_t get_bit(const uint8_t *data,
                              size_t index)
{
    return (uint8_t)(
        (data[index >> 3] >>
         (index & 7)) & 1u
    );
}


static inline void set_bit(uint8_t *data,
                           size_t index,
                           uint8_t value)
{
    uint8_t mask =
        (uint8_t)(1u << (index & 7));

    if (value)
        data[index >> 3] |= mask;
    else
        data[index >> 3] &= (uint8_t)~mask;
}


static inline void set_bit_1(uint8_t *data,
                             size_t index)
{
    data[index >> 3] |=
        (uint8_t)(1u << (index & 7));
}


/*
 * ================================================================
 * Randomness
 * ================================================================
 */

static void random_bytes(PRCDC_Random *random,
                         uint8_t *out,
                         size_t len)
{
    if (random == NULL ||
        random->rng == NULL) {

        fprintf(stderr,
                "PRC_DC: invalid RNG.\n");

        exit(EXIT_FAILURE);
    }

    if (!random->rng(random->ctx,
                     out,
                     len)) {

        fprintf(stderr,
                "PRC_DC: secure randomness failure.\n");

        exit(EXIT_FAILURE);
    }
}


/*
 * ================================================================
 * Majority
 * ================================================================
 *
 * Majority(z) =
 *
 *     1 if wt(z) > T/2
 *     0 otherwise
 *
 * Notice that for even T, wt(z) == T/2 gives 0.
 * ================================================================
 */

uint8_t prc_dc_majority(const uint8_t *bits,
                        size_t bit_offset,
                        size_t length)
{
    size_t weight = 0;

    for (size_t i = 0;
         i < length;
         ++i) {

        weight +=
            get_bit(bits,
                    bit_offset + i);
    }

    return weight > length / 2;
}


/*
 * ================================================================
 * Rejection sampling
 * ================================================================
 *
 * Sample uniformly from:
 *
 *     { z in F_2^T :
 *       Majority(z) = majority }
 *
 * Algorithm:
 *
 *     repeat
 *         sample z <- F_2^T uniformly
 *     until Majority(z) = majority
 *
 * Since every T-bit string is sampled with probability 2^-T,
 * conditioning on acceptance gives the exact uniform distribution
 * over the desired set.
 * ================================================================
 */

static void sample_majority_slice(
    uint8_t *output,
    size_t output_bit_offset,
    size_t T,
    uint8_t majority,
    PRCDC_Random *random)
{
    size_t bytes =
        prc_dc_bytes_for_bits(T);

    uint8_t *candidate =
        malloc(bytes);

    if (candidate == NULL) {
        fprintf(stderr,
                "PRC_DC: allocation failed.\n");
        exit(EXIT_FAILURE);
    }

    for (;;) {

        /*
         * Sample a uniformly random T-bit string.
         */
        memset(candidate, 0, bytes);

        random_bytes(random,
                     candidate,
                     bytes);

        /*
         * Remove unused padding bits.
         */
        if (T & 7) {

            uint8_t mask =
                (uint8_t)(
                    (1u << (T & 7)) - 1u
                );

            candidate[bytes - 1] &= mask;
        }

        /*
         * Test its majority.
         */
        uint8_t candidate_majority =
            prc_dc_majority(candidate,
                            0,
                            T);

        if (candidate_majority ==
            majority) {

            /*
             * Copy the accepted T-bit string into
             * the output at the specified bit offset.
             */
            for (size_t i = 0;
                 i < T;
                 ++i) {

                if (get_bit(candidate, i)) {

                    set_bit_1(
                        output,
                        output_bit_offset + i
                    );
                }
            }

            free(candidate);
            return;
        }
    }
}


/*
 * ================================================================
 * KeyGen
 * ================================================================
 */

PRCDC_Key *prc_dc_keygen(
    const PRCDC_Params *params,
    PRCDC_Random *random)
{
    if (params == NULL ||
        random == NULL ||
        params->T == 0)
        return NULL;

    if (params->lpc.k == 0 ||
        params->lpc.keygen == NULL ||
        params->lpc.encode == NULL ||
        params->lpc.decode == NULL ||
        params->lpc.free_key == NULL) {

        return NULL;
    }

    PRCDC_Key *key =
        calloc(1, sizeof(PRCDC_Key));

    if (key == NULL)
        return NULL;

    /*
     * K = PRC_LPC.KeyGen()
     */
    key->lpc_key =
        params->lpc.keygen(
            params->lpc.params,
            random);

    if (key->lpc_key == NULL) {
        free(key);
        return NULL;
    }

    /*
     * Keep the LPC description with the generated key.
     */
    key->lpc = params->lpc;
    key->T = params->T;

    return key;
}


/*
 * ================================================================
 * Encode
 * ================================================================
 */

uint8_t *prc_dc_encode(
    const PRCDC_Key *key,
    PRCDC_Random *random)
{
    if (key == NULL ||
        random == NULL)
        return NULL;

    size_t k = key->lpc.k;
    size_t T = key->T;

    /*
     * m = PRC_LPC.Encode(..., 1)
     *
     * The LPC returns k packed bits.
     */
    uint8_t *m =
        key->lpc.encode(
            key->lpc_key,
            random);

    if (m == NULL)
        return NULL;

    /*
     * Output length:
     *
     *     k*T bits
     */
    if (k > SIZE_MAX / T) {
        free(m);
        return NULL;
    }

    size_t output_bits =
        k * T;

    size_t output_bytes =
        prc_dc_bytes_for_bits(output_bits);

    uint8_t *output =
        calloc(output_bytes, 1);

    if (output == NULL) {
        free(m);
        return NULL;
    }

    /*
     * For each LPC bit m_i, sample
     *
     *     z_i <- { z in F_2^T :
     *              Majority(z) = m_i }.
     */
    for (size_t i = 0;
         i < k;
         ++i) {

        uint8_t majority =
            get_bit(m, i);

        sample_majority_slice(
            output,
            i * T,
            T,
            majority,
            random);
    }

    free(m);

    return output;
}


/*
 * ================================================================
 * Decode
 * ================================================================
 */

int prc_dc_decode(
    const PRCDC_Key *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits)
{
    if (key == NULL ||
        ciphertext == NULL)
        return 0;

    const size_t k = key->lpc.k;

    if (k == 0)
        return 0;

    /*
     * We cannot form k non-empty slices if fewer than k bits
     * were received.
     */
    if (ciphertext_bits < k)
        return 0;

    /*
     * The decoder must split the received codeword into k slices
     * whose lengths differ by at most one.
     *
     * Let:
     *
     *     q = floor(L / k)
     *     r = L mod k
     *
     * where L = ciphertext_bits.
     *
     * Then:
     *
     *     r slices have length q + 1
     *     k-r slices have length q.
     *
     * This is the unique standard balanced partition, up to the
     * ordering of the longer slices.
     */
    const size_t q =
        ciphertext_bits / k;

    const size_t r =
        ciphertext_bits % k;

    /*
     * c' contains exactly k bits.
     */
    const size_t c_prime_bytes =
        prc_dc_bytes_for_bits(k);

    uint8_t *c_prime =
        calloc(c_prime_bytes, 1);

    if (c_prime == NULL)
        return 0;

    size_t offset = 0;

    for (size_t i = 0;
         i < k;
         ++i) {

        /*
         * First r slices have q+1 bits.
         * Remaining slices have q bits.
         */
        const size_t slice_length =
            q + (i < r ? 1 : 0);

        /*
         * Compute:
         *
         *     Majority(ciphertext_i)
         */
        const uint8_t majority =
            prc_dc_majority(
                ciphertext,
                offset,
                slice_length);

        if (majority) {
            set_bit_1(c_prime, i);
        }

        offset += slice_length;
    }

    /*
     * Sanity check: all received bits should have been consumed.
     */
    if (offset != ciphertext_bits) {
        free(c_prime);
        return 0;
    }

    /*
     * Decode the recovered LPC codeword.
     */
    const int result =
        key->lpc.decode(
            key->lpc_key,
            c_prime);

    free(c_prime);

    return result;
}

/*
 * ================================================================
 * Cleanup
 * ================================================================
 */

void prc_dc_free_key(PRCDC_Key *key)
{
    if (key == NULL)
        return;

    if (key->lpc_key != NULL &&
        key->lpc.free_key != NULL) {

        key->lpc.free_key(key->lpc_key);
    }

    free(key);
}