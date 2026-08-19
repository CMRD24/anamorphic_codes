#include "channels.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>


/*
 * ================================================================
 * Bit helpers
 * ================================================================
 */

static inline uint8_t get_bit(
    const uint8_t *data,
    size_t index)
{
    return (uint8_t)(
        (data[index >> 3] >>
         (index & 7)) & 1u
    );
}


static inline void set_bit(
    uint8_t *data,
    size_t index,
    uint8_t value)
{
    const uint8_t mask =
        (uint8_t)(1u << (index & 7));

    if (value)
        data[index >> 3] |= mask;
    else
        data[index >> 3] &= (uint8_t)~mask;
}


static inline size_t bytes_for_bits(size_t bits)
{
    return (bits + 7) / 8;
}


/*
 * ================================================================
 * Randomness
 * ================================================================
 */

static uint64_t random_u64(PRCDC_Random *random)
{
    uint64_t value;

    if (random == NULL ||
        random->rng == NULL) {

        fprintf(stderr,
                "channels: invalid RNG.\n");

        exit(EXIT_FAILURE);
    }

    if (!random->rng(
            random->ctx,
            (uint8_t *)&value,
            sizeof(value))) {

        fprintf(stderr,
                "channels: secure randomness failure.\n");

        exit(EXIT_FAILURE);
    }

    return value;
}


/*
 * Generate a uniform random double in [0,1).
 *
 * 53 random bits are used, giving the precision of a
 * binary64 mantissa.
 */
static double random_unit(
    PRCDC_Random *random)
{
    const uint64_t x =
        random_u64(random) >> 11;

    return (double)x *
           (1.0 / 9007199254740992.0);
}


/*
 * Bernoulli(p).
 */
static int bernoulli(
    PRCDC_Random *random,
    double probability)
{
    if (probability <= 0.0)
        return 0;

    if (probability >= 1.0)
        return 1;

    return random_unit(random) < probability;
}


/*
 * Uniform random bit.
 */
static uint8_t random_bit(
    PRCDC_Random *random)
{
    return (uint8_t)(
        random_u64(random) & 1ULL
    );
}


/*
 * ================================================================
 * Edits
 * ================================================================
 */

uint8_t *channel_edits(
    const uint8_t *input,
    size_t input_bits,
    double edit_probability,
    size_t *output_bits,
    PRCDC_Random *random)
{
    if (output_bits == NULL ||
        random == NULL ||
        (input == NULL && input_bits != 0) ||
        edit_probability < 0.0 ||
        edit_probability > 1.0) {

        return NULL;
    }

    *output_bits = input_bits;

    const size_t output_bytes =
        bytes_for_bits(input_bits);

    uint8_t *output =
        calloc(output_bytes, 1);

    if (output == NULL &&
        output_bytes != 0) {

        return NULL;
    }

    for (size_t i = 0;
         i < input_bits;
         ++i) {

        uint8_t bit =
            get_bit(input, i);

        if (bernoulli(
                random,
                edit_probability)) {

            bit ^= 1u;
        }

        set_bit(output, i, bit);
    }

    return output;
}


/*
 * ================================================================
 * Deletions + edits
 * ================================================================
 */

uint8_t *channel_deletions_edits(
    const uint8_t *input,
    size_t input_bits,
    double deletion_probability,
    double edit_probability,
    size_t *output_bits,
    PRCDC_Random *random)
{
    if (output_bits == NULL ||
        random == NULL ||
        (input == NULL && input_bits != 0) ||
        deletion_probability < 0.0 ||
        deletion_probability > 1.0 ||
        edit_probability < 0.0 ||
        edit_probability > 1.0) {

        return NULL;
    }

    /*
     * The output can never contain more bits than the input.
     */
    const size_t max_output_bits =
        input_bits;

    uint8_t *output =
        calloc(
            bytes_for_bits(max_output_bits),
            1
        );

    if (output == NULL &&
        max_output_bits != 0) {

        return NULL;
    }

    size_t written = 0;

    for (size_t i = 0;
         i < input_bits;
         ++i) {

        /*
         * Delete this bit.
         */
        if (bernoulli(
                random,
                deletion_probability)) {

            continue;
        }

        /*
         * Surviving bit.
         */
        uint8_t bit =
            get_bit(input, i);

        /*
         * Edit / substitute.
         */
        if (bernoulli(
                random,
                edit_probability)) {

            bit ^= 1u;
        }

        set_bit(output,
                written,
                bit);

        ++written;
    }

    *output_bits = written;

    /*
     * Shrink the allocation to the actual number of bits.
     *
     * realloc(NULL, 0) semantics are avoided explicitly.
     */
    const size_t actual_bytes =
        bytes_for_bits(written);

    if (actual_bytes == 0) {
        free(output);
        return NULL;
    }

    uint8_t *shrunk =
        realloc(output, actual_bytes);

    if (shrunk != NULL)
        output = shrunk;

    return output;
}


/*
 * ================================================================
 * Deletions + edits + insertions
 * ================================================================
 */

uint8_t *channel_deletions_edits_insertions(
    const uint8_t *input,
    size_t input_bits,
    double deletion_probability,
    double edit_probability,
    double insertion_probability,
    size_t *output_bits,
    PRCDC_Random *random)
{
    if (output_bits == NULL ||
        random == NULL ||
        (input == NULL && input_bits != 0) ||
        deletion_probability < 0.0 ||
        deletion_probability > 1.0 ||
        edit_probability < 0.0 ||
        edit_probability > 1.0 ||
        insertion_probability < 0.0 ||
        insertion_probability > 1.0) {

        return NULL;
    }

    /*
     * Worst case:
     *
     *     every input bit survives
     *     and every input bit gets one insertion.
     *
     * Therefore:
     *
     *     output <= 2 * input_bits
     */
    if (input_bits >
        SIZE_MAX / 2) {

        return NULL;
    }

    const size_t max_output_bits =
        input_bits * 2;

    uint8_t *output =
        calloc(
            bytes_for_bits(max_output_bits),
            1
        );

    if (output == NULL &&
        max_output_bits != 0) {

        return NULL;
    }

    size_t written = 0;

    for (size_t i = 0;
         i < input_bits;
         ++i) {

        /*
         * --------------------------------------------------------
         * Deletion
         * --------------------------------------------------------
         */

        const int deleted =
            bernoulli(
                random,
                deletion_probability);

        if (!deleted) {

            /*
             * ----------------------------------------------------
             * Surviving input bit
             * ----------------------------------------------------
             */

            uint8_t bit =
                get_bit(input, i);

            /*
             * ----------------------------------------------------
             * Edit
             * ----------------------------------------------------
             */

            if (bernoulli(
                    random,
                    edit_probability)) {

                bit ^= 1u;
            }

            /*
             * Append surviving/edit bit.
             */
            set_bit(output,
                    written,
                    bit);

            ++written;
        }

        /*
         * --------------------------------------------------------
         * Insertion
         * --------------------------------------------------------
         *
         * Insert a random bit after processing the current input
         * position.
         *
         * Importantly, this happens independently of whether the
         * input bit was deleted.
         */

        if (bernoulli(
                random,
                insertion_probability)) {

            const uint8_t bit =
                random_bit(random);

            set_bit(output,
                    written,
                    bit);

            ++written;
        }
    }

    *output_bits = written;

    /*
     * Handle empty output explicitly.
     */
    if (written == 0) {
        free(output);
        return NULL;
    }

    /*
     * Shrink to the actual number of bytes.
     */
    const size_t actual_bytes =
        bytes_for_bits(written);

    uint8_t *shrunk =
        realloc(output, actual_bytes);

    if (shrunk != NULL)
        output = shrunk;

    return output;
}