#ifndef CHANNELS_H
#define CHANNELS_H

#include <stddef.h>
#include <stdint.h>

#include "prc_dc.h"


/*
 * Apply random bit substitutions.
 *
 * input_bits:
 *     Number of valid bits in input.
 *
 * edit_probability:
 *     Probability that each bit is flipped.
 *
 * output_bits:
 *     Set to input_bits.
 *
 * Returns a newly allocated packed bitstring.
 * The caller must free() it.
 */
uint8_t *channel_edits(
    const uint8_t *input,
    size_t input_bits,
    double edit_probability,
    size_t *output_bits,
    PRCDC_Random *random);


/*
 * Apply deletions followed by random bit substitutions.
 *
 * deletion_probability:
 *     Probability that each input bit is deleted.
 *
 * edit_probability:
 *     Probability that each surviving bit is flipped.
 *
 * output_bits:
 *     Set to the resulting number of bits.
 *
 * Returns a newly allocated packed bitstring.
 */
uint8_t *channel_deletions_edits(
    const uint8_t *input,
    size_t input_bits,
    double deletion_probability,
    double edit_probability,
    size_t *output_bits,
    PRCDC_Random *random);


/*
 * Apply deletions, substitutions and insertions.
 *
 * deletion_probability:
 *     Probability that each input bit is deleted.
 *
 * edit_probability:
 *     Probability that each surviving bit is flipped.
 *
 * insertion_probability:
 *     Probability of inserting a random bit after each
 *     processed input bit.
 *
 * output_bits:
 *     Set to the resulting number of bits.
 *
 * Returns a newly allocated packed bitstring.
 */
uint8_t *channel_deletions_edits_insertions(
    const uint8_t *input,
    size_t input_bits,
    double deletion_probability,
    double edit_probability,
    double insertion_probability,
    size_t *output_bits,
    PRCDC_Random *random);

#endif /* CHANNELS_H */