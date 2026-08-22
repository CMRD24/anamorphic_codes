#include "ecc.h"

/*
 * Hamming(7,4)
 *
 * Each byte is split into two 4-bit nibbles.
 * Each nibble is encoded into a 7-bit Hamming codeword.
 *
 * Therefore:
 *
 *     1 input byte  ->  2 output bytes
 *
 * Only bits 0..6 of each output byte are used.
 *
 * Hamming positions:
 *
 *     position:  1 2 3 4 5 6 7
 *                p p d p d d d
 *
 * stored as:
 *
 *     bit:       0 1 2 3 4 5 6
 */


/*
 * ------------------------------------------------------------
 * Encode one 4-bit nibble
 * ------------------------------------------------------------
 */
static uint8_t hamming_encode_nibble(uint8_t data)
{
    uint8_t d0 = (data >> 0) & 1;
    uint8_t d1 = (data >> 1) & 1;
    uint8_t d2 = (data >> 2) & 1;
    uint8_t d3 = (data >> 3) & 1;

    /*
     * Even parity bits.
     *
     * p1 covers positions 1,3,5,7
     * p2 covers positions 2,3,6,7
     * p4 covers positions 4,5,6,7
     */
    uint8_t p1 = d0 ^ d1 ^ d3;
    uint8_t p2 = d0 ^ d2 ^ d3;
    uint8_t p4 = d1 ^ d2 ^ d3;

    uint8_t codeword = 0;

    /*
     * Hamming positions:
     *
     * position 1 -> bit 0 = p1
     * position 2 -> bit 1 = p2
     * position 3 -> bit 2 = d0
     * position 4 -> bit 3 = p4
     * position 5 -> bit 4 = d1
     * position 6 -> bit 5 = d2
     * position 7 -> bit 6 = d3
     */
    codeword |= p1 << 0;
    codeword |= p2 << 1;
    codeword |= d0 << 2;
    codeword |= p4 << 3;
    codeword |= d1 << 4;
    codeword |= d2 << 5;
    codeword |= d3 << 6;

    return codeword;
}


/*
 * ------------------------------------------------------------
 * Decode one 7-bit Hamming codeword
 * ------------------------------------------------------------
 */
static uint8_t hamming_decode_codeword(uint8_t codeword)
{
    /*
     * Calculate the syndrome.
     *
     * s1 checks positions 1,3,5,7
     * s2 checks positions 2,3,6,7
     * s4 checks positions 4,5,6,7
     */
    uint8_t s1 =
        ((codeword >> 0) & 1) ^
        ((codeword >> 2) & 1) ^
        ((codeword >> 4) & 1) ^
        ((codeword >> 6) & 1);

    uint8_t s2 =
        ((codeword >> 1) & 1) ^
        ((codeword >> 2) & 1) ^
        ((codeword >> 5) & 1) ^
        ((codeword >> 6) & 1);

    uint8_t s4 =
        ((codeword >> 3) & 1) ^
        ((codeword >> 4) & 1) ^
        ((codeword >> 5) & 1) ^
        ((codeword >> 6) & 1);

    /*
     * The syndrome gives the one-based position of the
     * erroneous bit.
     *
     * syndrome = 0 -> no error
     * syndrome = 1..7 -> flip that bit
     */
    uint8_t error_position =
        s1 |
        (s2 << 1) |
        (s4 << 2);

    if (error_position >= 1 && error_position <= 7) {
        codeword ^= (uint8_t)1 << (error_position - 1);
    }

    /*
     * Extract the four data bits:
     *
     * position 3 -> d0
     * position 5 -> d1
     * position 6 -> d2
     * position 7 -> d3
     */
    uint8_t data = 0;

    data |= ((codeword >> 2) & 1) << 0;
    data |= ((codeword >> 4) & 1) << 1;
    data |= ((codeword >> 5) & 1) << 2;
    data |= ((codeword >> 6) & 1) << 3;

    return data;
}


/*
 * ------------------------------------------------------------
 * Encoded size
 * ------------------------------------------------------------
 */
size_t hamming_encoded_size(size_t input_len)
{
    /*
     * Every input byte becomes two Hamming(7,4) codewords,
     * each stored in one byte.
     */
    return input_len * 2;
}

/*
 * ------------------------------------------------------------
 * Decoded size
 * ------------------------------------------------------------
 */
size_t hamming_decoded_size(size_t encoded_len)
{
    /*
     * Two codewords are required for every decoded byte.
     */
    if (encoded_len % 2 != 0) {
        return 0;
    }

    return encoded_len / 2;
}


/*
 * ------------------------------------------------------------
 * Encode
 * ------------------------------------------------------------
 */
int hamming_encode(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
{
    if (output_len == NULL) {
        return -1;
    }

    /*
     * Handle zero-length input.
     */
    if (input_len == 0) {
        *output_len = 0;
        return 0;
    }

    if (input == NULL || output == NULL) {
        return -1;
    }

    /*
     * Encode every input byte as two nibbles.
     */
    for (size_t i = 0; i < input_len; i++) {

        uint8_t byte = input[i];

        uint8_t low_nibble =
            byte & 0x0F;

        uint8_t high_nibble =
            (byte >> 4) & 0x0F;

        /*
         * Store one Hamming codeword per byte.
         */
        output[2 * i] =
            hamming_encode_nibble(low_nibble);

        output[2 * i + 1] =
            hamming_encode_nibble(high_nibble);
    }

    *output_len = hamming_encoded_size(input_len);

    return 0;
}


/*
 * ------------------------------------------------------------
 * Decode
 * ------------------------------------------------------------
 */
int hamming_decode(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len)
{
    /*
     * A valid Hamming encoding always contains two codewords
     * per original byte.
     */
    if (input_len % 2 != 0) {
        return -1;
    }

    size_t expected_output_len =
        hamming_decoded_size(input_len);

    if (output_len != expected_output_len) {
        return -1;
    }

    if (input_len == 0) {
        return 0;
    }

    if (input == NULL || output == NULL) {
        return -1;
    }

    /*
     * Decode two Hamming codewords for every byte.
     */
    for (size_t i = 0; i < output_len; i++) {

        uint8_t low_nibble =
            hamming_decode_codeword(input[2 * i]);

        uint8_t high_nibble =
            hamming_decode_codeword(input[2 * i + 1]);

        output[i] =
            low_nibble |
            (high_nibble << 4);
    }

    return 0;
}







ECC
hamming74_ecc(void)
{
    ECC ecc = {
        .decode = hamming_decode,
        .decoded_size = hamming_decoded_size,
        .encode = hamming_encode,
        .encoded_size = hamming_encoded_size
    };

    return ecc;
}

