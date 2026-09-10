#include "none_ecc.h"

#include <stddef.h>
#include <stdint.h>
#include <string.h>

/*
 * Encoded size = input size.
 */
static size_t
none_ecc_encoded_size(size_t input_length)
{
    return input_length;
}

/*
 * Decoded size = encoded size.
 *
 * Every length is valid because there is no ECC
 * structure to validate.
 */
static size_t
none_ecc_decoded_size(size_t encoded_len)
{
    return encoded_len;
}

/*
 * Identity encoding.
 */
static int
none_ecc_encode(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t *output_len)
{
    if (output_len == NULL)
        return -1;

    if (input_len > 0 && (input == NULL || output == NULL))
        return -1;

    if (input_len > 0)
        memcpy(output, input, input_len);

    *output_len = input_len;

    return 0;
}

/*
 * Identity decoding.
 */
static int
none_ecc_decode(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len)
{
    /*
     * Since there is no redundancy, the output must have
     * exactly the same size as the input.
     */
    if (input_len != output_len)
        return -1;

    if (input_len > 0 && (input == NULL || output == NULL))
        return -1;

    if (input_len > 0)
        memcpy(output, input, input_len);

    return 0;
}

/*
 * Public ECC implementation.
 */
const ECC NONE_ECC = {
    .encoded_size = none_ecc_encoded_size,
    .decoded_size = none_ecc_decoded_size,
    .encode       = none_ecc_encode,
    .decode       = none_ecc_decode
};