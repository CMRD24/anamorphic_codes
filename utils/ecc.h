#ifndef ECC_H
#define ECC_H

#include <stddef.h>
#include <stdint.h>

/*
 * Error-correcting code interface.
 *
 * The ECC operates on arbitrary-length byte arrays.
 *
 * Encoding expands the input.
 * Decoding reconstructs the original input and corrects
 * errors supported by the underlying code.
 */

typedef struct {

    /*
    * ------------------------------------------------------------
    * Encoded size
    * ------------------------------------------------------------
    *
    * Returns the number of bytes required to encode input_len
    * bytes of data.
    */

    size_t (*encoded_size)(
        size_t input_length
    );

    /*
    * ------------------------------------------------------------
    * Decoded size
    * ------------------------------------------------------------
    *
    * Returns the number of original data bytes represented by
    * an encoded buffer of encoded_len bytes.
    *
    * Returns 0 for an invalid encoded length.
    */
    size_t (*decoded_size)(size_t encoded_len);

    /*
    * ------------------------------------------------------------
    * Encode
    * ------------------------------------------------------------
    *
    * Encodes input_len bytes from input into output.
    *
    * output must have at least ecc_encoded_size(input_len) bytes.
    *
    * Returns:
    *     0 on success
    *    -1 on error
    */

    int (*encode)(
        const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        size_t *output_len
    );

        /*
    * ------------------------------------------------------------
    * Decode
    * ------------------------------------------------------------
    *
    * Decodes encoded_len bytes from input into output.
    *
    * output must have enough space for the decoded data.
    *
    * Returns:
    *     0 on success
    *    -1 on error
    */


    int (*decode)(
        const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        size_t output_len
    );

} ECC;


//convenience




static inline size_t
ecc_encoded_size(
    const ECC *ecc, size_t input_length)
{
    return ecc->encoded_size(
        input_length
    );
}

static inline size_t
ecc_decoded_size(
    const ECC *ecc, size_t encoded_len)
{
    return ecc->decoded_size(
        encoded_len
    );
}

static inline int
ecc_encode(
    const ECC *ecc,
    const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        size_t *output_len)
{
    return ecc->encode(
        input, input_len, output, output_len
    );
}

static inline int
ecc_decode(
    const ECC *ecc,
    const uint8_t *input,
        size_t input_len,
        uint8_t *output,
        size_t output_len)
{
    return ecc->decode(
        input, input_len, output, output_len
    );
}





#endif /* ECC_H */