
#ifndef WIRETAP_H
#define WIRETAP_H

#include <stddef.h>
#include <stdint.h>

#include "../utils/ecc.h"
#include "../utils/random.h"


/*
 * Wiretap coding using OAEP4 as the IFE.
 *
 * K_bytes:
 *     Size of each message/IFE block in bytes.
 *     Must be even because OAEP4 splits it into two halves.
 *
 * ecc:
 *     Configurable error-correcting code. It must encode K_bytes
 *     bytes to a fixed-size codeword and decode that codeword back
 *     to exactly K_bytes bytes.
 *
 * security_parameter:
 *     Lambda, in bits. Retained for parameter documentation and
 *     validation by the application.
 */
typedef struct {
    size_t K_bytes;
    size_t security_parameter;
    const ECC *ecc;
} wiretap_config_t;

/* Validate configuration and required ECC callbacks. */
int wiretap_config_valid(const wiretap_config_t *cfg);

/* Encoded size of one ECC-protected block. Returns 0 on error. */
size_t wiretap_codeword_size(const wiretap_config_t *cfg);

/*
 * Encode message into wiretap ciphertext.
 *
 * message_len must be a multiple of K_bytes.
 * output must have capacity for wiretap_encoded_size().
 *
 * output_len receives the number of bytes written.
 * Returns 0 on success, -1 on error.
 */
size_t wiretap_encoded_size(
    const wiretap_config_t *cfg,
    size_t message_len);

int wiretap_encode(
    const wiretap_config_t *cfg,
    RandomnessSource *rng,
    const uint8_t *message,
    size_t message_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len);


/*
 * Decode a received wiretap ciphertext.
 *
 * ciphertext_len must be a positive multiple of the ECC
 * codeword size. output must have enough capacity.
 *
 * output_len receives the decoded message length.
 * Returns 0 on success, -1 on error.
 */
size_t wiretap_decoded_size(
    const wiretap_config_t *cfg,
    size_t ciphertext_len);

int wiretap_decode(
    const wiretap_config_t *cfg,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len);

/* Exposed for testing OAEP4 independently. */
int wiretap_oaep4(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output);

int wiretap_oaep4_inverse(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output);



//anamorphic:

//todo: define anamorphic construction first.

// uint8_t *wiretap_akeygen();

// int wiretap_aencode(
//     const wiretap_config_t *cfg,
//     RandomnessSource *rng,
//     const uint8_t *message,
//     size_t message_len,
//     uint8_t *output,
//     size_t output_capacity,
//     size_t *output_len,
//     const unsigned char *akey,
//     uint8_t amessage

// );

// int wiretap_adecode(
//     const wiretap_config_t *cfg,
//     const uint8_t *ciphertext,
//     size_t ciphertext_len,
//     uint8_t *output,
//     size_t output_capacity,
//     size_t *output_len,
//     const unsigned char *akey);


//ana_message_length in bytes
typedef struct {
    size_t ana_message_length;
} wiretap_ana_config_t;


#endif /* WIRETAP_H */