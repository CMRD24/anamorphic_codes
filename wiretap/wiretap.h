
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


/*
 * Encode with a given seed r_0 (K_bytes bytes) instead of a fresh uniform one.
 * wiretap_encode samples the seed uniformly; the anamorphic encoder below
 * sets it to a pseudorandom encryption of the anamorphic message.
 */
int wiretap_encode_ws(
    const wiretap_config_t *cfg,
    const uint8_t *seed,
    const uint8_t *message,
    size_t message_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len);

/* r_0 = ECC.Decode(c_0). seed_out must hold K_bytes. 0 on success, -1 on error. */
int wiretap_seed_decode(
    const wiretap_config_t *cfg,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *seed_out);


/*
 * Anamorphic wiretap code (randomness recoverability).
 *
 * The seed r_0 is set to Enc(akey, m_a) = nonce || (PRF(akey, nonce) XOR m_a),
 * with K_bytes - ana_message_length >= 16 nonce bytes. The key is symmetric
 * (double key = trapdoor key). Encryption is not authenticated, so adecode
 * returns some message for any ciphertext whose first block decodes; it is
 * not robust in the sense of the framework unless the encryption is made
 * authenticated.
 */

/* ana_message_length in bytes */
typedef struct {
    size_t ana_message_length;
} wiretap_ana_config_t;

int wiretap_ana_config_valid(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg);

/* crypto_generichash_KEYBYTES random bytes; free with wiretap_akey_free */
uint8_t *wiretap_akeygen(void);
void wiretap_akey_free(uint8_t *akey);

/*
 * Encodes message (a multiple of K_bytes) with amessage
 * (acfg->ana_message_length bytes) hidden in the seed.
 * Returns 0 on success, -1 on error. Regular wiretap_decode still
 * recovers message.
 */
int wiretap_aencode(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg,
    const uint8_t *akey,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *amessage,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len);

/*
 * Recovers the anamorphic message; output must hold
 * acfg->ana_message_length bytes. Returns 0 on success, -1 on error.
 */
int wiretap_adecode(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg,
    const uint8_t *akey,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *output);


#endif /* WIRETAP_H */
