#ifndef PRC_DC_H
#define PRC_DC_H

#include <stddef.h>
#include <stdint.h>


/*
 * ================================================================
 * Randomness interface
 * ================================================================
 */

typedef int (*prc_dc_rng)(void *ctx,
                          uint8_t *out,
                          size_t len);

typedef struct {
    prc_dc_rng rng;
    void *ctx;
} PRCDC_Random;


/*
 * ================================================================
 * Underlying length-preserving zero-bit PRC
 * ================================================================
 *
 * The underlying PRC must:
 *
 *   - have a fixed ciphertext length k bits;
 *   - Encode() the distinguished bit 1;
 *   - return its ciphertext as ceil(k/8) bytes;
 *   - Decode() a k-bit ciphertext and return 0/1.
 *
 * The PRC_DC construction is agnostic to how the LPC is
 * implemented.
 */


/*
 * Opaque underlying key.
 */
typedef struct PRCDC_LPCKey PRCDC_LPCKey;


/*
 * Key generation.
 *
 * The implementation-specific parameter object is passed through
 * void *params.
 */
typedef PRCDC_LPCKey *(*prc_dc_lpc_keygen)(
    const void *params,
    PRCDC_Random *random);


/*
 * Encode the distinguished bit 1.
 *
 * Returns a newly allocated packed k-bit codeword.
 * The caller of the LPC owns the returned buffer.
 */
typedef uint8_t *(*prc_dc_lpc_encode)(
    const PRCDC_LPCKey *key,
    PRCDC_Random *random);


/*
 * Decode a packed k-bit codeword.
 *
 * Returns:
 *
 *     1 = accept
 *     0 = reject
 */
typedef int (*prc_dc_lpc_decode)(
    const PRCDC_LPCKey *key,
    const uint8_t *ciphertext);


/*
 * Free the underlying LPC key.
 */
typedef void (*prc_dc_lpc_free_key)(
    PRCDC_LPCKey *key);


/*
 * Description of an underlying LPC.
 */
typedef struct {
    /*
     * Number of bits in the LPC ciphertext.
     */
    size_t k;

    /*
     * Underlying PRC operations.
     */
    prc_dc_lpc_keygen keygen;
    prc_dc_lpc_encode encode;
    prc_dc_lpc_decode decode;
    prc_dc_lpc_free_key free_key;

    /*
     * Construction-specific parameters.
     *
     * The LPC implementation interprets this pointer.
     */
    const void *params;

} PRCDC_LPC;


/*
 * ================================================================
 * PRC_DC parameters
 * ================================================================
 */

typedef struct {
    /*
     * Length of every majority slice before concatenation.
     */
    size_t T;

    /*
     * Underlying length-preserving PRC.
     */
    PRCDC_LPC lpc;

} PRCDC_Params;


/*
 * ================================================================
 * PRC_DC key
 * ================================================================
 */

typedef struct {
    PRCDC_LPCKey *lpc_key;

    /*
     * Copy of the LPC description.
     */
    PRCDC_LPC lpc;

    /*
     * Majority slice length.
     */
    size_t T;
} PRCDC_Key;


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

PRCDC_Key *prc_dc_keygen(
    const PRCDC_Params *params,
    PRCDC_Random *random);


/*
 * ================================================================
 * Encode
 * ================================================================
 *
 * Encodes the distinguished bit 1.
 *
 * The LPC produces:
 *
 *     m_1 || ... || m_k
 *
 * and every m_i is expanded into a uniformly sampled T-bit
 * string whose majority equals m_i.
 *
 * The resulting ciphertext has k*T bits.
 *
 * The returned buffer contains ceil(k*T/8) bytes.
 * The caller must free() it.
 */
uint8_t *prc_dc_encode(
    const PRCDC_Key *key,
    PRCDC_Random *random);


/*
 * Decode an arbitrary received codeword.
 *
 * The received codeword may have a different length from the
 * originally encoded k*T bits.
 *
 * The decoder partitions ciphertext_bits into k slices such that
 * their lengths differ by at most one.
 */
int prc_dc_decode(
    const PRCDC_Key *key,
    const uint8_t *ciphertext,
    size_t ciphertext_bits);


/*
 * ================================================================
 * Cleanup
 * ================================================================
 */

void prc_dc_free_key(PRCDC_Key *key);


/*
 * ================================================================
 * Utility
 * ================================================================
 */

/*
 * Number of bytes required to store n packed bits.
 */
size_t prc_dc_bytes_for_bits(size_t n);


/*
 * Majority of a packed T-bit string.
 */
uint8_t prc_dc_majority(
    const uint8_t *bits,
    size_t bit_offset,
    size_t length);

#endif /* PRC_DC_H */