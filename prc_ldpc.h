#ifndef ZEROBIT_PRC_H
#define ZEROBIT_PRC_H

#include <stddef.h>
#include <stdint.h>

/*
 * ================================================================
 * Randomness interface
 * ================================================================
 */

typedef int (*prc_rng)(void *ctx,
                       uint8_t *out,
                       size_t len);

typedef struct {
    prc_rng rng;
    void *ctx;
} PRCRandom;


/*
 * ================================================================
 * PRC parameters
 * ================================================================
 */

typedef struct {
    size_t n;
    size_t r;
    size_t g;
    size_t t;
    double eta;
} PRCParams;


/*
 * ================================================================
 * Opaque key types
 * ================================================================
 */

typedef struct PRCEncKey PRCEncKey;
typedef struct PRCDecKey PRCDecKey;

typedef struct {
    PRCEncKey *enc;
    PRCDecKey *dec;
} PRCKeys;


/*
 * ================================================================
 * Key generation
 * ================================================================
 */

PRCKeys *prc_keygen(const PRCParams *params,
                    PRCRandom *random);


/*
 * ================================================================
 * Encoding
 * ================================================================
 *
 * Returns n bits packed into ceil(n/8) bytes.
 *
 * The caller owns the returned buffer and must free() it.
 */

uint8_t *prc_encode(const PRCParams *params,
                    const PRCEncKey *key,
                    PRCRandom *random);


/*
 * ================================================================
 * Decoding
 * ================================================================
 *
 * c must contain ceil(n/8) bytes.
 *
 * Returns:
 *
 *     1 = accept
 *     0 = reject
 */

int prc_decode(const PRCParams *params,
               const PRCDecKey *key,
               const uint8_t *c);


/*
 * ================================================================
 * Cleanup
 * ================================================================
 */

void prc_free_keys(PRCKeys *keys);



/*
 * Debug / inspection functions.
 *
 * These print the complete keys and ciphertexts in binary form.
 */
void prc_print_enc_key(const PRCParams *params,
                       const PRCEncKey *key);

void prc_print_dec_key(const PRCParams *params,
                       const PRCDecKey *key);

void prc_print_codeword(const PRCParams *params,
                        const uint8_t *c);

#endif /* ZEROBIT_PRC_H */