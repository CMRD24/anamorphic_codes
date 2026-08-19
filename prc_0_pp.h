#ifndef PRC_0_PP_H
#define PRC_0_PP_H

#include <stddef.h>
#include <stdint.h>

#include "prc_code.h"
#include "prc_dc.h"   /* PRCDC_Random */

/*
 * PRC^{0,PP} from Christ et al., "Improved Pseudorandom Codes
 * from Permuted Puzzles", Algorithm 1.
 *
 * n and q must be powers of two. The binary representation of an
 * index/symbol is fixed width: log2(n) / log2(q) bits respectively.
 *
 * The implementation uses the paper's exhaustive decoder:
 * every length-ell substring is compared against every
 * (i,z) in [n] x [q].
 */

typedef struct {
    PRCCode code;

    /* Substitution rate used by Encode. */
    double eta;

    /* Decoder Hamming/edit-ball parameters. */
    double p_dec;
    double epsilon_dec;

    /* Maximum size of every coordinate list. */
    size_t L_max;

    /* Agreement threshold passed to ListRecovery. */
    size_t t_rec;

    /* Number m of sampled indexed symbols emitted by Encode. */
    size_t m;
} PRC0PPParams;

typedef PRCDC_Random PRC0PPRandom;

typedef struct {
    size_t *sigma;

    /*
     * pi[i][a] = pi_i(a)
     * pi_inv[i][a] = pi_i^{-1}(a)
     *
     * Both arrays have q entries for every i.
     */
    uint64_t **pi;
    uint64_t **pi_inv;

    /* One-time pad o in [q]^n. */
    uint64_t *otp;

    size_t n;
    uint64_t q;
} PRC0PPKey;

/*
 * KeyGen(1^lambda).
 */
PRC0PPKey *prc_0_pp_keygen(
    const PRC0PPParams *params,
    PRC0PPRandom *random);

/*
 * Encode(1^lambda, key, 1).
 *
 * Returns an LSB-packed bit string containing
 *
 *   bin(i_1)||bin(z'_1)||...||bin(i_m)||bin(z'_m)
 *
 * and stores its bit length in output_bits.
 *
 * The caller owns the returned buffer.
 */
uint8_t *prc_0_pp_encode(
    const PRC0PPParams *params,
    const PRC0PPKey *key,
    PRC0PPRandom *random,
    size_t *output_bits);

/*
 * Decode(1^lambda, key, y).
 *
 * received_bits may be arbitrary; it does not need to be a multiple
 * of log2(n)+log2(q).
 */
int prc_0_pp_decode(
    const PRC0PPParams *params,
    const PRC0PPKey *key,
    const uint8_t *received,
    size_t received_bits);

/*
 * Free a key.
 */
void prc_0_pp_free_key(PRC0PPKey *key);

/*
 * Utility functions.
 */
size_t prc_0_pp_log2_power_of_two(uint64_t x);
size_t prc_0_pp_bytes_for_bits(size_t bits);

#endif /* PRC_0_PP_H */
