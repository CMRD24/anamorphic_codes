#ifndef DEMO_PRC_H
#define DEMO_PRC_H

/*
 * Shared operations of the PRC demos: one generic implementation for zero-bit
 * and multibit PRCs, with the optional randomness-recovery or lifting anamorphic
 * mode. A demo only has to describe its code in a DemoPrc and call
 * demo_prc_finish.
 */

#include "demo_common.h"
#include "prcs/anamorphism/aprc_rr.h"
#include "prcs/anamorphism/multibit/a_multibit_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "prcs/multibit/multibit_prc.h"
#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/zerobit/zerobit_prc.h"

typedef struct DemoPrc {
    /* ---- filled in by the demo ---- */
    int zerobit;                     /* 1: zero-bit PRC, 0: multibit PRC */
    ZBPRC zerobit_prc;
    MBPRC multibit_prc;
    size_t message_bits;             /* multibit: bits of the regular message */

    /* randomness-recovery anamorphism (enabled by a non-NULL PRC) */
    const ZBPRC_RR *zerobit_rr;
    const MBPRC_RR *multibit_rr;
    size_t seed_bits;                /* k, a multiple of 8: the seed the decoder recovers */
    size_t indication_seeds;         /* z (0: none, mu = 1 is possible) */
    size_t amessage_bytes;           /* the nonce takes the rest of the ciphertext seeds,
                                        at least RR_MIN_NONCE_BYTES */

    /* anamorphic lifting (enabled by a non-NULL lifting): one bit per block, given
     * as a string of 0/1 characters */
    const aMBPRC *lifting;

    void *storage;                   /* code specific structures, released with free() */

    /* ---- set up by demo_prc_finish ---- */
    ZBPRC_Keys *zerobit_keys;
    MBPRC_Keys *multibit_keys;
    RR_AKeys *rr_akeys;
    AMBPRC_Keys *lifting_akeys;
    aZBPRC_RR zerobit_rr_aprc;
    aMBPRC_RR multibit_rr_aprc;
} DemoPrc;

/*
 * Generates the keys that are present in `keys` (deterministically from the
 * key files) and prepares the anamorphic parameters. Returns 0 on success.
 */
int demo_prc_finish(DemoPrc *prc, const DemoKeys *keys);

void demo_prc_close(void *handle);
int demo_prc_encode(void *handle, const char *message, DemoCiphertext *out);
int demo_prc_decode(void *handle, const DemoCiphertext *in);
int demo_prc_aencode(void *handle, const char *message, const char *amessage,
                     DemoCiphertext *out);
int demo_prc_adecode(void *handle, const DemoCiphertext *in);

/* the anamorphic key stream domain (regular: 'R', anamorphic: 'A') */
#define DEMO_DOMAIN_REGULAR 'R'
#define DEMO_DOMAIN_ANAMORPHIC 'A'

/*
 * Parameter entries of the LDPC zero-bit PRC: the admissible choice of the thesis,
 * r = r' = ceil(n^(epsilon/2)), kappa = ceil(n^epsilon), g = kappa + r',
 * t = floor(delta log2 n). Every default pair (n, epsilon) has
 * n^epsilon = 2^12, i.e. r = r' = 64, kappa = 4096 and g = 4160, the smallest
 * number of parity checks for which the threshold (1/2 - r^(-1/4)) r separates
 * codewords from random strings well; t = 4 for n = 2^16 and t = 3 for n = 2^14.
 */
#define DEMO_LDPC_SPECS(n, epsilon) \
    {"n", n, "LDPC block length n (= lambda)"}, \
    {"epsilon", epsilon, "LPN constant: r = r' = n^(epsilon/2), kappa = n^epsilon, g = kappa + r'"}, \
    {"delta", "1/4", "sparsity t = floor(delta log2 n)"}, \
    {"eta", "0.005", "noise rate of the encoder"}

/* defaults of the demos with a single LDPC block per codeword */
#define DEMO_LDPC_SPECS_LARGE DEMO_LDPC_SPECS("65536", "3/4")

/* defaults of the nested PRCs, whose codewords consist of many LDPC blocks */
#define DEMO_LDPC_SPECS_SMALL DEMO_LDPC_SPECS("16384", "6/7")

/*
 * The LDPC parameters of the demo; aparams may be NULL for the regular PRC only.
 * Returns 0, or -1 (after a message) if they violate a requirement.
 */
int demo_ldpc_params(const DemoParams *demo_params, LDPCParams *params, A_LDPCParams *aparams);

/* Allocates a DemoPrc (zeroed); `storage` is for the code specific parameters. */
DemoPrc *demo_prc_new(size_t storage_bytes);

#endif /* DEMO_PRC_H */
