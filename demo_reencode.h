#ifndef DEMO_REENCODE_H
#define DEMO_REENCODE_H

/*
 * Shared part of demo_sharp and demo_cca: PRC_sharp / PRC_cca on top of
 * PRC_high (with PRC^lambda_low over the LDPC PRC and Hamming(7,4)), with the
 * randomness-recovery anamorphic mode.
 */

#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_high.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "prcs/multibit/implementations/prc_reencode.h"
#include "utils/hamming74.h"

#define DEMO_REENCODE_SPECS \
    DEMO_LDPC_SPECS_SMALL, \
    {"lambda", "128", "security parameter in bits (multiple of 8); length of the recovered seed"}, \
    {"message_bits", "64", "message length in bits (multiple of 8)"}, \
    {"distance", "0.05", "maximal relative distance delta of the re-encoded codeword"}, \
    {"indication_seeds", "0", "indication seeds (extra codewords that make adecode reject other strings)"}, \
    {"amessage_bytes", "8", "anamorphic message bytes; the nonce fills the rest of the seed (>= 8 bytes)"}

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
    ECC ecc;
    PRCHigh_Params high_params;
    MBPRC high;
    PRCReencode_Params params;
    MBPRC_RR rr;
} DemoReencodeStorage;

/* make_rr is prc_sharp_rr or prc_cca_rr */
static inline void *demo_reencode_open(const DemoParams *params, const DemoKeys *keys,
                                       MBPRC_RR (*make_rr)(const PRCReencode_Params *))
{
    DemoPrc *prc = demo_prc_new(sizeof(DemoReencodeStorage));

    if (prc == NULL)
        return NULL;

    DemoReencodeStorage *storage = prc->storage;
    const size_t lambda = demo_param_size(params, "lambda");
    const size_t message_bits = demo_param_size(params, "message_bits");

    if (message_bits % 8 != 0) {
        fprintf(stderr, "message_bits must be a multiple of 8 (PRC_high encodes bytes)\n");
        demo_prc_close(prc);
        return NULL;
    }

    if (demo_ldpc_params(params, &storage->ldpc, NULL) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    storage->underlying = prc_ldpc(&storage->ldpc);
    /* PRC^lambda_low carries the lambda-bit seed of PRC_high */
    storage->low_params = (PRCLow_Params){
        .underlying = &storage->underlying,
        .ell = lambda,
    };
    storage->low = prc_low(&storage->low_params);
    storage->ecc = hamming74_ecc();
    /* the inner PRC_high encodes r || m || R2 */
    storage->high_params = (PRCHigh_Params){
        .inner = &storage->low,
        .ecc = &storage->ecc,
        .lambda = lambda,
        .message_bits = 2 * lambda + message_bits,
    };
    storage->high = prc_high(&storage->high_params);
    storage->params = (PRCReencode_Params){
        .inner = &storage->high,
        .lambda = lambda,
        .delta = demo_param_double(params, "distance"),
    };
    storage->rr = make_rr(&storage->params);

    prc->multibit_rr = &storage->rr;
    prc->message_bits = message_bits;
    prc->seed_bits = lambda;
    prc->indication_seeds = demo_param_size(params, "indication_seeds");
    prc->amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
}

#endif /* DEMO_REENCODE_H */
