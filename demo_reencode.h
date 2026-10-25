#ifndef DEMO_REENCODE_H
#define DEMO_REENCODE_H

/*
 * Shared part of demo_sharp and demo_cca: PRC_sharp / PRC_cca on top of
 * PRC^ell_low over the LDPC PRC, with the randomness-recovery anamorphic mode.
 */

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "prcs/multibit/implementations/prc_reencode.h"

#define DEMO_REENCODE_SPECS \
    DEMO_LDPC_SPECS_SMALL, \
    {"lambda", "128", "security parameter in bits (multiple of 8); length of the recovered seed"}, \
    {"message_bits", "32", "message length in bits"}, \
    {"distance", "0.05", "maximal relative distance delta of the re-encoded codeword"}, \
    {"indication_seeds", "0", "indication seeds (extra codewords that make adecode reject other strings)"}, \
    {"amessage_bytes", "8", "anamorphic message bytes; the nonce fills the rest of the seed (>= 8 bytes)"}

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
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

    if (demo_ldpc_params(params, &storage->ldpc, NULL) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    storage->underlying = prc_ldpc(&storage->ldpc);
    /* the inner PRC encodes r || m || R2 */
    storage->low_params = (PRCLow_Params){
        .underlying = &storage->underlying,
        .ell = 2 * lambda + message_bits,
    };
    storage->low = prc_low(&storage->low_params);
    storage->params = (PRCReencode_Params){
        .inner = &storage->low,
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
