/* PRC_high: message_bits-bit PRC with the randomness-recovery anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_high.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "utils/hamming74.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS_SMALL,
    {"lambda", "128", "security parameter in bits (multiple of 8); length of the recovered seed"},
    {"message_bits", "64", "message length in bits (multiple of 8)"},
    {"indication_seeds", "0", "indication seeds (extra codewords that make adecode reject other strings)"},
    {"amessage_bytes", "8", "anamorphic message bytes; the nonce fills the rest of the seed (>= 8 bytes)"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
    ECC ecc;
    PRCHigh_Params high;
    MBPRC_RR rr;
} Storage;

static void *high_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *prc = demo_prc_new(sizeof(Storage));

    if (prc == NULL)
        return NULL;

    Storage *storage = prc->storage;

    if (demo_ldpc_params(params, &storage->ldpc, NULL) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    storage->underlying = prc_ldpc(&storage->ldpc);
    /* the inner PRC carries the lambda-bit seed r */
    storage->low_params = (PRCLow_Params){
        .underlying = &storage->underlying,
        .ell = demo_param_size(params, "lambda"),
    };
    storage->low = prc_low(&storage->low_params);
    storage->ecc = hamming74_ecc();
    storage->high = (PRCHigh_Params){
        .inner = &storage->low,
        .ecc = &storage->ecc,
        .lambda = demo_param_size(params, "lambda"),
        .message_bits = demo_param_size(params, "message_bits"),
    };
    storage->rr = prc_high_rr(&storage->high);

    prc->multibit_rr = &storage->rr;
    prc->message_bits = storage->high.message_bits;
    prc->seed_bits = storage->high.lambda;
    prc->indication_seeds = demo_param_size(params, "indication_seeds");
    prc->amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_high_ops = {
    .name = "high",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = high_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = demo_prc_aencode,
    .adecode = demo_prc_adecode,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_high_ops, argc, argv);
}
#endif
