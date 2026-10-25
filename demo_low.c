/* PRC^ell_low: ell-bit PRC from the LDPC zero-bit PRC with the lifted anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "prcs/multibit/implementations/prc_low.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS_LARGE,
    {"ell", "40", "message length in bits"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    A_LDPCParams ldpc_aparams;
    ZBPRC underlying;
    aZBPRC underlying_aprc;
    PRCLow_Params low;
    APRCLow_Params alow;
    aMBPRC lifting;
} Storage;

static void *low_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *prc = demo_prc_new(sizeof(Storage));

    if (prc == NULL)
        return NULL;

    Storage *storage = prc->storage;

    if (demo_ldpc_params(params, &storage->ldpc, &storage->ldpc_aparams) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    storage->underlying = prc_ldpc(&storage->ldpc);
    storage->low = (PRCLow_Params){
        .underlying = &storage->underlying,
        .ell = demo_param_size(params, "ell"),
    };

    storage->underlying_aprc = aprc_ldpc(&storage->ldpc_aparams);
    storage->alow = (APRCLow_Params){.underlying_aprc = &storage->underlying_aprc};
    storage->lifting = aprc_low(&storage->alow);

    prc->multibit_prc = prc_low(&storage->low);
    prc->lifting = &storage->lifting;
    prc->message_bits = storage->low.ell;

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_low_ops = {
    .name = "low",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = low_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = demo_prc_aencode,
    .adecode = demo_prc_adecode,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_low_ops, argc, argv);
}
#endif
