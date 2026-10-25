/* Deletion-channel zero-bit PRC on top of the LDPC PRC (no anamorphic mode). */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/zerobit/implementations/prc_dc.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS_SMALL,
    {"slice_bits", "211", "bits per underlying codeword bit"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCDC_Params dc;
} Storage;

static void *dc_open(const DemoParams *params, const DemoKeys *keys)
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
    storage->dc = (PRCDC_Params){
        .slice_bits = demo_param_size(params, "slice_bits"),
        .underlying = &storage->underlying,
    };

    prc->zerobit = 1;
    prc->zerobit_prc = prc_dc(&storage->dc);

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_dc_ops = {
    .name = "dc",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 0,
    .open = dc_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_dc_ops, argc, argv);
}
#endif
