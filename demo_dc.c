/* Deletion-channel zero-bit PRC on top of the LDPC PRC (no anamorphic mode). */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/zerobit/implementations/prc_dc.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("128", "64", "32", "4", "0.01"),
    {"T", "211", "bits per underlying codeword bit"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCDC_Params dc;
} Storage;

static void *dc_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *p = demo_prc_new(sizeof(Storage));
    Storage *s;

    if (p == NULL)
        return NULL;

    s = p->storage;
    s->ldpc = demo_ldpc_params(params);
    s->underlying = prc_ldpc(&s->ldpc);
    s->dc = (PRCDC_Params){
        .k = s->ldpc.n,
        .T = demo_param_size(params, "T"),
        .underlying = &s->underlying,
    };

    p->zerobit = 1;
    p->zb = prc_dc(&s->dc);

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
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
