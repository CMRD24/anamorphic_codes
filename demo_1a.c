/* PRC^1_adapt: one-bit PRC from the LDPC zero-bit PRC with the lifted anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "prcs/multibit/implementations/prc1_adapt.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "256", "512", "10", "0.01"),
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRC1AdaptParams adapt;
    A_LDPCParams ldpc_aparams;
    aZBPRC azb;
    APRC1AdaptParams aadapt;
    aMBPRC lift;
} Storage;

static void *adapt_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *p = demo_prc_new(sizeof(Storage));
    Storage *s;

    if (p == NULL)
        return NULL;

    s = p->storage;
    s->ldpc = demo_ldpc_params(params);
    s->underlying = prc_ldpc(&s->ldpc);
    s->adapt = (PRC1AdaptParams){.underlying_prc = &s->underlying};

    s->azb = aprc_ldpc(&s->ldpc_aparams);
    s->aadapt = (APRC1AdaptParams){.underlying_aprc = &s->azb};
    s->lift = aprc1_adapt(&s->aadapt);

    p->mb = prc1_adapt(&s->adapt);
    p->lift = &s->lift;
    p->message_bits = 1;

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_1a_ops = {
    .name = "1a",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = adapt_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = demo_prc_aencode,
    .adecode = demo_prc_adecode,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_1a_ops, argc, argv);
}
#endif
