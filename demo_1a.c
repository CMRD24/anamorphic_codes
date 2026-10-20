/* PRC^1_adapt: one-bit PRC from the LDPC zero-bit PRC (no anamorphic mode). */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc1_adapt.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "512", "256", "10", "0.01"),
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRC1AdaptParams adapt;
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

    p->mb = prc1_adapt(&s->adapt);
    p->message_bits = 1;

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
}

static const DemoOps ops = {
    .name = "1a",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 0,
    .open = adapt_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
};

int main(int argc, char **argv)
{
    return demo_main(&ops, argc, argv);
}
