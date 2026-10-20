/* PRC^ell_low: ell-bit PRC from the LDPC zero-bit PRC (no anamorphic mode). */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_low.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "512", "256", "10", "0.01"),
    {"ell", "40", "message length in bits"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low;
} Storage;

static void *low_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *p = demo_prc_new(sizeof(Storage));
    Storage *s;

    if (p == NULL)
        return NULL;

    s = p->storage;
    s->ldpc = demo_ldpc_params(params);
    s->underlying = prc_ldpc(&s->ldpc);
    s->low = (PRCLow_Params){
        .underlying = &s->underlying,
        .ell = demo_param_size(params, "ell"),
    };

    p->mb = prc_low(&s->low);
    p->message_bits = s->low.ell;

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
}

static const DemoOps ops = {
    .name = "low",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 0,
    .open = low_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
};

int main(int argc, char **argv)
{
    return demo_main(&ops, argc, argv);
}
