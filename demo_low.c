/* PRC^ell_low: ell-bit PRC from the LDPC zero-bit PRC with the lifted anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "prcs/multibit/implementations/prc_low.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "256", "512", "10", "0.01"),
    {"ell", "40", "message length in bits"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low;
    A_LDPCParams ldpc_aparams;
    aZBPRC azb;
    APRCLow_Params alow;
    aMBPRC lift;
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

    s->azb = aprc_ldpc(&s->ldpc_aparams);
    s->alow = (APRCLow_Params){.underlying_aprc = &s->azb};
    s->lift = aprc_low(&s->alow);

    p->mb = prc_low(&s->low);
    p->lift = &s->lift;
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
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = low_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = demo_prc_aencode,
    .adecode = demo_prc_adecode,
};

int main(int argc, char **argv)
{
    return demo_main(&ops, argc, argv);
}
