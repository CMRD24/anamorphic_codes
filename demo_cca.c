/* PRC_cca: message_bits-bit PRC (lambda-bit seed) with the randomness-recovery anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_cca.h"
#include "prcs/multibit/implementations/prc_low.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "512", "256", "11", "0.01"),
    {"lambda_bits", "16", "security parameter in bits (multiple of 8); seed length"},
    {"message_bits", "32", "message length in bits"},
    {"delta", "0.05", "maximal relative distance of the re-encoded codeword"},
    {"indication_len", "32", "number of indication seeds"},
    {"amessage_bytes", "16", "anamorphic message bytes (multiple of lambda_bits/8)"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
    PRC_CCA_Params params;
    MBPRC_RR rr;
} Storage;

static void *cca_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *p = demo_prc_new(sizeof(Storage));
    Storage *s;

    if (p == NULL)
        return NULL;

    s = p->storage;
    s->ldpc = demo_ldpc_params(params);
    s->underlying = prc_ldpc(&s->ldpc);
    /* the inner PRC encodes seed || message || mask */
    s->low_params = (PRCLow_Params){
        .underlying = &s->underlying,
        .ell = 2 * demo_param_size(params, "lambda_bits") + demo_param_size(params, "message_bits"),
    };
    s->low = prc_low(&s->low_params);
    s->params = (PRC_CCA_Params){
        .prc = &s->low,
        .lambda_bits = demo_param_size(params, "lambda_bits"),
        .delta = demo_param_double(params, "delta"),
    };
    s->rr = prc_cca_rr(&s->params);

    p->mb_rr = &s->rr;
    p->message_bits = demo_param_size(params, "message_bits");
    p->seed_bits = s->params.lambda_bits;
    p->indication_len = demo_param_size(params, "indication_len");
    p->amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
}

static const DemoOps ops = {
    .name = "cca",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = cca_open,
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
