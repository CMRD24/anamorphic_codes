/* PRC_sharp: message_bits-bit PRC (lambda-bit seed) with the randomness-recovery anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "prcs/multibit/implementations/prc_sharp.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "512", "256", "11", "0.01"),
    {"lambda_bits", "128", "security parameter in bits (multiple of 8); length of the recovered seed"},
    {"message_bits", "32", "message length in bits"},
    {"delta", "0.05", "maximal relative distance of the re-encoded codeword"},
    {"indication_len", "0", "indication seeds (extra codewords that make adecode reject other strings)"},
    {"amessage_bytes", "8", "anamorphic message bytes; the nonce fills the rest of the seed (>= 8 bytes)"},
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
    PRCSharp_Params params;
    MBPRC_RR rr;
} Storage;

static void *sharp_open(const DemoParams *params, const DemoKeys *keys)
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
    s->params = (PRCSharp_Params){
        .prc = &s->low,
        .lambda_bits = demo_param_size(params, "lambda_bits"),
        .delta = demo_param_double(params, "delta"),
    };
    s->rr = prc_sharp_rr(&s->params);

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

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_sharp_ops = {
    .name = "sharp",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = sharp_open,
    .close = demo_prc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = demo_prc_aencode,
    .adecode = demo_prc_adecode,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_sharp_ops, argc, argv);
}
#endif
