/* PRC_cca: message_bits-bit PRC (lambda-bit seed) with the randomness-recovery anamorphic mode. */
#include "demo_reencode.h"

static const DemoParamSpec specs[] = {
    DEMO_REENCODE_SPECS,
    {NULL, NULL, NULL}
};

static void *cca_open(const DemoParams *params, const DemoKeys *keys)
{
    return demo_reencode_open(params, keys, prc_cca_rr);
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_cca_ops = {
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

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_cca_ops, argc, argv);
}
#endif
