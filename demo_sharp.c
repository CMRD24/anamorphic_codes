/* PRC_sharp: message_bits-bit PRC (lambda-bit seed) with the randomness-recovery anamorphic mode. */
#include "demo_reencode.h"

static const DemoParamSpec specs[] = {
    DEMO_REENCODE_SPECS,
    {NULL, NULL, NULL}
};

static void *sharp_open(const DemoParams *params, const DemoKeys *keys)
{
    return demo_reencode_open(params, keys, prc_sharp_rr);
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
    .akeygen = demo_prc_akeygen,
    .sample_messages = demo_prc_sample_messages,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_sharp_ops, argc, argv);
}
#endif
