/* PRC^1_adapt: one-bit PRC from the LDPC zero-bit PRC with the lifted anamorphic mode. */
#include <stdio.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "prcs/multibit/implementations/prc1_adapt.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS_LARGE,
    {NULL, NULL, NULL}
};

typedef struct {
    LDPCParams ldpc;
    A_LDPCParams ldpc_aparams;
    ZBPRC underlying;
    aZBPRC underlying_aprc;
    PRC1AdaptParams adapt;
    APRC1AdaptParams aadapt;
    aMBPRC lifting;
} Storage;

static void *adapt_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *prc = demo_prc_new(sizeof(Storage));

    if (prc == NULL)
        return NULL;

    Storage *storage = prc->storage;

    if (demo_ldpc_params(params, &storage->ldpc, &storage->ldpc_aparams) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    storage->underlying = prc_ldpc(&storage->ldpc);
    storage->adapt = (PRC1AdaptParams){.underlying_prc = &storage->underlying};

    storage->underlying_aprc = aprc_ldpc(&storage->ldpc_aparams);
    storage->aadapt = (APRC1AdaptParams){.underlying_aprc = &storage->underlying_aprc};
    storage->lifting = aprc1_adapt(&storage->aadapt);

    prc->multibit_prc = prc1_adapt(&storage->adapt);
    prc->lifting = &storage->lifting;
    prc->message_bits = 1;

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
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
    .akeygen = demo_prc_akeygen,
    .sample_messages = demo_prc_sample_messages,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_1a_ops, argc, argv);
}
#endif
