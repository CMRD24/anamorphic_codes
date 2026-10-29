/* LDPC zero-bit PRC with the native anamorphic mode (second parity-check matrix P'). */
#include <stdio.h>
#include <stdlib.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "utils/csprg_sodium.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS_LARGE,
    {NULL, NULL, NULL}
};

typedef struct {
    DemoPrc base;           /* must be first */
    LDPCParams params;
    A_LDPCParams aparams;
    aZBPRC aprc;
    AZBPRC_Keys *akeys;
} LdpcDemo;

static void ldpc_close(void *handle)
{
    LdpcDemo *demo = handle;

    if (demo == NULL)
        return;

    zbprc_free_akeys(&demo->base.zerobit_prc, &demo->aprc, demo->akeys);
    demo_prc_close(&demo->base);
}

/* the native anamorphic key (P', B) on top of the regular keys (P, G, z) of the handle */
static int ldpc_akeygen(void *handle, const uint8_t key[DEMO_KEY_BYTES])
{
    LdpcDemo *demo = handle;

    if (demo->base.zerobit_keys == NULL) {
        fprintf(stderr, "the anamorphic key generation needs the regular key\n");
        return -1;
    }

    zbprc_free_akeys(&demo->base.zerobit_prc, &demo->aprc, demo->akeys);

    RandomnessSource stream = demo_key_stream(key, DEMO_DOMAIN_ANAMORPHIC);

    demo->akeys = zbprc_akeygen(&demo->base.zerobit_prc, &demo->aprc,
                                demo->base.zerobit_keys, &stream);
    csprg_randomness_free(&stream);

    if (demo->akeys == NULL) {
        fprintf(stderr, "anamorphic key generation failed (check the parameters)\n");
        return -1;
    }

    return 0;
}

static void *ldpc_open(const DemoParams *params, const DemoKeys *keys)
{
    LdpcDemo *demo = calloc(1, sizeof(*demo));

    if (demo == NULL)
        return NULL;

    if (demo_ldpc_params(params, &demo->params, &demo->aparams) != 0) {
        free(demo);
        return NULL;
    }

    demo->base.zerobit = 1;
    demo->base.zerobit_prc = prc_ldpc(&demo->params);
    demo->aprc = aprc_ldpc(&demo->aparams);

    if (demo_prc_finish(&demo->base, keys) != 0) {
        ldpc_close(demo);
        return NULL;
    }

    if (keys->have_anamorphic && demo->base.zerobit_keys != NULL &&
        ldpc_akeygen(demo, keys->anamorphic) != 0) {
        ldpc_close(demo);
        return NULL;
    }

    return demo;
}

static int ldpc_aencode(void *handle, const char *message, const char *amessage,
                        DemoCiphertext *out)
{
    LdpcDemo *demo = handle;
    RandomnessSource random = linux_randomness();
    size_t bits = 0;

    /* zero-bit: the regular and the anamorphic message are the bit 1 */
    (void)message;
    (void)amessage;

    uint8_t *codeword = zbprc_aencode(&demo->base.zerobit_prc, &demo->aprc,
                                      demo->base.zerobit_keys->enc, demo->akeys->double_key,
                                      &random, &bits);

    if (codeword == NULL || demo_ct_alloc(out, 1, bits) != 0) {
        free(codeword);
        fprintf(stderr, "anamorphic encoding failed\n");
        return -1;
    }

    for (size_t i = 0; i < (bits + 7) / 8; ++i)
        out->data[0][i] = codeword[i];

    free(codeword);

    return 0;
}

static int ldpc_adecode(void *handle, const DemoCiphertext *in)
{
    LdpcDemo *demo = handle;
    int failed = 0;

    for (size_t i = 0; i < in->count; ++i) {
        const int accepted = zbprc_adecode(&demo->base.zerobit_prc, &demo->aprc,
                                           demo->base.zerobit_keys->dec,
                                           demo->akeys->trapdoor_key, in->data[i],
                                           in->bits) == 1;

        printf("codeword %zu: %s\n", i,
               accepted ? "anamorphic message present" : "no anamorphic message");
        failed |= !accepted;
    }

    return failed ? -1 : 0;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_ldpc_ops = {
    .name = "ldpc",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = ldpc_open,
    .close = ldpc_close,
    .encode = demo_prc_encode,
    .decode = demo_prc_decode,
    .aencode = ldpc_aencode,
    .adecode = ldpc_adecode,
    .akeygen = ldpc_akeygen,
    .sample_messages = demo_prc_sample_messages,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_ldpc_ops, argc, argv);
}
#endif
