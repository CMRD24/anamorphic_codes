/* LDPC zero-bit PRC with the native anamorphic mode (second parity check matrix). */
#include <stdio.h>
#include <stdlib.h>

#include "demo_prc.h"
#include "prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "utils/csprg_sodium.h"

static const DemoParamSpec specs[] = {
    DEMO_LDPC_SPECS("1024", "256", "512", "10", "0.01"),
    {NULL, NULL, NULL}
};

typedef struct {
    DemoPrc base;           /* must be first */
    LDPCParams params;
    A_LDPCParams aparams;
    aZBPRC aprc;
    APRC_Keys *akeys;
} LdpcDemo;

static void ldpc_close(void *handle)
{
    LdpcDemo *d = handle;

    if (d == NULL)
        return;

    if (d->akeys != NULL) {
        zbprc_free_enc_akey(&d->base.zb, &d->aprc, d->akeys->enc);
        zbprc_free_dec_akey(&d->base.zb, &d->aprc, d->akeys->dec);
        free(d->akeys);
    }

    demo_prc_close(&d->base);
}

static void *ldpc_open(const DemoParams *params, const DemoKeys *keys)
{
    LdpcDemo *d = calloc(1, sizeof(*d));

    if (d == NULL)
        return NULL;

    d->params = demo_ldpc_params(params);
    d->aparams.g_prime = 0;
    d->base.zerobit = 1;
    d->base.zb = prc_ldpc(&d->params);
    d->aprc = aprc_ldpc(&d->aparams);

    if (demo_prc_finish(&d->base, keys) != 0) {
        ldpc_close(d);
        return NULL;
    }

    if (keys->have_anamorphic && d->base.zb_keys != NULL) {
        RandomnessSource stream = demo_key_stream(keys->anamorphic, DEMO_DOMAIN_ANAMORPHIC);

        d->akeys = zbprc_akeygen(&d->base.zb, &d->aprc, d->base.zb_keys, &stream);
        csprg_randomness_free(&stream);

        if (d->akeys == NULL) {
            fprintf(stderr, "anamorphic key generation failed (check the parameters)\n");
            ldpc_close(d);
            return NULL;
        }
    }

    return d;
}

static int ldpc_aencode(void *handle, const char *message, const char *amessage,
                        DemoCiphertext *out)
{
    LdpcDemo *d = handle;
    RandomnessSource rng = linux_randomness();
    size_t bits = 0;
    uint8_t *c;

    /* zero-bit: the regular and the anamorphic message are the bit 1 */
    (void)message;
    (void)amessage;

    c = zbprc_aencode(&d->base.zb, &d->aprc, d->base.zb_keys->enc, d->akeys->enc, &rng, &bits);

    if (c == NULL || demo_ct_alloc(out, 1, bits) != 0) {
        free(c);
        fprintf(stderr, "anamorphic encoding failed\n");
        return -1;
    }

    for (size_t i = 0; i < (bits + 7) / 8; ++i)
        out->data[0][i] = c[i];

    free(c);

    return 0;
}

static int ldpc_adecode(void *handle, const DemoCiphertext *in)
{
    LdpcDemo *d = handle;
    int failed = 0;

    for (size_t i = 0; i < in->count; ++i) {
        int accepted = zbprc_adecode(&d->base.zb, &d->aprc, d->base.zb_keys->dec,
                                     d->akeys->dec, in->data[i], in->bits) == 1;

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
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_ldpc_ops, argc, argv);
}
#endif
