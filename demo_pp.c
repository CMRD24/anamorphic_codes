/* Permuted puzzle zero-bit PRC with the randomness-recovery anamorphic mode. */
#include <stdio.h>
#include <string.h>

#include "demo_prc.h"
#include "prcs/zerobit/implementations/prc_pp.h"
#include "utils/hamming74.h"
#include "utils/none_ecc.h"

static const DemoParamSpec specs[] = {
    {"n", "128", "codeword length in symbols"},
    {"q", "2", "alphabet size"},
    {"symbol_bits", "1", "bits per symbol"},
    {"message_bytes", "8", "bytes encoded by the ECC"},
    {"delta", "0", "noise parameter"},
    {"ecc", "hamming", "error-correcting code: hamming or none"},
    {"seed_bits", "64", "bits of the encoding seed recovered by the decoder"},
    {"indication_len", "32", "number of indication seeds"},
    {"amessage_bytes", "16", "anamorphic message bytes (multiple of seed_bits/8)"},
    {NULL, NULL, NULL}
};

typedef struct {
    ECC ecc;
    PPParams params;
    ZBPRC_RR rr;
} Storage;

static void *pp_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *p = demo_prc_new(sizeof(Storage));
    Storage *s;
    const char *ecc;

    if (p == NULL)
        return NULL;

    s = p->storage;
    ecc = demo_param(params, "ecc");

    if (strcmp(ecc, "hamming") == 0) {
        s->ecc = hamming74_ecc();
    } else if (strcmp(ecc, "none") == 0) {
        s->ecc = NONE_ECC;
    } else {
        fprintf(stderr, "ecc must be hamming or none\n");
        demo_prc_close(p);
        return NULL;
    }

    s->params = (PPParams){
        .delta = demo_param_double(params, "delta"),
        .ecc = &s->ecc,
        .n = demo_param_size(params, "n"),
        .q = demo_param_size(params, "q"),
        .message_bytes = demo_param_size(params, "message_bytes"),
        .symbol_bits = demo_param_size(params, "symbol_bits"),
    };
    s->rr = prc_pp_rr(&s->params);

    p->zerobit = 1;
    p->zb_rr = &s->rr;
    p->seed_bits = demo_param_size(params, "seed_bits");
    p->indication_len = demo_param_size(params, "indication_len");
    p->amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (demo_prc_finish(p, keys) != 0) {
        demo_prc_close(p);
        return NULL;
    }

    return p;
}

static const DemoOps ops = {
    .name = "pp",
    .params = specs,
    .regular_keys = 1,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 1,
    .open = pp_open,
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
