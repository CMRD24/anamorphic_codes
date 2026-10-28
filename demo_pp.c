/* Permuted puzzle zero-bit PRC with the randomness-recovery anamorphic mode. */
#include <stdio.h>
#include <string.h>

#include "demo_prc.h"
#include "prcs/zerobit/implementations/prc_pp.h"
#include "utils/hamming74.h"
#include "utils/none_ecc.h"

static const DemoParamSpec specs[] = {
    {"n", "384", "codeword length in symbols"},
    {"q", "2", "alphabet size"},
    {"symbol_bits", "1", "bits per symbol"},
    {"seed_bytes", "24", "bytes x encoded by the ECC; the decoder recovers them as the seed"},
    {"delta", "0", "noise parameter"},
    {"ecc", "hamming", "error-correcting code: hamming or none"},
    {"indication_seeds", "0", "indication seeds (extra codewords that make adecode reject other strings)"},
    {"amessage_bytes", "16", "anamorphic message bytes; the nonce fills the rest of the seed (>= 8 bytes)"},
    {NULL, NULL, NULL}
};

typedef struct {
    ECC ecc;
    PPParams params;
    ZBPRC_RR rr;
} Storage;

static void *pp_open(const DemoParams *params, const DemoKeys *keys)
{
    DemoPrc *prc = demo_prc_new(sizeof(Storage));

    if (prc == NULL)
        return NULL;

    Storage *storage = prc->storage;
    const char *ecc = demo_param(params, "ecc");

    if (strcmp(ecc, "hamming") == 0) {
        storage->ecc = hamming74_ecc();
    } else if (strcmp(ecc, "none") == 0) {
        storage->ecc = NONE_ECC;
    } else {
        fprintf(stderr, "ecc must be hamming or none\n");
        demo_prc_close(prc);
        return NULL;
    }

    storage->params = (PPParams){
        .ecc = &storage->ecc,
        .seed_bytes = demo_param_size(params, "seed_bytes"),
        .q = demo_param_size(params, "q"),
        .symbol_bits = demo_param_size(params, "symbol_bits"),
        .n = demo_param_size(params, "n"),
        .delta = demo_param_double(params, "delta"),
    };
    storage->rr = prc_pp_rr(&storage->params);

    prc->zerobit = 1;
    prc->zerobit_rr = &storage->rr;
    prc->seed_bits = 8 * storage->params.seed_bytes;
    prc->indication_seeds = demo_param_size(params, "indication_seeds");
    prc->amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (demo_prc_finish(prc, keys) != 0) {
        demo_prc_close(prc);
        return NULL;
    }

    return prc;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_pp_ops = {
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
    .akeygen = demo_prc_akeygen,
    .sample_messages = demo_prc_sample_messages,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_pp_ops, argc, argv);
}
#endif
