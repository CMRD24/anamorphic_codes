#ifndef DEMO_PRC_H
#define DEMO_PRC_H

/*
 * Shared operations of the PRC demos: one generic implementation for zero-bit
 * and multibit PRCs, with the optional randomness-recovery anamorphic mode.
 * A demo only has to describe its code in a DemoPrc and call demo_prc_finish.
 */

#include "demo_common.h"
#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/anamorphism/aprc_rr.h"
#include "prcs/multibit/multibit_prc.h"
#include "prcs/zerobit/zerobit_prc.h"

typedef struct DemoPrc {
    /* ---- filled in by the demo ---- */
    int zerobit;                 /* 1: ZBPRC, 0: MBPRC */
    ZBPRC zb;
    MBPRC mb;
    size_t message_bits;         /* multibit: bits of the regular message */

    /* randomness-recovery anamorphism (rr != NULL enables it) */
    const ZBPRC_RR *zb_rr;
    const MBPRC_RR *mb_rr;
    size_t seed_bits;            /* k, a multiple of 8 */
    size_t indication_len;       /* z */
    size_t amessage_bytes;       /* a multiple of seed_bits / 8 */

    void *storage;               /* code specific structures, released with free() */

    /* ---- set up by demo_prc_finish ---- */
    ZBPRC_Keys *zb_keys;
    MBPRC_Keys *mb_keys;
    APRC_RR_Keys *akeys;
    aZBPRC_RR_Params zb_ap;
    aMBPRC_RR_Params mb_ap;
    aZBPRC_RR zb_aprc;
    aMBPRC_RR mb_aprc;
} DemoPrc;

/*
 * Generates the keys that are present in `keys` (deterministically from the
 * key files) and prepares the anamorphic parameters. Returns 0 on success.
 */
int demo_prc_finish(DemoPrc *prc, const DemoKeys *keys);

void demo_prc_close(void *handle);
int demo_prc_encode(void *handle, const char *message, DemoCiphertext *out);
int demo_prc_decode(void *handle, const DemoCiphertext *in);
int demo_prc_aencode(void *handle, const char *message, const char *amessage,
                     DemoCiphertext *out);
int demo_prc_adecode(void *handle, const DemoCiphertext *in);

/* the anamorphic key stream domain (regular: 'R', anamorphic: 'A') */
#define DEMO_DOMAIN_REGULAR 'R'
#define DEMO_DOMAIN_ANAMORPHIC 'A'

/* Parameter entries of the LDPC zero-bit PRC with the given defaults. */
#define DEMO_LDPC_SPECS(n, r, g, t, eta) \
    {"n", n, "LDPC block length (bits)"}, \
    {"r", r, "number of parity checks"}, \
    {"g", g, "columns of the generator matrix"}, \
    {"t", t, "sparsity of the parity checks"}, \
    {"eta", eta, "noise rate added by the encoder"}

static inline LDPCParams demo_ldpc_params(const DemoParams *p)
{
    LDPCParams params = {
        .n = demo_param_size(p, "n"),
        .r = demo_param_size(p, "r"),
        .g = demo_param_size(p, "g"),
        .t = demo_param_size(p, "t"),
        .eta = demo_param_double(p, "eta"),
    };

    return params;
}

/* Allocates a DemoPrc (zeroed); `storage` is for the code specific parameters. */
DemoPrc *demo_prc_new(size_t storage_bytes);

#endif /* DEMO_PRC_H */
