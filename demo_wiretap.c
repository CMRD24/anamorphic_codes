/*
 * Wiretap code (OAEP4 as the IFE, Hamming(7,4) as ECC) with the
 * randomness-recovery anamorphic mode.
 *
 * The regular message is zero-padded to a multiple of K_bytes. The code is
 * keyless; the anamorphic key is a 32 byte symmetric key.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "demo_common.h"
#include "utils/hamming74.h"
#include "wiretap/wiretap.h"

static const DemoParamSpec specs[] = {
    {"K_bytes", "32", "block size in bytes (even)"},
    {"security_parameter", "128", "lambda in bits"},
    {"ana_message_length", "16", "anamorphic message bytes (K_bytes - ana_message_length >= 16)"},
    {NULL, NULL, NULL}
};

typedef struct {
    ECC ecc;
    wiretap_config_t cfg;
    wiretap_ana_config_t acfg;
    int have_key;
    uint8_t key[DEMO_KEY_BYTES];
} Wiretap;

static void *wiretap_open(const DemoParams *params, const DemoKeys *keys)
{
    Wiretap *w = calloc(1, sizeof(*w));

    if (w == NULL)
        return NULL;

    w->ecc = hamming74_ecc();
    w->cfg = (wiretap_config_t){
        .K_bytes = demo_param_size(params, "K_bytes"),
        .security_parameter = demo_param_size(params, "security_parameter"),
        .ecc = &w->ecc,
    };
    w->acfg.ana_message_length = demo_param_size(params, "ana_message_length");

    if (!wiretap_config_valid(&w->cfg)) {
        fprintf(stderr, "invalid wiretap parameters (K_bytes must be positive and even)\n");
    } else if (!wiretap_ana_config_valid(&w->cfg, &w->acfg)) {
        fprintf(stderr, "invalid ana_message_length: need 0 < length <= K_bytes - 16\n");
    } else {
        w->have_key = keys->have_anamorphic;
        memcpy(w->key, keys->anamorphic, sizeof(w->key));
        return w;
    }

    free(w);

    return NULL;
}

static void wiretap_close(void *handle)
{
    free(handle);
}

/* pads the message to a positive multiple of K_bytes */
static uint8_t *padded_message(const Wiretap *w, const char *message, size_t *len)
{
    size_t n = message != NULL ? strlen(message) : 0;
    uint8_t *buf;

    *len = n == 0 ? w->cfg.K_bytes : (n + w->cfg.K_bytes - 1) / w->cfg.K_bytes * w->cfg.K_bytes;
    buf = calloc(*len, 1);

    if (buf != NULL)
        memcpy(buf, message != NULL ? message : "", n);

    return buf;
}

static int finish_encode(const Wiretap *w, const uint8_t *amessage_or_null, const char *message,
                         DemoCiphertext *out)
{
    size_t mlen, olen = 0, cap;
    uint8_t *msg = padded_message(w, message, &mlen);
    uint8_t *ct;
    RandomnessSource rng = linux_randomness();
    int rc = -1;

    cap = wiretap_encoded_size(&w->cfg, mlen);
    ct = msg != NULL && cap > 0 ? malloc(cap) : NULL;

    if (ct != NULL) {
        rc = amessage_or_null == NULL
            ? wiretap_encode(&w->cfg, &rng, msg, mlen, ct, cap, &olen)
            : wiretap_aencode(&w->cfg, &w->acfg, w->key, msg, mlen, amessage_or_null, ct, cap, &olen);
    }

    if (rc == 0 && demo_ct_alloc(out, 1, 8 * olen) == 0)
        memcpy(out->data[0], ct, olen);
    else
        rc = -1;

    free(ct);
    free(msg);

    return rc;
}

static int wiretap_encode_op(void *handle, const char *message, DemoCiphertext *out)
{
    if (finish_encode(handle, NULL, message, out) != 0) {
        fprintf(stderr, "encoding failed\n");
        return -1;
    }

    return 0;
}

static int wiretap_aencode_op(void *handle, const char *message, const char *amessage,
                              DemoCiphertext *out)
{
    Wiretap *w = handle;
    uint8_t *amsg = calloc(w->acfg.ana_message_length, 1);
    int rc = -1;

    if (amsg != NULL && demo_pad_message(amessage, amsg, w->acfg.ana_message_length) == 0)
        rc = finish_encode(w, amsg, message, out);

    free(amsg);

    if (rc != 0)
        fprintf(stderr, "anamorphic encoding failed\n");

    return rc;
}

static int wiretap_decode_op(void *handle, const DemoCiphertext *in)
{
    Wiretap *w = handle;
    size_t cap = wiretap_decoded_size(&w->cfg, in->bits / 8), olen = 0;
    uint8_t *out = cap > 0 ? malloc(cap) : NULL;
    int rc = -1;

    if (in->count == 1 && out != NULL &&
        wiretap_decode(&w->cfg, in->data[0], in->bits / 8, out, cap, &olen) == 0) {
        demo_print_bytes("message", out, olen);
        rc = 0;
    } else {
        printf("decoding failed\n");
    }

    free(out);

    return rc;
}

static int wiretap_adecode_op(void *handle, const DemoCiphertext *in)
{
    Wiretap *w = handle;
    uint8_t *amsg = calloc(w->acfg.ana_message_length, 1);
    int rc = -1;

    /* the encryption of the seed is not authenticated: any ciphertext decodes */
    if (in->count == 1 && amsg != NULL &&
        wiretap_adecode(&w->cfg, &w->acfg, w->key, in->data[0], in->bits / 8, amsg) == 0) {
        demo_print_bytes("anamorphic message", amsg, w->acfg.ana_message_length);
        rc = 0;
    } else {
        printf("no anamorphic message\n");
    }

    free(amsg);

    return rc;
}

static const DemoOps ops = {
    .name = "wiretap",
    .params = specs,
    .regular_keys = 0,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 0,
    .open = wiretap_open,
    .close = wiretap_close,
    .encode = wiretap_encode_op,
    .decode = wiretap_decode_op,
    .aencode = wiretap_aencode_op,
    .adecode = wiretap_adecode_op,
};

int main(int argc, char **argv)
{
    return demo_main(&ops, argc, argv);
}
