/*
 * RLNC with the anamorphic mode (Reed-Solomon points in the headers).
 *
 * The regular message is one generation of generation_size packets (the message
 * text, zero-padded to generation_size * packet_size bytes). A ciphertext file
 * holds `sent` symbols, each the global encoding vector followed by the payload.
 * The receiver collects the first `received` symbols for the anamorphic
 * decoding and all symbols for the regular decoding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "demo_common.h"
#include "rlnc/rlnc.h"

static const DemoParamSpec specs[] = {
    {"q", "256", "field size, a power of two up to 256"},
    {"packet_size", "64", "payload bytes per symbol"},
    {"generation_size", "16", "K: source packets per generation"},
    {"lambda", "64", "security parameter in bits (label length a = lambda / log2 q, K >= 2a)"},
    {"received", "20", "S >= K: symbols the anamorphic receiver collects"},
    {"sent", "40", "T >= S: symbols the sender emits"},
    {NULL, NULL, NULL}
};

typedef struct {
    rlnc_config_t cfg;
    rlnc_aconfig_t acfg;
    size_t sent;
    int have_key;
    uint8_t key[DEMO_KEY_BYTES];
} Rlnc;

static void *rlnc_open(const DemoParams *params, const DemoKeys *keys)
{
    Rlnc *r = calloc(1, sizeof(*r));

    if (r == NULL)
        return NULL;

    r->cfg.q = (uint32_t)demo_param_size(params, "q");
    r->cfg.packet_size = demo_param_size(params, "packet_size");
    r->cfg.generation_size = demo_param_size(params, "generation_size");
    r->acfg.lambda = demo_param_size(params, "lambda");
    r->acfg.received = demo_param_size(params, "received");
    r->sent = demo_param_size(params, "sent");

    if (!rlnc_config_valid(&r->cfg)) {
        fprintf(stderr, "invalid q / packet_size / generation_size\n");
    } else if (rlnc_amsg_len(&r->cfg, &r->acfg) == 0) {
        fprintf(stderr, "invalid anamorphic parameters: need received >= K and K >= 2 * ceil(lambda / log2 q)\n");
    } else if (r->sent < r->acfg.received) {
        fprintf(stderr, "sent must be at least received\n");
    } else {
        r->have_key = keys->have_anamorphic;
        memcpy(r->key, keys->anamorphic, sizeof(r->key));
        return r;
    }

    free(r);

    return NULL;
}

static void rlnc_close(void *handle)
{
    free(handle);
}

static size_t symbol_bytes(const Rlnc *r)
{
    return r->cfg.generation_size + r->cfg.packet_size;
}

/* packets that point into the ciphertext codewords */
static rlnc_packet_t *view_packets(const Rlnc *r, const DemoCiphertext *ct, size_t count)
{
    rlnc_packet_t *p = calloc(count, sizeof(*p));

    for (size_t i = 0; p != NULL && i < count; ++i) {
        p[i].global = ct->data[i];
        p[i].payload = ct->data[i] + r->cfg.generation_size;
    }

    return p;
}

/* generation_size source packets with the canonical global vectors */
static rlnc_packet_t *make_source(const Rlnc *r, const char *message)
{
    const size_t K = r->cfg.generation_size, P = r->cfg.packet_size;
    uint8_t *flat = calloc(K * P, 1);
    rlnc_packet_t *src = calloc(K, sizeof(*src));
    size_t made = 0;

    if (flat == NULL || src == NULL || demo_pad_message(message, flat, K * P) != 0)
        goto fail;

    for (; made < K; ++made) {
        if (rlnc_packet_alloc(&r->cfg, &src[made]) != 0)
            goto fail;

        memcpy(src[made].payload, flat + made * P, P);
        src[made].global[made] = 1;
    }

    free(flat);

    return src;

fail:
    for (size_t i = 0; src != NULL && i < made; ++i)
        rlnc_packet_free(&src[i]);
    free(src);
    free(flat);

    return NULL;
}

static void free_packets(rlnc_packet_t *p, size_t count)
{
    for (size_t i = 0; p != NULL && i < count; ++i)
        rlnc_packet_free(&p[i]);

    free(p);
}

static int store_symbols(const Rlnc *r, const rlnc_packet_t *syms, DemoCiphertext *out)
{
    if (demo_ct_alloc(out, r->sent, 8 * symbol_bytes(r)) != 0)
        return -1;

    for (size_t i = 0; i < r->sent; ++i) {
        memcpy(out->data[i], syms[i].global, r->cfg.generation_size);
        memcpy(out->data[i] + r->cfg.generation_size, syms[i].payload, r->cfg.packet_size);
    }

    return 0;
}

static rlnc_packet_t *alloc_symbols(const Rlnc *r)
{
    rlnc_packet_t *syms = calloc(r->sent, sizeof(*syms));
    size_t i = 0;

    for (; syms != NULL && i < r->sent; ++i) {
        if (rlnc_packet_alloc(&r->cfg, &syms[i]) != 0) {
            free_packets(syms, i);
            return NULL;
        }
    }

    return syms;
}

static int rlnc_encode_op(void *handle, const char *message, DemoCiphertext *out)
{
    Rlnc *r = handle;
    RandomnessSource rng = linux_randomness();
    rlnc_packet_t *src = make_source(r, message);
    rlnc_packet_t *syms = alloc_symbols(r);
    int rc = -1;

    if (src != NULL && syms != NULL) {
        rc = 0;
        for (size_t i = 0; rc == 0 && i < r->sent; ++i)
            rc = rlnc_encode(&r->cfg, src, r->cfg.generation_size, &syms[i], &rng);
    }

    if (rc == 0)
        rc = store_symbols(r, syms, out);

    free_packets(src, r->cfg.generation_size);
    free_packets(syms, r->sent);

    if (rc != 0)
        fprintf(stderr, "encoding failed\n");

    return rc;
}

static int rlnc_decode_op(void *handle, const DemoCiphertext *in)
{
    Rlnc *r = handle;
    const size_t K = r->cfg.generation_size, P = r->cfg.packet_size;
    rlnc_packet_t *recv, *dec = calloc(K, sizeof(*dec));
    uint8_t *flat = calloc(K * P, 1);
    int rc = -1;

    if (in->bits != 8 * symbol_bytes(r) || in->count < K) {
        fprintf(stderr, "ciphertext does not match the parameters\n");
        free(dec);
        free(flat);
        return -1;
    }

    recv = view_packets(r, in, in->count);

    for (size_t i = 0; dec != NULL && i < K; ++i) {
        if (rlnc_packet_alloc(&r->cfg, &dec[i]) != 0)
            goto done;
    }

    if (recv != NULL && dec != NULL && flat != NULL &&
        rlnc_decode(&r->cfg, recv, in->count, dec) == 0) {
        for (size_t i = 0; i < K; ++i)
            memcpy(flat + i * P, dec[i].payload, P);

        demo_print_bytes("message", flat, K * P);
        rc = 0;
    } else {
        printf("decoding failed: the symbols do not span the generation\n");
    }

done:
    free_packets(dec, K);
    free(recv);
    free(flat);

    return rc;
}

static int rlnc_aencode_op(void *handle, const char *message, const char *amessage,
                           DemoCiphertext *out)
{
    Rlnc *r = handle;
    RandomnessSource rng = linux_randomness();
    const size_t L = rlnc_amsg_len(&r->cfg, &r->acfg);
    uint8_t *amsg = calloc(L, 1);
    rlnc_packet_t *src = make_source(r, message);
    rlnc_packet_t *syms = alloc_symbols(r);
    int rc = -1;

    if (amsg != NULL && src != NULL && syms != NULL &&
        demo_pad_message(amessage, amsg, L) == 0) {
        /* one GF(q) symbol per byte */
        for (size_t i = 0; i < L; ++i)
            amsg[i] &= (uint8_t)(r->cfg.q - 1);

        rc = rlnc_aencode(&r->cfg, &r->acfg, src, syms, r->sent, &rng, r->key, amsg);
    }

    if (rc == 0)
        rc = store_symbols(r, syms, out);

    free_packets(src, r->cfg.generation_size);
    free_packets(syms, r->sent);
    free(amsg);

    if (rc != 0)
        fprintf(stderr, "anamorphic encoding failed\n");

    return rc;
}

static int rlnc_adecode_op(void *handle, const DemoCiphertext *in)
{
    Rlnc *r = handle;
    const size_t L = rlnc_amsg_len(&r->cfg, &r->acfg);
    uint8_t *amsg = calloc(L, 1);
    rlnc_packet_t *recv;
    int rc = -1;

    if (in->bits != 8 * symbol_bytes(r) || in->count < r->acfg.received) {
        fprintf(stderr, "ciphertext does not match the parameters\n");
        free(amsg);
        return -1;
    }

    recv = view_packets(r, in, in->count);

    if (amsg != NULL && recv != NULL &&
        rlnc_adecode(&r->cfg, &r->acfg, recv, r->acfg.received, r->key, amsg) == 0) {
        demo_print_bytes("anamorphic message", amsg, L);
        rc = 0;
    } else {
        printf("no anamorphic message\n");
    }

    free(recv);
    free(amsg);

    return rc;
}

static const DemoOps ops = {
    .name = "rlnc",
    .params = specs,
    .regular_keys = 0,
    .anamorphic = 1,
    .anamorphic_key_is_seed = 0,
    .open = rlnc_open,
    .close = rlnc_close,
    .encode = rlnc_encode_op,
    .decode = rlnc_decode_op,
    .aencode = rlnc_aencode_op,
    .adecode = rlnc_adecode_op,
};

int main(int argc, char **argv)
{
    return demo_main(&ops, argc, argv);
}
