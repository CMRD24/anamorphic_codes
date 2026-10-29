/*
 * RLNC with the anamorphic mode (Reed-Solomon points in the global encoding
 * vectors).
 *
 * The regular message is one generation of K = generation_size packets (the
 * message text, zero-padded to generation_size * payload_bytes bytes). A
 * ciphertext file holds T = sent_symbols symbols, each the global encoding vector
 * followed by the payload. The receiver collects the first S = received_symbols
 * symbols for the anamorphic decoding and all symbols for the regular decoding.
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "demo_common.h"
#include "rlnc/rlnc.h"

static const DemoParamSpec specs[] = {
    {"q", "256", "field size, a power of two up to 256"},
    {"payload_bytes", "1024", "payload bytes per symbol"},
    {"generation_size", "32", "K: source packets per generation"},
    {"lambda", "128", "security parameter in bits (label length a = lambda / log2 q, K >= 2a)"},
    {"received_symbols", "33", "S >= K: symbols the anamorphic receiver collects"},
    {"sent_symbols", "50", "T >= S: symbols the sender emits"},
    {NULL, NULL, NULL}
};

typedef struct {
    rlnc_config_t config;
    rlnc_aconfig_t aconfig;
    size_t sent_symbols;
    int have_key;
    uint8_t key[DEMO_KEY_BYTES];
} RlncDemo;

static void *rlnc_open(const DemoParams *params, const DemoKeys *keys)
{
    RlncDemo *demo = calloc(1, sizeof(*demo));

    if (demo == NULL)
        return NULL;

    demo->config = (rlnc_config_t){
        .q = (uint32_t)demo_param_size(params, "q"),
        .payload_bytes = demo_param_size(params, "payload_bytes"),
        .generation_size = demo_param_size(params, "generation_size"),
    };
    demo->aconfig = (rlnc_aconfig_t){
        .lambda = demo_param_size(params, "lambda"),
        .received_symbols = demo_param_size(params, "received_symbols"),
    };
    demo->sent_symbols = demo_param_size(params, "sent_symbols");

    if (!rlnc_config_valid(&demo->config)) {
        fprintf(stderr, "invalid q / payload_bytes / generation_size\n");
    } else if (rlnc_amessage_symbols(&demo->config, &demo->aconfig) == 0) {
        fprintf(stderr, "invalid anamorphic parameters: need received_symbols >= K and "
                "K >= 2 * ceil(lambda / log2 q)\n");
    } else if (demo->sent_symbols < demo->aconfig.received_symbols) {
        fprintf(stderr, "sent_symbols must be at least received_symbols\n");
    } else {
        demo->have_key = keys->have_anamorphic;
        memcpy(demo->key, keys->anamorphic, sizeof(demo->key));
        return demo;
    }

    free(demo);

    return NULL;
}

/* keyless code: the anamorphic key is the symmetric key itself */
static int rlnc_akeygen_op(void *handle, const uint8_t key[DEMO_KEY_BYTES])
{
    RlncDemo *demo = handle;

    demo->have_key = 1;
    memcpy(demo->key, key, sizeof(demo->key));

    return 0;
}

/*
 * A uniformly random generation (every packet payload uniform) and a uniformly
 * random anamorphic message (one byte per GF(q) symbol, reduced by aencode).
 */
static int rlnc_sample_messages(void *handle, char **message, char **amessage)
{
    const RlncDemo *demo = handle;

    *message = demo_random_message(8 * demo->config.generation_size * demo->config.payload_bytes);
    *amessage = demo_random_message(8 * rlnc_amessage_symbols(&demo->config, &demo->aconfig));

    if (*message == NULL || *amessage == NULL) {
        free(*message);
        free(*amessage);
        *message = *amessage = NULL;
        return -1;
    }

    return 0;
}

static void rlnc_close(void *handle)
{
    free(handle);
}

static size_t symbol_bytes(const RlncDemo *demo)
{
    return demo->config.generation_size + demo->config.payload_bytes;
}

/* packets that point into the ciphertext codewords */
static rlnc_packet_t *view_packets(const RlncDemo *demo, const DemoCiphertext *ciphertext)
{
    rlnc_packet_t *packets = calloc(ciphertext->count, sizeof(*packets));

    for (size_t i = 0; packets != NULL && i < ciphertext->count; ++i) {
        packets[i].global_vector = ciphertext->data[i];
        packets[i].payload = ciphertext->data[i] + demo->config.generation_size;
    }

    return packets;
}

static void free_packets(rlnc_packet_t *packets, size_t count)
{
    for (size_t i = 0; packets != NULL && i < count; ++i)
        rlnc_packet_free(&packets[i]);

    free(packets);
}

static rlnc_packet_t *alloc_packets(const RlncDemo *demo, size_t count)
{
    rlnc_packet_t *packets = calloc(count, sizeof(*packets));

    for (size_t i = 0; packets != NULL && i < count; ++i) {
        if (rlnc_packet_alloc(&demo->config, &packets[i]) != 0) {
            free_packets(packets, i);
            return NULL;
        }
    }

    return packets;
}

/* the K source packets of the message with the canonical global vectors e_k */
static rlnc_packet_t *make_source(const RlncDemo *demo, const char *message)
{
    const size_t K = demo->config.generation_size;
    const size_t payload_bytes = demo->config.payload_bytes;
    uint8_t *generation = calloc(K * payload_bytes, 1);
    rlnc_packet_t *source = alloc_packets(demo, K);

    if (generation == NULL || source == NULL ||
        demo_pad_message(message, generation, K * payload_bytes) != 0) {
        free(generation);
        free_packets(source, K);
        return NULL;
    }

    for (size_t k = 0; k < K; ++k) {
        memcpy(source[k].payload, generation + k * payload_bytes, payload_bytes);
        source[k].global_vector[k] = 1;
    }

    free(generation);

    return source;
}

static int store_symbols(const RlncDemo *demo, const rlnc_packet_t *symbols, DemoCiphertext *out)
{
    if (demo_ct_alloc(out, demo->sent_symbols, 8 * symbol_bytes(demo)) != 0)
        return -1;

    for (size_t i = 0; i < demo->sent_symbols; ++i) {
        memcpy(out->data[i], symbols[i].global_vector, demo->config.generation_size);
        memcpy(out->data[i] + demo->config.generation_size, symbols[i].payload,
               demo->config.payload_bytes);
    }

    return 0;
}

static int rlnc_encode_op(void *handle, const char *message, DemoCiphertext *out)
{
    RlncDemo *demo = handle;
    RandomnessSource random = linux_randomness();
    rlnc_packet_t *source = make_source(demo, message);
    rlnc_packet_t *symbols = alloc_packets(demo, demo->sent_symbols);
    int result = -1;

    if (source != NULL && symbols != NULL) {
        result = 0;
        for (size_t i = 0; result == 0 && i < demo->sent_symbols; ++i)
            result = rlnc_encode(&demo->config, source, demo->config.generation_size,
                                 &symbols[i], &random);
    }

    if (result == 0)
        result = store_symbols(demo, symbols, out);

    free_packets(source, demo->config.generation_size);
    free_packets(symbols, demo->sent_symbols);

    if (result != 0)
        fprintf(stderr, "encoding failed\n");

    return result;
}

static int rlnc_decode_op(void *handle, const DemoCiphertext *in)
{
    RlncDemo *demo = handle;
    const size_t K = demo->config.generation_size;
    const size_t payload_bytes = demo->config.payload_bytes;

    if (in->bits != 8 * symbol_bytes(demo) || in->count < K) {
        fprintf(stderr, "ciphertext does not match the parameters\n");
        return -1;
    }

    rlnc_packet_t *received = view_packets(demo, in);
    rlnc_packet_t *decoded = alloc_packets(demo, K);
    uint8_t *generation = calloc(K * payload_bytes, 1);
    int result = -1;

    if (received != NULL && decoded != NULL && generation != NULL &&
        rlnc_decode(&demo->config, received, in->count, decoded) == 0) {
        for (size_t k = 0; k < K; ++k)
            memcpy(generation + k * payload_bytes, decoded[k].payload, payload_bytes);

        demo_print_bytes("message", generation, K * payload_bytes);
        result = 0;
    } else {
        printf("decoding failed: the symbols do not span the generation\n");
    }

    free_packets(decoded, K);
    free(received);
    free(generation);

    return result;
}

static int rlnc_aencode_op(void *handle, const char *message, const char *amessage_text,
                           DemoCiphertext *out)
{
    RlncDemo *demo = handle;
    RandomnessSource random = linux_randomness();
    const size_t amessage_length = rlnc_amessage_symbols(&demo->config, &demo->aconfig);
    uint8_t *amessage = calloc(amessage_length, 1);
    rlnc_packet_t *source = make_source(demo, message);
    rlnc_packet_t *symbols = alloc_packets(demo, demo->sent_symbols);
    int result = -1;

    if (amessage != NULL && source != NULL && symbols != NULL &&
        demo_pad_message(amessage_text, amessage, amessage_length) == 0) {
        /* one GF(q) symbol per byte */
        for (size_t i = 0; i < amessage_length; ++i)
            amessage[i] &= (uint8_t)(demo->config.q - 1);

        result = rlnc_aencode(&demo->config, &demo->aconfig, source, symbols,
                              demo->sent_symbols, &random, demo->key, amessage);
    }

    if (result == 0)
        result = store_symbols(demo, symbols, out);

    free_packets(source, demo->config.generation_size);
    free_packets(symbols, demo->sent_symbols);
    free(amessage);

    if (result != 0)
        fprintf(stderr, "anamorphic encoding failed\n");

    return result;
}

static int rlnc_adecode_op(void *handle, const DemoCiphertext *in)
{
    RlncDemo *demo = handle;
    const size_t amessage_length = rlnc_amessage_symbols(&demo->config, &demo->aconfig);

    if (in->bits != 8 * symbol_bytes(demo) || in->count < demo->aconfig.received_symbols) {
        fprintf(stderr, "ciphertext does not match the parameters\n");
        return -1;
    }

    uint8_t *amessage = calloc(amessage_length, 1);
    rlnc_packet_t *received = view_packets(demo, in);
    int result = -1;

    if (amessage != NULL && received != NULL &&
        rlnc_adecode(&demo->config, &demo->aconfig, received, demo->aconfig.received_symbols,
                     demo->key, amessage) == 0) {
        demo_print_bytes("anamorphic message", amessage, amessage_length);
        result = 0;
    } else {
        printf("no anamorphic message\n");
    }

    free(received);
    free(amessage);

    return result;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_rlnc_ops = {
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
    .akeygen = rlnc_akeygen_op,
    .sample_messages = rlnc_sample_messages,
};

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_rlnc_ops, argc, argv);
}
#endif
