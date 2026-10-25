/*
 * Wiretap code (OAEP4 as the IFE, Hamming(7,4) as ECC) with the
 * randomness-recovery anamorphic mode.
 *
 * The regular message is zero-padded to a multiple of block_bytes. The code is
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
    {"block_bytes", "32", "block size in bytes (even)"},
    {"lambda", "128", "lambda in bits"},
    {"amessage_bytes", "16", "anamorphic message bytes (block_bytes - amessage_bytes >= 16)"},
    {NULL, NULL, NULL}
};

typedef struct {
    ECC ecc;
    wiretap_config_t config;
    wiretap_aconfig_t aconfig;
    int have_key;
    uint8_t key[DEMO_KEY_BYTES];
} Wiretap;

static void *wiretap_open(const DemoParams *params, const DemoKeys *keys)
{
    Wiretap *wiretap = calloc(1, sizeof(*wiretap));

    if (wiretap == NULL)
        return NULL;

    wiretap->ecc = hamming74_ecc();
    wiretap->config = (wiretap_config_t){
        .block_bytes = demo_param_size(params, "block_bytes"),
        .lambda = demo_param_size(params, "lambda"),
        .ecc = &wiretap->ecc,
    };
    wiretap->aconfig.amessage_bytes = demo_param_size(params, "amessage_bytes");

    if (!wiretap_config_valid(&wiretap->config)) {
        fprintf(stderr, "invalid wiretap parameters (block_bytes must be positive and even)\n");
    } else if (!wiretap_aconfig_valid(&wiretap->config, &wiretap->aconfig)) {
        fprintf(stderr, "invalid amessage_bytes: need 0 < length <= block_bytes - 16\n");
    } else {
        wiretap->have_key = keys->have_anamorphic;
        memcpy(wiretap->key, keys->anamorphic, sizeof(wiretap->key));
        return wiretap;
    }

    free(wiretap);

    return NULL;
}

static void wiretap_close(void *handle)
{
    free(handle);
}

/* pads the message to a positive multiple of block_bytes */
static uint8_t *padded_message(const Wiretap *wiretap, const char *message, size_t *padded_len)
{
    const size_t block_bytes = wiretap->config.block_bytes;
    const size_t text_len = message != NULL ? strlen(message) : 0;
    const size_t blocks = text_len == 0 ? 1 : (text_len + block_bytes - 1) / block_bytes;
    uint8_t *padded;

    *padded_len = blocks * block_bytes;
    padded = calloc(*padded_len, 1);

    if (padded != NULL)
        memcpy(padded, message != NULL ? message : "", text_len);

    return padded;
}

static int finish_encode(const Wiretap *wiretap, const uint8_t *amessage, const char *message,
                         DemoCiphertext *out)
{
    size_t message_len, codeword_len = 0, capacity;
    uint8_t *message_buffer = padded_message(wiretap, message, &message_len);
    uint8_t *codeword;
    RandomnessSource random = linux_randomness();
    int result = -1;

    capacity = wiretap_encoded_size(&wiretap->config, message_len);
    codeword = message_buffer != NULL && capacity > 0 ? malloc(capacity) : NULL;

    if (codeword != NULL) {
        result = amessage == NULL
            ? wiretap_encode(&wiretap->config, &random, message_buffer, message_len, codeword,
                             capacity, &codeword_len)
            : wiretap_aencode(&wiretap->config, &wiretap->aconfig, wiretap->key, message_buffer,
                              message_len, amessage, codeword, capacity, &codeword_len);
    }

    if (result == 0 && demo_ct_alloc(out, 1, 8 * codeword_len) == 0)
        memcpy(out->data[0], codeword, codeword_len);
    else
        result = -1;

    free(codeword);
    free(message_buffer);

    return result;
}

static int wiretap_encode_op(void *handle, const char *message, DemoCiphertext *out)
{
    if (finish_encode(handle, NULL, message, out) != 0) {
        fprintf(stderr, "encoding failed\n");
        return -1;
    }

    return 0;
}

static int wiretap_aencode_op(void *handle, const char *message, const char *amessage_text,
                              DemoCiphertext *out)
{
    Wiretap *wiretap = handle;
    uint8_t *amessage = calloc(wiretap->aconfig.amessage_bytes, 1);
    int result = -1;

    if (amessage != NULL &&
        demo_pad_message(amessage_text, amessage, wiretap->aconfig.amessage_bytes) == 0)
        result = finish_encode(wiretap, amessage, message, out);

    free(amessage);

    if (result != 0)
        fprintf(stderr, "anamorphic encoding failed\n");

    return result;
}

static int wiretap_decode_op(void *handle, const DemoCiphertext *in)
{
    Wiretap *wiretap = handle;
    const size_t capacity = wiretap_decoded_size(&wiretap->config, in->bits / 8);
    uint8_t *message = capacity > 0 ? malloc(capacity) : NULL;
    size_t message_len = 0;
    int result = -1;

    if (in->count == 1 && message != NULL &&
        wiretap_decode(&wiretap->config, in->data[0], in->bits / 8, message, capacity,
                       &message_len) == 0) {
        demo_print_bytes("message", message, message_len);
        result = 0;
    } else {
        printf("decoding failed\n");
    }

    free(message);

    return result;
}

static int wiretap_adecode_op(void *handle, const DemoCiphertext *in)
{
    Wiretap *wiretap = handle;
    uint8_t *amessage = calloc(wiretap->aconfig.amessage_bytes, 1);
    int result = -1;

    /* the encryption of the seed is not authenticated: any ciphertext decodes */
    if (in->count == 1 && amessage != NULL &&
        wiretap_adecode(&wiretap->config, &wiretap->aconfig, wiretap->key, in->data[0],
                        in->bits / 8, amessage) == 0) {
        demo_print_bytes("anamorphic message", amessage, wiretap->aconfig.amessage_bytes);
        result = 0;
    } else {
        printf("no anamorphic message\n");
    }

    free(amessage);

    return result;
}

/* exported so that the benchmark can use the code without its main */
const DemoOps demo_wiretap_ops = {
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

#ifndef DEMO_NO_MAIN
int main(int argc, char **argv)
{
    return demo_main(&demo_wiretap_ops, argc, argv);
}
#endif
