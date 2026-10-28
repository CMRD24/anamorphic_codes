#define _POSIX_C_SOURCE 200809L

#include "demo_prc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <sodium.h>

#include "utils/csprg_sodium.h"
#include "utils/helpers.h"

#define MESSAGE_CAPACITY 4096

int demo_ldpc_params(const DemoParams *demo_params, LDPCParams *params, A_LDPCParams *aparams)
{
    const double epsilon = demo_param_double(demo_params, "epsilon");
    A_LDPCParams anamorphic;

    if (ldpc_admissible_choice(demo_param_size(demo_params, "n"), epsilon,
                               demo_param_double(demo_params, "delta"),
                               demo_param_double(demo_params, "eta"),
                               params, &anamorphic) != 0) {
        fprintf(stderr, "invalid LDPC parameters: n >= 2, 0 < epsilon < 1, delta > 0 and "
                "0 < eta < 1/2 are required\n");
        return -1;
    }

    if (aparams != NULL)
        *aparams = anamorphic;

    return ldpc_check_requirements(params, aparams, epsilon);
}

/* mu: the indication seeds plus the fewest seeds that hold nonce and ciphertext */
static size_t codeword_count_of(const DemoPrc *prc)
{
    return prc->indication_seeds + rr_min_ciphertext_seeds(prc->seed_bits, prc->amessage_bytes);
}

static int has_rr(const DemoPrc *prc)
{
    return prc->zerobit ? prc->zerobit_rr != NULL : prc->multibit_rr != NULL;
}

DemoPrc *demo_prc_new(size_t storage_bytes)
{
    DemoPrc *prc = calloc(1, sizeof(*prc));

    if (prc == NULL)
        return NULL;

    prc->storage = calloc(1, storage_bytes);
    if (prc->storage == NULL) {
        free(prc);
        return NULL;
    }

    return prc;
}

int demo_prc_finish(DemoPrc *prc, const DemoKeys *keys)
{
    RandomnessSource stream;

    if (prc->zerobit && prc->zerobit_rr != NULL)
        prc->zerobit_prc = prc->zerobit_rr->base;
    if (!prc->zerobit && prc->multibit_rr != NULL)
        prc->multibit_prc = prc->multibit_rr->base;

    if (keys->have_regular) {
        stream = demo_key_stream(keys->regular, DEMO_DOMAIN_REGULAR);

        if (prc->zerobit)
            prc->zerobit_keys = zbprc_keygen(&prc->zerobit_prc, &stream);
        else
            prc->multibit_keys = mbprc_keygen(&prc->multibit_prc, &stream);

        csprg_randomness_free(&stream);

        if (prc->zerobit_keys == NULL && prc->multibit_keys == NULL) {
            fprintf(stderr, "key generation failed (check the parameters)\n");
            return -1;
        }
    }

    if (prc->lifting != NULL)
        return keys->have_anamorphic && prc->multibit_keys != NULL
            ? demo_prc_akeygen(prc, keys->anamorphic) : 0;

    if (!has_rr(prc))
        return 0;

    if (prc->seed_bits == 0 || prc->seed_bits % 8 != 0 || prc->amessage_bytes == 0) {
        fprintf(stderr, "invalid anamorphic parameters: the seed length (%zu bits) must be a "
                "positive multiple of 8 and amessage_bytes positive\n", prc->seed_bits);
        return -1;
    }

    const RR_Shape shape = {
        .seed_bits = prc->seed_bits,
        .indication_seeds = prc->indication_seeds,
        .codeword_count = codeword_count_of(prc),
        .amessage_bytes = prc->amessage_bytes,
    };

    prc->zerobit_rr_aprc = (aZBPRC_RR){.shape = shape, .prc = prc->zerobit_rr};
    prc->multibit_rr_aprc = (aMBPRC_RR){.shape = shape, .prc = prc->multibit_rr};

    return keys->have_anamorphic ? demo_prc_akeygen(prc, keys->anamorphic) : 0;
}

int demo_prc_akeygen(void *handle, const uint8_t key[DEMO_KEY_BYTES])
{
    DemoPrc *prc = handle;
    RandomnessSource stream;

    if (prc->lifting != NULL) {
        if (prc->multibit_keys == NULL) {
            fprintf(stderr, "the anamorphic key generation needs the regular key\n");
            return -1;
        }

        mbprc_free_akeys(&prc->multibit_prc, prc->lifting, prc->lifting_akeys);

        stream = demo_key_stream(key, DEMO_DOMAIN_ANAMORPHIC);
        prc->lifting_akeys = mbprc_akeygen(&prc->multibit_prc, prc->lifting,
                                           prc->multibit_keys, &stream);
        csprg_randomness_free(&stream);

        if (prc->lifting_akeys == NULL) {
            fprintf(stderr, "anamorphic key generation failed (check the parameters)\n");
            return -1;
        }

        return 0;
    }

    if (!has_rr(prc))
        return 0;

    rr_free_akeys(prc->rr_akeys);

    stream = demo_key_stream(key, DEMO_DOMAIN_ANAMORPHIC);
    prc->rr_akeys = rr_akeygen(&stream);
    csprg_randomness_free(&stream);

    if (prc->rr_akeys == NULL) {
        fprintf(stderr, "anamorphic key generation failed\n");
        return -1;
    }

    return 0;
}

/* a uniformly random string of count characters 0/1 that contains a 1 */
static char *random_nonzero_bits(size_t count)
{
    char *text = malloc(count + 1);
    int nonzero = 0;

    if (text == NULL || count == 0) {
        free(text);
        return NULL;
    }

    while (!nonzero) {
        for (size_t i = 0; i < count; ++i) {
            text[i] = (char)('0' + randombytes_uniform(2));
            nonzero |= text[i] == '1';
        }
    }

    text[count] = '\0';

    return text;
}

int demo_prc_sample_messages(void *handle, char **message, char **amessage)
{
    DemoPrc *prc = handle;

    if (prc->zerobit) {
        *message = strdup("");
    } else if (prc->message_bits < 8) {
        /* written as a number, see parse_message */
        char number[4];

        snprintf(number, sizeof(number), "%u",
                 (unsigned)randombytes_uniform(1u << prc->message_bits));
        *message = strdup(number);
    } else {
        *message = demo_random_message(prc->message_bits);
    }

    if (prc->lifting != NULL)
        *amessage = random_nonzero_bits(mbprc_amessage_bits(&prc->multibit_prc, prc->lifting));
    else if (has_rr(prc))
        *amessage = demo_random_message(8 * prc->amessage_bytes);
    else
        *amessage = strdup("");

    if (*message == NULL || *amessage == NULL) {
        free(*message);
        free(*amessage);
        *message = *amessage = NULL;
        return -1;
    }

    return 0;
}

void demo_prc_close(void *handle)
{
    DemoPrc *prc = handle;

    if (prc == NULL)
        return;

    if (prc->lifting_akeys != NULL)
        mbprc_free_akeys(&prc->multibit_prc, prc->lifting, prc->lifting_akeys);

    rr_free_akeys(prc->rr_akeys);

    if (prc->zerobit_keys != NULL)
        zbprc_free_keys(&prc->zerobit_prc, prc->zerobit_keys);
    if (prc->multibit_keys != NULL)
        mbprc_free_keys(&prc->multibit_prc, prc->multibit_keys);

    free(prc->storage);
    free(prc);
}

/* ------------------------------------------------------------------------
 * Regular messages
 * ------------------------------------------------------------------------ */

static size_t message_bytes(const DemoPrc *prc)
{
    return (prc->message_bits + 7) / 8;
}

/* messages of fewer than 8 bits are written as a number ("0", "1") */
static int parse_message(const DemoPrc *prc, const char *text, uint8_t *message)
{
    if (prc->message_bits < 8) {
        message[0] = text != NULL
            ? (uint8_t)(strtoul(text, NULL, 10) & ((1u << prc->message_bits) - 1)) : 0;
        return 0;
    }

    return demo_pad_message(text, message, message_bytes(prc));
}

static void print_message(const DemoPrc *prc, const char *label, const uint8_t *message)
{
    if (prc->message_bits < 8)
        printf("%s: %u\n", label, message[0] & ((1u << prc->message_bits) - 1));
    else
        demo_print_bytes(label, message, message_bytes(prc));
}

/* ------------------------------------------------------------------------
 * Encoding / decoding
 * ------------------------------------------------------------------------ */

static int single_codeword(DemoCiphertext *out, uint8_t *codeword, size_t bits)
{
    int result = -1;

    if (codeword != NULL && demo_ct_alloc(out, 1, bits) == 0) {
        memcpy(out->data[0], codeword, (bits + 7) / 8);
        result = 0;
    }

    free(codeword);

    return result;
}

int demo_prc_encode(void *handle, const char *message_text, DemoCiphertext *out)
{
    DemoPrc *prc = handle;
    RandomnessSource random = linux_randomness();
    size_t bits = 0;
    uint8_t *codeword;

    if (prc->zerobit) {
        codeword = zbprc_encode(&prc->zerobit_prc, prc->zerobit_keys->enc, &random, &bits);
    } else {
        uint8_t message[MESSAGE_CAPACITY];

        if (message_bytes(prc) > sizeof(message) || parse_message(prc, message_text, message) != 0)
            return -1;

        codeword = mbprc_encode(&prc->multibit_prc, prc->multibit_keys->enc, message,
                                prc->message_bits, &random, &bits);
    }

    if (single_codeword(out, codeword, bits) != 0) {
        fprintf(stderr, "encoding failed\n");
        return -1;
    }

    return 0;
}

int demo_prc_decode(void *handle, const DemoCiphertext *in)
{
    DemoPrc *prc = handle;
    int failed = 0;

    for (size_t i = 0; i < in->count; ++i) {
        char label[32];

        snprintf(label, sizeof(label), "codeword %zu", i);

        if (prc->zerobit) {
            const int accepted = zbprc_decode(&prc->zerobit_prc, prc->zerobit_keys->dec,
                                              in->data[i], in->bits) == 1;

            printf("%s: %s\n", label, accepted ? "accepted" : "rejected");
            failed |= !accepted;
        } else {
            uint8_t message[MESSAGE_CAPACITY] = {0};
            size_t decoded_bits = 0;

            if (mbprc_decode(&prc->multibit_prc, prc->multibit_keys->dec, in->data[i], in->bits,
                             message, &decoded_bits) != 1) {
                printf("%s: rejected\n", label);
                failed = 1;
            } else {
                print_message(prc, label, message);
            }
        }
    }

    return failed ? -1 : 0;
}

/* anamorphic message of the lifting construction: a string of 0/1 characters */
static int parse_bits(const char *text, uint8_t *bits, size_t count)
{
    const size_t length = text != NULL ? strlen(text) : 0;

    if (length > count) {
        fprintf(stderr, "anamorphic message too long: %zu bits, at most %zu\n", length, count);
        return -1;
    }

    memset(bits, 0, (count + 7) / 8);

    for (size_t i = 0; i < length; ++i) {
        if (text[i] != '0' && text[i] != '1') {
            fprintf(stderr, "the anamorphic message must be a string of 0 and 1\n");
            return -1;
        }

        set_bit(bits, i, (uint8_t)(text[i] == '1'));
    }

    return 0;
}

static int lifting_aencode(DemoPrc *prc, const char *message_text, const char *amessage_text,
                           DemoCiphertext *out)
{
    RandomnessSource random = linux_randomness();
    const size_t gamma = mbprc_amessage_bits(&prc->multibit_prc, prc->lifting);
    uint8_t *amessage = calloc((gamma + 7) / 8, 1);
    uint8_t message[MESSAGE_CAPACITY];
    size_t bits = 0;
    uint8_t *codeword = NULL;

    if (amessage != NULL && message_bytes(prc) <= sizeof(message) &&
        parse_bits(amessage_text, amessage, gamma) == 0 &&
        parse_message(prc, message_text, message) == 0)
        codeword = mbprc_aencode(&prc->multibit_prc, prc->lifting, prc->multibit_keys->enc,
                                 prc->lifting_akeys->double_key, message, prc->message_bits,
                                 amessage, &random, &bits);

    free(amessage);

    if (codeword == NULL) {
        fprintf(stderr, "anamorphic encoding failed (the message must contain a 1)\n");
        return -1;
    }

    return single_codeword(out, codeword, bits);
}

static int lifting_adecode(DemoPrc *prc, const DemoCiphertext *in)
{
    const size_t gamma = mbprc_amessage_bits(&prc->multibit_prc, prc->lifting);
    uint8_t *amessage = calloc((gamma + 7) / 8, 1);
    int failed = amessage == NULL;

    for (size_t i = 0; !failed && i < in->count; ++i) {
        if (mbprc_adecode(&prc->multibit_prc, prc->lifting, prc->multibit_keys->dec,
                          prc->lifting_akeys->trapdoor_key, in->data[i], in->bits,
                          amessage) == 1) {
            printf("codeword %zu: anamorphic message ", i);
            for (size_t bit = 0; bit < gamma; ++bit)
                putchar('0' + get_bit(amessage, bit));
            putchar('\n');
        } else {
            printf("codeword %zu: no anamorphic message\n", i);
            failed = 1;
        }
    }

    free(amessage);

    return failed ? -1 : 0;
}

/*
 * The mu regular messages "m1;m2;..." (the last one is repeated) as an array of
 * message pointers into one buffer; NULL on error. Free with free().
 */
static const uint8_t **parse_messages(const DemoPrc *prc, const char *text, size_t count)
{
    const size_t bytes = message_bytes(prc);
    const uint8_t **messages = calloc(count, sizeof(*messages) + bytes);
    char *copy = strdup(text != NULL ? text : "");
    char *cursor = copy, *piece = copy;
    int parsed = messages != NULL && copy != NULL;
    uint8_t *buffer = messages != NULL ? (uint8_t *)(messages + count) : NULL;

    for (size_t i = 0; parsed && i < count; ++i) {
        char *separator = cursor != NULL ? strchr(cursor, ';') : NULL;

        if (cursor != NULL) {
            piece = cursor;
            if (separator != NULL)
                *separator = '\0';
            cursor = separator != NULL ? separator + 1 : NULL;
        }

        messages[i] = buffer + i * bytes;
        parsed = parse_message(prc, piece, buffer + i * bytes) == 0;
    }

    free(copy);

    if (!parsed) {
        free(messages);
        return NULL;
    }

    return messages;
}

int demo_prc_aencode(void *handle, const char *message_text, const char *amessage_text,
                     DemoCiphertext *out)
{
    DemoPrc *prc = handle;

    if (prc->lifting != NULL)
        return lifting_aencode(prc, message_text, amessage_text, out);

    RandomnessSource random = linux_randomness();
    const size_t codeword_count = codeword_count_of(prc);
    uint8_t *amessage = calloc(prc->amessage_bytes, 1);
    uint8_t **codewords = NULL;
    size_t bits = 0;
    int result = -1;

    if (amessage == NULL || demo_pad_message(amessage_text, amessage, prc->amessage_bytes) != 0)
        goto done;

    if (prc->zerobit) {
        codewords = azbprc_rr_aencode(&prc->zerobit_rr_aprc, prc->zerobit_keys->enc,
                                      prc->rr_akeys, amessage, &random, &bits);
    } else {
        const uint8_t **messages = parse_messages(prc, message_text, codeword_count);

        if (messages != NULL)
            codewords = ambprc_rr_aencode(&prc->multibit_rr_aprc, prc->multibit_keys->enc,
                                          prc->rr_akeys, messages, prc->message_bits,
                                          amessage, &random, &bits);
        free(messages);
    }

    if (codewords == NULL) {
        fprintf(stderr, "anamorphic encoding failed\n");
        goto done;
    }

    if (demo_ct_alloc(out, codeword_count, bits) == 0) {
        for (size_t i = 0; i < codeword_count; ++i)
            memcpy(out->data[i], codewords[i], (bits + 7) / 8);
        result = 0;
    }

    rr_free_codewords(codewords, codeword_count);

done:
    free(amessage);
    return result;
}

int demo_prc_adecode(void *handle, const DemoCiphertext *in)
{
    DemoPrc *prc = handle;

    if (prc->lifting != NULL)
        return lifting_adecode(prc, in);

    if (in->count != codeword_count_of(prc)) {
        fprintf(stderr, "expected %zu codewords, the file has %zu\n", codeword_count_of(prc),
                in->count);
        return -1;
    }

    uint8_t *amessage = calloc(prc->amessage_bytes, 1);
    int ok;

    if (amessage == NULL)
        return -1;

    if (prc->zerobit)
        ok = azbprc_rr_adecode(&prc->zerobit_rr_aprc, prc->zerobit_keys->dec, prc->rr_akeys,
                               (const uint8_t *const *)in->data, in->bits, amessage);
    else
        ok = ambprc_rr_adecode(&prc->multibit_rr_aprc, prc->multibit_keys->dec, prc->rr_akeys,
                               (const uint8_t *const *)in->data, in->bits, prc->message_bits,
                               amessage);

    if (ok)
        demo_print_bytes("anamorphic message", amessage, prc->amessage_bytes);
    else
        printf("no anamorphic message\n");

    free(amessage);

    return ok ? 0 : -1;
}
