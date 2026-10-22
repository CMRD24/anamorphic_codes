#define _POSIX_C_SOURCE 200809L

#include "demo_prc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "prcs/anamorphism/rr_core.h"
#include "utils/csprg_sodium.h"
#include "utils/helpers.h"

#define DECODED_MESSAGE_CAPACITY 4096

/* indication seeds plus the fewest seeds that hold nonce and ciphertext */
static size_t mu_of(const DemoPrc *p)
{
    return p->indication_len + rr_min_ciphertext_seeds(p->seed_bits, p->amessage_bytes);
}

static int has_rr(const DemoPrc *p)
{
    return p->zerobit ? p->zb_rr != NULL : p->mb_rr != NULL;
}

DemoPrc *demo_prc_new(size_t storage_bytes)
{
    DemoPrc *p = calloc(1, sizeof(*p));

    if (p == NULL)
        return NULL;

    p->storage = calloc(1, storage_bytes);
    if (p->storage == NULL) {
        free(p);
        return NULL;
    }

    return p;
}

int demo_prc_finish(DemoPrc *p, const DemoKeys *keys)
{
    RandomnessSource stream;

    if (p->zerobit && p->zb_rr)
        p->zb = p->zb_rr->base;
    if (!p->zerobit && p->mb_rr)
        p->mb = p->mb_rr->base;

    if (keys->have_regular) {
        stream = demo_key_stream(keys->regular, DEMO_DOMAIN_REGULAR);

        if (p->zerobit)
            p->zb_keys = zbprc_keygen(&p->zb, &stream);
        else
            p->mb_keys = mbprc_keygen(&p->mb, &stream);

        csprg_randomness_free(&stream);

        if (p->zb_keys == NULL && p->mb_keys == NULL) {
            fprintf(stderr, "key generation failed (check the parameters)\n");
            return -1;
        }
    }

    if (p->lift != NULL) {
        if (keys->have_anamorphic && p->mb_keys != NULL) {
            stream = demo_key_stream(keys->anamorphic, DEMO_DOMAIN_ANAMORPHIC);
            p->lift_keys = mbprc_akeygen(&p->mb, p->lift, p->mb_keys, &stream);
            csprg_randomness_free(&stream);

            if (p->lift_keys == NULL) {
                fprintf(stderr, "anamorphic key generation failed (check the parameters)\n");
                return -1;
            }
        }

        return 0;
    }

    if (!has_rr(p))
        return 0;

    if (p->seed_bits == 0 || p->seed_bits % 8 != 0 || p->amessage_bytes == 0) {
        fprintf(stderr, "invalid anamorphic parameters: the seed length (%zu bits) must be a "
                "positive multiple of 8 and amessage_bytes positive\n", p->seed_bits);
        return -1;
    }

    if (p->zerobit) {
        const aZBPRC_RR_Params ap = {.seed_len = p->seed_bits,
                                     .indication_len = p->indication_len,
                                     .mu = mu_of(p),
                                     .message_bytes = p->amessage_bytes,
                                     .prc_rr = p->zb_rr};
        memcpy(&p->zb_ap, &ap, sizeof(ap));
        p->zb_aprc = aZBPRC_RR_init(&p->zb_ap);
    } else {
        const aMBPRC_RR_Params ap = {.seed_len = p->seed_bits,
                                     .indication_len = p->indication_len,
                                     .mu = mu_of(p),
                                     .message_bytes = p->amessage_bytes,
                                     .prc_rr = p->mb_rr};
        memcpy(&p->mb_ap, &ap, sizeof(ap));
        p->mb_aprc = aMBPRC_RR_init(&p->mb_ap);
    }

    if (keys->have_anamorphic) {
        stream = demo_key_stream(keys->anamorphic, DEMO_DOMAIN_ANAMORPHIC);

        p->akeys = p->zerobit ? p->zb_aprc.akeygen(&p->zb_ap, &stream)
                              : p->mb_aprc.akeygen(&p->mb_ap, &stream);

        csprg_randomness_free(&stream);

        if (p->akeys == NULL) {
            fprintf(stderr, "anamorphic key generation failed\n");
            return -1;
        }
    }

    return 0;
}

void demo_prc_close(void *handle)
{
    DemoPrc *p = handle;

    if (p == NULL)
        return;

    if (p->lift_keys != NULL) {
        mbprc_free_aenc_key(&p->mb, p->lift, p->lift_keys->enc);
        mbprc_free_adec_key(&p->mb, p->lift, p->lift_keys->dec);
        free(p->lift_keys);
    }

    if (p->akeys != NULL) {
        if (p->zerobit)
            p->zb_aprc.free_akey(&p->zb_ap, p->akeys);
        else
            p->mb_aprc.free_akey(p->mb.params, &p->mb_ap, p->akeys);
    }

    if (p->zb_keys != NULL)
        zbprc_free_keys(&p->zb, p->zb_keys);
    if (p->mb_keys != NULL)
        mbprc_free_keys(&p->mb, p->mb_keys);

    free(p->storage);
    free(p);
}

/* ------------------------------------------------------------------------
 * Regular messages
 * ------------------------------------------------------------------------ */

static size_t message_bytes(const DemoPrc *p)
{
    return (p->message_bits + 7) / 8;
}

/* messages of fewer than 8 bits are written as a number ("0", "1") */
static int parse_message(const DemoPrc *p, const char *text, uint8_t *buf)
{
    if (p->message_bits < 8) {
        buf[0] = text != NULL ? (uint8_t)(strtoul(text, NULL, 10) & ((1u << p->message_bits) - 1)) : 0;
        return 0;
    }

    return demo_pad_message(text, buf, message_bytes(p));
}

static void print_message(const DemoPrc *p, const char *label, const uint8_t *buf)
{
    if (p->message_bits < 8)
        printf("%s: %u\n", label, buf[0] & ((1u << p->message_bits) - 1));
    else
        demo_print_bytes(label, buf, message_bytes(p));
}

/* ------------------------------------------------------------------------
 * Encoding / decoding
 * ------------------------------------------------------------------------ */

static int single_codeword(DemoCiphertext *out, uint8_t *codeword, size_t bits)
{
    int rc = -1;

    if (codeword != NULL && demo_ct_alloc(out, 1, bits) == 0) {
        memcpy(out->data[0], codeword, (bits + 7) / 8);
        rc = 0;
    }

    free(codeword);

    return rc;
}

int demo_prc_encode(void *handle, const char *message, DemoCiphertext *out)
{
    DemoPrc *p = handle;
    RandomnessSource rng = linux_randomness();
    size_t bits = 0;
    uint8_t *c;

    if (p->zerobit) {
        c = zbprc_encode(&p->zb, p->zb_keys->enc, &rng, &bits);
    } else {
        uint8_t msg[DECODED_MESSAGE_CAPACITY];

        if (message_bytes(p) > sizeof(msg) || parse_message(p, message, msg) != 0)
            return -1;

        c = mbprc_encode(&p->mb, p->mb_keys->enc, msg, p->message_bits, &rng, &bits);
    }

    if (single_codeword(out, c, bits) != 0) {
        fprintf(stderr, "encoding failed\n");
        return -1;
    }

    return 0;
}

int demo_prc_decode(void *handle, const DemoCiphertext *in)
{
    DemoPrc *p = handle;
    int failed = 0;

    for (size_t i = 0; i < in->count; ++i) {
        char label[32];

        snprintf(label, sizeof(label), "codeword %zu", i);

        if (p->zerobit) {
            int accepted = zbprc_decode(&p->zb, p->zb_keys->dec, in->data[i], in->bits) == 1;

            printf("%s: %s\n", label, accepted ? "accepted" : "rejected");
            failed |= !accepted;
        } else {
            uint8_t out[DECODED_MESSAGE_CAPACITY] = {0};
            size_t out_bits = 0;

            if (mbprc_decode(&p->mb, p->mb_keys->dec, in->data[i], in->bits, out, &out_bits) != 1) {
                printf("%s: rejected\n", label);
                failed = 1;
            } else {
                print_message(p, label, out);
            }
        }
    }

    return failed ? -1 : 0;
}

/* anamorphic message of the lifting construction: a string of 0/1 characters */
static int parse_bits(const char *text, uint8_t *bits, size_t count)
{
    size_t n = text != NULL ? strlen(text) : 0;

    if (n > count) {
        fprintf(stderr, "anamorphic message too long: %zu bits, at most %zu\n", n, count);
        return -1;
    }

    memset(bits, 0, (count + 7) / 8);

    for (size_t i = 0; i < n; ++i) {
        if (text[i] != '0' && text[i] != '1') {
            fprintf(stderr, "the anamorphic message must be a string of 0 and 1\n");
            return -1;
        }

        set_bit(bits, i, (uint8_t)(text[i] == '1'));
    }

    return 0;
}

static int lift_aencode(DemoPrc *p, const char *message, const char *amessage,
                        DemoCiphertext *out)
{
    RandomnessSource rng = linux_randomness();
    const size_t gamma = mbprc_amessage_bits(&p->mb, p->lift);
    uint8_t *amsg = calloc((gamma + 7) / 8, 1);
    uint8_t msg[DECODED_MESSAGE_CAPACITY];
    size_t bits = 0;
    uint8_t *c = NULL;

    if (amsg != NULL && message_bytes(p) <= sizeof(msg) &&
        parse_bits(amessage, amsg, gamma) == 0 && parse_message(p, message, msg) == 0)
        c = mbprc_aencode(&p->mb, p->lift, p->mb_keys->enc, p->lift_keys->enc, msg,
                          p->message_bits, amsg, &rng, &bits);

    free(amsg);

    if (c == NULL) {
        fprintf(stderr, "anamorphic encoding failed (the message must contain a 1)\n");
        return -1;
    }

    return single_codeword(out, c, bits);
}

static int lift_adecode(DemoPrc *p, const DemoCiphertext *in)
{
    const size_t gamma = mbprc_amessage_bits(&p->mb, p->lift);
    uint8_t *amsg = calloc((gamma + 7) / 8, 1);
    int failed = amsg == NULL;

    for (size_t i = 0; !failed && i < in->count; ++i) {
        if (mbprc_adecode(&p->mb, p->lift, p->mb_keys->dec, p->lift_keys->dec,
                          in->data[i], in->bits, amsg) == 1) {
            printf("codeword %zu: anamorphic message ", i);
            for (size_t b = 0; b < gamma; ++b)
                putchar('0' + get_bit(amsg, b));
            putchar('\n');
        } else {
            printf("codeword %zu: no anamorphic message\n", i);
            failed = 1;
        }
    }

    free(amsg);

    return failed ? -1 : 0;
}

int demo_prc_aencode(void *handle, const char *message, const char *amessage,
                     DemoCiphertext *out)
{
    DemoPrc *p = handle;

    if (p->lift != NULL)
        return lift_aencode(p, message, amessage, out);
    RandomnessSource rng = linux_randomness();
    const size_t mu = mu_of(p);
    uint8_t *amsg = calloc(p->amessage_bytes, 1);
    uint8_t **codewords = NULL;
    size_t bits = 0;
    int rc = -1;

    if (amsg == NULL || demo_pad_message(amessage, amsg, p->amessage_bytes) != 0)
        goto done;

    if (p->zerobit) {
        codewords = p->zb_aprc.aencode(&p->zb_ap, p->zb_keys->enc, p->akeys, amsg, &rng, &bits);
    } else {
        /* mu regular messages "m1;m2;...", the last one is repeated */
        const size_t mbytes = message_bytes(p);
        uint8_t *regs = calloc(mu, mbytes);
        const uint8_t **ptrs = calloc(mu, sizeof(*ptrs));
        char *copy = strdup(message != NULL ? message : "");
        char *cursor = copy, *piece = copy;
        int parsed = regs && ptrs && copy;

        for (size_t i = 0; parsed && i < mu; ++i) {
            char *sep = cursor != NULL ? strchr(cursor, ';') : NULL;

            if (cursor != NULL) {
                piece = cursor;
                if (sep != NULL) *sep = '\0';
                cursor = sep != NULL ? sep + 1 : NULL;
            }

            parsed = parse_message(p, piece, regs + i * mbytes) == 0;
            ptrs[i] = regs + i * mbytes;
        }

        if (parsed)
            codewords = p->mb_aprc.aencode(&p->mb_ap, p->mb_keys->enc, p->akeys, ptrs,
                                           p->message_bits, amsg, &rng, &bits);
        free(regs);
        free(ptrs);
        free(copy);
    }

    if (codewords == NULL) {
        fprintf(stderr, "anamorphic encoding failed\n");
        goto done;
    }

    if (demo_ct_alloc(out, mu, bits) == 0) {
        for (size_t i = 0; i < mu; ++i)
            memcpy(out->data[i], codewords[i], (bits + 7) / 8);
        rc = 0;
    }

    rr_free_codewords(codewords, mu);

done:
    free(amsg);
    return rc;
}

int demo_prc_adecode(void *handle, const DemoCiphertext *in)
{
    DemoPrc *p = handle;

    if (p->lift != NULL)
        return lift_adecode(p, in);

    uint8_t *amsg = calloc(p->amessage_bytes, 1);
    int ok;

    if (in->count != mu_of(p)) {
        fprintf(stderr, "expected %zu codewords, the file has %zu\n", mu_of(p), in->count);
        free(amsg);
        return -1;
    }

    if (amsg == NULL)
        return -1;

    if (p->zerobit) {
        ok = p->zb_aprc.adecode(&p->zb_ap, p->zb_keys->dec, p->akeys,
                                (const uint8_t *const *)in->data, in->bits, amsg);
    } else {
        ok = p->mb_aprc.adecode(&p->mb_ap, p->mb_keys->dec, p->akeys,
                                (const uint8_t *const *)in->data, in->bits, amsg,
                                p->message_bits);
    }

    if (ok)
        demo_print_bytes("anamorphic message", amsg, p->amessage_bytes);
    else
        printf("no anamorphic message\n");

    free(amsg);

    return ok ? 0 : -1;
}
