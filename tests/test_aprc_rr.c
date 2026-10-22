/*
 * Anamorphic PRCs from randomness recoverability: permuted-puzzle zero-bit PRC
 * and the CCA multibit PRC.
 */
#include "test_common.h"
#include "../prcs/zerobit/implementations/prc_pp.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../prcs/multibit/implementations/prc_low.h"
#include "../prcs/multibit/implementations/prc_cca.h"
#include "../prcs/anamorphism/aprc_rr.h"
#include "../prcs/anamorphism/rr_core.h"
#include "../utils/hamming74.h"

#include <sodium.h>

static RandomnessSource rng;

static void free_codewords(uint8_t **cw, size_t n)
{
    if (cw == NULL) return;
    for (size_t i = 0; i < n; ++i) free(cw[i]);
    free(cw);
}

static void test_pp_anamorphic(void)
{
    enum { AMSG = 16 };
    ECC ecc = hamming74_ecc();
    PPParams params = {.delta = 0.0, .ecc = &ecc, .n = 16 * 8, .q = 2,
                       .message_bytes = 8, .symbol_bits = 1};
    ZBPRC_RR prc = prc_pp_rr(&params);

    /* 32 indication seeds, 3 seeds (24 bytes) hold an 8 byte nonce and the message */
    aZBPRC_RR_Params ap = {.prc_rr = &prc, .mu = 32 + 3, .message_bytes = AMSG,
                           .indication_len = 32, .seed_len = 64};
    aZBPRC_RR aprc = aZBPRC_RR_init(&ap);

    ZBPRC_Keys *keys = zbprc_keygen(&prc.base, &rng);
    APRC_RR_Keys *dk = aprc.akeygen(&ap, &rng);
    APRC_RR_Keys *dk2 = aprc.akeygen(&ap, &rng);
    CHECK(keys != NULL && dk != NULL && dk2 != NULL);
    if (!keys || !dk || !dk2) return;

    for (int t = 0; t < 5; ++t) {
        uint8_t msg[AMSG], out[AMSG] = {0};
        rng.rng(rng.ctx, msg, sizeof msg);

        size_t bits = 0;
        uint8_t **cw = aprc.aencode(&ap, keys->enc, dk, msg, &rng, &bits);
        CHECK(cw != NULL);
        if (cw == NULL) continue;

        CHECK(aprc.adecode(&ap, keys->dec, dk, (const uint8_t *const *)cw, bits, out) == 1);
        CHECK(memcmp(msg, out, AMSG) == 0);

        /* every codeword is still a valid regular codeword */
        for (size_t i = 0; i < ap.mu; ++i)
            CHECK(zbprc_decode(&prc.base, keys->dec, cw[i], bits) == 1);

        /* wrong anamorphic keys: indication bits fail or message differs */
        uint8_t out2[AMSG] = {0};
        int r = aprc.adecode(&ap, keys->dec, dk2, (const uint8_t *const *)cw, bits, out2);
        CHECK(r == 0 || memcmp(msg, out2, AMSG) != 0);

        free_codewords(cw, ap.mu);
    }

    /* regular codewords (random seeds) are not accepted as anamorphic */
    int accepted = 0;
    for (int t = 0; t < 10; ++t) {
        uint8_t **cw = calloc(ap.mu, sizeof *cw);
        size_t bits = 0;
        for (size_t i = 0; i < ap.mu; ++i)
            cw[i] = zbprc_encode(&prc.base, keys->enc, &rng, &bits);
        uint8_t out[AMSG];
        accepted += aprc.adecode(&ap, keys->dec, dk, (const uint8_t *const *)cw, bits, out) == 1;
        free_codewords(cw, ap.mu);
    }
    CHECK_MSG(accepted == 0, "regular accepted as anamorphic: %d/10", accepted);

    aprc.free_akey(&ap, dk);
    aprc.free_akey(&ap, dk2);
    zbprc_free_keys(&prc.base, keys);
}

static void test_cca_anamorphic(void)
{
    enum { MSG = 4, AMSG = 8 };
    static const LDPCParams lp = {.n = 1024, .r = 512, .g = 256, .t = 11, .eta = 0.01};
    ZBPRC under = prc_ldpc(&lp);
    PRCLow_Params low_p = {.underlying = &under, .ell = 64};
    MBPRC low = prc_low(&low_p);
    PRC_CCA_Params cp = {.prc = &low, .lambda_bits = 16, .delta = 0.05};
    MBPRC_RR prc = prc_cca_rr(&cp);

    /* 2 byte seeds: 8 seeds (16 bytes) hold an 8 byte nonce and the message */
    aMBPRC_RR_Params ap = {.prc_rr = &prc, .mu = 32 + 8, .message_bytes = AMSG,
                           .indication_len = 32, .seed_len = 16};
    aMBPRC_RR aprc = aMBPRC_RR_init(&ap);

    MBPRC_Keys *keys = mbprc_keygen(&prc.base, &rng);
    APRC_RR_Keys *dk = aprc.akeygen(&ap, &rng);
    CHECK(keys != NULL && dk != NULL);
    if (!keys || !dk) return;

    for (int t = 0; t < 2; ++t) {
        uint8_t **regs = calloc(ap.mu, sizeof *regs);
        for (size_t i = 0; i < ap.mu; ++i) {
            regs[i] = malloc(MSG);
            rng.rng(rng.ctx, regs[i], MSG);
        }
        uint8_t amsg[AMSG], out[AMSG] = {0};
        rng.rng(rng.ctx, amsg, sizeof amsg);

        size_t bits = 0;
        uint8_t **cw = aprc.aencode(&ap, keys->enc, dk, (const uint8_t **)regs,
                                    MSG * 8, amsg, &rng, &bits);
        CHECK(cw != NULL);
        if (cw != NULL) {
            CHECK(aprc.adecode(&ap, keys->dec, dk, (const uint8_t *const *)cw,
                               bits, out, MSG * 8) == 1);
            CHECK(memcmp(amsg, out, AMSG) == 0);

            /* regular messages are preserved */
            for (size_t i = 0; i < ap.mu; ++i) {
                uint8_t m[64] = {0};
                size_t mb = 0;
                CHECK(mbprc_decode(&prc.base, keys->dec, cw[i], bits, m, &mb) == 1);
                CHECK(mb == MSG * 8 && memcmp(m, regs[i], MSG) == 0);
            }
            free_codewords(cw, ap.mu);
        }
        free_codewords(regs, ap.mu);
    }

    aprc.free_akey(prc.base.params, &ap, dk);
    mbprc_free_keys(&prc.base, keys);
}

/*
 * mu = 1: no indication seeds, the ciphertext is the seed of a single codeword
 * (nonce || masked message, the nonce takes the bytes the message leaves).
 */
static void test_pp_single_codeword(void)
{
    enum { AMSG = 16 };
    ECC ecc = hamming74_ecc();
    /* 24 byte seed, Hamming(7,4) doubles it: 48 bytes = 384 symbols */
    PPParams params = {.delta = 0.0, .ecc = &ecc, .n = 384, .q = 2,
                       .message_bytes = 24, .symbol_bits = 1};
    ZBPRC_RR prc = prc_pp_rr(&params);

    CHECK(rr_min_ciphertext_seeds(192, AMSG) == 1);

    aZBPRC_RR_Params ap = {.prc_rr = &prc, .mu = 1, .message_bytes = AMSG,
                           .indication_len = 0, .seed_len = 192};
    aZBPRC_RR aprc = aZBPRC_RR_init(&ap);

    ZBPRC_Keys *keys = zbprc_keygen(&prc.base, &rng);
    APRC_RR_Keys *dk = aprc.akeygen(&ap, &rng);
    APRC_RR_Keys *dk2 = aprc.akeygen(&ap, &rng);
    CHECK(keys != NULL && dk != NULL && dk2 != NULL);
    if (!keys || !dk || !dk2) return;

    for (int t = 0; t < 10; ++t) {
        uint8_t msg[AMSG], out[AMSG] = {0}, out2[AMSG] = {0};
        rng.rng(rng.ctx, msg, sizeof msg);

        size_t bits = 0;
        uint8_t **cw = aprc.aencode(&ap, keys->enc, dk, msg, &rng, &bits);
        CHECK(cw != NULL);
        if (cw == NULL) continue;

        CHECK(aprc.adecode(&ap, keys->dec, dk, (const uint8_t *const *)cw, bits, out) == 1);
        CHECK(memcmp(msg, out, AMSG) == 0);

        /* still a regular codeword, and the wrong key reads garbage */
        CHECK(zbprc_decode(&prc.base, keys->dec, cw[0], bits) == 1);
        CHECK(aprc.adecode(&ap, keys->dec, dk2, (const uint8_t *const *)cw, bits, out2) == 1);
        CHECK(memcmp(msg, out2, AMSG) != 0);

        free_codewords(cw, 1);
    }

    /* the nonce must keep RR_MIN_NONCE_BYTES: a 24 byte seed cannot hold a 17 byte message */
    {
        aZBPRC_RR_Params bad = {.prc_rr = &prc, .mu = 1, .message_bytes = 17,
                                .indication_len = 0, .seed_len = 192};
        aZBPRC_RR abad = aZBPRC_RR_init(&bad);
        uint8_t msg[24] = {0};
        size_t bits;

        CHECK(abad.aencode(&bad, keys->enc, dk, msg, &rng, &bits) == NULL);
        CHECK(rr_min_ciphertext_seeds(192, 17) == 2);
    }

    aprc.free_akey(&ap, dk);
    aprc.free_akey(&ap, dk2);
    zbprc_free_keys(&prc.base, keys);
}

static void test_cca_single_codeword(void)
{
    enum { MSG = 4, AMSG = 8 };
    static const LDPCParams lp = {.n = 1024, .r = 512, .g = 256, .t = 11, .eta = 0.01};
    ZBPRC under = prc_ldpc(&lp);
    /* seed (128) || message (32) || mask (128) bits */
    PRCLow_Params low_p = {.underlying = &under, .ell = 288};
    MBPRC low = prc_low(&low_p);
    PRC_CCA_Params cp = {.prc = &low, .lambda_bits = 128, .delta = 0.05};
    MBPRC_RR prc = prc_cca_rr(&cp);

    /* a 16 byte seed holds an 8 byte nonce and an 8 byte message */
    aMBPRC_RR_Params ap = {.prc_rr = &prc, .mu = 1, .message_bytes = AMSG,
                           .indication_len = 0, .seed_len = 128};
    aMBPRC_RR aprc = aMBPRC_RR_init(&ap);

    MBPRC_Keys *keys = mbprc_keygen(&prc.base, &rng);
    APRC_RR_Keys *dk = aprc.akeygen(&ap, &rng);
    CHECK(keys != NULL && dk != NULL);
    if (!keys || !dk) return;

    for (int t = 0; t < 2; ++t) {
        uint8_t reg[MSG], amsg[AMSG], out[AMSG] = {0};
        const uint8_t *regs[1] = {reg};
        rng.rng(rng.ctx, reg, sizeof reg);
        rng.rng(rng.ctx, amsg, sizeof amsg);

        size_t bits = 0;
        uint8_t **cw = aprc.aencode(&ap, keys->enc, dk, regs, MSG * 8, amsg, &rng, &bits);
        CHECK(cw != NULL);
        if (cw == NULL) continue;

        CHECK(aprc.adecode(&ap, keys->dec, dk, (const uint8_t *const *)cw, bits, out, MSG * 8) == 1);
        CHECK(memcmp(amsg, out, AMSG) == 0);

        uint8_t m[64] = {0};
        size_t mb = 0;
        CHECK(mbprc_decode(&prc.base, keys->dec, cw[0], bits, m, &mb) == 1);
        CHECK(mb == MSG * 8 && memcmp(m, reg, MSG) == 0);

        free_codewords(cw, 1);
    }

    aprc.free_akey(prc.base.params, &ap, dk);
    mbprc_free_keys(&prc.base, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    RUN(test_pp_anamorphic);
    RUN(test_cca_anamorphic);
    RUN(test_pp_single_codeword);
    RUN(test_cca_single_codeword);

    return test_summary("aprc_rr");
}
