#include "test_common.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../prcs/zerobit/implementations/prc_pp.h"
#include "../prcs/zerobit/implementations/prc_dc.h"
#include "../prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "../utils/hamming74.h"
#include "../utils/none_ecc.h"

#include <sodium.h>

static RandomnessSource rng;

/*
 * r' = g/2 parity checks decide anamorphic acceptance, so g must be large
 * enough for the threshold (1/2 - r'^(-1/4)) r' to separate the noise.
 */
static const LDPCParams ldpc_params = {
    .n = 1024, .r = 256, .g = 512, .t = 10, .eta = 0.01};

static const A_LDPCParams ldpc_aparams = {.g_prime = 174};

#define TRIALS 20
#define BSC_P 0.003

/* ------------------------------------------------------------------ */
/* regular zero-bit PRCs                                               */
/* ------------------------------------------------------------------ */

static void zb_regular_suite(const ZBPRC *prc, double p, int expect_noise_ok)
{
    ZBPRC_Keys *keys = zbprc_keygen(prc, &rng);
    CHECK(keys != NULL);
    if (keys == NULL) return;

    size_t n = zbprc_blocksize(prc);
    CHECK(n > 0);

    int accepted = 0, noisy_accepted = 0, random_accepted = 0;

    for (int t = 0; t < TRIALS; ++t) {
        size_t bits = 0;
        uint8_t *c = zbprc_encode(prc, keys->enc, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) continue;
        CHECK(bits == n);

        accepted += zbprc_decode(prc, keys->dec, c, bits) == 1;

        if (expect_noise_ok) {
            test_bsc(c, bits, p, &rng);
            noisy_accepted += zbprc_decode(prc, keys->dec, c, bits) == 1;
        }
        free(c);

        uint8_t *r = test_random_bits(bits, &rng);
        random_accepted += zbprc_decode(prc, keys->dec, r, bits) == 1;
        free(r);
    }

    CHECK_MSG(accepted == TRIALS, "accepted %d/%d codewords", accepted, TRIALS);
    if (expect_noise_ok)
        CHECK_MSG(noisy_accepted >= TRIALS - 1, "noisy accepted %d/%d",
                  noisy_accepted, TRIALS);
    CHECK_MSG(random_accepted == 0, "random accepted %d", random_accepted);

    /* a second key must reject codewords of the first (soundness w.r.t. key) */
    ZBPRC_Keys *other = zbprc_keygen(prc, &rng);
    size_t bits = 0;
    uint8_t *c = zbprc_encode(prc, keys->enc, &rng, &bits);
    CHECK(zbprc_decode(prc, other->dec, c, bits) == 0);
    free(c);

    zbprc_free_keys(prc, other);
    zbprc_free_keys(prc, keys);
}

static void test_ldpc_regular(void)
{
    ZBPRC prc = prc_ldpc(&ldpc_params);
    zb_regular_suite(&prc, BSC_P, 1);
}

static void test_pp_regular(void)
{
    ECC ecc = hamming74_ecc();
    PPParams params = {.delta = 0.0, .ecc = &ecc, .n = 16 * 8, .q = 2,
                       .message_bytes = 8, .symbol_bits = 1};
    ZBPRC_RR rr = prc_pp_rr(&params);
    zb_regular_suite(&rr.base, 0, 0);
}

static void test_pp_seed_recovery(void)
{
    ECC ecc = hamming74_ecc();
    PPParams params = {.delta = 0.0, .ecc = &ecc, .n = 16 * 8, .q = 2,
                       .message_bytes = 8, .symbol_bits = 1};
    ZBPRC_RR rr = prc_pp_rr(&params);
    ZBPRC_Keys *keys = zbprc_keygen(&rr.base, &rng);
    CHECK(keys != NULL);

    for (int t = 0; t < TRIALS; ++t) {
        uint8_t seed[8], back[8] = {0};
        rng.rng(rng.ctx, seed, sizeof seed);

        size_t bits = 0;
        uint8_t *c = rr.encode_ws(rr.base.params, keys->enc, &rng, &bits, seed);
        CHECK(c != NULL);
        if (c == NULL) continue;

        CHECK(rr.decode_ws(rr.base.params, keys->dec, c, bits, back) == 1);
        CHECK(memcmp(seed, back, sizeof seed) == 0);
        CHECK(zbprc_decode(&rr.base, keys->dec, c, bits) == 1);
        free(c);
    }
    zbprc_free_keys(&rr.base, keys);
}

static void test_dc_regular(void)
{
    static const LDPCParams dc_ldpc = {.n = 128, .r = 64, .g = 32, .t = 4, .eta = 0.01};
    ZBPRC underlying = prc_ldpc(&dc_ldpc);
    PRCDC_Params dcp = {.k = dc_ldpc.n, .T = 211, .underlying = &underlying};
    ZBPRC prc = prc_dc(&dcp);

    ZBPRC_Keys *keys = zbprc_keygen(&prc, &rng);
    CHECK(keys != NULL);
    if (keys == NULL) return;

    int accepted = 0, random_accepted = 0;
    for (int t = 0; t < 10; ++t) {
        size_t bits = 0;
        uint8_t *c = zbprc_encode(&prc, keys->enc, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) continue;
        accepted += zbprc_decode(&prc, keys->dec, c, bits) == 1;
        free(c);

        uint8_t *r = test_random_bits(bits, &rng);
        random_accepted += zbprc_decode(&prc, keys->dec, r, bits) == 1;
        free(r);
    }
    /* the tiny underlying LDPC parameters reject about 2% of the codewords */
    CHECK_MSG(accepted >= 8, "accepted %d/10", accepted);
    CHECK(random_accepted == 0);
    zbprc_free_keys(&prc, keys);
}

/* ------------------------------------------------------------------ */
/* anamorphic LDPC (second parity-check matrix P')                     */
/* ------------------------------------------------------------------ */

static void test_ldpc_anamorphic(void)
{
    ZBPRC prc = prc_ldpc(&ldpc_params);
    aZBPRC aprc = aprc_ldpc(&ldpc_aparams);

    ZBPRC_Keys *keys = zbprc_keygen(&prc, &rng);
    CHECK(keys != NULL);
    APRC_Keys *ak = zbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(ak != NULL);
    APRC_Keys *ak2 = zbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(ak2 != NULL);
    if (!keys || !ak || !ak2) return;

    int a_acc = 0, a_noisy = 0, a_regdec = 0;
    int reg_in_adec = 0, rand_in_adec = 0, wrongkey_adec = 0;

    for (int t = 0; t < TRIALS; ++t) {
        size_t bits = 0;
        uint8_t *c = zbprc_aencode(&prc, &aprc, keys->enc, ak->enc, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) continue;
        CHECK(bits == ldpc_params.n);

        /* noiseless and through the BSC */
        a_acc += zbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits) == 1;
        /* preservation of the regular functionality */
        a_regdec += zbprc_decode(&prc, keys->dec, c, bits) == 1;
        /* a different anamorphic key does not accept */
        wrongkey_adec += zbprc_adecode(&prc, &aprc, keys->dec, ak2->dec, c, bits) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        a_noisy += zbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits) == 1;
        free(c);

        /* robustness: regular codewords and random strings are not anamorphic */
        uint8_t *rc = zbprc_encode(&prc, keys->enc, &rng, &bits);
        test_bsc(rc, bits, BSC_P, &rng);
        reg_in_adec += zbprc_adecode(&prc, &aprc, keys->dec, ak->dec, rc, bits) == 1;
        free(rc);

        uint8_t *r = test_random_bits(ldpc_params.n, &rng);
        rand_in_adec += zbprc_adecode(&prc, &aprc, keys->dec, ak->dec, r, ldpc_params.n) == 1;
        free(r);
    }

    CHECK_MSG(a_acc == TRIALS, "anamorphic accepted %d/%d", a_acc, TRIALS);
    CHECK_MSG(a_noisy >= TRIALS - 1, "anamorphic noisy accepted %d/%d", a_noisy, TRIALS);
    CHECK_MSG(a_regdec == TRIALS, "regular decoding of anamorphic %d/%d", a_regdec, TRIALS);
    CHECK_MSG(reg_in_adec == 0, "regular accepted as anamorphic %d", reg_in_adec);
    CHECK_MSG(rand_in_adec == 0, "random accepted as anamorphic %d", rand_in_adec);
    CHECK_MSG(wrongkey_adec == 0, "wrong anamorphic key accepted %d", wrongkey_adec);

    zbprc_free_enc_akey(&prc, &aprc, ak->enc);
    zbprc_free_dec_akey(&prc, &aprc, ak->dec);
    free(ak);
    zbprc_free_enc_akey(&prc, &aprc, ak2->enc);
    zbprc_free_dec_akey(&prc, &aprc, ak2->dec);
    free(ak2);
    zbprc_free_keys(&prc, keys);
}

/* The rank check: akeygen must always yield B whose columns satisfy P'GB = 0,
 * which shows up as anamorphic acceptance even for many independent keys. */
static void test_ldpc_akeygen_repeated(void)
{
    ZBPRC prc = prc_ldpc(&ldpc_params);
    aZBPRC aprc = aprc_ldpc(&ldpc_aparams);
    ZBPRC_Keys *keys = zbprc_keygen(&prc, &rng);

    for (int t = 0; t < 15; ++t) {
        APRC_Keys *ak = zbprc_akeygen(&prc, &aprc, keys, &rng);
        CHECK(ak != NULL);
        if (ak == NULL) continue;

        size_t bits = 0;
        uint8_t *c = zbprc_aencode(&prc, &aprc, keys->enc, ak->enc, &rng, &bits);
        CHECK(c != NULL && zbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits) == 1);
        free(c);

        zbprc_free_enc_akey(&prc, &aprc, ak->enc);
        zbprc_free_dec_akey(&prc, &aprc, ak->dec);
        free(ak);
    }
    zbprc_free_keys(&prc, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    RUN(test_ldpc_regular);
    RUN(test_pp_regular);
    RUN(test_pp_seed_recovery);
    RUN(test_dc_regular);
    RUN(test_ldpc_anamorphic);
    RUN(test_ldpc_akeygen_repeated);

    return test_summary("prc_zerobit");
}
