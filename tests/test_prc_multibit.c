#include "test_common.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../prcs/multibit/implementations/prc1_adapt.h"
#include "../prcs/multibit/implementations/prc_low.h"
#include "../prcs/multibit/implementations/prc_high.h"
#include "../prcs/multibit/implementations/prc_sharp.h"
#include "../prcs/multibit/implementations/prc_cca.h"
#include "../utils/hamming74.h"

#include <sodium.h>

static RandomnessSource rng;

static const LDPCParams ldpc_params = {
    .n = 1024, .r = 512, .g = 256, .t = 11, .eta = 0.01};

#define BSC_P 0.003

/*
 * Encodes random messages of message_bits bits, optionally sends them through a
 * BSC, and checks that they are recovered. Also checks that random strings and
 * codewords under another key do not decode.
 */
static void mb_suite(const MBPRC *prc, size_t message_bits, int trials, double p)
{
    MBPRC_Keys *keys = mbprc_keygen(prc, &rng);
    MBPRC_Keys *other = mbprc_keygen(prc, &rng);
    CHECK(keys != NULL && other != NULL);
    if (!keys || !other) return;

    size_t mbytes = (message_bits + 7) / 8;
    int ok = 0, wrong_key = 0, random_acc = 0;

    for (int t = 0; t < trials; ++t) {
        uint8_t *m = test_random_bits(message_bits, &rng);
        size_t bits = 0;
        uint8_t *c = mbprc_encode(prc, keys->enc, m, message_bits, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) { free(m); continue; }

        uint8_t *noisy = test_copy(c, (bits + 7) / 8);
        if (p > 0) test_bsc(noisy, bits, p, &rng);

        uint8_t out[512] = {0};
        size_t out_bits = 0;
        int rc = mbprc_decode(prc, keys->dec, noisy, bits, out, &out_bits);
        ok += rc == 1 && out_bits == message_bits &&
              memcmp(out, m, mbytes) == 0;

        uint8_t out2[512] = {0};
        size_t out2_bits = 0;
        wrong_key += mbprc_decode(prc, other->dec, c, bits, out2, &out2_bits) == 1;

        uint8_t *r = test_random_bits(bits, &rng);
        random_acc += mbprc_decode(prc, keys->dec, r, bits, out2, &out2_bits) == 1;

        free(r); free(noisy); free(c); free(m);
    }

    /* over a noisy channel a rare unlucky key/noise combination may fail once */
    CHECK_MSG(ok >= (p > 0 ? trials - 1 : trials), "recovered %d/%d", ok, trials);
    CHECK_MSG(wrong_key == 0, "wrong key accepted %d", wrong_key);
    CHECK_MSG(random_acc == 0, "random accepted %d", random_acc);

    mbprc_free_keys(prc, other);
    mbprc_free_keys(prc, keys);
}

static void test_adapt1(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRC1AdaptParams ap = {.underlying_prc = &under};
    MBPRC prc = prc1_adapt(&ap);

    /* both message values */
    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    CHECK(keys != NULL);
    for (int b = 0; b < 2; ++b) {
        for (int t = 0; t < 5; ++t) {
            uint8_t m = (uint8_t)b, out[8] = {0};
            size_t bits = 0, ob = 0;
            uint8_t *c = mbprc_encode(&prc, keys->enc, &m, 1, &rng, &bits);
            CHECK(c != NULL);
            test_bsc(c, bits, BSC_P, &rng);
            CHECK(mbprc_decode(&prc, keys->dec, c, bits, out, &ob) == 1);
            CHECK(ob == 1 && (out[0] & 1) == b);
            free(c);
        }
    }
    mbprc_free_keys(&prc, keys);
}

static void test_low(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRCLow_Params lp = {.underlying = &under, .ell = 40};
    MBPRC prc = prc_low(&lp);
    mb_suite(&prc, 40, 5, BSC_P);
}

static void test_high(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRCLow_Params lp = {.underlying = &under, .ell = 64};
    MBPRC low = prc_low(&lp);
    ECC ecc = hamming74_ecc();
    PRCHigh_Params hp = {.low_prc = &low, .lambda = 64, .ecc = &ecc, .message_bits = 64};
    MBPRC prc = prc_high(&hp);
    mb_suite(&prc, 64, 5, 0.0005); /* Hamming(7,4) only corrects one error per block */
}

static void test_sharp(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRCLow_Params lp = {.underlying = &under, .ell = 64};
    MBPRC low = prc_low(&lp);
    PRCSharp_Params sp = {.prc = &low, .lambda_bits = 16, .delta = 0.05};
    MBPRC prc = prc_sharp(&sp);
    mb_suite(&prc, 32, 5, BSC_P);
}

static void test_cca(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRCLow_Params lp = {.underlying = &under, .ell = 64};
    MBPRC low = prc_low(&lp);
    PRC_CCA_Params cp = {.prc = &low, .lambda_bits = 16, .delta = 0.05};
    MBPRC_RR rr = prc_cca_rr(&cp);
    mb_suite(&rr.base, 32, 5, BSC_P);
}

static void test_cca_seed_recovery(void)
{
    ZBPRC under = prc_ldpc(&ldpc_params);
    PRCLow_Params lp = {.underlying = &under, .ell = 64};
    MBPRC low = prc_low(&lp);
    PRC_CCA_Params cp = {.prc = &low, .lambda_bits = 16, .delta = 0.05};
    MBPRC_RR rr = prc_cca_rr(&cp);
    MBPRC_Keys *keys = mbprc_keygen(&rr.base, &rng);
    CHECK(keys != NULL);

    for (int t = 0; t < 5; ++t) {
        uint8_t seed[2], back[2] = {0}, m[4], out[64] = {0};
        rng.rng(rng.ctx, seed, sizeof seed);
        rng.rng(rng.ctx, m, sizeof m);

        size_t bits = 0, ob = 0;
        uint8_t *c = rr.encode_ws(rr.base.params, keys->enc, m, 32, &rng, &bits, seed);
        CHECK(c != NULL);
        if (c == NULL) continue;
        test_bsc(c, bits, BSC_P, &rng);

        CHECK(rr.decode_ws(rr.base.params, keys->dec, c, bits, out, &ob, back) == 1);
        CHECK(ob == 32 && memcmp(out, m, 4) == 0);
        CHECK(memcmp(seed, back, 2) == 0);
        free(c);
    }
    mbprc_free_keys(&rr.base, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    RUN(test_adapt1);
    RUN(test_low);
    RUN(test_high);
    RUN(test_sharp);
    RUN(test_cca);
    RUN(test_cca_seed_recovery);

    return test_summary("prc_multibit");
}
