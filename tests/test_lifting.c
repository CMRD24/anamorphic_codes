/*
 * Anamorphic lifting: PRC^1_adapt and PRC^ell_low on top of the anamorphic
 * LDPC zero-bit PRC.
 */
#include "test_common.h"
#include "../prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "../prcs/multibit/implementations/prc1_adapt.h"
#include "../prcs/multibit/implementations/prc_low.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../utils/helpers.h"

#include <sodium.h>

static RandomnessSource rng;

/* g must be large enough for the anamorphic decoding threshold of the LDPC PRC */
static const LDPCParams ldpc_params = {
    .n = 1024, .r = 256, .g = 512, .t = 10, .eta = 0.01};

#define BSC_P 0.003

typedef struct {
    ZBPRC zb;
    A_LDPCParams ldpc_aparams;
    aZBPRC azb;
} Underlying;

static void underlying_init(Underlying *u)
{
    u->zb = prc_ldpc(&ldpc_params);
    u->ldpc_aparams.g_prime = 0;
    u->azb = aprc_ldpc(&u->ldpc_aparams);
}

static int is_zero(const uint8_t *bits, size_t n)
{
    for (size_t i = 0; i < n; ++i) {
        if (get_bit(bits, i))
            return 0;
    }
    return 1;
}

/* ---------------------------------------------------------------------- */

static void test_adapt(void)
{
    Underlying u;
    underlying_init(&u);

    PRC1AdaptParams params = {.underlying_prc = &u.zb};
    APRC1AdaptParams aparams = {.underlying_aprc = &u.azb};
    MBPRC prc = prc1_adapt(&params);
    aMBPRC aprc = aprc1_adapt(&aparams);

    CHECK(mbprc_amessage_bits(&prc, &aprc) == 1);

    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    AMBPRC_Keys *ak = mbprc_akeygen(&prc, &aprc, keys, &rng);
    AMBPRC_Keys *other = mbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(keys && ak && other);
    if (!keys || !ak || !other)
        return;

    int adec = 0, adec_noisy = 0, regdec = 0;
    int regular_flagged = 0, random_flagged = 0, wrong_key = 0;

    for (int t = 0; t < 12; ++t) {
        const uint8_t m = (uint8_t)(t & 1), one = 1;
        uint8_t out[8] = {0}, aout[8] = {0};
        size_t bits = 0, out_bits = 0;

        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, ak->enc, &m, 1, &one, &rng, &bits);
        CHECK(c != NULL);
        if (!c)
            continue;

        /* anamorphic and regular decoding of the same codeword */
        adec += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1 && aout[0] == 1;
        regdec += mbprc_decode(&prc, keys->dec, c, bits, out, &out_bits) == 1 &&
                  out_bits == 1 && (out[0] & 1) == m;
        wrong_key += mbprc_adecode(&prc, &aprc, keys->dec, other->dec, c, bits, aout) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        adec_noisy += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        free(c);

        /* robustness */
        c = mbprc_encode(&prc, keys->enc, &m, 1, &rng, &bits);
        test_bsc(c, bits, BSC_P, &rng);
        regular_flagged += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        free(c);

        c = test_random_bits(bits, &rng);
        random_flagged += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        free(c);
    }

    CHECK_MSG(adec == 12, "anamorphic decoding %d/12", adec);
    CHECK_MSG(adec_noisy >= 11, "anamorphic decoding after noise %d/12", adec_noisy);
    CHECK_MSG(regdec == 12, "regular decoding of anamorphic codewords %d/12", regdec);
    CHECK_MSG(regular_flagged == 0, "regular codewords flagged anamorphic: %d", regular_flagged);
    CHECK_MSG(random_flagged == 0, "random strings flagged anamorphic: %d", random_flagged);
    CHECK_MSG(wrong_key == 0, "wrong anamorphic key accepted: %d", wrong_key);

    /* the only anamorphic message is 1 */
    {
        const uint8_t m = 0, zero = 0;
        size_t bits;
        CHECK(mbprc_aencode(&prc, &aprc, keys->enc, ak->enc, &m, 1, &zero, &rng, &bits) == NULL);
    }

    mbprc_free_aenc_key(&prc, &aprc, ak->enc);
    mbprc_free_adec_key(&prc, &aprc, ak->dec);
    free(ak);
    mbprc_free_aenc_key(&prc, &aprc, other->enc);
    mbprc_free_adec_key(&prc, &aprc, other->dec);
    free(other);
    mbprc_free_keys(&prc, keys);
}

/* ---------------------------------------------------------------------- */

static void test_low(void)
{
    enum { ELL = 16 };
    Underlying u;
    underlying_init(&u);

    PRCLow_Params params = {.underlying = &u.zb, .ell = ELL};
    APRCLow_Params aparams = {.underlying_aprc = &u.azb};
    MBPRC prc = prc_low(&params);
    aMBPRC aprc = aprc_low(&aparams);

    CHECK(mbprc_amessage_bits(&prc, &aprc) == ELL + 1);

    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    AMBPRC_Keys *ak = mbprc_akeygen(&prc, &aprc, keys, &rng);
    AMBPRC_Keys *other = mbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(keys && ak && other);
    if (!keys || !ak || !other)
        return;

    int adec = 0, adec_noisy = 0, regdec = 0;
    int regular_flagged = 0, random_flagged = 0, wrong_key = 0;
    const int trials = 6;

    for (int t = 0; t < trials; ++t) {
        uint8_t m[4], am[4], out[4] = {0}, aout[4] = {0};
        size_t bits = 0, out_bits = 0;

        rng.rng(rng.ctx, m, sizeof m);
        rng.rng(rng.ctx, am, sizeof am);
        am[2] &= 1;                /* only ELL + 1 = 17 bits are used */
        am[3] = 0;
        am[0] |= 1;                /* not all zero */

        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, ak->enc, m, ELL, am, &rng, &bits);
        CHECK(c != NULL);
        if (!c)
            continue;

        /* the regular message is preserved, the anamorphic one is recovered */
        regdec += mbprc_decode(&prc, keys->dec, c, bits, out, &out_bits) == 1 &&
                  out_bits == ELL && memcmp(out, m, 2) == 0;

        memset(aout, 0, sizeof aout);
        int ok = mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        adec += ok && memcmp(aout, am, 2) == 0 && (aout[2] & 1) == (am[2] & 1);

        wrong_key += mbprc_adecode(&prc, &aprc, keys->dec, other->dec, c, bits, aout) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        memset(aout, 0, sizeof aout);
        ok = mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        adec_noisy += ok && memcmp(aout, am, 2) == 0 && (aout[2] & 1) == (am[2] & 1);
        free(c);

        /* robustness */
        c = mbprc_encode(&prc, keys->enc, m, ELL, &rng, &bits);
        test_bsc(c, bits, BSC_P, &rng);
        regular_flagged += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        free(c);

        c = test_random_bits(bits, &rng);
        random_flagged += mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1;
        free(c);
    }

    CHECK_MSG(adec == trials, "anamorphic decoding %d/%d", adec, trials);
    CHECK_MSG(adec_noisy >= trials - 1, "anamorphic decoding after noise %d/%d", adec_noisy, trials);
    CHECK_MSG(regdec == trials, "regular decoding of anamorphic codewords %d/%d", regdec, trials);
    CHECK_MSG(regular_flagged == 0, "regular codewords flagged anamorphic: %d", regular_flagged);
    CHECK_MSG(random_flagged == 0, "random strings flagged anamorphic: %d", random_flagged);
    CHECK_MSG(wrong_key == 0, "wrong anamorphic key accepted: %d", wrong_key);

    /* the all-zero anamorphic message is not allowed */
    {
        uint8_t m[4] = {0x5a, 0xa5}, zero[4] = {0};
        size_t bits;
        CHECK(is_zero(zero, ELL + 1));
        CHECK(mbprc_aencode(&prc, &aprc, keys->enc, ak->enc, m, ELL, zero, &rng, &bits) == NULL);
    }

    /* a single hidden bit in an arbitrary block */
    {
        uint8_t m[4] = {0x0f, 0xf0}, am[4] = {0}, aout[4] = {0}, out[4] = {0};
        size_t bits, out_bits;
        set_bit(am, ELL, 1);       /* the soundness block carries the message */
        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, ak->enc, m, ELL, am, &rng, &bits);
        CHECK(c != NULL);
        if (c) {
            CHECK(mbprc_adecode(&prc, &aprc, keys->dec, ak->dec, c, bits, aout) == 1);
            CHECK(get_bit(aout, ELL) == 1 && (aout[0] | aout[1]) == 0);
            CHECK(mbprc_decode(&prc, keys->dec, c, bits, out, &out_bits) == 1);
            CHECK(memcmp(out, m, 2) == 0);
            free(c);
        }
    }

    mbprc_free_aenc_key(&prc, &aprc, ak->enc);
    mbprc_free_adec_key(&prc, &aprc, ak->dec);
    free(ak);
    mbprc_free_aenc_key(&prc, &aprc, other->enc);
    mbprc_free_adec_key(&prc, &aprc, other->dec);
    free(other);
    mbprc_free_keys(&prc, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    RUN(test_adapt);
    RUN(test_low);

    return test_summary("lifting");
}
