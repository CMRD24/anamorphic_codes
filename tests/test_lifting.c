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

/* the admissible LDPC instance with n^epsilon = 2^12: r = r' = 64, g = 4160, t = 3 */
static LDPCParams ldpc_params;
static A_LDPCParams ldpc_aparams;

#define BSC_P 0.003

typedef struct {
    ZBPRC prc;
    aZBPRC aprc;
} Underlying;

static void underlying_init(Underlying *underlying)
{
    underlying->prc = prc_ldpc(&ldpc_params);
    underlying->aprc = aprc_ldpc(&ldpc_aparams);
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
    Underlying underlying;
    underlying_init(&underlying);

    PRC1AdaptParams params = {.underlying_prc = &underlying.prc};
    APRC1AdaptParams aparams = {.underlying_aprc = &underlying.aprc};
    MBPRC prc = prc1_adapt(&params);
    aMBPRC aprc = aprc1_adapt(&aparams);

    CHECK(mbprc_amessage_bits(&prc, &aprc) == 1);

    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    AMBPRC_Keys *akeys = mbprc_akeygen(&prc, &aprc, keys, &rng);
    AMBPRC_Keys *other_akeys = mbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(keys && akeys && other_akeys);
    if (!keys || !akeys || !other_akeys)
        return;

    int anamorphic_decoded = 0, noisy_anamorphic_decoded = 0, regular_decoded = 0;
    int regular_flagged = 0, random_flagged = 0, wrong_key = 0;

    for (int t = 0; t < 12; ++t) {
        const uint8_t message = (uint8_t)(t & 1), one = 1;
        uint8_t decoded[8] = {0}, adecoded[8] = {0};
        size_t bits = 0, decoded_bits = 0;

        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, &message, 1, &one, &rng, &bits);
        CHECK(c != NULL);
        if (!c)
            continue;

        /* anamorphic and regular decoding of the same codeword */
        anamorphic_decoded += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1 && adecoded[0] == 1;
        regular_decoded += mbprc_decode(&prc, keys->dec, c, bits, decoded, &decoded_bits) == 1 &&
                  decoded_bits == 1 && (decoded[0] & 1) == message;
        wrong_key += mbprc_adecode(&prc, &aprc, keys->dec, other_akeys->trapdoor_key, c, bits, adecoded) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        noisy_anamorphic_decoded += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        free(c);

        /* robustness */
        c = mbprc_encode(&prc, keys->enc, &message, 1, &rng, &bits);
        test_bsc(c, bits, BSC_P, &rng);
        regular_flagged += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        free(c);

        c = test_random_bits(bits, &rng);
        random_flagged += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        free(c);
    }

    CHECK_MSG(anamorphic_decoded == 12, "anamorphic decoding %d/12", anamorphic_decoded);
    CHECK_MSG(noisy_anamorphic_decoded >= 11, "anamorphic decoding after noise %d/12", noisy_anamorphic_decoded);
    CHECK_MSG(regular_decoded == 12, "regular decoding of anamorphic codewords %d/12", regular_decoded);
    CHECK_MSG(regular_flagged == 0, "regular codewords flagged anamorphic: %d", regular_flagged);
    CHECK_MSG(random_flagged == 0, "random strings flagged anamorphic: %d", random_flagged);
    CHECK_MSG(wrong_key == 0, "wrong anamorphic key accepted: %d", wrong_key);

    /* the only anamorphic message is 1 */
    {
        const uint8_t message = 0, zero = 0;
        size_t bits;
        CHECK(mbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, &message, 1, &zero, &rng, &bits) == NULL);
    }

    mbprc_free_akeys(&prc, &aprc, akeys);
    mbprc_free_akeys(&prc, &aprc, other_akeys);
    mbprc_free_keys(&prc, keys);
}

/* ---------------------------------------------------------------------- */

static void test_low(void)
{
    enum { ELL = 16 };
    Underlying underlying;
    underlying_init(&underlying);

    PRCLow_Params params = {.underlying = &underlying.prc, .ell = ELL};
    APRCLow_Params aparams = {.underlying_aprc = &underlying.aprc};
    MBPRC prc = prc_low(&params);
    aMBPRC aprc = aprc_low(&aparams);

    CHECK(mbprc_amessage_bits(&prc, &aprc) == ELL + 1);

    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    AMBPRC_Keys *akeys = mbprc_akeygen(&prc, &aprc, keys, &rng);
    AMBPRC_Keys *other_akeys = mbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(keys && akeys && other_akeys);
    if (!keys || !akeys || !other_akeys)
        return;

    int anamorphic_decoded = 0, noisy_anamorphic_decoded = 0, regular_decoded = 0;
    int regular_flagged = 0, random_flagged = 0, wrong_key = 0;
    const int trials = 6;

    for (int t = 0; t < trials; ++t) {
        uint8_t message[4], amessage[4], decoded[4] = {0}, adecoded[4] = {0};
        size_t bits = 0, decoded_bits = 0;

        rng.rng(rng.ctx, message, sizeof message);
        rng.rng(rng.ctx, amessage, sizeof amessage);
        amessage[2] &= 1;                /* only ELL + 1 = 17 bits are used */
        amessage[3] = 0;
        amessage[0] |= 1;                /* not all zero */

        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, message, ELL, amessage, &rng, &bits);
        CHECK(c != NULL);
        if (!c)
            continue;

        /* the regular message is preserved, the anamorphic one is recovered */
        regular_decoded += mbprc_decode(&prc, keys->dec, c, bits, decoded, &decoded_bits) == 1 &&
                  decoded_bits == ELL && memcmp(decoded, message, 2) == 0;

        memset(adecoded, 0, sizeof adecoded);
        int ok = mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        anamorphic_decoded += ok && memcmp(adecoded, amessage, 2) == 0 && (adecoded[2] & 1) == (amessage[2] & 1);

        wrong_key += mbprc_adecode(&prc, &aprc, keys->dec, other_akeys->trapdoor_key, c, bits, adecoded) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        memset(adecoded, 0, sizeof adecoded);
        ok = mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        noisy_anamorphic_decoded += ok && memcmp(adecoded, amessage, 2) == 0 && (adecoded[2] & 1) == (amessage[2] & 1);
        free(c);

        /* robustness */
        c = mbprc_encode(&prc, keys->enc, message, ELL, &rng, &bits);
        test_bsc(c, bits, BSC_P, &rng);
        regular_flagged += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        free(c);

        c = test_random_bits(bits, &rng);
        random_flagged += mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1;
        free(c);
    }

    CHECK_MSG(anamorphic_decoded == trials, "anamorphic decoding %d/%d", anamorphic_decoded, trials);
    CHECK_MSG(noisy_anamorphic_decoded >= trials - 1, "anamorphic decoding after noise %d/%d", noisy_anamorphic_decoded, trials);
    CHECK_MSG(regular_decoded == trials, "regular decoding of anamorphic codewords %d/%d", regular_decoded, trials);
    CHECK_MSG(regular_flagged == 0, "regular codewords flagged anamorphic: %d", regular_flagged);
    CHECK_MSG(random_flagged == 0, "random strings flagged anamorphic: %d", random_flagged);
    CHECK_MSG(wrong_key == 0, "wrong anamorphic key accepted: %d", wrong_key);

    /* the all-zero anamorphic message is not allowed */
    {
        uint8_t message[4] = {0x5a, 0xa5}, zero[4] = {0};
        size_t bits;
        CHECK(is_zero(zero, ELL + 1));
        CHECK(mbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, message, ELL, zero, &rng, &bits) == NULL);
    }

    /* a single hidden bit in an arbitrary block */
    {
        uint8_t message[4] = {0x0f, 0xf0}, amessage[4] = {0}, adecoded[4] = {0}, decoded[4] = {0};
        size_t bits, decoded_bits;
        set_bit(amessage, ELL, 1);       /* the soundness block carries the message */
        uint8_t *c = mbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, message, ELL, amessage, &rng, &bits);
        CHECK(c != NULL);
        if (c) {
            CHECK(mbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits, adecoded) == 1);
            CHECK(get_bit(adecoded, ELL) == 1 && (adecoded[0] | adecoded[1]) == 0);
            CHECK(mbprc_decode(&prc, keys->dec, c, bits, decoded, &decoded_bits) == 1);
            CHECK(memcmp(decoded, message, 2) == 0);
            free(c);
        }
    }

    mbprc_free_akeys(&prc, &aprc, akeys);
    mbprc_free_akeys(&prc, &aprc, other_akeys);
    mbprc_free_keys(&prc, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    if (ldpc_admissible_choice(16384, 6.0 / 7.0, 0.25, 0.005, &ldpc_params, &ldpc_aparams) != 0)
        return 1;

    RUN(test_adapt);
    RUN(test_low);

    return test_summary("lifting");
}
