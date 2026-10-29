#include "test_common.h"
#include "../prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../prcs/multibit/implementations/prc1_adapt.h"
#include "../prcs/multibit/implementations/prc_low.h"
#include "../prcs/multibit/implementations/prc_high.h"
#include "../prcs/multibit/implementations/prc_reencode.h"
#include "../utils/hamming74.h"

#include <sodium.h>

static RandomnessSource rng;

/* the admissible LDPC instance of the nested PRCs (r = 64, g = 4160, t = 3) */
static LDPCParams ldpc_params;

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

    const size_t message_bytes = (message_bits + 7) / 8;
    int recovered = 0, other_key_accepted = 0, random_accepted = 0;

    for (int t = 0; t < trials; ++t) {
        uint8_t *message = test_random_bits(message_bits, &rng);
        size_t bits = 0;
        uint8_t *c = mbprc_encode(prc, keys->enc, message, message_bits, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) { free(message); continue; }
        CHECK(bits == mbprc_block_length(prc));

        uint8_t *noisy = test_copy(c, (bits + 7) / 8);
        if (p > 0) test_bsc(noisy, bits, p, &rng);

        uint8_t decoded[512] = {0};
        size_t decoded_bits = 0;
        recovered += mbprc_decode(prc, keys->dec, noisy, bits, decoded, &decoded_bits) == 1 &&
                     decoded_bits == message_bits &&
                     memcmp(decoded, message, message_bytes) == 0;

        other_key_accepted += mbprc_decode(prc, other->dec, c, bits, decoded,
                                           &decoded_bits) == 1;

        uint8_t *random_string = test_random_bits(bits, &rng);
        random_accepted += mbprc_decode(prc, keys->dec, random_string, bits, decoded,
                                        &decoded_bits) == 1;

        free(random_string); free(noisy); free(c); free(message);
    }

    /* over a noisy channel a rare unlucky key/noise combination may fail once */
    CHECK_MSG(recovered >= (p > 0 ? trials - 1 : trials), "recovered %d/%d", recovered, trials);
    CHECK_MSG(other_key_accepted == 0, "wrong key accepted %d", other_key_accepted);
    CHECK_MSG(random_accepted == 0, "random accepted %d", random_accepted);

    mbprc_free_keys(prc, other);
    mbprc_free_keys(prc, keys);
}

static void test_adapt1(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRC1AdaptParams adapt_params = {.underlying_prc = &underlying};
    MBPRC prc = prc1_adapt(&adapt_params);

    /* both message values */
    MBPRC_Keys *keys = mbprc_keygen(&prc, &rng);
    CHECK(keys != NULL);
    for (int b = 0; b < 2; ++b) {
        for (int t = 0; t < 5; ++t) {
            uint8_t message = (uint8_t)b, decoded[8] = {0};
            size_t bits = 0, decoded_bits = 0;
            uint8_t *c = mbprc_encode(&prc, keys->enc, &message, 1, &rng, &bits);
            CHECK(c != NULL);
            test_bsc(c, bits, BSC_P, &rng);
            CHECK(mbprc_decode(&prc, keys->dec, c, bits, decoded, &decoded_bits) == 1);
            CHECK(decoded_bits == 1 && (decoded[0] & 1) == b);
            free(c);
        }
    }
    mbprc_free_keys(&prc, keys);
}

static void test_low(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 40};
    MBPRC prc = prc_low(&low_params);
    mb_suite(&prc, 40, 5, BSC_P);
}

static void test_high(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 64};
    MBPRC low = prc_low(&low_params);
    ECC ecc = hamming74_ecc();
    PRCHigh_Params high_params = {.inner = &low, .ecc = &ecc, .lambda = 64, .message_bits = 64};
    MBPRC prc = prc_high(&high_params);
    mb_suite(&prc, 64, 5, 0.0005); /* Hamming(7,4) only corrects one error per block */
}

/* the inner PRC encodes r || m || R2: 16 + 32 + 16 bits */
static void test_sharp(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 64};
    MBPRC low = prc_low(&low_params);
    PRCReencode_Params params = {.inner = &low, .lambda = 16, .delta = 0.05};
    MBPRC prc = prc_sharp(&params);
    mb_suite(&prc, 32, 5, BSC_P);
}

static void test_cca(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 64};
    MBPRC low = prc_low(&low_params);
    PRCReencode_Params params = {.inner = &low, .lambda = 16, .delta = 0.05};
    MBPRC_RR rr = prc_cca_rr(&params);
    mb_suite(&rr.base, 32, 5, BSC_P);
}

/* RecDecode returns the seed r chosen by Encode, also through the BSC */
static void reencode_seed_recovery(MBPRC_RR (*make_rr)(const PRCReencode_Params *))
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 64};
    MBPRC low = prc_low(&low_params);
    PRCReencode_Params params = {.inner = &low, .lambda = 16, .delta = 0.05};
    MBPRC_RR rr = make_rr(&params);
    MBPRC_Keys *keys = mbprc_keygen(&rr.base, &rng);
    CHECK(keys != NULL);

    for (int t = 0; t < 5; ++t) {
        uint8_t seed[2], recovered[2] = {0}, message[4], decoded[64] = {0};
        rng.rng(rng.ctx, seed, sizeof seed);
        rng.rng(rng.ctx, message, sizeof message);

        size_t bits = 0, decoded_bits = 0;
        uint8_t *c = rr.encode_with_seed(rr.base.params, keys->enc, message, 32, &rng, &bits,
                                         seed);
        CHECK(c != NULL);
        if (c == NULL) continue;
        test_bsc(c, bits, BSC_P, &rng);

        CHECK(rr.recover_decode(rr.base.params, keys->dec, c, bits, decoded, &decoded_bits,
                                recovered) == 1);
        CHECK(decoded_bits == 32 && memcmp(decoded, message, 4) == 0);
        CHECK(memcmp(seed, recovered, 2) == 0);
        free(c);
    }
    mbprc_free_keys(&rr.base, keys);
}

static void test_sharp_seed_recovery(void)
{
    reencode_seed_recovery(prc_sharp_rr);
}

static void test_cca_seed_recovery(void)
{
    reencode_seed_recovery(prc_cca_rr);
}

/* all coins are derived from (sk, r, m): Encode with a fixed seed is deterministic */
static void test_reencode_deterministic(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCLow_Params low_params = {.underlying = &underlying, .ell = 64};
    MBPRC low = prc_low(&low_params);
    PRCReencode_Params params = {.inner = &low, .lambda = 16, .delta = 0.05};
    MBPRC_RR rr = prc_sharp_rr(&params);
    MBPRC_Keys *keys = mbprc_keygen(&rr.base, &rng);
    uint8_t seed[2] = {1, 2}, message[4] = {3, 4, 5, 6};
    size_t bits = 0;

    uint8_t *c1 = rr.encode_with_seed(rr.base.params, keys->enc, message, 32, &rng, &bits, seed);
    uint8_t *c2 = rr.encode_with_seed(rr.base.params, keys->enc, message, 32, &rng, &bits, seed);
    CHECK(c1 != NULL && c2 != NULL && memcmp(c1, c2, (bits + 7) / 8) == 0);
    free(c1);
    free(c2);
    mbprc_free_keys(&rr.base, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    if (ldpc_admissible_choice(16384, 6.0 / 7.0, 0.25, 0.005, &ldpc_params, NULL) != 0 ||
        ldpc_check_requirements(&ldpc_params, NULL, 6.0 / 7.0) != 0)
        return 1;

    RUN(test_adapt1);
    RUN(test_low);
    RUN(test_high);
    RUN(test_sharp);
    RUN(test_cca);
    RUN(test_sharp_seed_recovery);
    RUN(test_cca_seed_recovery);
    RUN(test_reencode_deterministic);

    return test_summary("prc_multibit");
}
