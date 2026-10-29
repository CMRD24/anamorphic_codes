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
 * The admissible choice of the thesis with n^epsilon = 2^12: r = r' = 64,
 * kappa = 4096, g = 4160, t = floor(log2(n) / 4) = 3 (the demos of the nested PRCs
 * use the same instance).
 */
static LDPCParams ldpc_params;
static A_LDPCParams ldpc_aparams;

#define LDPC_N 16384
#define LDPC_EPSILON (6.0 / 7.0)
#define LDPC_DELTA 0.25
#define LDPC_ETA 0.005

#define TRIALS 20
#define BSC_P 0.003

/* ------------------------------------------------------------------ */
/* parameters                                                          */
/* ------------------------------------------------------------------ */

static void test_ldpc_admissible_choice(void)
{
    LDPCParams params;
    A_LDPCParams aparams;

    /* the defaults of the LDPC demo: n = 2^16, epsilon = 3/4 */
    CHECK(ldpc_admissible_choice(65536, 0.75, 0.25, 0.005, &params, &aparams) == 0);
    CHECK(params.n == 65536 && params.r == 64 && params.g == 4160 && params.t == 4);
    CHECK(aparams.r_prime == 64 && params.g - aparams.r_prime == 4096);
    CHECK(ldpc_check_requirements(&params, &aparams, 0.75) == 0);

    CHECK(ldpc_params.r == 64 && ldpc_params.g == 4160 && ldpc_params.t == 3);
    CHECK(ldpc_check_requirements(&ldpc_params, &ldpc_aparams, LDPC_EPSILON) == 0);

    /* r = 14: the decoding threshold is negative */
    CHECK(ldpc_admissible_choice(1024, 0.75, 0.25, 0.005, &params, &aparams) == 0);
    CHECK(ldpc_check_requirements(&params, &aparams, 0.75) != 0);

    /* (R4): g + r = 1015 > n - log2(n)^2 */
    CHECK(ldpc_admissible_choice(1024, 0.99, 0.25, 0.005, &params, &aparams) == 0);
    CHECK(ldpc_check_requirements(&params, &aparams, 0.99) != 0);

    /* (R3): r' >= g */
    aparams = ldpc_aparams;
    aparams.r_prime = ldpc_params.g;
    CHECK(ldpc_check_requirements(&ldpc_params, &aparams, LDPC_EPSILON) != 0);

    /* out of range */
    CHECK(ldpc_admissible_choice(65536, 1.0, 0.25, 0.005, &params, &aparams) != 0);
    CHECK(ldpc_admissible_choice(65536, 0.75, 0.25, 0.5, &params, &aparams) != 0);
}

/* ------------------------------------------------------------------ */
/* regular zero-bit PRCs                                               */
/* ------------------------------------------------------------------ */

static void zb_regular_suite(const ZBPRC *prc, double p, int expect_noise_ok)
{
    ZBPRC_Keys *keys = zbprc_keygen(prc, &rng);
    CHECK(keys != NULL);
    if (keys == NULL) return;

    size_t n = zbprc_block_length(prc);
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

        uint8_t *random_string = test_random_bits(bits, &rng);
        random_accepted += zbprc_decode(prc, keys->dec, random_string, bits) == 1;
        free(random_string);
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
    PPParams params = {.ecc = &ecc, .seed_bytes = 8, .q = 2, .symbol_bits = 1,
                       .n = 16 * 8, .delta = 0.0};
    ZBPRC_RR rr = prc_pp_rr(&params);
    zb_regular_suite(&rr.base, 0, 0);
}

static void test_pp_seed_recovery(void)
{
    ECC ecc = hamming74_ecc();
    PPParams params = {.ecc = &ecc, .seed_bytes = 8, .q = 2, .symbol_bits = 1,
                       .n = 16 * 8, .delta = 0.0};
    ZBPRC_RR rr = prc_pp_rr(&params);
    ZBPRC_Keys *keys = zbprc_keygen(&rr.base, &rng);
    CHECK(keys != NULL);

    for (int t = 0; t < TRIALS; ++t) {
        uint8_t seed[8], recovered[8] = {0};
        rng.rng(rng.ctx, seed, sizeof seed);

        size_t bits = 0;
        uint8_t *c = rr.encode_with_seed(rr.base.params, keys->enc, &rng, &bits, seed);
        CHECK(c != NULL);
        if (c == NULL) continue;

        CHECK(rr.recover_decode(rr.base.params, keys->dec, c, bits, recovered) == 1);
        CHECK(memcmp(seed, recovered, sizeof seed) == 0);
        CHECK(zbprc_decode(&rr.base, keys->dec, c, bits) == 1);
        free(c);
    }
    zbprc_free_keys(&rr.base, keys);
}

static void test_dc_regular(void)
{
    ZBPRC underlying = prc_ldpc(&ldpc_params);
    PRCDC_Params dc_params = {.slice_bits = 15, .underlying = &underlying};
    ZBPRC prc = prc_dc(&dc_params);

    ZBPRC_Keys *keys = zbprc_keygen(&prc, &rng);
    CHECK(keys != NULL);
    if (keys == NULL) return;

    CHECK(zbprc_block_length(&prc) == 15 * ldpc_params.n);

    int accepted = 0, random_accepted = 0;
    for (int t = 0; t < 10; ++t) {
        size_t bits = 0;
        uint8_t *c = zbprc_encode(&prc, keys->enc, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) continue;
        accepted += zbprc_decode(&prc, keys->dec, c, bits) == 1;
        free(c);

        uint8_t *random_string = test_random_bits(bits, &rng);
        random_accepted += zbprc_decode(&prc, keys->dec, random_string, bits) == 1;
        free(random_string);
    }
    CHECK_MSG(accepted == 10, "accepted %d/10", accepted);
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
    AZBPRC_Keys *akeys = zbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(akeys != NULL);
    AZBPRC_Keys *other_akeys = zbprc_akeygen(&prc, &aprc, keys, &rng);
    CHECK(other_akeys != NULL);
    if (!keys || !akeys || !other_akeys) return;

    int accepted = 0, noisy_accepted = 0, regular_decoded = 0;
    int regular_accepted = 0, random_accepted = 0, other_key_accepted = 0;

    for (int t = 0; t < TRIALS; ++t) {
        size_t bits = 0;
        uint8_t *c = zbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, &rng, &bits);
        CHECK(c != NULL);
        if (c == NULL) continue;
        CHECK(bits == ldpc_params.n);

        /* noiseless and through the BSC */
        accepted += zbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits) == 1;
        /* preservation of the regular functionality */
        regular_decoded += zbprc_decode(&prc, keys->dec, c, bits) == 1;
        /* a different anamorphic key does not accept */
        other_key_accepted += zbprc_adecode(&prc, &aprc, keys->dec, other_akeys->trapdoor_key,
                                            c, bits) == 1;

        test_bsc(c, bits, BSC_P, &rng);
        noisy_accepted += zbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c,
                                        bits) == 1;
        free(c);

        /* robustness: regular codewords and random strings are not anamorphic */
        uint8_t *regular = zbprc_encode(&prc, keys->enc, &rng, &bits);
        test_bsc(regular, bits, BSC_P, &rng);
        regular_accepted += zbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key,
                                          regular, bits) == 1;
        free(regular);

        uint8_t *random_string = test_random_bits(ldpc_params.n, &rng);
        random_accepted += zbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key,
                                         random_string, ldpc_params.n) == 1;
        free(random_string);
    }

    CHECK_MSG(accepted == TRIALS, "anamorphic accepted %d/%d", accepted, TRIALS);
    CHECK_MSG(noisy_accepted >= TRIALS - 1, "anamorphic noisy accepted %d/%d", noisy_accepted,
              TRIALS);
    CHECK_MSG(regular_decoded == TRIALS, "regular decoding of anamorphic %d/%d",
              regular_decoded, TRIALS);
    CHECK_MSG(regular_accepted == 0, "regular accepted as anamorphic %d", regular_accepted);
    CHECK_MSG(random_accepted == 0, "random accepted as anamorphic %d", random_accepted);
    CHECK_MSG(other_key_accepted == 0, "wrong anamorphic key accepted %d", other_key_accepted);

    zbprc_free_akeys(&prc, &aprc, akeys);
    zbprc_free_akeys(&prc, &aprc, other_akeys);
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
        AZBPRC_Keys *akeys = zbprc_akeygen(&prc, &aprc, keys, &rng);
        CHECK(akeys != NULL);
        if (akeys == NULL) continue;

        size_t bits = 0;
        uint8_t *c = zbprc_aencode(&prc, &aprc, keys->enc, akeys->double_key, &rng, &bits);
        CHECK(c != NULL &&
              zbprc_adecode(&prc, &aprc, keys->dec, akeys->trapdoor_key, c, bits) == 1);
        free(c);

        zbprc_free_akeys(&prc, &aprc, akeys);
    }
    zbprc_free_keys(&prc, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    if (ldpc_admissible_choice(LDPC_N, LDPC_EPSILON, LDPC_DELTA, LDPC_ETA, &ldpc_params,
                               &ldpc_aparams) != 0)
        return 1;

    RUN(test_ldpc_admissible_choice);
    RUN(test_ldpc_regular);
    RUN(test_pp_regular);
    RUN(test_pp_seed_recovery);
    RUN(test_dc_regular);
    RUN(test_ldpc_anamorphic);
    RUN(test_ldpc_akeygen_repeated);

    return test_summary("prc_zerobit");
}
