/*
 * Anamorphic PRCs from randomness recoverability: permuted-puzzle zero-bit PRC
 * and the CCA multibit PRC.
 */
#include "test_common.h"
#include "../prcs/zerobit/implementations/prc_pp.h"
#include "../prcs/zerobit/implementations/prc_ldpc.h"
#include "../prcs/anamorphism/zerobit/aprc_ldpc.h"
#include "../prcs/multibit/implementations/prc_low.h"
#include "../prcs/multibit/implementations/prc_reencode.h"
#include "../prcs/anamorphism/aprc_rr.h"
#include "../utils/hamming74.h"

#include <sodium.h>

static RandomnessSource rng;

/* the admissible LDPC instance of the nested PRCs (r = 64, g = 4160, t = 3) */
static LDPCParams ldpc_params;

static void test_pp_anamorphic(void)
{
    enum { AMESSAGE_BYTES = 16 };
    ECC ecc = hamming74_ecc();
    PPParams params = {.ecc = &ecc, .seed_bytes = 8, .q = 2, .symbol_bits = 1,
                       .n = 16 * 8, .delta = 0.0};
    ZBPRC_RR prc = prc_pp_rr(&params);

    /* 32 indication seeds, 3 seeds (24 bytes) hold an 8 byte nonce and the message */
    const aZBPRC_RR aprc = {
        .shape = {.seed_bits = 64, .indication_seeds = 32, .codeword_count = 32 + 3,
                  .amessage_bytes = AMESSAGE_BYTES},
        .prc = &prc,
    };
    const size_t count = aprc.shape.codeword_count;

    ZBPRC_Keys *keys = zbprc_keygen(&prc.base, &rng);
    RR_AKeys *akeys = rr_akeygen(&rng);
    RR_AKeys *other_akeys = rr_akeygen(&rng);
    CHECK(keys != NULL && akeys != NULL && other_akeys != NULL);
    if (!keys || !akeys || !other_akeys) return;

    for (int t = 0; t < 5; ++t) {
        uint8_t amessage[AMESSAGE_BYTES], decoded[AMESSAGE_BYTES] = {0};
        rng.rng(rng.ctx, amessage, sizeof amessage);

        size_t bits = 0;
        uint8_t **codewords = azbprc_rr_aencode(&aprc, keys->enc, akeys, amessage, &rng, &bits);
        CHECK(codewords != NULL);
        if (codewords == NULL) continue;

        CHECK(azbprc_rr_adecode(&aprc, keys->dec, akeys, (const uint8_t *const *)codewords,
                                bits, decoded) == 1);
        CHECK(memcmp(amessage, decoded, AMESSAGE_BYTES) == 0);

        /* every codeword is still a valid regular codeword */
        for (size_t i = 0; i < count; ++i)
            CHECK(zbprc_decode(&prc.base, keys->dec, codewords[i], bits) == 1);

        /* wrong anamorphic keys: indication seeds fail or the message differs */
        uint8_t other_decoded[AMESSAGE_BYTES] = {0};
        const int accepted = azbprc_rr_adecode(&aprc, keys->dec, other_akeys,
                                               (const uint8_t *const *)codewords, bits,
                                               other_decoded);
        CHECK(accepted == 0 || memcmp(amessage, other_decoded, AMESSAGE_BYTES) != 0);

        rr_free_codewords(codewords, count);
    }

    /* regular codewords (random seeds) are not accepted as anamorphic */
    int accepted = 0;
    for (int t = 0; t < 10; ++t) {
        uint8_t **codewords = calloc(count, sizeof *codewords);
        size_t bits = 0;
        for (size_t i = 0; i < count; ++i)
            codewords[i] = zbprc_encode(&prc.base, keys->enc, &rng, &bits);
        uint8_t decoded[AMESSAGE_BYTES];
        accepted += azbprc_rr_adecode(&aprc, keys->dec, akeys,
                                      (const uint8_t *const *)codewords, bits, decoded) == 1;
        rr_free_codewords(codewords, count);
    }
    CHECK_MSG(accepted == 0, "regular accepted as anamorphic: %d/10", accepted);

    rr_free_akeys(akeys);
    rr_free_akeys(other_akeys);
    zbprc_free_keys(&prc.base, keys);
}

/* PRC_cca over PRC^ell_low over the LDPC PRC; the caller frees *low and the result */
typedef struct {
    ZBPRC underlying;
    PRCLow_Params low_params;
    MBPRC low;
    PRCReencode_Params params;
    MBPRC_RR prc;
} CcaInstance;

static void cca_instance_init(CcaInstance *instance, size_t lambda, size_t message_bits)
{
    instance->underlying = prc_ldpc(&ldpc_params);
    instance->low_params = (PRCLow_Params){
        .underlying = &instance->underlying,
        .ell = 2 * lambda + message_bits,
    };
    instance->low = prc_low(&instance->low_params);
    instance->params = (PRCReencode_Params){.inner = &instance->low, .lambda = lambda,
                                            .delta = 0.05};
    instance->prc = prc_cca_rr(&instance->params);
}

static void test_cca_anamorphic(void)
{
    enum { MESSAGE_BYTES = 4, AMESSAGE_BYTES = 8 };
    CcaInstance cca;

    cca_instance_init(&cca, 16, 8 * MESSAGE_BYTES);

    /* 2 byte seeds: 8 seeds (16 bytes) hold an 8 byte nonce and the message */
    const aMBPRC_RR aprc = {
        .shape = {.seed_bits = 16, .indication_seeds = 32, .codeword_count = 32 + 8,
                  .amessage_bytes = AMESSAGE_BYTES},
        .prc = &cca.prc,
    };
    const size_t count = aprc.shape.codeword_count;

    MBPRC_Keys *keys = mbprc_keygen(&cca.prc.base, &rng);
    RR_AKeys *akeys = rr_akeygen(&rng);
    CHECK(keys != NULL && akeys != NULL);
    if (!keys || !akeys) return;

    for (int t = 0; t < 2; ++t) {
        uint8_t **messages = calloc(count, sizeof *messages);
        for (size_t i = 0; i < count; ++i) {
            messages[i] = malloc(MESSAGE_BYTES);
            rng.rng(rng.ctx, messages[i], MESSAGE_BYTES);
        }
        uint8_t amessage[AMESSAGE_BYTES], decoded[AMESSAGE_BYTES] = {0};
        rng.rng(rng.ctx, amessage, sizeof amessage);

        size_t bits = 0;
        uint8_t **codewords = ambprc_rr_aencode(&aprc, keys->enc, akeys,
                                                (const uint8_t *const *)messages,
                                                8 * MESSAGE_BYTES, amessage, &rng, &bits);
        CHECK(codewords != NULL);
        if (codewords != NULL) {
            CHECK(ambprc_rr_adecode(&aprc, keys->dec, akeys, (const uint8_t *const *)codewords,
                                    bits, 8 * MESSAGE_BYTES, decoded) == 1);
            CHECK(memcmp(amessage, decoded, AMESSAGE_BYTES) == 0);

            /* regular messages are preserved */
            for (size_t i = 0; i < count; ++i) {
                uint8_t message[64] = {0};
                size_t message_bits = 0;
                CHECK(mbprc_decode(&cca.prc.base, keys->dec, codewords[i], bits, message,
                                   &message_bits) == 1);
                CHECK(message_bits == 8 * MESSAGE_BYTES &&
                      memcmp(message, messages[i], MESSAGE_BYTES) == 0);
            }
            rr_free_codewords(codewords, count);
        }
        rr_free_codewords(messages, count);
    }

    rr_free_akeys(akeys);
    mbprc_free_keys(&cca.prc.base, keys);
}

/*
 * mu = 1: no indication seeds, the ciphertext is the seed of a single codeword
 * (nonce || masked message, the nonce takes the bytes the message leaves).
 */
static void test_pp_single_codeword(void)
{
    enum { AMESSAGE_BYTES = 16 };
    ECC ecc = hamming74_ecc();
    /* 24 byte seed, Hamming(7,4) doubles it: 48 bytes = 384 symbols */
    PPParams params = {.ecc = &ecc, .seed_bytes = 24, .q = 2, .symbol_bits = 1,
                       .n = 384, .delta = 0.0};
    ZBPRC_RR prc = prc_pp_rr(&params);

    CHECK(rr_min_ciphertext_seeds(192, AMESSAGE_BYTES) == 1);

    const aZBPRC_RR aprc = {
        .shape = {.seed_bits = 192, .indication_seeds = 0, .codeword_count = 1,
                  .amessage_bytes = AMESSAGE_BYTES},
        .prc = &prc,
    };

    ZBPRC_Keys *keys = zbprc_keygen(&prc.base, &rng);
    RR_AKeys *akeys = rr_akeygen(&rng);
    RR_AKeys *other_akeys = rr_akeygen(&rng);
    CHECK(keys != NULL && akeys != NULL && other_akeys != NULL);
    if (!keys || !akeys || !other_akeys) return;

    for (int t = 0; t < 10; ++t) {
        uint8_t amessage[AMESSAGE_BYTES], decoded[AMESSAGE_BYTES] = {0};
        uint8_t other_decoded[AMESSAGE_BYTES] = {0};
        rng.rng(rng.ctx, amessage, sizeof amessage);

        size_t bits = 0;
        uint8_t **codewords = azbprc_rr_aencode(&aprc, keys->enc, akeys, amessage, &rng, &bits);
        CHECK(codewords != NULL);
        if (codewords == NULL) continue;

        CHECK(azbprc_rr_adecode(&aprc, keys->dec, akeys, (const uint8_t *const *)codewords,
                                bits, decoded) == 1);
        CHECK(memcmp(amessage, decoded, AMESSAGE_BYTES) == 0);

        /* still a regular codeword, and the wrong key reads garbage */
        CHECK(zbprc_decode(&prc.base, keys->dec, codewords[0], bits) == 1);
        CHECK(azbprc_rr_adecode(&aprc, keys->dec, other_akeys,
                                (const uint8_t *const *)codewords, bits, other_decoded) == 1);
        CHECK(memcmp(amessage, other_decoded, AMESSAGE_BYTES) != 0);

        rr_free_codewords(codewords, 1);
    }

    /* the nonce must keep RR_MIN_NONCE_BYTES: a 24 byte seed cannot hold a 17 byte message */
    {
        const aZBPRC_RR too_long = {
            .shape = {.seed_bits = 192, .indication_seeds = 0, .codeword_count = 1,
                      .amessage_bytes = 17},
            .prc = &prc,
        };
        uint8_t amessage[24] = {0};
        size_t bits;

        CHECK(azbprc_rr_aencode(&too_long, keys->enc, akeys, amessage, &rng, &bits) == NULL);
        CHECK(rr_min_ciphertext_seeds(192, 17) == 2);
    }

    rr_free_akeys(akeys);
    rr_free_akeys(other_akeys);
    zbprc_free_keys(&prc.base, keys);
}

static void test_cca_single_codeword(void)
{
    enum { MESSAGE_BYTES = 4, AMESSAGE_BYTES = 8 };
    CcaInstance cca;

    /* r (128) || m (32) || R2 (128) bits */
    cca_instance_init(&cca, 128, 8 * MESSAGE_BYTES);

    /* a 16 byte seed holds an 8 byte nonce and an 8 byte message */
    const aMBPRC_RR aprc = {
        .shape = {.seed_bits = 128, .indication_seeds = 0, .codeword_count = 1,
                  .amessage_bytes = AMESSAGE_BYTES},
        .prc = &cca.prc,
    };

    MBPRC_Keys *keys = mbprc_keygen(&cca.prc.base, &rng);
    RR_AKeys *akeys = rr_akeygen(&rng);
    CHECK(keys != NULL && akeys != NULL);
    if (!keys || !akeys) return;

    for (int t = 0; t < 2; ++t) {
        uint8_t message[MESSAGE_BYTES], amessage[AMESSAGE_BYTES], decoded[AMESSAGE_BYTES] = {0};
        const uint8_t *messages[1] = {message};
        rng.rng(rng.ctx, message, sizeof message);
        rng.rng(rng.ctx, amessage, sizeof amessage);

        size_t bits = 0;
        uint8_t **codewords = ambprc_rr_aencode(&aprc, keys->enc, akeys, messages,
                                                8 * MESSAGE_BYTES, amessage, &rng, &bits);
        CHECK(codewords != NULL);
        if (codewords == NULL) continue;

        CHECK(ambprc_rr_adecode(&aprc, keys->dec, akeys, (const uint8_t *const *)codewords,
                                bits, 8 * MESSAGE_BYTES, decoded) == 1);
        CHECK(memcmp(amessage, decoded, AMESSAGE_BYTES) == 0);

        uint8_t regular[64] = {0};
        size_t regular_bits = 0;
        CHECK(mbprc_decode(&cca.prc.base, keys->dec, codewords[0], bits, regular,
                           &regular_bits) == 1);
        CHECK(regular_bits == 8 * MESSAGE_BYTES && memcmp(regular, message, MESSAGE_BYTES) == 0);

        rr_free_codewords(codewords, 1);
    }

    rr_free_akeys(akeys);
    mbprc_free_keys(&cca.prc.base, keys);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    if (ldpc_admissible_choice(16384, 6.0 / 7.0, 0.25, 0.005, &ldpc_params, NULL) != 0)
        return 1;

    RUN(test_pp_anamorphic);
    RUN(test_cca_anamorphic);
    RUN(test_pp_single_codeword);
    RUN(test_cca_single_codeword);

    return test_summary("aprc_rr");
}
