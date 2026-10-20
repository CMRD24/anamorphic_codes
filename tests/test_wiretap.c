#include "test_common.h"
#include "../wiretap/wiretap.h"
#include "../utils/hamming74.h"

#include <sodium.h>

static RandomnessSource rng;

static void test_oaep_inverse(void)
{
    for (size_t len = 2; len <= 64; len += 2) {
        uint8_t in[64], mid[64], back[64];
        rng.rng(rng.ctx, in, len);

        CHECK(wiretap_oaep4(in, len, mid) == 0);
        CHECK(wiretap_oaep4_inverse(mid, len, back) == 0);
        CHECK(memcmp(in, back, len) == 0);
        /* the transform actually changes the data */
        CHECK(memcmp(in, mid, len) != 0);
    }
}

static void test_config(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t ok = {.K_bytes = 32, .security_parameter = 128, .ecc = &ecc};
    wiretap_config_t odd = {.K_bytes = 31, .security_parameter = 128, .ecc = &ecc};
    wiretap_config_t noecc = {.K_bytes = 32, .security_parameter = 128, .ecc = NULL};

    CHECK(wiretap_config_valid(&ok));
    CHECK(!wiretap_config_valid(&odd));
    CHECK(!wiretap_config_valid(&noecc));
    CHECK(!wiretap_config_valid(NULL));
}

static void roundtrip(size_t blocks, double flip_prob)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t cfg = {.K_bytes = 32, .security_parameter = 128, .ecc = &ecc};

    size_t mlen = blocks * cfg.K_bytes;
    uint8_t *msg = malloc(mlen), *dec = malloc(mlen + 64);
    rng.rng(rng.ctx, msg, mlen);

    size_t cap = wiretap_encoded_size(&cfg, mlen), clen = 0;
    CHECK(cap > 0);
    uint8_t *ct = malloc(cap);

    CHECK(wiretap_encode(&cfg, &rng, msg, mlen, ct, cap, &clen) == 0);
    CHECK(clen == cap);

    if (flip_prob > 0)
        test_bsc(ct, clen * 8, flip_prob, &rng);

    size_t dlen = 0;
    CHECK(wiretap_decode(&cfg, ct, clen, dec, mlen + 64, &dlen) == 0);
    CHECK(dlen >= mlen);
    CHECK(memcmp(dec, msg, mlen) == 0);

    free(msg); free(dec); free(ct);
}

static void test_roundtrip_noiseless(void)
{
    roundtrip(1, 0);
    roundtrip(3, 0);
    roundtrip(10, 0);
}

static void test_roundtrip_noisy(void)
{
    /* Hamming(7,4) corrects one error per 7-bit block: p = 0.0003 is safe */
    for (int i = 0; i < 5; ++i)
        roundtrip(2, 0.0003);
}

static void test_encoding_is_randomized(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t cfg = {.K_bytes = 32, .security_parameter = 128, .ecc = &ecc};
    uint8_t msg[32] = {0};
    size_t cap = wiretap_encoded_size(&cfg, 32), l1, l2;
    uint8_t *a = malloc(cap), *b = malloc(cap);

    CHECK(wiretap_encode(&cfg, &rng, msg, 32, a, cap, &l1) == 0);
    CHECK(wiretap_encode(&cfg, &rng, msg, 32, b, cap, &l2) == 0);
    CHECK(l1 == l2 && memcmp(a, b, l1) != 0);

    free(a); free(b);
}

static void test_bad_arguments(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t cfg = {.K_bytes = 32, .security_parameter = 128, .ecc = &ecc};
    uint8_t msg[33] = {0}, out[4096];
    size_t olen;

    /* message length must be a multiple of K_bytes */
    CHECK(wiretap_encode(&cfg, &rng, msg, 33, out, sizeof out, &olen) != 0 ||
          olen % wiretap_codeword_size(&cfg) == 0);
    /* output capacity too small */
    CHECK(wiretap_encode(&cfg, &rng, msg, 32, out, 4, &olen) != 0);
    /* ciphertext length not a multiple of the codeword size */
    CHECK(wiretap_decode(&cfg, out, 5, out, sizeof out, &olen) != 0);
}

static void test_anamorphic(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t cfg = {.K_bytes = 32, .security_parameter = 128, .ecc = &ecc};
    wiretap_ana_config_t acfg = {.ana_message_length = 16};

    CHECK(wiretap_ana_config_valid(&cfg, &acfg));
    /* nonce must keep at least 16 bytes */
    wiretap_ana_config_t too_long = {.ana_message_length = 24};
    wiretap_ana_config_t zero = {.ana_message_length = 0};
    CHECK(!wiretap_ana_config_valid(&cfg, &too_long));
    CHECK(!wiretap_ana_config_valid(&cfg, &zero));

    uint8_t *k1 = wiretap_akeygen(), *k2 = wiretap_akeygen();
    CHECK(k1 && k2);

    size_t mlen = 3 * cfg.K_bytes;
    size_t cap = wiretap_encoded_size(&cfg, mlen);
    uint8_t *msg = malloc(mlen), *ct = malloc(cap), *dec = malloc(mlen);
    uint8_t am[16], out[16];

    for (int t = 0; t < 10; ++t) {
        rng.rng(rng.ctx, msg, mlen);
        rng.rng(rng.ctx, am, sizeof am);
        size_t clen = 0, dlen = 0;

        CHECK(wiretap_aencode(&cfg, &acfg, k1, msg, mlen, am, ct, cap, &clen) == 0);
        CHECK(clen == cap);

        /* preserved regular functionality */
        CHECK(wiretap_decode(&cfg, ct, clen, dec, mlen, &dlen) == 0);
        CHECK(dlen == mlen && memcmp(dec, msg, mlen) == 0);

        /* anamorphic decoding, also after channel noise */
        memset(out, 0, sizeof out);
        CHECK(wiretap_adecode(&cfg, &acfg, k1, ct, clen, out) == 0);
        CHECK(memcmp(out, am, sizeof am) == 0);

        test_bsc(ct, clen * 8, 0.0005, &rng);
        memset(out, 0, sizeof out);
        CHECK(wiretap_adecode(&cfg, &acfg, k1, ct, clen, out) == 0);
        CHECK(memcmp(out, am, sizeof am) == 0);

        /* a different key does not reveal the message */
        CHECK(wiretap_adecode(&cfg, &acfg, k2, ct, clen, out) != 0 ||
              memcmp(out, am, sizeof am) != 0);
    }

    /* the seed block of anamorphic codewords differs between encodings of the
     * same message (fresh nonce) */
    uint8_t *ct2 = malloc(cap);
    size_t l1, l2;
    CHECK(wiretap_aencode(&cfg, &acfg, k1, msg, mlen, am, ct, cap, &l1) == 0);
    CHECK(wiretap_aencode(&cfg, &acfg, k1, msg, mlen, am, ct2, cap, &l2) == 0);
    CHECK(memcmp(ct, ct2, l1) != 0);

    /* argument checks */
    size_t ol;
    CHECK(wiretap_aencode(&cfg, &acfg, NULL, msg, mlen, am, ct, cap, &ol) != 0);
    CHECK(wiretap_adecode(&cfg, &acfg, k1, ct, 3, out) != 0);

    free(ct2); free(msg); free(ct); free(dec);
    wiretap_akey_free(k1); wiretap_akey_free(k2);
}

int main(void)
{
    if (sodium_init() < 0)
        return 1;
    rng = linux_randomness();

    RUN(test_oaep_inverse);
    RUN(test_config);
    RUN(test_roundtrip_noiseless);
    RUN(test_roundtrip_noisy);
    RUN(test_encoding_is_randomized);
    RUN(test_bad_arguments);
    RUN(test_anamorphic);

    return test_summary("wiretap");
}
