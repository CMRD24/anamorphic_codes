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
    wiretap_config_t ok = {.block_bytes = 32, .lambda = 128, .ecc = &ecc};
    wiretap_config_t odd = {.block_bytes = 31, .lambda = 128, .ecc = &ecc};
    wiretap_config_t noecc = {.block_bytes = 32, .lambda = 128, .ecc = NULL};

    CHECK(wiretap_config_valid(&ok));
    CHECK(!wiretap_config_valid(&odd));
    CHECK(!wiretap_config_valid(&noecc));
    CHECK(!wiretap_config_valid(NULL));
}

static void roundtrip(size_t blocks, double flip_prob)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t config = {.block_bytes = 32, .lambda = 128, .ecc = &ecc};

    size_t message_len = blocks * config.block_bytes;
    uint8_t *message = malloc(message_len), *decoded = malloc(message_len + 64);
    rng.rng(rng.ctx, message, message_len);

    size_t capacity = wiretap_encoded_size(&config, message_len), codeword_len = 0;
    CHECK(capacity > 0);
    uint8_t *codeword = malloc(capacity);

    CHECK(wiretap_encode(&config, &rng, message, message_len, codeword, capacity, &codeword_len) == 0);
    CHECK(codeword_len == capacity);

    if (flip_prob > 0)
        test_bsc(codeword, codeword_len * 8, flip_prob, &rng);

    size_t decoded_len = 0;
    CHECK(wiretap_decode(&config, codeword, codeword_len, decoded, message_len + 64, &decoded_len) == 0);
    CHECK(decoded_len >= message_len);
    CHECK(memcmp(decoded, message, message_len) == 0);

    free(message); free(decoded); free(codeword);
}

static void test_roundtrip_noiseless(void)
{
    roundtrip(1, 0);
    roundtrip(3, 0);
    roundtrip(10, 0);
}

static void test_roundtrip_noisy(void)
{
    /* Hamming(7,4) corrects one error per 7-bit block: packets = 0.0003 is safe */
    for (int i = 0; i < 5; ++i)
        roundtrip(2, 0.0003);
}

static void test_encoding_is_randomized(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t config = {.block_bytes = 32, .lambda = 128, .ecc = &ecc};
    uint8_t message[32] = {0};
    size_t capacity = wiretap_encoded_size(&config, 32), l1, l2;
    uint8_t *a = malloc(capacity), *b = malloc(capacity);

    CHECK(wiretap_encode(&config, &rng, message, 32, a, capacity, &l1) == 0);
    CHECK(wiretap_encode(&config, &rng, message, 32, b, capacity, &l2) == 0);
    CHECK(l1 == l2 && memcmp(a, b, l1) != 0);

    free(a); free(b);
}

static void test_bad_arguments(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t config = {.block_bytes = 32, .lambda = 128, .ecc = &ecc};
    uint8_t message[33] = {0}, out[4096];
    size_t olen;

    /* message length must be a multiple of block_bytes */
    CHECK(wiretap_encode(&config, &rng, message, 33, out, sizeof out, &olen) != 0 ||
          olen % wiretap_block_codeword_size(&config) == 0);
    /* output capacity too small */
    CHECK(wiretap_encode(&config, &rng, message, 32, out, 4, &olen) != 0);
    /* ciphertext length not a multiple of the codeword size */
    CHECK(wiretap_decode(&config, out, 5, out, sizeof out, &olen) != 0);
}

static void test_anamorphic(void)
{
    ECC ecc = hamming74_ecc();
    wiretap_config_t config = {.block_bytes = 32, .lambda = 128, .ecc = &ecc};
    wiretap_aconfig_t aconfig = {.amessage_bytes = 16};

    CHECK(wiretap_aconfig_valid(&config, &aconfig));
    /* nonce must keep at least 16 bytes */
    wiretap_aconfig_t too_long = {.amessage_bytes = 24};
    wiretap_aconfig_t zero = {.amessage_bytes = 0};
    CHECK(!wiretap_aconfig_valid(&config, &too_long));
    CHECK(!wiretap_aconfig_valid(&config, &zero));

    uint8_t *akey = wiretap_akeygen(), *other_akey = wiretap_akeygen();
    CHECK(akey && other_akey);

    size_t message_len = 3 * config.block_bytes;
    size_t capacity = wiretap_encoded_size(&config, message_len);
    uint8_t *message = malloc(message_len), *codeword = malloc(capacity), *decoded = malloc(message_len);
    uint8_t am[16], out[16];

    for (int t = 0; t < 10; ++t) {
        rng.rng(rng.ctx, message, message_len);
        rng.rng(rng.ctx, am, sizeof am);
        size_t codeword_len = 0, decoded_len = 0;

        CHECK(wiretap_aencode(&config, &aconfig, akey, message, message_len, am, codeword, capacity, &codeword_len) == 0);
        CHECK(codeword_len == capacity);

        /* preserved regular functionality */
        CHECK(wiretap_decode(&config, codeword, codeword_len, decoded, message_len, &decoded_len) == 0);
        CHECK(decoded_len == message_len && memcmp(decoded, message, message_len) == 0);

        /* anamorphic decoding, also after channel noise */
        memset(out, 0, sizeof out);
        CHECK(wiretap_adecode(&config, &aconfig, akey, codeword, codeword_len, out) == 0);
        CHECK(memcmp(out, am, sizeof am) == 0);

        test_bsc(codeword, codeword_len * 8, 0.0005, &rng);
        memset(out, 0, sizeof out);
        CHECK(wiretap_adecode(&config, &aconfig, akey, codeword, codeword_len, out) == 0);
        CHECK(memcmp(out, am, sizeof am) == 0);

        /* a different key does not reveal the message */
        CHECK(wiretap_adecode(&config, &aconfig, other_akey, codeword, codeword_len, out) != 0 ||
              memcmp(out, am, sizeof am) != 0);
    }

    /* the seed block of anamorphic codewords differs between encodings of the
     * same message (fresh nonce) */
    uint8_t *ct2 = malloc(capacity);
    size_t l1, l2;
    CHECK(wiretap_aencode(&config, &aconfig, akey, message, message_len, am, codeword, capacity, &l1) == 0);
    CHECK(wiretap_aencode(&config, &aconfig, akey, message, message_len, am, ct2, capacity, &l2) == 0);
    CHECK(memcmp(codeword, ct2, l1) != 0);

    /* argument checks */
    size_t ol;
    CHECK(wiretap_aencode(&config, &aconfig, NULL, message, message_len, am, codeword, capacity, &ol) != 0);
    CHECK(wiretap_adecode(&config, &aconfig, akey, codeword, 3, out) != 0);

    free(ct2); free(message); free(codeword); free(decoded);
    wiretap_akey_free(akey); wiretap_akey_free(other_akey);
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
