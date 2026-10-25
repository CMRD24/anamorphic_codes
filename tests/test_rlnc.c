#include "test_common.h"
#include "../rlnc/rlnc.h"
#include "../rlnc/gf_ext.h"

static RandomnessSource rng;

static void alloc_source(const rlnc_config_t *config, rlnc_packet_t *source)
{
    for (size_t i = 0; i < config->generation_size; ++i) {
        rlnc_packet_alloc(config, &source[i]);
        source[i].global_vector[i] = 1;
        rng.rng(rng.ctx, source[i].payload, config->payload_bytes);
    }
}

static void free_packets(rlnc_packet_t *packets, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        rlnc_packet_free(&packets[i]);
}

static void test_gf_inverse_and_distributivity(void)
{
    for (unsigned n = 2; n <= 300; n += (n < 24 ? 1 : 29)) {
        gf_field_t field;
        CHECK(gf_field_init(&field, n) == 0);

        for (int t = 0; t < 10; ++t) {
            gf_elem_t a, b, c, one, ab, aconfig, bc, lhs, rhs;
            gf_zero(&a); gf_zero(&b); gf_zero(&c); gf_zero(&one);
            one.w[0] = 1;
            for (unsigned i = 0; i < n; ++i) {
                if (rand() & 1) a.w[i / 64] |= (uint64_t)1 << (i % 64);
                if (rand() & 1) b.w[i / 64] |= (uint64_t)1 << (i % 64);
                if (rand() & 1) c.w[i / 64] |= (uint64_t)1 << (i % 64);
            }

            /* a(b+c) = ab + aconfig */
            gf_add(&field, &bc, &b, &c);
            gf_mul(&field, &lhs, &a, &bc);
            gf_mul(&field, &ab, &a, &b);
            gf_mul(&field, &aconfig, &a, &c);
            gf_add(&field, &rhs, &ab, &aconfig);
            CHECK(gf_equal(&field, &lhs, &rhs));

            if (!gf_is_zero(&a)) {
                gf_elem_t inv, prod;
                gf_inv(&field, &inv, &a);
                gf_mul(&field, &prod, &a, &inv);
                CHECK_MSG(gf_equal(&field, &prod, &one), "n=%u", n);
            }
        }
    }
}

/*
 * Every field of the polynomial table is a field: in a reducible quotient ring the
 * unit group does not have order 2^n - 1, so a^(2^n - 2) is not the inverse of a
 * random element a (checked with gf_inv, which uses exactly that exponent).
 */
static void test_gf_table_fields(void)
{
    for (unsigned n = 2; n <= GF_MAX_BITS; n = (n < 256 ? n + 1 : (n == 1023 ? 1024 : n + 31))) {
        gf_field_t field;
        gf_elem_t a, inv, prod, one;

        CHECK(gf_field_init(&field, n) == 0);

        gf_zero(&a);
        gf_zero(&one);
        one.w[0] = 1;
        for (unsigned i = 0; i < n; ++i) {
            if (rand() & 1)
                a.w[i / 64] |= (uint64_t)1 << (i % 64);
        }
        a.w[0] |= 2;     /* non-zero */

        gf_inv(&field, &inv, &a);
        gf_mul(&field, &prod, &a, &inv);
        CHECK_MSG(gf_equal(&field, &prod, &one), "n=%u", n);
    }

    gf_field_t field;
    CHECK(gf_field_init(&field, 1) != 0);
    CHECK(gf_field_init(&field, GF_MAX_BITS + 1) != 0);
}

static void test_gf_interpolation(void)
{
    gf_field_t field;
    CHECK(gf_field_init(&field, 96) == 0);

    enum { K = 20 };
    gf_elem_t coefficients[K], xs[K], ys[K], recovered[K];

    for (int i = 0; i < K; ++i) {
        gf_zero(&coefficients[i]);
        gf_zero(&xs[i]);
        coefficients[i].w[0] = (uint64_t)rand() * 7919u;
        coefficients[i].w[1] = (uint64_t)rand() & 0xffffffffu;
        xs[i].w[0] = (uint64_t)i + 5;
    }
    for (int i = 0; i < K; ++i)
        gf_poly_eval(&field, &ys[i], coefficients, K, &xs[i]);

    CHECK(gf_poly_interpolate(&field, recovered, xs, ys, K) == 0);
    for (int i = 0; i < K; ++i)
        CHECK(gf_equal(&field, &recovered[i], &coefficients[i]));

    /* repeated abscissa is rejected */
    xs[3] = xs[4];
    CHECK(gf_poly_interpolate(&field, recovered, xs, ys, K) != 0);
}

static void test_regular_roundtrip(void)
{
    rlnc_config_t config = {.q = 256, .payload_bytes = 32, .generation_size = 6};
    rlnc_packet_t source[6], coded[10], decoded[6];
    alloc_source(&config, source);
    for (int i = 0; i < 10; ++i) {
        rlnc_packet_alloc(&config, &coded[i]);
        CHECK(rlnc_encode(&config, source, 6, &coded[i], &rng) == 0);
    }
    for (int i = 0; i < 6; ++i)
        rlnc_packet_alloc(&config, &decoded[i]);

    CHECK(rlnc_decode(&config, coded, 10, decoded) == 0);
    for (int i = 0; i < 6; ++i)
        CHECK(memcmp(decoded[i].payload, source[i].payload, config.payload_bytes) == 0);

    free_packets(source, 6); free_packets(coded, 10); free_packets(decoded, 6);
}

/* one anamorphic round trip; returns 1 if message and generation recovered */
static int arlnc_roundtrip(uint32_t q, size_t K, size_t lambda, size_t S, size_t T)
{
    rlnc_config_t config = {.q = q, .payload_bytes = 48, .generation_size = K};
    rlnc_aconfig_t aconfig = {.lambda = lambda, .received_symbols = S};
    size_t amessage_symbols = rlnc_amessage_symbols(&config, &aconfig);
    if (amessage_symbols == 0) { printf("  q=%u: invalid parameters\n", q); return 0; }

    rlnc_packet_t *source = calloc(K, sizeof *source);
    rlnc_packet_t *sent = calloc(T, sizeof *sent);
    rlnc_packet_t *recovered = calloc(S, sizeof *recovered);
    rlnc_packet_t *decoded = calloc(K, sizeof *decoded);
    alloc_source(&config, source);
    for (size_t i = 0; i < T; ++i) rlnc_packet_alloc(&config, &sent[i]);
    for (size_t i = 0; i < K; ++i) rlnc_packet_alloc(&config, &decoded[i]);

    uint8_t *key = rlnc_akeygen();
    uint8_t *amessage = malloc(amessage_symbols), *decoded_amessage = malloc(amessage_symbols);
    rng.rng(rng.ctx, amessage, amessage_symbols);
    for (size_t i = 0; i < amessage_symbols; ++i) amessage[i] &= (uint8_t)(q - 1);

    int ok = rlnc_aencode(&config, &aconfig, source, sent, T, &rng, key, amessage) == 0;

    /* receiver sees a random subset of S of the T symbols */
    size_t *order = malloc(T * sizeof *order);
    for (size_t i = 0; i < T; ++i) order[i] = i;
    for (size_t i = T - 1; i > 0; --i) {
        size_t j = (size_t)rand() % (i + 1), t = order[i];
        order[i] = order[j]; order[j] = t;
    }
    for (size_t i = 0; i < S; ++i) recovered[i] = sent[order[i]];

    int adecode_result = rlnc_adecode(&config, &aconfig, recovered, S, key, decoded_amessage);
    if (!ok || adecode_result != 0 || memcmp(amessage, decoded_amessage, amessage_symbols) != 0)
        printf("  q=%u K=%zu: aencode/adecode stage failed (enc ok=%d, dec=%d)\n",
               q, K, ok, adecode_result);
    ok &= adecode_result == 0;
    ok &= memcmp(amessage, decoded_amessage, amessage_symbols) == 0;

    /* the regular message is still decodable from the same symbols */
    int decode_result = rlnc_decode(&config, recovered, S, decoded);
    if (decode_result != 0)
        printf("  q=%u K=%zu: regular decode failed (%d)\n", q, K, decode_result);
    ok &= decode_result == 0;
    for (size_t i = 0; ok && i < K; ++i) {
        ok &= memcmp(decoded[i].payload, source[i].payload, config.payload_bytes) == 0;
        if (!ok)
            printf("  q=%u K=%zu: decoded payload %zu differs\n", q, K, i);
    }

    free_packets(source, K); free_packets(sent, T); free_packets(decoded, K);
    free(source); free(sent); free(recovered); free(decoded);
    rlnc_akey_free(key); free(amessage); free(decoded_amessage); free(order);
    return ok;
}

static void test_anamorphic_roundtrip(void)
{
    /* GF(256), tiny lambda */
    for (int t = 0; t < 20; ++t)
        CHECK(arlnc_roundtrip(256, 5, 16, 7, 12));
    /* GF(16) with lambda = 128, K = 2a = 64 */
    CHECK(arlnc_roundtrip(16, 64, 128, 66, 100));
    /* GF(2): a = 128, K = 256 */
    /* S = K + 20: a random binary matrix with 20 extra rows is singular w.p. ~2^-20 */
    CHECK(arlnc_roundtrip(2, 256, 128, 276, 300));
    /* S close to K (a square system over GF(256) is singular with probability ~1/255) */
    CHECK(arlnc_roundtrip(256, 8, 32, 10, 16));
}

static void test_anamorphic_rejections(void)
{
    rlnc_config_t config = {.q = 256, .payload_bytes = 32, .generation_size = 8};
    rlnc_aconfig_t aconfig = {.lambda = 32, .received_symbols = 10};
    size_t amessage_symbols = rlnc_amessage_symbols(&config, &aconfig);
    CHECK(amessage_symbols > 0);

    rlnc_packet_t source[8], sent[20];
    alloc_source(&config, source);
    for (int i = 0; i < 20; ++i) rlnc_packet_alloc(&config, &sent[i]);

    uint8_t *key = rlnc_akeygen(), *other_key = rlnc_akeygen();
    uint8_t *amessage = calloc(amessage_symbols, 1), *decoded_amessage = calloc(amessage_symbols, 1);
    memset(amessage, 0x5a, amessage_symbols);
    CHECK(rlnc_aencode(&config, &aconfig, source, sent, 20, &rng, key, amessage) == 0);

    CHECK(rlnc_adecode(&config, &aconfig, sent, 10, key, decoded_amessage) == 0);
    CHECK(memcmp(amessage, decoded_amessage, amessage_symbols) == 0);

    /* wrong key (robustness: unmasked points are not on a polynomial) */
    CHECK(rlnc_adecode(&config, &aconfig, sent, 10, other_key, decoded_amessage) != 0);
    /* wrong number of symbols */
    CHECK(rlnc_adecode(&config, &aconfig, sent, 9, key, decoded_amessage) != 0);
    CHECK(rlnc_adecode(&config, &aconfig, sent, 11, key, decoded_amessage) != 0);

    /* repeated label */
    rlnc_packet_t dup[10];
    for (int i = 0; i < 10; ++i) dup[i] = sent[i];
    dup[5] = dup[2];
    CHECK(rlnc_adecode(&config, &aconfig, dup, 10, key, decoded_amessage) != 0);

    /* a corrupted header symbol breaks the check point */
    rlnc_packet_t bad[10];
    for (int i = 0; i < 10; ++i) bad[i] = sent[i];
    rlnc_packet_t tamper;
    rlnc_packet_alloc(&config, &tamper);
    memcpy(tamper.global_vector, sent[9].global_vector, 8);
    memcpy(tamper.payload, sent[9].payload, 32);
    tamper.global_vector[7] ^= 1;
    bad[9] = tamper;
    CHECK(rlnc_adecode(&config, &aconfig, bad, 10, key, decoded_amessage) != 0);
    rlnc_packet_free(&tamper);

    /* regular RLNC symbols are not mistaken for anamorphic ones */
    rlnc_packet_t regular[10];
    for (int i = 0; i < 10; ++i)
        rlnc_packet_alloc(&config, &regular[i]);
    int accepted = 0;
    for (int t = 0; t < 50; ++t) {
        for (int i = 0; i < 10; ++i)
            rlnc_encode(&config, source, 8, &regular[i], &rng);
        accepted += rlnc_adecode(&config, &aconfig, regular, 10, key, decoded_amessage) == 0;
    }
    CHECK(accepted == 0);

    /* invalid parameters: K < 2a */
    rlnc_aconfig_t bad_aconfig = {.lambda = 64, .received_symbols = 10};
    CHECK(rlnc_amessage_symbols(&config, &bad_aconfig) == 0);
    /* T < S */
    CHECK(rlnc_aencode(&config, &aconfig, source, sent, 9, &rng, key, amessage) != 0);

    free_packets(source, 8); free_packets(sent, 20); free_packets(regular, 10);
    rlnc_akey_free(key); rlnc_akey_free(other_key); free(amessage); free(decoded_amessage);
}

/* Headers must look uniform: byte histogram over many anamorphic headers. */
static void test_headers_uniform(void)
{
    rlnc_config_t config = {.q = 256, .payload_bytes = 16, .generation_size = 8};
    rlnc_aconfig_t aconfig = {.lambda = 32, .received_symbols = 8};
    size_t amessage_symbols = rlnc_amessage_symbols(&config, &aconfig);
    rlnc_packet_t source[8], sent[400];
    alloc_source(&config, source);
    for (int i = 0; i < 400; ++i) rlnc_packet_alloc(&config, &sent[i]);

    uint8_t *key = rlnc_akeygen();
    uint8_t *amessage = calloc(amessage_symbols, 1); /* all-zero message: worst case for leakage */
    CHECK(rlnc_aencode(&config, &aconfig, source, sent, 400, &rng, key, amessage) == 0);

    /* chi^2 on the y-part of the headers (positions >= a = 4) */
    long hist[256] = {0}; long N = 0;
    for (int i = 0; i < 400; ++i)
        for (int s = 4; s < 8; ++s) { hist[sent[i].global_vector[s]]++; N++; }
    double chi = 0, e = (double)N / 256;
    for (int v = 0; v < 256; ++v) chi += (hist[v] - e) * (hist[v] - e) / e;
    /* 255 dof: mean 255, sd ~22.6; allow a wide margin (~6 sd) */
    CHECK_MSG(chi < 255 + 6 * 22.6 && chi > 255 - 6 * 22.6, "chi2=%.1f", chi);

    free_packets(source, 8); free_packets(sent, 400);
    rlnc_akey_free(key); free(amessage);
}

int main(void)
{
    srand(12345);
    rng = linux_randomness();

    RUN(test_gf_inverse_and_distributivity);
    RUN(test_gf_table_fields);
    RUN(test_gf_interpolation);
    RUN(test_regular_roundtrip);
    RUN(test_anamorphic_roundtrip);
    RUN(test_anamorphic_rejections);
    RUN(test_headers_uniform);

    return test_summary("rlnc");
}
