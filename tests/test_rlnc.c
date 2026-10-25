#include "test_common.h"
#include "../rlnc/rlnc.h"
#include "../rlnc/gf_ext.h"

static RandomnessSource rng;

static void alloc_source(const rlnc_config_t *cfg, rlnc_packet_t *src)
{
    for (size_t i = 0; i < cfg->generation_size; ++i) {
        rlnc_packet_alloc(cfg, &src[i]);
        src[i].global[i] = 1;
        rng.rng(rng.ctx, src[i].payload, cfg->packet_size);
    }
}

static void free_packets(rlnc_packet_t *p, size_t n)
{
    for (size_t i = 0; i < n; ++i)
        rlnc_packet_free(&p[i]);
}

static void test_gf_inverse_and_distributivity(void)
{
    for (unsigned n = 2; n <= 300; n += (n < 24 ? 1 : 29)) {
        gf_field_t F;
        CHECK(gf_field_init(&F, n) == 0);

        for (int t = 0; t < 10; ++t) {
            gf_elem_t a, b, c, one, ab, ac, bc, lhs, rhs;
            gf_zero(&a); gf_zero(&b); gf_zero(&c); gf_zero(&one);
            one.w[0] = 1;
            for (unsigned i = 0; i < n; ++i) {
                if (rand() & 1) a.w[i / 64] |= (uint64_t)1 << (i % 64);
                if (rand() & 1) b.w[i / 64] |= (uint64_t)1 << (i % 64);
                if (rand() & 1) c.w[i / 64] |= (uint64_t)1 << (i % 64);
            }

            /* a(b+c) = ab + ac */
            gf_add(&F, &bc, &b, &c);
            gf_mul(&F, &lhs, &a, &bc);
            gf_mul(&F, &ab, &a, &b);
            gf_mul(&F, &ac, &a, &c);
            gf_add(&F, &rhs, &ab, &ac);
            CHECK(gf_equal(&F, &lhs, &rhs));

            if (!gf_is_zero(&a)) {
                gf_elem_t inv, prod;
                gf_inv(&F, &inv, &a);
                gf_mul(&F, &prod, &a, &inv);
                CHECK_MSG(gf_equal(&F, &prod, &one), "n=%u", n);
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
        gf_field_t F;
        gf_elem_t a, inv, prod, one;

        CHECK(gf_field_init(&F, n) == 0);

        gf_zero(&a);
        gf_zero(&one);
        one.w[0] = 1;
        for (unsigned i = 0; i < n; ++i) {
            if (rand() & 1)
                a.w[i / 64] |= (uint64_t)1 << (i % 64);
        }
        a.w[0] |= 2;     /* non-zero */

        gf_inv(&F, &inv, &a);
        gf_mul(&F, &prod, &a, &inv);
        CHECK_MSG(gf_equal(&F, &prod, &one), "n=%u", n);
    }

    gf_field_t F;
    CHECK(gf_field_init(&F, 1) != 0);
    CHECK(gf_field_init(&F, GF_MAX_BITS + 1) != 0);
}

static void test_gf_interpolation(void)
{
    gf_field_t F;
    CHECK(gf_field_init(&F, 96) == 0);

    enum { K = 20 };
    gf_elem_t co[K], xs[K], ys[K], rec[K];

    for (int i = 0; i < K; ++i) {
        gf_zero(&co[i]);
        gf_zero(&xs[i]);
        co[i].w[0] = (uint64_t)rand() * 7919u;
        co[i].w[1] = (uint64_t)rand() & 0xffffffffu;
        xs[i].w[0] = (uint64_t)i + 5;
    }
    for (int i = 0; i < K; ++i)
        gf_poly_eval(&F, &ys[i], co, K, &xs[i]);

    CHECK(gf_poly_interpolate(&F, rec, xs, ys, K) == 0);
    for (int i = 0; i < K; ++i)
        CHECK(gf_equal(&F, &rec[i], &co[i]));

    /* repeated abscissa is rejected */
    xs[3] = xs[4];
    CHECK(gf_poly_interpolate(&F, rec, xs, ys, K) != 0);
}

static void test_regular_roundtrip(void)
{
    rlnc_config_t cfg = {.q = 256, .packet_size = 32, .generation_size = 6};
    rlnc_packet_t src[6], coded[10], dec[6];
    alloc_source(&cfg, src);
    for (int i = 0; i < 10; ++i) {
        rlnc_packet_alloc(&cfg, &coded[i]);
        CHECK(rlnc_encode(&cfg, src, 6, &coded[i], &rng) == 0);
    }
    for (int i = 0; i < 6; ++i)
        rlnc_packet_alloc(&cfg, &dec[i]);

    CHECK(rlnc_decode(&cfg, coded, 10, dec) == 0);
    for (int i = 0; i < 6; ++i)
        CHECK(memcmp(dec[i].payload, src[i].payload, cfg.packet_size) == 0);

    free_packets(src, 6); free_packets(coded, 10); free_packets(dec, 6);
}

/* one anamorphic round trip; returns 1 if message and generation recovered */
static int arlnc_roundtrip(uint32_t q, size_t K, size_t lambda, size_t S, size_t T)
{
    rlnc_config_t cfg = {.q = q, .packet_size = 48, .generation_size = K};
    rlnc_aconfig_t ac = {.lambda = lambda, .received = S};
    size_t L = rlnc_amsg_len(&cfg, &ac);
    if (L == 0) { printf("  q=%u: invalid parameters\n", q); return 0; }

    rlnc_packet_t *src = calloc(K, sizeof *src);
    rlnc_packet_t *out = calloc(T, sizeof *out);
    rlnc_packet_t *rec = calloc(S, sizeof *rec);
    rlnc_packet_t *dec = calloc(K, sizeof *dec);
    alloc_source(&cfg, src);
    for (size_t i = 0; i < T; ++i) rlnc_packet_alloc(&cfg, &out[i]);
    for (size_t i = 0; i < K; ++i) rlnc_packet_alloc(&cfg, &dec[i]);

    uint8_t *key = rlnc_akeygen();
    uint8_t *m = malloc(L), *r = malloc(L);
    rng.rng(rng.ctx, m, L);
    for (size_t i = 0; i < L; ++i) m[i] &= (uint8_t)(q - 1);

    int ok = rlnc_aencode(&cfg, &ac, src, out, T, &rng, key, m) == 0;

    /* receiver sees a random subset of S of the T symbols */
    size_t *idx = malloc(T * sizeof *idx);
    for (size_t i = 0; i < T; ++i) idx[i] = i;
    for (size_t i = T - 1; i > 0; --i) {
        size_t j = (size_t)rand() % (i + 1), t = idx[i];
        idx[i] = idx[j]; idx[j] = t;
    }
    for (size_t i = 0; i < S; ++i) rec[i] = out[idx[i]];

    int ad = rlnc_adecode(&cfg, &ac, rec, S, key, r);
    if (!ok || ad != 0 || memcmp(m, r, L) != 0)
        printf("  q=%u K=%zu: aencode/adecode stage failed (enc ok=%d, dec=%d)\n",
               q, K, ok, ad);
    ok &= ad == 0;
    ok &= memcmp(m, r, L) == 0;

    /* the regular message is still decodable from the same symbols */
    int rd = rlnc_decode(&cfg, rec, S, dec);
    if (rd != 0)
        printf("  q=%u K=%zu: regular decode failed (%d)\n", q, K, rd);
    ok &= rd == 0;
    for (size_t i = 0; ok && i < K; ++i) {
        ok &= memcmp(dec[i].payload, src[i].payload, cfg.packet_size) == 0;
        if (!ok)
            printf("  q=%u K=%zu: decoded payload %zu differs\n", q, K, i);
    }

    free_packets(src, K); free_packets(out, T); free_packets(dec, K);
    free(src); free(out); free(rec); free(dec);
    rlnc_akey_free(key); free(m); free(r); free(idx);
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
    rlnc_config_t cfg = {.q = 256, .packet_size = 32, .generation_size = 8};
    rlnc_aconfig_t ac = {.lambda = 32, .received = 10};
    size_t L = rlnc_amsg_len(&cfg, &ac);
    CHECK(L > 0);

    rlnc_packet_t src[8], out[20];
    alloc_source(&cfg, src);
    for (int i = 0; i < 20; ++i) rlnc_packet_alloc(&cfg, &out[i]);

    uint8_t *k1 = rlnc_akeygen(), *k2 = rlnc_akeygen();
    uint8_t *m = calloc(L, 1), *r = calloc(L, 1);
    memset(m, 0x5a, L);
    CHECK(rlnc_aencode(&cfg, &ac, src, out, 20, &rng, k1, m) == 0);

    CHECK(rlnc_adecode(&cfg, &ac, out, 10, k1, r) == 0);
    CHECK(memcmp(m, r, L) == 0);

    /* wrong key (robustness: unmasked points are not on a polynomial) */
    CHECK(rlnc_adecode(&cfg, &ac, out, 10, k2, r) != 0);
    /* wrong number of symbols */
    CHECK(rlnc_adecode(&cfg, &ac, out, 9, k1, r) != 0);
    CHECK(rlnc_adecode(&cfg, &ac, out, 11, k1, r) != 0);

    /* repeated label */
    rlnc_packet_t dup[10];
    for (int i = 0; i < 10; ++i) dup[i] = out[i];
    dup[5] = dup[2];
    CHECK(rlnc_adecode(&cfg, &ac, dup, 10, k1, r) != 0);

    /* a corrupted header symbol breaks the check point */
    rlnc_packet_t bad[10];
    for (int i = 0; i < 10; ++i) bad[i] = out[i];
    rlnc_packet_t tamper;
    rlnc_packet_alloc(&cfg, &tamper);
    memcpy(tamper.global, out[9].global, 8);
    memcpy(tamper.payload, out[9].payload, 32);
    tamper.global[7] ^= 1;
    bad[9] = tamper;
    CHECK(rlnc_adecode(&cfg, &ac, bad, 10, k1, r) != 0);
    rlnc_packet_free(&tamper);

    /* regular RLNC symbols are not mistaken for anamorphic ones */
    rlnc_packet_t reg[10];
    for (int i = 0; i < 10; ++i)
        rlnc_packet_alloc(&cfg, &reg[i]);
    int accepted = 0;
    for (int t = 0; t < 50; ++t) {
        for (int i = 0; i < 10; ++i)
            rlnc_encode(&cfg, src, 8, &reg[i], &rng);
        accepted += rlnc_adecode(&cfg, &ac, reg, 10, k1, r) == 0;
    }
    CHECK(accepted == 0);

    /* invalid parameters: K < 2a */
    rlnc_aconfig_t bad_ac = {.lambda = 64, .received = 10};
    CHECK(rlnc_amsg_len(&cfg, &bad_ac) == 0);
    /* T < S */
    CHECK(rlnc_aencode(&cfg, &ac, src, out, 9, &rng, k1, m) != 0);

    free_packets(src, 8); free_packets(out, 20); free_packets(reg, 10);
    rlnc_akey_free(k1); rlnc_akey_free(k2); free(m); free(r);
}

/* Headers must look uniform: byte histogram over many anamorphic headers. */
static void test_headers_uniform(void)
{
    rlnc_config_t cfg = {.q = 256, .packet_size = 16, .generation_size = 8};
    rlnc_aconfig_t ac = {.lambda = 32, .received = 8};
    size_t L = rlnc_amsg_len(&cfg, &ac);
    rlnc_packet_t src[8], out[400];
    alloc_source(&cfg, src);
    for (int i = 0; i < 400; ++i) rlnc_packet_alloc(&cfg, &out[i]);

    uint8_t *key = rlnc_akeygen();
    uint8_t *m = calloc(L, 1); /* all-zero message: worst case for leakage */
    CHECK(rlnc_aencode(&cfg, &ac, src, out, 400, &rng, key, m) == 0);

    /* chi^2 on the y-part of the headers (positions >= a = 4) */
    long hist[256] = {0}; long N = 0;
    for (int i = 0; i < 400; ++i)
        for (int s = 4; s < 8; ++s) { hist[out[i].global[s]]++; N++; }
    double chi = 0, e = (double)N / 256;
    for (int v = 0; v < 256; ++v) chi += (hist[v] - e) * (hist[v] - e) / e;
    /* 255 dof: mean 255, sd ~22.6; allow a wide margin (~6 sd) */
    CHECK_MSG(chi < 255 + 6 * 22.6 && chi > 255 - 6 * 22.6, "chi2=%.1f", chi);

    free_packets(src, 8); free_packets(out, 400);
    rlnc_akey_free(key); free(m);
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
