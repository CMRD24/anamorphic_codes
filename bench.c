#define _POSIX_C_SOURCE 200809L

/*
 * Benchmark: anamorphic versus regular operations.
 *
 *   bench [--keys K] [--ops N] [--codes LIST] [--param CODE:NAME=VALUE]...
 *         [--csv FILE]
 *
 * For every selected code the benchmark
 *   - generates K keys (a fresh random key each time),
 *   - for every key performs N rounds of
 *         encode -> decode -> aencode -> adecode
 *     on the same messages,
 * and reports mean, standard deviation and minimum of every operation, the
 * overhead of the anamorphic operations, and the ciphertext sizes.
 *
 * Key generation is measured through the demo front end: opening a code with
 * only the regular key is the regular key generation, opening it with both
 * keys additionally runs the anamorphic key generation (reported as the
 * difference). Keyless codes (rlnc, wiretap) only have an anamorphic key.
 */

#include <fcntl.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include <sodium.h>

#include "demo_codes.h"

#define MAX_PARAM_OVERRIDES 64

typedef struct {
    const char *name;
    const DemoOps *ops;
    const char *message;     /* regular message */
    const char *amessage;    /* anamorphic message */
} BenchCode;

static const BenchCode codes[] = {
    {"ldpc",    &demo_ldpc_ops,    "",             ""},
    {"pp",      &demo_pp_ops,      "",             "anamorphic-text"},
    {"1a",      &demo_1a_ops,      "1",            "1"},
    {"low",     &demo_low_ops,     "hello",        "10110"},
    {"high",    &demo_high_ops,    "hi-there",     "hide-me"},
    {"sharp",   &demo_sharp_ops,   "ping",         "hide-me"},
    {"cca",     &demo_cca_ops,     "ping",         "hide-me"},
    {"rlnc",    &demo_rlnc_ops,    "regular text", "hidden text"},
#ifndef BENCH_NO_WIRETAP
    {"wiretap", &demo_wiretap_ops, "regular text", "hidden text"},
#endif
};

#define NUM_CODES (sizeof(codes) / sizeof(codes[0]))

typedef struct {
    char code[32];
    char name[64];
    char value[64];
} ParamOverride;

typedef struct {
    size_t keys;
    size_t ops;
    char selection[256];
    ParamOverride overrides[MAX_PARAM_OVERRIDES];
    size_t num_overrides;
    const char *csv;
} Options;

/* ------------------------------------------------------------------------
 * Timing and statistics
 * ------------------------------------------------------------------------ */

static double now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (double)ts.tv_sec * 1e3 + (double)ts.tv_nsec / 1e6;
}

typedef struct {
    double *v;
    size_t n;
    size_t cap;
    size_t failures;
} Samples;

static int samples_init(Samples *s, size_t cap)
{
    s->v = malloc((cap ? cap : 1) * sizeof(double));
    s->n = 0;
    s->cap = cap;
    s->failures = 0;

    return s->v != NULL ? 0 : -1;
}

static void samples_add(Samples *s, double ms)
{
    if (s->n < s->cap)
        s->v[s->n++] = ms;
}

typedef struct {
    double mean, stddev, min;
    size_t n;
} Stats;

static Stats stats_of(const Samples *s)
{
    Stats st = {0, 0, 0, s->n};
    double sum = 0, sq = 0;

    if (s->n == 0)
        return st;

    st.min = s->v[0];
    for (size_t i = 0; i < s->n; ++i) {
        sum += s->v[i];
        if (s->v[i] < st.min)
            st.min = s->v[i];
    }
    st.mean = sum / (double)s->n;

    for (size_t i = 0; i < s->n; ++i)
        sq += (s->v[i] - st.mean) * (s->v[i] - st.mean);
    st.stddev = s->n > 1 ? sqrt(sq / (double)(s->n - 1)) : 0;

    return st;
}

/* element-wise sum of two sample sets of equal length (a + b of one round) */
static int samples_sum(Samples *out, const Samples *a, const Samples *b)
{
    size_t n = a->n < b->n ? a->n : b->n;

    if (samples_init(out, n) != 0)
        return -1;

    for (size_t i = 0; i < n; ++i)
        samples_add(out, a->v[i] + b->v[i]);

    return 0;
}

/* ------------------------------------------------------------------------
 * stdout of the codes is discarded while measuring
 * ------------------------------------------------------------------------ */

static int saved_stdout = -1;

static void quiet_begin(void)
{
    int devnull;

    fflush(stdout);
    saved_stdout = dup(1);
    devnull = open("/dev/null", O_WRONLY);

    if (devnull >= 0) {
        dup2(devnull, 1);
        close(devnull);
    }
}

static void quiet_end(void)
{
    fflush(stdout);

    if (saved_stdout >= 0) {
        dup2(saved_stdout, 1);
        close(saved_stdout);
        saved_stdout = -1;
    }
}

/* ------------------------------------------------------------------------
 * One code
 * ------------------------------------------------------------------------ */

typedef struct {
    Samples keygen_regular, keygen_ana;
    Samples encode, decode, aencode, adecode;
    size_t ct_count, ct_bits, act_count, act_bits;
    int ok;
} Result;

static void result_free(Result *r)
{
    free(r->keygen_regular.v);
    free(r->keygen_ana.v);
    free(r->encode.v);
    free(r->decode.v);
    free(r->aencode.v);
    free(r->adecode.v);
}

static int build_params(const BenchCode *code, const Options *opt, DemoParams *params)
{
    demo_params_defaults(params, code->ops->params);

    for (size_t i = 0; i < opt->num_overrides; ++i) {
        const ParamOverride *o = &opt->overrides[i];

        if (strcmp(o->code, code->name) == 0 &&
            demo_params_set(params, o->name, o->value) != 0)
            return -1;
    }

    return 0;
}

static int run_code(const BenchCode *code, const Options *opt, Result *r)
{
    const DemoOps *ops = code->ops;
    DemoParams params;
    const size_t rounds = opt->keys * opt->ops;

    memset(r, 0, sizeof(*r));

    if (build_params(code, opt, &params) != 0)
        return -1;

    if (samples_init(&r->keygen_regular, opt->keys) != 0 ||
        samples_init(&r->keygen_ana, opt->keys) != 0 ||
        samples_init(&r->encode, rounds) != 0 ||
        samples_init(&r->decode, rounds) != 0 ||
        samples_init(&r->aencode, rounds) != 0 ||
        samples_init(&r->adecode, rounds) != 0)
        return -1;

    for (size_t k = 0; k < opt->keys; ++k) {
        DemoKeys keys = {0};
        void *handle, *regular_only;
        double t0;

        randombytes_buf(keys.regular, sizeof(keys.regular));
        randombytes_buf(keys.anamorphic, sizeof(keys.anamorphic));

        /* regular key generation (opening with the regular key only) */
        keys.have_regular = ops->regular_keys;
        keys.have_anamorphic = 0;
        t0 = now_ms();
        regular_only = ops->open(&params, &keys);
        const double t_regular = now_ms() - t0;

        if (regular_only == NULL)
            return -1;
        ops->close(regular_only);

        /* with the anamorphic key as well */
        keys.have_anamorphic = 1;
        t0 = now_ms();
        handle = ops->open(&params, &keys);
        const double t_both = now_ms() - t0;

        if (handle == NULL)
            return -1;

        if (ops->regular_keys)
            samples_add(&r->keygen_regular, t_regular);
        samples_add(&r->keygen_ana, ops->regular_keys ? (t_both > t_regular ? t_both - t_regular : 0)
                                                      : t_both);

        /* one untimed round per key: first-use costs (cold caches, lazy
         * allocation) would otherwise dominate small samples */
        {
            DemoCiphertext ct = {0}, act = {0};

            if (ops->encode(handle, code->message, &ct) == 0) {
                ops->decode(handle, &ct);
                demo_ct_free(&ct);
            }
            if (ops->aencode(handle, code->message, code->amessage, &act) == 0) {
                ops->adecode(handle, &act);
                demo_ct_free(&act);
            }
        }

        for (size_t i = 0; i < opt->ops; ++i) {
            DemoCiphertext ct = {0}, act = {0};

            t0 = now_ms();
            int rc = ops->encode(handle, code->message, &ct);
            samples_add(&r->encode, now_ms() - t0);
            if (rc != 0) {
                r->encode.failures++;
                continue;
            }

            t0 = now_ms();
            rc = ops->decode(handle, &ct);
            samples_add(&r->decode, now_ms() - t0);
            if (rc != 0)
                r->decode.failures++;

            t0 = now_ms();
            rc = ops->aencode(handle, code->message, code->amessage, &act);
            samples_add(&r->aencode, now_ms() - t0);
            if (rc != 0) {
                r->aencode.failures++;
                demo_ct_free(&ct);
                continue;
            }

            t0 = now_ms();
            rc = ops->adecode(handle, &act);
            samples_add(&r->adecode, now_ms() - t0);
            if (rc != 0)
                r->adecode.failures++;

            if (r->ct_count == 0) {
                r->ct_count = ct.count;
                r->ct_bits = ct.bits;
                r->act_count = act.count;
                r->act_bits = act.bits;
            }

            demo_ct_free(&ct);
            demo_ct_free(&act);
        }

        ops->close(handle);
    }

    r->ok = 1;

    return 0;
}

/* ------------------------------------------------------------------------
 * Reporting
 * ------------------------------------------------------------------------ */

static void print_row(FILE *out, const char *name, const Samples *s)
{
    Stats st = stats_of(s);

    if (st.n == 0) {
        fprintf(out, "  %-24s %10s\n", name, "n/a");
        return;
    }

    fprintf(out, "  %-24s %10.3f %10.3f %10.3f %7zu", name, st.mean, st.stddev, st.min, st.n);
    if (s->failures > 0)
        fprintf(out, "   (%zu failed)", s->failures);
    fprintf(out, "\n");
}

static void print_ratio(FILE *out, const char *name, const Samples *regular,
                        const Samples *ana)
{
    Stats a = stats_of(regular), b = stats_of(ana);

    if (a.n == 0 || b.n == 0 || a.mean <= 0)
        return;

    fprintf(out, "  %-24s x%-8.2f (%+.3f ms)\n", name, b.mean / a.mean, b.mean - a.mean);
}

static void csv_row(FILE *csv, const char *code, const char *op, const Samples *s)
{
    Stats st = stats_of(s);

    if (csv != NULL && st.n > 0)
        fprintf(csv, "%s,%s,%zu,%.6f,%.6f,%.6f,%zu\n", code, op, st.n, st.mean, st.stddev,
                st.min, s->failures);
}

static void report(FILE *out, FILE *csv, const BenchCode *code, const Options *opt, Result *r)
{
    Samples regular_total, ana_total;
    int have_totals = samples_sum(&regular_total, &r->encode, &r->decode) == 0 &&
                      samples_sum(&ana_total, &r->aencode, &r->adecode) == 0;

    fprintf(out, "\n== %s  (%zu key%s x %zu round%s)\n", code->name, opt->keys,
            opt->keys == 1 ? "" : "s", opt->ops, opt->ops == 1 ? "" : "s");
    fprintf(out, "  %-24s %10s %10s %10s %7s\n", "operation", "mean [ms]", "stddev", "min", "n");

    if (code->ops->regular_keys)
        print_row(out, "keygen (regular)", &r->keygen_regular);
    print_row(out, code->ops->regular_keys ? "keygen (anamorphic, +)" : "keygen (anamorphic)",
              &r->keygen_ana);
    print_row(out, "encode", &r->encode);
    print_row(out, "aencode", &r->aencode);
    print_row(out, "decode", &r->decode);
    print_row(out, "adecode", &r->adecode);

    if (have_totals) {
        print_row(out, "encode + decode", &regular_total);
        print_row(out, "aencode + adecode", &ana_total);
    }

    fprintf(out, "  anamorphic / regular:\n");
    print_ratio(out, "encode", &r->encode, &r->aencode);
    print_ratio(out, "decode", &r->decode, &r->adecode);
    if (have_totals)
        print_ratio(out, "encode + decode", &regular_total, &ana_total);

    fprintf(out, "  ciphertext: regular %zu x %zu bits, anamorphic %zu x %zu bits\n",
            r->ct_count, r->ct_bits, r->act_count, r->act_bits);

    csv_row(csv, code->name, "keygen_regular", &r->keygen_regular);
    csv_row(csv, code->name, "keygen_anamorphic", &r->keygen_ana);
    csv_row(csv, code->name, "encode", &r->encode);
    csv_row(csv, code->name, "aencode", &r->aencode);
    csv_row(csv, code->name, "decode", &r->decode);
    csv_row(csv, code->name, "adecode", &r->adecode);
    if (have_totals) {
        csv_row(csv, code->name, "encode_decode", &regular_total);
        csv_row(csv, code->name, "aencode_adecode", &ana_total);
        free(regular_total.v);
        free(ana_total.v);
    }
}

/* ------------------------------------------------------------------------
 * Command line
 * ------------------------------------------------------------------------ */

static void usage(const char *prog)
{
    fprintf(stderr,
        "usage: %s [options]\n"
        "\n"
        "  --keys K                  number of key generations per code (default 3)\n"
        "  --ops N                   encode/decode rounds per key (default 10)\n"
        "  --codes LIST              comma separated codes or 'all' (default all):\n"
        "                            ",
        prog);

    for (size_t i = 0; i < NUM_CODES; ++i)
        fprintf(stderr, "%s%s", i ? "," : "", codes[i].name);

    fprintf(stderr,
        "\n"
        "  --param CODE:NAME=VALUE   override a parameter of a code (repeatable),\n"
        "                            e.g. --param low:ell=16 --param rlnc:lambda=32\n"
        "  --csv FILE                additionally write the results as CSV\n"
        "\n"
        "Every round runs encode, decode, aencode and adecode with fresh randomness.\n");
}

static int parse_size(const char *s, size_t *out)
{
    char *end;
    unsigned long long v = strtoull(s, &end, 10);

    if (*s == '\0' || *end != '\0' || v == 0)
        return -1;

    *out = (size_t)v;

    return 0;
}

static int parse_options(int argc, char **argv, Options *opt)
{
    opt->keys = 3;
    opt->ops = 10;
    strcpy(opt->selection, "all");
    opt->num_overrides = 0;
    opt->csv = NULL;

    for (int i = 1; i < argc; ++i) {
        const char *a = argv[i];
        const char *v = i + 1 < argc ? argv[i + 1] : NULL;

        if (strcmp(a, "--keys") == 0 && v) {
            if (parse_size(v, &opt->keys) != 0) {
                fprintf(stderr, "--keys needs a positive integer\n");
                return -1;
            }
            ++i;
        } else if (strcmp(a, "--ops") == 0 && v) {
            if (parse_size(v, &opt->ops) != 0) {
                fprintf(stderr, "--ops needs a positive integer\n");
                return -1;
            }
            ++i;
        } else if (strcmp(a, "--codes") == 0 && v) {
            if (strlen(v) >= sizeof(opt->selection)) {
                fprintf(stderr, "--codes list too long\n");
                return -1;
            }
            strcpy(opt->selection, v);
            ++i;
        } else if (strcmp(a, "--csv") == 0 && v) {
            opt->csv = v;
            ++i;
        } else if (strcmp(a, "--param") == 0 && v) {
            ParamOverride *o;
            const char *colon = strchr(v, ':');
            const char *eq = strchr(v, '=');

            if (opt->num_overrides >= MAX_PARAM_OVERRIDES || !colon || !eq || colon > eq ||
                (size_t)(colon - v) >= sizeof(o->code) || (size_t)(eq - colon - 1) >= sizeof(o->name) ||
                strlen(eq + 1) >= sizeof(o->value)) {
                fprintf(stderr, "--param expects CODE:NAME=VALUE, got '%s'\n", v);
                return -1;
            }

            o = &opt->overrides[opt->num_overrides++];
            memset(o, 0, sizeof(*o));
            memcpy(o->code, v, (size_t)(colon - v));
            memcpy(o->name, colon + 1, (size_t)(eq - colon - 1));
            strcpy(o->value, eq + 1);
            ++i;
        } else {
            return -1;
        }
    }

    return 0;
}

static int selected(const Options *opt, const char *name)
{
    char list[256];
    char *tok;

    if (strcmp(opt->selection, "all") == 0)
        return 1;

    strcpy(list, opt->selection);
    for (tok = strtok(list, ","); tok != NULL; tok = strtok(NULL, ",")) {
        if (strcmp(tok, name) == 0)
            return 1;
    }

    return 0;
}

int main(int argc, char **argv)
{
    Options opt;
    FILE *out, *csv = NULL;
    int status = 0, ran = 0;

    if (parse_options(argc, argv, &opt) != 0) {
        usage(argv[0]);
        return 2;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
        return 1;
    }

    /* results go to the real stdout, which is silenced while the codes run */
    out = stdout;

    if (opt.csv != NULL) {
        csv = fopen(opt.csv, "w");
        if (csv == NULL) {
            perror(opt.csv);
            return 1;
        }
        fprintf(csv, "code,operation,n,mean_ms,stddev_ms,min_ms,failures\n");
    }

    for (size_t i = 0; i < NUM_CODES; ++i) {
        Result r;
        int rc;

        if (!selected(&opt, codes[i].name))
            continue;

        ran = 1;
        fprintf(stderr, "running %s ...\n", codes[i].name);

        quiet_begin();
        rc = run_code(&codes[i], &opt, &r);
        quiet_end();

        if (rc != 0) {
            fprintf(stderr, "%s: benchmark failed (check --param values)\n", codes[i].name);
            status = 1;
        } else {
            report(out, csv, &codes[i], &opt, &r);
        }

        result_free(&r);
    }

    if (!ran) {
        fprintf(stderr, "no code selected\n");
        status = 2;
    }

    if (csv != NULL)
        fclose(csv);

    return status;
}
