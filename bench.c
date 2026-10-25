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
    double *values;
    size_t count;
    size_t capacity;
    size_t failures;
} Samples;

static int samples_init(Samples *samples, size_t capacity)
{
    samples->values = malloc((capacity ? capacity : 1) * sizeof(double));
    samples->count = 0;
    samples->capacity = capacity;
    samples->failures = 0;

    return samples->values != NULL ? 0 : -1;
}

static void samples_add(Samples *samples, double ms)
{
    if (samples->count < samples->capacity)
        samples->values[samples->count++] = ms;
}

typedef struct {
    double mean, stddev, min;
    size_t count;
} Stats;

static Stats stats_of(const Samples *samples)
{
    Stats stats = {0, 0, 0, samples->count};
    double sum = 0, squares = 0;

    if (samples->count == 0)
        return stats;

    stats.min = samples->values[0];
    for (size_t i = 0; i < samples->count; ++i) {
        sum += samples->values[i];
        if (samples->values[i] < stats.min)
            stats.min = samples->values[i];
    }
    stats.mean = sum / (double)samples->count;

    for (size_t i = 0; i < samples->count; ++i)
        squares += (samples->values[i] - stats.mean) * (samples->values[i] - stats.mean);
    stats.stddev = samples->count > 1 ? sqrt(squares / (double)(samples->count - 1)) : 0;

    return stats;
}

/* element-wise sum of two sample sets of equal length (a + b of one round) */
static int samples_sum(Samples *out, const Samples *a, const Samples *b)
{
    size_t count = a->count < b->count ? a->count : b->count;

    if (samples_init(out, count) != 0)
        return -1;

    for (size_t i = 0; i < count; ++i)
        samples_add(out, a->values[i] + b->values[i]);

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
    Samples keygen_regular, keygen_anamorphic;
    Samples encode, decode, aencode, adecode;
    size_t regular_count, regular_bits, anamorphic_count, anamorphic_bits;
    int ok;
} CodeResult;

static void code_result_free(CodeResult *result)
{
    free(result->keygen_regular.values);
    free(result->keygen_anamorphic.values);
    free(result->encode.values);
    free(result->decode.values);
    free(result->aencode.values);
    free(result->adecode.values);
}

static int build_params(const BenchCode *code, const Options *opt, DemoParams *params)
{
    demo_params_defaults(params, code->ops->params);

    for (size_t i = 0; i < opt->num_overrides; ++i) {
        const ParamOverride *override = &opt->overrides[i];

        if (strcmp(override->code, code->name) == 0 &&
            demo_params_set(params, override->name, override->value) != 0)
            return -1;
    }

    return 0;
}

static int run_code(const BenchCode *code, const Options *opt, CodeResult *result)
{
    const DemoOps *ops = code->ops;
    DemoParams params;
    const size_t rounds = opt->keys * opt->ops;

    memset(result, 0, sizeof(*result));

    if (build_params(code, opt, &params) != 0)
        return -1;

    if (samples_init(&result->keygen_regular, opt->keys) != 0 ||
        samples_init(&result->keygen_anamorphic, opt->keys) != 0 ||
        samples_init(&result->encode, rounds) != 0 ||
        samples_init(&result->decode, rounds) != 0 ||
        samples_init(&result->aencode, rounds) != 0 ||
        samples_init(&result->adecode, rounds) != 0)
        return -1;

    for (size_t k = 0; k < opt->keys; ++k) {
        DemoKeys keys = {0};
        void *handle, *regular_only;
        double start;

        randombytes_buf(keys.regular, sizeof(keys.regular));
        randombytes_buf(keys.anamorphic, sizeof(keys.anamorphic));

        /* regular key generation (opening with the regular key only) */
        keys.have_regular = ops->regular_keys;
        keys.have_anamorphic = 0;
        start = now_ms();
        regular_only = ops->open(&params, &keys);
        const double t_regular = now_ms() - start;

        if (regular_only == NULL)
            return -1;
        ops->close(regular_only);

        /* with the anamorphic key as well */
        keys.have_anamorphic = 1;
        start = now_ms();
        handle = ops->open(&params, &keys);
        const double t_both = now_ms() - start;

        if (handle == NULL)
            return -1;

        if (ops->regular_keys)
            samples_add(&result->keygen_regular, t_regular);
        samples_add(&result->keygen_anamorphic, ops->regular_keys ? (t_both > t_regular ? t_both - t_regular : 0)
                                                      : t_both);

        /* one untimed round per key: first-use costs (cold caches, lazy
         * allocation) would otherwise dominate small samples */
        {
            DemoCiphertext ciphertext = {0}, aciphertext = {0};

            if (ops->encode(handle, code->message, &ciphertext) == 0) {
                ops->decode(handle, &ciphertext);
                demo_ct_free(&ciphertext);
            }
            if (ops->aencode(handle, code->message, code->amessage, &aciphertext) == 0) {
                ops->adecode(handle, &aciphertext);
                demo_ct_free(&aciphertext);
            }
        }

        for (size_t i = 0; i < opt->ops; ++i) {
            DemoCiphertext ciphertext = {0}, aciphertext = {0};

            start = now_ms();
            int code_status = ops->encode(handle, code->message, &ciphertext);
            samples_add(&result->encode, now_ms() - start);
            if (code_status != 0) {
                result->encode.failures++;
                continue;
            }

            start = now_ms();
            code_status = ops->decode(handle, &ciphertext);
            samples_add(&result->decode, now_ms() - start);
            if (code_status != 0)
                result->decode.failures++;

            start = now_ms();
            code_status = ops->aencode(handle, code->message, code->amessage, &aciphertext);
            samples_add(&result->aencode, now_ms() - start);
            if (code_status != 0) {
                result->aencode.failures++;
                demo_ct_free(&ciphertext);
                continue;
            }

            start = now_ms();
            code_status = ops->adecode(handle, &aciphertext);
            samples_add(&result->adecode, now_ms() - start);
            if (code_status != 0)
                result->adecode.failures++;

            if (result->regular_count == 0) {
                result->regular_count = ciphertext.count;
                result->regular_bits = ciphertext.bits;
                result->anamorphic_count = aciphertext.count;
                result->anamorphic_bits = aciphertext.bits;
            }

            demo_ct_free(&ciphertext);
            demo_ct_free(&aciphertext);
        }

        ops->close(handle);
    }

    result->ok = 1;

    return 0;
}

/* ------------------------------------------------------------------------
 * Reporting
 * ------------------------------------------------------------------------ */

static void print_row(FILE *out, const char *name, const Samples *samples)
{
    Stats stats = stats_of(samples);

    if (stats.count == 0) {
        fprintf(out, "  %-24s %10s\n", name, "n/a");
        return;
    }

    fprintf(out, "  %-24s %10.3f %10.3f %10.3f %7zu", name, stats.mean, stats.stddev, stats.min, stats.count);
    if (samples->failures > 0)
        fprintf(out, "   (%zu failed)", samples->failures);
    fprintf(out, "\n");
}

static void print_ratio(FILE *out, const char *name, const Samples *regular,
                        const Samples *anamorphic)
{
    Stats a = stats_of(regular), b = stats_of(anamorphic);

    if (a.count == 0 || b.count == 0 || a.mean <= 0)
        return;

    fprintf(out, "  %-24s x%-8.2f (%+.3f ms)\n", name, b.mean / a.mean, b.mean - a.mean);
}

static void csv_row(FILE *csv, const char *code, const char *op, const Samples *samples)
{
    Stats stats = stats_of(samples);

    if (csv != NULL && stats.count > 0)
        fprintf(csv, "%s,%s,%zu,%.6f,%.6f,%.6f,%zu\n", code, op, stats.count, stats.mean, stats.stddev,
                stats.min, samples->failures);
}

static void report(FILE *out, FILE *csv, const BenchCode *code, const Options *opt, CodeResult *result)
{
    Samples regular_total, anamorphic_total;
    int have_totals = samples_sum(&regular_total, &result->encode, &result->decode) == 0 &&
                      samples_sum(&anamorphic_total, &result->aencode, &result->adecode) == 0;

    fprintf(out, "\n== %s  (%zu key%s x %zu round%s)\n", code->name, opt->keys,
            opt->keys == 1 ? "" : "s", opt->ops, opt->ops == 1 ? "" : "s");
    fprintf(out, "  %-24s %10s %10s %10s %7s\n", "operation", "mean [ms]", "stddev", "min", "n");

    if (code->ops->regular_keys)
        print_row(out, "keygen (regular)", &result->keygen_regular);
    print_row(out, code->ops->regular_keys ? "keygen (anamorphic, +)" : "keygen (anamorphic)",
              &result->keygen_anamorphic);
    print_row(out, "encode", &result->encode);
    print_row(out, "aencode", &result->aencode);
    print_row(out, "decode", &result->decode);
    print_row(out, "adecode", &result->adecode);

    if (have_totals) {
        print_row(out, "encode + decode", &regular_total);
        print_row(out, "aencode + adecode", &anamorphic_total);
    }

    fprintf(out, "  anamorphic / regular:\n");
    print_ratio(out, "encode", &result->encode, &result->aencode);
    print_ratio(out, "decode", &result->decode, &result->adecode);
    if (have_totals)
        print_ratio(out, "encode + decode", &regular_total, &anamorphic_total);

    fprintf(out, "  ciphertext: regular %zu x %zu bits, anamorphic %zu x %zu bits\n",
            result->regular_count, result->regular_bits, result->anamorphic_count, result->anamorphic_bits);

    csv_row(csv, code->name, "keygen_regular", &result->keygen_regular);
    csv_row(csv, code->name, "keygen_anamorphic", &result->keygen_anamorphic);
    csv_row(csv, code->name, "encode", &result->encode);
    csv_row(csv, code->name, "aencode", &result->aencode);
    csv_row(csv, code->name, "decode", &result->decode);
    csv_row(csv, code->name, "adecode", &result->adecode);
    if (have_totals) {
        csv_row(csv, code->name, "encode_decode", &regular_total);
        csv_row(csv, code->name, "aencode_adecode", &anamorphic_total);
        free(regular_total.values);
        free(anamorphic_total.values);
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

static int parse_size(const char *samples, size_t *out)
{
    char *end;
    unsigned long long values = strtoull(samples, &end, 10);

    if (*samples == '\0' || *end != '\0' || values == 0)
        return -1;

    *out = (size_t)values;

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
        const char *argument = argv[i];
        const char *value = i + 1 < argc ? argv[i + 1] : NULL;

        if (strcmp(argument, "--keys") == 0 && value) {
            if (parse_size(value, &opt->keys) != 0) {
                fprintf(stderr, "--keys needs argument positive integer\n");
                return -1;
            }
            ++i;
        } else if (strcmp(argument, "--ops") == 0 && value) {
            if (parse_size(value, &opt->ops) != 0) {
                fprintf(stderr, "--ops needs argument positive integer\n");
                return -1;
            }
            ++i;
        } else if (strcmp(argument, "--codes") == 0 && value) {
            if (strlen(value) >= sizeof(opt->selection)) {
                fprintf(stderr, "--codes list too long\n");
                return -1;
            }
            strcpy(opt->selection, value);
            ++i;
        } else if (strcmp(argument, "--csv") == 0 && value) {
            opt->csv = value;
            ++i;
        } else if (strcmp(argument, "--param") == 0 && value) {
            ParamOverride *override;
            const char *colon = strchr(value, ':');
            const char *equals = strchr(value, '=');

            if (opt->num_overrides >= MAX_PARAM_OVERRIDES || !colon || !equals || colon > equals ||
                (size_t)(colon - value) >= sizeof(override->code) || (size_t)(equals - colon - 1) >= sizeof(override->name) ||
                strlen(equals + 1) >= sizeof(override->value)) {
                fprintf(stderr, "--param expects CODE:NAME=VALUE, got '%s'\n", value);
                return -1;
            }

            override = &opt->overrides[opt->num_overrides++];
            memset(override, 0, sizeof(*override));
            memcpy(override->code, value, (size_t)(colon - value));
            memcpy(override->name, colon + 1, (size_t)(equals - colon - 1));
            strcpy(override->value, equals + 1);
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
    char *token;

    if (strcmp(opt->selection, "all") == 0)
        return 1;

    strcpy(list, opt->selection);
    for (token = strtok(list, ","); token != NULL; token = strtok(NULL, ",")) {
        if (strcmp(token, name) == 0)
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
        CodeResult result;
        int code_status;

        if (!selected(&opt, codes[i].name))
            continue;

        ran = 1;
        fprintf(stderr, "running %s ...\n", codes[i].name);

        quiet_begin();
        code_status = run_code(&codes[i], &opt, &result);
        quiet_end();

        if (code_status != 0) {
            fprintf(stderr, "%s: benchmark failed (check --param values)\n", codes[i].name);
            status = 1;
        } else {
            report(out, csv, &codes[i], &opt, &result);
        }

        code_result_free(&result);
    }

    if (!ran) {
        fprintf(stderr, "no code selected\n");
        status = 2;
    }

    if (csv != NULL)
        fclose(csv);

    return status;
}
