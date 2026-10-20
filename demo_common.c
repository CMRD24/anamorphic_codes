#define _POSIX_C_SOURCE 200809L

#include "demo_common.h"

#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include <sodium.h>

#include "utils/csprg_sodium.h"

/* ------------------------------------------------------------------------
 * Parameters
 * ------------------------------------------------------------------------ */

static int spec_index(const DemoParamSpec *specs, const char *name)
{
    for (size_t i = 0; specs[i].name != NULL; ++i) {
        if (strcmp(specs[i].name, name) == 0)
            return (int)i;
    }

    return -1;
}

static void params_defaults(DemoParams *p, const DemoParamSpec *specs)
{
    memset(p, 0, sizeof(*p));
    p->specs = specs;

    for (size_t i = 0; specs[i].name != NULL; ++i) {
        strncpy(p->values[i], specs[i].default_value, sizeof(p->values[i]) - 1);
    }
}

static int params_set(DemoParams *p, const char *name, const char *value)
{
    int i = spec_index(p->specs, name);

    if (i < 0) {
        fprintf(stderr, "unknown parameter '%s'\n", name);
        return -1;
    }

    if (strlen(value) >= sizeof(p->values[i])) {
        fprintf(stderr, "value of '%s' is too long\n", name);
        return -1;
    }

    strcpy(p->values[i], value);

    return 0;
}

const char *demo_param(const DemoParams *p, const char *name)
{
    int i = spec_index(p->specs, name);

    return i < 0 ? "" : p->values[i];
}

size_t demo_param_size(const DemoParams *p, const char *name)
{
    return (size_t)strtoull(demo_param(p, name), NULL, 10);
}

double demo_param_double(const DemoParams *p, const char *name)
{
    return strtod(demo_param(p, name), NULL);
}

static int params_save(const DemoParams *p, const char *path)
{
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        perror(path);
        return -1;
    }

    for (size_t i = 0; p->specs[i].name != NULL; ++i)
        fprintf(f, "%s=%s\n", p->specs[i].name, p->values[i]);

    fclose(f);

    return 0;
}

/* a missing file means "all defaults" */
static int params_load(DemoParams *p, const DemoParamSpec *specs, const char *path)
{
    char line[256];
    FILE *f;

    params_defaults(p, specs);

    f = fopen(path, "r");
    if (f == NULL)
        return 0;

    while (fgets(line, sizeof(line), f) != NULL) {
        char *eq = strchr(line, '=');

        if (eq == NULL)
            continue;

        *eq = '\0';
        eq[1 + strcspn(eq + 1, "\r\n")] = '\0';

        /* parameters unknown to this version are ignored */
        if (spec_index(specs, line) >= 0)
            params_set(p, line, eq + 1);
    }

    fclose(f);

    return 0;
}

/* ------------------------------------------------------------------------
 * Keys
 * ------------------------------------------------------------------------ */

RandomnessSource demo_key_stream(const uint8_t key[DEMO_KEY_BYTES], uint8_t domain)
{
    uint8_t seed[DEMO_KEY_BYTES + 1];

    memcpy(seed, key, DEMO_KEY_BYTES);
    seed[DEMO_KEY_BYTES] = domain;

    return csprg_randomness(seed, sizeof(seed));
}

static void to_hex(const uint8_t *in, size_t len, char *out)
{
    static const char digits[] = "0123456789abcdef";

    for (size_t i = 0; i < len; ++i) {
        out[2 * i] = digits[in[i] >> 4];
        out[2 * i + 1] = digits[in[i] & 15];
    }

    out[2 * len] = '\0';
}

static int hex_value(int c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

/* parses exactly len bytes of hex, ignoring surrounding whitespace */
static int from_hex(const char *in, uint8_t *out, size_t len)
{
    size_t n = 0;

    while (isspace((unsigned char)*in))
        ++in;

    for (; n < len; ++n) {
        int hi = hex_value(in[2 * n]);
        int lo = hi < 0 ? -1 : hex_value(in[2 * n + 1]);

        if (hi < 0 || lo < 0)
            return -1;

        out[n] = (uint8_t)(hi << 4 | lo);
    }

    in += 2 * len;
    while (isspace((unsigned char)*in))
        ++in;

    return *in == '\0' ? 0 : -1;
}

static int key_write(const char *path, const uint8_t key[DEMO_KEY_BYTES])
{
    char hex[2 * DEMO_KEY_BYTES + 1];
    FILE *f = fopen(path, "w");

    if (f == NULL) {
        perror(path);
        return -1;
    }

    to_hex(key, DEMO_KEY_BYTES, hex);
    fprintf(f, "%s\n", hex);
    fclose(f);

    return 0;
}

/* 0: read, 1: file missing, -1: malformed */
static int key_read(const char *path, uint8_t key[DEMO_KEY_BYTES])
{
    char hex[2 * DEMO_KEY_BYTES + 8] = {0};
    FILE *f = fopen(path, "r");

    if (f == NULL)
        return 1;

    if (fgets(hex, sizeof(hex), f) == NULL) {
        fclose(f);
        return -1;
    }

    fclose(f);

    return from_hex(hex, key, DEMO_KEY_BYTES) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------------
 * Ciphertexts: "demo-ciphertext", "<count> <bits>", one hex line per codeword
 * ------------------------------------------------------------------------ */

int demo_ct_alloc(DemoCiphertext *ct, size_t count, size_t bits)
{
    size_t bytes = (bits + 7) / 8;

    ct->count = 0;
    ct->bits = bits;
    ct->data = calloc(count ? count : 1, sizeof(*ct->data));

    if (ct->data == NULL)
        return -1;

    for (size_t i = 0; i < count; ++i) {
        ct->data[i] = calloc(bytes ? bytes : 1, 1);

        if (ct->data[i] == NULL) {
            ct->count = i;
            demo_ct_free(ct);
            return -1;
        }
    }

    ct->count = count;

    return 0;
}

void demo_ct_free(DemoCiphertext *ct)
{
    if (ct->data != NULL) {
        for (size_t i = 0; i < ct->count; ++i)
            free(ct->data[i]);

        free(ct->data);
    }

    ct->data = NULL;
    ct->count = 0;
}

static int ct_write(const char *path, const DemoCiphertext *ct)
{
    size_t bytes = (ct->bits + 7) / 8;
    char *hex = malloc(2 * bytes + 1);
    FILE *f = fopen(path, "w");

    if (f == NULL || hex == NULL) {
        if (f == NULL)
            perror(path);
        else
            fclose(f);
        free(hex);
        return -1;
    }

    fprintf(f, "demo-ciphertext\n%zu %zu\n", ct->count, ct->bits);

    for (size_t i = 0; i < ct->count; ++i) {
        to_hex(ct->data[i], bytes, hex);
        fprintf(f, "%s\n", hex);
    }

    free(hex);
    fclose(f);

    return 0;
}

static int ct_read(const char *path, DemoCiphertext *ct)
{
    char header[64];
    size_t count, bits, bytes;
    char *line = NULL;
    FILE *f = fopen(path, "r");

    memset(ct, 0, sizeof(*ct));

    if (f == NULL) {
        perror(path);
        return -1;
    }

    if (fgets(header, sizeof(header), f) == NULL ||
        strncmp(header, "demo-ciphertext", 15) != 0 ||
        fgets(header, sizeof(header), f) == NULL ||
        sscanf(header, "%zu %zu", &count, &bits) != 2 ||
        count == 0 || bits == 0 || count > (1u << 20) || bits > (1u << 30)) {
        fprintf(stderr, "%s: not a ciphertext file\n", path);
        fclose(f);
        return -1;
    }

    bytes = (bits + 7) / 8;
    line = malloc(2 * bytes + 8);

    if (line == NULL || demo_ct_alloc(ct, count, bits) != 0) {
        free(line);
        fclose(f);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        if (fgets(line, (int)(2 * bytes + 8), f) == NULL ||
            from_hex(line, ct->data[i], bytes) != 0) {
            fprintf(stderr, "%s: malformed codeword %zu\n", path, i);
            demo_ct_free(ct);
            free(line);
            fclose(f);
            return -1;
        }
    }

    free(line);
    fclose(f);

    return 0;
}

/* ------------------------------------------------------------------------
 * Messages
 * ------------------------------------------------------------------------ */

int demo_pad_message(const char *s, uint8_t *buf, size_t len)
{
    size_t n = s == NULL ? 0 : strlen(s);

    if (n > len) {
        fprintf(stderr, "message too long: %zu bytes, at most %zu\n", n, len);
        return -1;
    }

    memset(buf, 0, len);
    if (n > 0)
        memcpy(buf, s, n);

    return 0;
}

void demo_print_bytes(const char *label, const uint8_t *buf, size_t len)
{
    int printable = 1;
    char *hex;

    while (len > 0 && buf[len - 1] == 0)
        --len;

    for (size_t i = 0; i < len; ++i) {
        if (!isprint(buf[i]))
            printable = 0;
    }

    if (printable) {
        printf("%s: %.*s\n", label, (int)len, (const char *)buf);
        return;
    }

    hex = malloc(2 * len + 1);
    if (hex == NULL)
        return;

    to_hex(buf, len, hex);
    printf("%s (hex): %s\n", label, hex);
    free(hex);
}

/* ------------------------------------------------------------------------
 * Commands
 * ------------------------------------------------------------------------ */

typedef struct {
    const DemoOps *ops;
    const char *dir;
    char params_path[512];
    char regular_path[512];
    char anamorphic_path[512];
} DemoState;

static void usage(const DemoOps *ops)
{
    const char *n = ops->name;

    fprintf(stderr,
        "usage: demo_%s [--dir DIR] <command> ...\n"
        "\n"
        "  setup [name=value ...]    write the parameters (shown below)\n",
        n);

    if (ops->regular_keys)
        fprintf(stderr, "  keygen                    generate the regular key\n");

    if (ops->anamorphic)
        fprintf(stderr, "  akeygen                   generate the anamorphic key\n");

    fprintf(stderr, "  export-key %s FILE\n", ops->anamorphic ? (ops->regular_keys ? "regular|anamorphic" : "anamorphic") : "regular");
    fprintf(stderr, "  import-key %s FILE\n", ops->anamorphic ? (ops->regular_keys ? "regular|anamorphic" : "anamorphic") : "regular");
    fprintf(stderr, "  encode [MESSAGE] CIPHERTEXT\n");
    fprintf(stderr, "  decode CIPHERTEXT\n");

    if (ops->anamorphic) {
        fprintf(stderr, "  aencode AMESSAGE [MESSAGE] CIPHERTEXT\n");
        fprintf(stderr, "  adecode CIPHERTEXT\n");
    }

    fprintf(stderr, "\nparameters (default):\n");
    for (size_t i = 0; ops->params[i].name != NULL; ++i) {
        fprintf(stderr, "  %-16s %-8s %s\n", ops->params[i].name,
                ops->params[i].default_value, ops->params[i].help);
    }
}

static int load_state(const DemoState *st, DemoParams *params, DemoKeys *keys)
{
    int rc;

    memset(keys, 0, sizeof(*keys));
    params_load(params, st->ops->params, st->params_path);

    rc = key_read(st->regular_path, keys->regular);
    if (rc < 0) {
        fprintf(stderr, "%s: malformed key\n", st->regular_path);
        return -1;
    }
    keys->have_regular = rc == 0;

    rc = key_read(st->anamorphic_path, keys->anamorphic);
    if (rc < 0) {
        fprintf(stderr, "%s: malformed key\n", st->anamorphic_path);
        return -1;
    }
    keys->have_anamorphic = rc == 0;

    return 0;
}

static int cmd_setup(DemoState *st, int argc, char **argv)
{
    DemoParams params;
    DemoKeys keys = {0};
    void *handle;

    params_load(&params, st->ops->params, st->params_path);

    for (int i = 0; i < argc; ++i) {
        char *eq = strchr(argv[i], '=');
        char name[64];

        if (eq == NULL || (size_t)(eq - argv[i]) >= sizeof(name)) {
            fprintf(stderr, "expected name=value, got '%s'\n", argv[i]);
            return -1;
        }

        memcpy(name, argv[i], (size_t)(eq - argv[i]));
        name[eq - argv[i]] = '\0';

        if (params_set(&params, name, eq + 1) != 0)
            return -1;
    }

    /* check the parameters by building the code with throw-away keys */
    randombytes_buf(keys.regular, sizeof(keys.regular));
    randombytes_buf(keys.anamorphic, sizeof(keys.anamorphic));
    keys.have_regular = keys.have_anamorphic = 1;

    handle = st->ops->open(&params, &keys);
    if (handle == NULL)
        return -1;
    st->ops->close(handle);

    if (params_save(&params, st->params_path) != 0)
        return -1;

    for (size_t i = 0; st->ops->params[i].name != NULL; ++i)
        printf("%s=%s\n", st->ops->params[i].name, params.values[i]);

    return 0;
}

static int cmd_keygen(DemoState *st, int anamorphic)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = anamorphic ? st->anamorphic_path : st->regular_path;

    if (anamorphic ? !st->ops->anamorphic : !st->ops->regular_keys) {
        fprintf(stderr, "demo_%s has no %s key\n", st->ops->name,
                anamorphic ? "anamorphic" : "regular");
        return -1;
    }

    randombytes_buf(key, sizeof(key));

    if (key_write(path, key) != 0)
        return -1;

    printf("%s key written to %s\n", anamorphic ? "anamorphic" : "regular", path);

    return 0;
}

/* which: "regular" or "anamorphic"; returns the state path or NULL */
static const char *key_path(const DemoState *st, const char *which)
{
    if (strcmp(which, "regular") == 0 && st->ops->regular_keys)
        return st->regular_path;

    if (strcmp(which, "anamorphic") == 0 && st->ops->anamorphic)
        return st->anamorphic_path;

    fprintf(stderr, "demo_%s has no %s key\n", st->ops->name, which);

    return NULL;
}

static int cmd_export(const DemoState *st, const char *which, const char *file)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = key_path(st, which);

    if (path == NULL)
        return -1;

    if (key_read(path, key) != 0) {
        fprintf(stderr, "no %s key, run %s first\n", which,
                strcmp(which, "regular") == 0 ? "keygen" : "akeygen");
        return -1;
    }

    if (key_write(file, key) != 0)
        return -1;

    printf("%s key exported to %s\n", which, file);

    return 0;
}

static int cmd_import(const DemoState *st, const char *which, const char *file)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = key_path(st, which);

    if (path == NULL)
        return -1;

    if (key_read(file, key) != 0) {
        fprintf(stderr, "%s: cannot read a key (expected %d hex digits)\n", file,
                2 * DEMO_KEY_BYTES);
        return -1;
    }

    if (key_write(path, key) != 0)
        return -1;

    printf("%s key imported from %s\n", which, file);

    return 0;
}

/* opens the code; the keys needed by the operation must be present */
static void *open_code(const DemoState *st, int need_regular, int need_anamorphic)
{
    DemoParams params;
    DemoKeys keys;

    if (load_state(st, &params, &keys) != 0)
        return NULL;

    if (need_regular && st->ops->regular_keys && !keys.have_regular) {
        fprintf(stderr, "no regular key: run keygen or import-key regular\n");
        return NULL;
    }

    if (need_anamorphic && !keys.have_anamorphic) {
        fprintf(stderr, "no anamorphic key: run akeygen or import-key anamorphic\n");
        return NULL;
    }

    return st->ops->open(&params, &keys);
}

static int cmd_encode(const DemoState *st, int anamorphic, int argc, char **argv)
{
    const char *message = NULL, *amessage = NULL, *file;
    DemoCiphertext ct = {0};
    void *handle;
    int rc;

    if (anamorphic) {
        if (argc < 2 || argc > 3)
            return -2;
        amessage = argv[0];
        message = argc == 3 ? argv[1] : NULL;
    } else {
        if (argc < 1 || argc > 2)
            return -2;
        message = argc == 2 ? argv[0] : NULL;
    }
    file = argv[argc - 1];

    handle = open_code(st, 1, anamorphic);
    if (handle == NULL)
        return -1;

    rc = anamorphic ? st->ops->aencode(handle, message, amessage, &ct)
                    : st->ops->encode(handle, message, &ct);

    if (rc == 0)
        rc = ct_write(file, &ct);

    if (rc == 0)
        printf("wrote %zu codeword%s of %zu bits to %s\n", ct.count,
               ct.count == 1 ? "" : "s", ct.bits, file);

    demo_ct_free(&ct);
    st->ops->close(handle);

    return rc;
}

static int cmd_decode(const DemoState *st, int anamorphic, const char *file)
{
    DemoCiphertext ct;
    void *handle;
    int rc;

    if (ct_read(file, &ct) != 0)
        return -1;

    handle = open_code(st, 1, anamorphic);
    if (handle == NULL) {
        demo_ct_free(&ct);
        return -1;
    }

    rc = anamorphic ? st->ops->adecode(handle, &ct) : st->ops->decode(handle, &ct);

    demo_ct_free(&ct);
    st->ops->close(handle);

    return rc;
}

int demo_main(const DemoOps *ops, int argc, char **argv)
{
    DemoState st = {.ops = ops};
    char default_dir[128];
    const char *cmd;
    int rc = -1;

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
        return 1;
    }

    ++argv;
    --argc;

    snprintf(default_dir, sizeof(default_dir), "%s_demo", ops->name);
    st.dir = default_dir;

    if (argc >= 2 && strcmp(argv[0], "--dir") == 0) {
        st.dir = argv[1];
        argv += 2;
        argc -= 2;
    }

    if (argc < 1) {
        usage(ops);
        return 2;
    }

    cmd = argv[0];
    ++argv;
    --argc;

    mkdir(st.dir, 0777);
    snprintf(st.params_path, sizeof(st.params_path), "%s/params.txt", st.dir);
    snprintf(st.regular_path, sizeof(st.regular_path), "%s/key.regular", st.dir);
    snprintf(st.anamorphic_path, sizeof(st.anamorphic_path), "%s/key.anamorphic", st.dir);

    if (strcmp(cmd, "setup") == 0) {
        rc = cmd_setup(&st, argc, argv);
    } else if (strcmp(cmd, "keygen") == 0 && argc == 0) {
        rc = cmd_keygen(&st, 0);
    } else if (strcmp(cmd, "akeygen") == 0 && argc == 0) {
        rc = cmd_keygen(&st, 1);
    } else if (strcmp(cmd, "export-key") == 0 && argc == 2) {
        rc = cmd_export(&st, argv[0], argv[1]);
    } else if (strcmp(cmd, "import-key") == 0 && argc == 2) {
        rc = cmd_import(&st, argv[0], argv[1]);
    } else if (strcmp(cmd, "encode") == 0) {
        rc = cmd_encode(&st, 0, argc, argv);
    } else if (strcmp(cmd, "aencode") == 0 && ops->anamorphic) {
        rc = cmd_encode(&st, 1, argc, argv);
    } else if (strcmp(cmd, "decode") == 0 && argc == 1) {
        rc = cmd_decode(&st, 0, argv[0]);
    } else if (strcmp(cmd, "adecode") == 0 && argc == 1 && ops->anamorphic) {
        rc = cmd_decode(&st, 1, argv[0]);
    } else {
        rc = -2;
    }

    if (rc == -2) {
        usage(ops);
        return 2;
    }

    return rc == 0 ? 0 : 1;
}
