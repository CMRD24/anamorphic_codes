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

void demo_params_defaults(DemoParams *params, const DemoParamSpec *specs)
{
    memset(params, 0, sizeof(*params));
    params->specs = specs;

    for (size_t i = 0; specs[i].name != NULL; ++i) {
        strncpy(params->values[i], specs[i].default_value, sizeof(params->values[i]) - 1);
    }
}

int demo_params_set(DemoParams *params, const char *name, const char *value)
{
    int i = spec_index(params->specs, name);

    if (i < 0) {
        fprintf(stderr, "unknown parameter '%s'\n", name);
        return -1;
    }

    if (strlen(value) >= sizeof(params->values[i])) {
        fprintf(stderr, "value of '%s' is too long\n", name);
        return -1;
    }

    strcpy(params->values[i], value);

    return 0;
}

const char *demo_param(const DemoParams *params, const char *name)
{
    int i = spec_index(params->specs, name);

    return i < 0 ? "" : params->values[i];
}

size_t demo_param_size(const DemoParams *params, const char *name)
{
    return (size_t)strtoull(demo_param(params, name), NULL, 10);
}

/* a decimal number or a fraction "a/b" */
double demo_param_double(const DemoParams *params, const char *name)
{
    char *end;
    const double value = strtod(demo_param(params, name), &end);

    if (*end == '/')
        return value / strtod(end + 1, NULL);

    return value;
}

static int params_save(const DemoParams *params, const char *path)
{
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    for (size_t i = 0; params->specs[i].name != NULL; ++i)
        fprintf(file, "%s=%s\n", params->specs[i].name, params->values[i]);

    fclose(file);

    return 0;
}

/* a missing file means "all defaults" */
static int params_load(DemoParams *params, const DemoParamSpec *specs, const char *path)
{
    char line[256];
    FILE *file;

    demo_params_defaults(params, specs);

    file = fopen(path, "r");
    if (file == NULL)
        return 0;

    while (fgets(line, sizeof(line), file) != NULL) {
        char *equals = strchr(line, '=');

        if (equals == NULL)
            continue;

        *equals = '\0';
        equals[1 + strcspn(equals + 1, "\r\n")] = '\0';

        /* parameters unknown to this version are ignored */
        if (spec_index(specs, line) >= 0)
            demo_params_set(params, line, equals + 1);
    }

    fclose(file);

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
    size_t count = 0;

    while (isspace((unsigned char)*in))
        ++in;

    for (; count < len; ++count) {
        int high = hex_value(in[2 * count]);
        int low = high < 0 ? -1 : hex_value(in[2 * count + 1]);

        if (high < 0 || low < 0)
            return -1;

        out[count] = (uint8_t)(high << 4 | low);
    }

    in += 2 * len;
    while (isspace((unsigned char)*in))
        ++in;

    return *in == '\0' ? 0 : -1;
}

static int key_write(const char *path, const uint8_t key[DEMO_KEY_BYTES])
{
    char hex[2 * DEMO_KEY_BYTES + 1];
    FILE *file = fopen(path, "w");

    if (file == NULL) {
        perror(path);
        return -1;
    }

    to_hex(key, DEMO_KEY_BYTES, hex);
    fprintf(file, "%s\n", hex);
    fclose(file);

    return 0;
}

/* 0: read, 1: file missing, -1: malformed */
static int key_read(const char *path, uint8_t key[DEMO_KEY_BYTES])
{
    char hex[2 * DEMO_KEY_BYTES + 8] = {0};
    FILE *file = fopen(path, "r");

    if (file == NULL)
        return 1;

    if (fgets(hex, sizeof(hex), file) == NULL) {
        fclose(file);
        return -1;
    }

    fclose(file);

    return from_hex(hex, key, DEMO_KEY_BYTES) == 0 ? 0 : -1;
}

/* ------------------------------------------------------------------------
 * Ciphertexts: "demo-ciphertext", "<count> <bits>", one hex line per codeword
 * ------------------------------------------------------------------------ */

int demo_ct_alloc(DemoCiphertext *ciphertext, size_t count, size_t bits)
{
    size_t bytes = (bits + 7) / 8;

    ciphertext->count = 0;
    ciphertext->bits = bits;
    ciphertext->data = calloc(count ? count : 1, sizeof(*ciphertext->data));

    if (ciphertext->data == NULL)
        return -1;

    for (size_t i = 0; i < count; ++i) {
        ciphertext->data[i] = calloc(bytes ? bytes : 1, 1);

        if (ciphertext->data[i] == NULL) {
            ciphertext->count = i;
            demo_ct_free(ciphertext);
            return -1;
        }
    }

    ciphertext->count = count;

    return 0;
}

void demo_ct_free(DemoCiphertext *ciphertext)
{
    if (ciphertext->data != NULL) {
        for (size_t i = 0; i < ciphertext->count; ++i)
            free(ciphertext->data[i]);

        free(ciphertext->data);
    }

    ciphertext->data = NULL;
    ciphertext->count = 0;
}

static int ct_write(const char *path, const DemoCiphertext *ciphertext)
{
    size_t bytes = (ciphertext->bits + 7) / 8;
    char *hex = malloc(2 * bytes + 1);
    FILE *file = fopen(path, "w");

    if (file == NULL || hex == NULL) {
        if (file == NULL)
            perror(path);
        else
            fclose(file);
        free(hex);
        return -1;
    }

    fprintf(file, "demo-ciphertext\n%zu %zu\n", ciphertext->count, ciphertext->bits);

    for (size_t i = 0; i < ciphertext->count; ++i) {
        to_hex(ciphertext->data[i], bytes, hex);
        fprintf(file, "%s\n", hex);
    }

    free(hex);
    fclose(file);

    return 0;
}

static int ct_read(const char *path, DemoCiphertext *ciphertext)
{
    char header[64];
    size_t count, bits, bytes;
    char *line = NULL;
    FILE *file = fopen(path, "r");

    memset(ciphertext, 0, sizeof(*ciphertext));

    if (file == NULL) {
        perror(path);
        return -1;
    }

    if (fgets(header, sizeof(header), file) == NULL ||
        strncmp(header, "demo-ciphertext", 15) != 0 ||
        fgets(header, sizeof(header), file) == NULL ||
        sscanf(header, "%zu %zu", &count, &bits) != 2 ||
        count == 0 || bits == 0 || count > (1u << 20) || bits > (1u << 30)) {
        fprintf(stderr, "%s: not a ciphertext file\n", path);
        fclose(file);
        return -1;
    }

    bytes = (bits + 7) / 8;
    line = malloc(2 * bytes + 8);

    if (line == NULL || demo_ct_alloc(ciphertext, count, bits) != 0) {
        free(line);
        fclose(file);
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        if (fgets(line, (int)(2 * bytes + 8), file) == NULL ||
            from_hex(line, ciphertext->data[i], bytes) != 0) {
            fprintf(stderr, "%s: malformed codeword %zu\n", path, i);
            demo_ct_free(ciphertext);
            free(line);
            fclose(file);
            return -1;
        }
    }

    free(line);
    fclose(file);

    return 0;
}

/* ------------------------------------------------------------------------
 * Messages
 * ------------------------------------------------------------------------ */

#define HEX_PREFIX "hex:"
#define HEX_PREFIX_LENGTH (sizeof(HEX_PREFIX) - 1)

static int is_hex_message(const char *text)
{
    return text != NULL && strncmp(text, HEX_PREFIX, HEX_PREFIX_LENGTH) == 0;
}

size_t demo_message_length(const char *text)
{
    if (text == NULL)
        return 0;

    if (is_hex_message(text))
        return strlen(text + HEX_PREFIX_LENGTH) / 2;

    return strlen(text);
}

int demo_pad_message(const char *text, uint8_t *buffer, size_t len)
{
    const size_t length = demo_message_length(text);

    if (length > len) {
        fprintf(stderr, "message too long: %zu bytes, at most %zu\n", length, len);
        return -1;
    }

    memset(buffer, 0, len);

    if (is_hex_message(text)) {
        const char *digits = text + HEX_PREFIX_LENGTH;

        if (strlen(digits) % 2 != 0 || from_hex(digits, buffer, length) != 0) {
            fprintf(stderr, "malformed hex message\n");
            return -1;
        }
    } else if (length > 0) {
        memcpy(buffer, text, length);
    }

    return 0;
}

char *demo_random_message(size_t bits)
{
    const size_t bytes = (bits + 7) / 8;
    uint8_t *buffer = malloc(bytes ? bytes : 1);
    char *text = malloc(HEX_PREFIX_LENGTH + 2 * bytes + 1);

    if (buffer == NULL || text == NULL) {
        free(buffer);
        free(text);
        return NULL;
    }

    randombytes_buf(buffer, bytes);
    if (bits % 8 != 0)
        buffer[bytes - 1] &= (uint8_t)((1u << (bits % 8)) - 1);

    memcpy(text, HEX_PREFIX, HEX_PREFIX_LENGTH);
    to_hex(buffer, bytes, text + HEX_PREFIX_LENGTH);
    free(buffer);

    return text;
}

void demo_print_bytes(const char *label, const uint8_t *buffer, size_t len)
{
    int printable = 1;
    char *hex;

    while (len > 0 && buffer[len - 1] == 0)
        --len;

    for (size_t i = 0; i < len; ++i) {
        if (!isprint(buffer[i]))
            printable = 0;
    }

    if (printable) {
        printf("%s: %.*s\n", label, (int)len, (const char *)buffer);
        return;
    }

    hex = malloc(2 * len + 1);
    if (hex == NULL)
        return;

    to_hex(buffer, len, hex);
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
    const char *name = ops->name;

    fprintf(stderr,
        "usage: demo_%s [--dir DIR] <command> ...\n"
        "\n"
        "  setup [name=value ...]    write the parameters (shown below)\n",
        name);

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

    fprintf(stderr, "\nmessages are text, or hex:<hex digits> for arbitrary bytes\n");
    fprintf(stderr, "\nparameters (default):\n");
    for (size_t i = 0; ops->params[i].name != NULL; ++i) {
        fprintf(stderr, "  %-16s %-8s %s\n", ops->params[i].name,
                ops->params[i].default_value, ops->params[i].help);
    }
}

static int load_state(const DemoState *state, DemoParams *params, DemoKeys *keys)
{
    int result;

    memset(keys, 0, sizeof(*keys));
    params_load(params, state->ops->params, state->params_path);

    result = key_read(state->regular_path, keys->regular);
    if (result < 0) {
        fprintf(stderr, "%s: malformed key\n", state->regular_path);
        return -1;
    }
    keys->have_regular = result == 0;

    result = key_read(state->anamorphic_path, keys->anamorphic);
    if (result < 0) {
        fprintf(stderr, "%s: malformed key\n", state->anamorphic_path);
        return -1;
    }
    keys->have_anamorphic = result == 0;

    return 0;
}

static int cmd_setup(DemoState *state, int argc, char **argv)
{
    DemoParams params;
    DemoKeys keys = {0};
    void *handle;

    params_load(&params, state->ops->params, state->params_path);

    for (int i = 0; i < argc; ++i) {
        char *equals = strchr(argv[i], '=');
        char name[64];

        if (equals == NULL || (size_t)(equals - argv[i]) >= sizeof(name)) {
            fprintf(stderr, "expected name=value, got '%s'\n", argv[i]);
            return -1;
        }

        memcpy(name, argv[i], (size_t)(equals - argv[i]));
        name[equals - argv[i]] = '\0';

        if (demo_params_set(&params, name, equals + 1) != 0)
            return -1;
    }

    /* check the parameters by building the code with throw-away keys */
    randombytes_buf(keys.regular, sizeof(keys.regular));
    randombytes_buf(keys.anamorphic, sizeof(keys.anamorphic));
    keys.have_regular = keys.have_anamorphic = 1;

    handle = state->ops->open(&params, &keys);
    if (handle == NULL)
        return -1;
    state->ops->close(handle);

    if (params_save(&params, state->params_path) != 0)
        return -1;

    for (size_t i = 0; state->ops->params[i].name != NULL; ++i)
        printf("%s=%s\n", state->ops->params[i].name, params.values[i]);

    return 0;
}

static int cmd_keygen(DemoState *state, int anamorphic)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = anamorphic ? state->anamorphic_path : state->regular_path;

    if (anamorphic ? !state->ops->anamorphic : !state->ops->regular_keys) {
        fprintf(stderr, "demo_%s has no %s key\n", state->ops->name,
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
static const char *key_path(const DemoState *state, const char *which)
{
    if (strcmp(which, "regular") == 0 && state->ops->regular_keys)
        return state->regular_path;

    if (strcmp(which, "anamorphic") == 0 && state->ops->anamorphic)
        return state->anamorphic_path;

    fprintf(stderr, "demo_%s has no %s key\n", state->ops->name, which);

    return NULL;
}

static int cmd_export(const DemoState *state, const char *which, const char *file)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = key_path(state, which);

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

static int cmd_import(const DemoState *state, const char *which, const char *file)
{
    uint8_t key[DEMO_KEY_BYTES];
    const char *path = key_path(state, which);

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
static void *open_code(const DemoState *state, int need_regular, int need_anamorphic)
{
    DemoParams params;
    DemoKeys keys;

    if (load_state(state, &params, &keys) != 0)
        return NULL;

    if (need_regular && state->ops->regular_keys && !keys.have_regular) {
        fprintf(stderr, "no regular key: run keygen or import-key regular\n");
        return NULL;
    }

    if (need_anamorphic && !keys.have_anamorphic) {
        fprintf(stderr, "no anamorphic key: run akeygen or import-key anamorphic\n");
        return NULL;
    }

    return state->ops->open(&params, &keys);
}

static int cmd_encode(const DemoState *state, int anamorphic, int argc, char **argv)
{
    const char *message = NULL, *amessage = NULL, *file;
    DemoCiphertext ciphertext = {0};
    void *handle;
    int result;

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

    handle = open_code(state, 1, anamorphic);
    if (handle == NULL)
        return -1;

    result = anamorphic ? state->ops->aencode(handle, message, amessage, &ciphertext)
                    : state->ops->encode(handle, message, &ciphertext);

    if (result == 0)
        result = ct_write(file, &ciphertext);

    if (result == 0)
        printf("wrote %zu codeword%s of %zu bits to %s\n", ciphertext.count,
               ciphertext.count == 1 ? "" : "s", ciphertext.bits, file);

    demo_ct_free(&ciphertext);
    state->ops->close(handle);

    return result;
}

static int cmd_decode(const DemoState *state, int anamorphic, const char *file)
{
    DemoCiphertext ciphertext;
    void *handle;
    int result;

    if (ct_read(file, &ciphertext) != 0)
        return -1;

    handle = open_code(state, 1, anamorphic);
    if (handle == NULL) {
        demo_ct_free(&ciphertext);
        return -1;
    }

    result = anamorphic ? state->ops->adecode(handle, &ciphertext) : state->ops->decode(handle, &ciphertext);

    demo_ct_free(&ciphertext);
    state->ops->close(handle);

    return result;
}

int demo_main(const DemoOps *ops, int argc, char **argv)
{
    DemoState state = {.ops = ops};
    char default_dir[128];
    const char *cmd;
    int result = -1;

    if (sodium_init() < 0) {
        fprintf(stderr, "libsodium initialisation failed\n");
        return 1;
    }

    ++argv;
    --argc;

    snprintf(default_dir, sizeof(default_dir), "%s_demo", ops->name);
    state.dir = default_dir;

    if (argc >= 2 && strcmp(argv[0], "--dir") == 0) {
        state.dir = argv[1];
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

    mkdir(state.dir, 0777);
    snprintf(state.params_path, sizeof(state.params_path), "%s/params.txt", state.dir);
    snprintf(state.regular_path, sizeof(state.regular_path), "%s/key.regular", state.dir);
    snprintf(state.anamorphic_path, sizeof(state.anamorphic_path), "%s/key.anamorphic", state.dir);

    if (strcmp(cmd, "setup") == 0) {
        result = cmd_setup(&state, argc, argv);
    } else if (strcmp(cmd, "keygen") == 0 && argc == 0) {
        result = cmd_keygen(&state, 0);
    } else if (strcmp(cmd, "akeygen") == 0 && argc == 0) {
        result = cmd_keygen(&state, 1);
    } else if (strcmp(cmd, "export-key") == 0 && argc == 2) {
        result = cmd_export(&state, argv[0], argv[1]);
    } else if (strcmp(cmd, "import-key") == 0 && argc == 2) {
        result = cmd_import(&state, argv[0], argv[1]);
    } else if (strcmp(cmd, "encode") == 0) {
        result = cmd_encode(&state, 0, argc, argv);
    } else if (strcmp(cmd, "aencode") == 0 && ops->anamorphic) {
        result = cmd_encode(&state, 1, argc, argv);
    } else if (strcmp(cmd, "decode") == 0 && argc == 1) {
        result = cmd_decode(&state, 0, argv[0]);
    } else if (strcmp(cmd, "adecode") == 0 && argc == 1 && ops->anamorphic) {
        result = cmd_decode(&state, 1, argv[0]);
    } else {
        result = -2;
    }

    if (result == -2) {
        usage(ops);
        return 2;
    }

    return result == 0 ? 0 : 1;
}
