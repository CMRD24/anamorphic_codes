#ifndef DEMO_COMMON_H
#define DEMO_COMMON_H

/*
 * Shared command line front end of the demo_<code> programs.
 *
 *   demo_<code> [--dir DIR] setup [name=value ...]
 *   demo_<code> [--dir DIR] keygen                       (PRCs)
 *   demo_<code> [--dir DIR] akeygen                      (anamorphic codes)
 *   demo_<code> [--dir DIR] export-key regular|anamorphic FILE
 *   demo_<code> [--dir DIR] import-key regular|anamorphic FILE
 *   demo_<code> [--dir DIR] encode [MESSAGE] CIPHERTEXT
 *   demo_<code> [--dir DIR] aencode AMESSAGE [MESSAGE] CIPHERTEXT
 *   demo_<code> [--dir DIR] decode CIPHERTEXT
 *   demo_<code> [--dir DIR] adecode CIPHERTEXT
 *
 * The state (parameters and keys) lives in DIR (default ./<code>_demo).
 *
 * Keys. The keys of the PRCs are not stored as expanded matrices: a key file
 * holds a 32 byte seed (hex) from which the code's key generation is re-run
 * with a deterministic generator. The key file is therefore the secret of both
 * the encoding and the decoding key. The symmetric keys of the wiretap code
 * and RLNC are the 32 key bytes themselves.
 */

#include <stddef.h>
#include <stdint.h>

#include "utils/random.h"

#define DEMO_KEY_BYTES 32

/* ---- parameters ------------------------------------------------------- */

typedef struct {
    const char *name;
    const char *default_value;
    const char *help;
} DemoParamSpec;

#define DEMO_MAX_PARAMS 24

typedef struct {
    const DemoParamSpec *specs;     /* terminated by name == NULL */
    char values[DEMO_MAX_PARAMS][64];
} DemoParams;

/* fills params with the default values of specs */
void demo_params_defaults(DemoParams *params, const DemoParamSpec *specs);
/* sets a parameter; -1 (after a message) if the name is unknown or the value too long */
int demo_params_set(DemoParams *params, const char *name, const char *value);

const char *demo_param(const DemoParams *params, const char *name);
size_t demo_param_size(const DemoParams *params, const char *name);
double demo_param_double(const DemoParams *params, const char *name);

/* ---- keys ------------------------------------------------------------- */

typedef struct {
    int have_regular;
    int have_anamorphic;
    uint8_t regular[DEMO_KEY_BYTES];
    uint8_t anamorphic[DEMO_KEY_BYTES];
} DemoKeys;

/* deterministic generator for key generation; free with csprg_randomness_free */
RandomnessSource demo_key_stream(const uint8_t key[DEMO_KEY_BYTES], uint8_t domain);

/* ---- ciphertexts ------------------------------------------------------ */

typedef struct {
    size_t count;       /* number of codewords / packets */
    size_t bits;        /* bits per codeword (a multiple of 8 for byte strings) */
    uint8_t **data;     /* packed bits, LSB first */
} DemoCiphertext;

/* allocates count codewords of the given size (zeroed) */
int demo_ct_alloc(DemoCiphertext *ciphertext, size_t count, size_t bits);
void demo_ct_free(DemoCiphertext *ciphertext);

/* ---- messages --------------------------------------------------------- */

/*
 * A message is text, or "hex:" followed by hex digits for arbitrary bytes
 * (e.g. "hex:00ff10").
 */

/* the length of a message in bytes */
size_t demo_message_length(const char *text);

/* copies the message into buffer, zero-padded; -1 if it is malformed or longer than len */
int demo_pad_message(const char *text, uint8_t *buffer, size_t len);

/* a uniformly random message of bits bits as "hex:..." (the unused high bits of
 * the last byte are zero); NULL on allocation failure, free with free() */
char *demo_random_message(size_t bits);

/* prints bytes as text (trailing zeros trimmed), or as hex if not printable */
void demo_print_bytes(const char *label, const uint8_t *buffer, size_t len);

/* ---- a code ----------------------------------------------------------- */

typedef struct {
    const char *name;                       /* "ldpc", "wiretap", ... */
    const DemoParamSpec *params;            /* terminated by name == NULL */
    int regular_keys;                       /* 1 for PRCs (seed keys) */
    int anamorphic;                         /* 1 if the code has an anamorphic mode */
    int anamorphic_key_is_seed;             /* 1: seed (PRCs), 0: raw symmetric key */

    /*
     * Builds the code from the parameters and (re-)generates its keys.
     * Keys that are not present in `keys` are not needed by the operations
     * that are called afterwards. Returns a handle or NULL (after printing the
     * reason).
     */
    void *(*open)(const DemoParams *params, const DemoKeys *keys);
    void (*close)(void *handle);

    /*
     * Generates the anamorphic key of a code that was opened without it, from
     * the anamorphic key seed and the regular keys of the handle (which are not
     * generated again). open calls it when the anamorphic key is present.
     * Returns 0, or -1 after printing the reason. NULL without anamorphic mode.
     */
    int (*akeygen)(void *handle, const uint8_t key[DEMO_KEY_BYTES]);

    /*
     * Samples a uniformly random regular and anamorphic message, written in the
     * format that encode and aencode expect (used by the benchmark). Free both
     * with free(). Returns 0, or -1 on allocation failure.
     */
    int (*sample_messages)(void *handle, char **message, char **amessage);

    /* All operations return 0 on success and -1 on failure/rejection and
     * print their result themselves. */
    int (*encode)(void *handle, const char *message, DemoCiphertext *out);
    int (*decode)(void *handle, const DemoCiphertext *in);
    int (*aencode)(void *handle, const char *message, const char *amessage,
                   DemoCiphertext *out);
    int (*adecode)(void *handle, const DemoCiphertext *in);
} DemoOps;

int demo_main(const DemoOps *ops, int argc, char **argv);

#endif /* DEMO_COMMON_H */
