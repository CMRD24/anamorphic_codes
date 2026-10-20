
#include "wiretap.h"

#include <limits.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/evp.h>
#include <sodium.h>
#include "../utils/random.h"
#include "../utils/random_utils.h"
#include "../utils/ske.h"

#define WT_ROUNDS 4

static int add_overflow_size(size_t a, size_t b, size_t *out)
{
    if (a > SIZE_MAX - b)
        return 1;
    *out = a + b;
    return 0;
}

static int mul_overflow_size(size_t a, size_t b, size_t *out)
{
    if (a != 0 && b > SIZE_MAX / a)
        return 1;
    *out = a * b;
    return 0;
}

static void xor_bytes(
    uint8_t *out,
    const uint8_t *a,
    const uint8_t *b,
    size_t len)
{
    for (size_t i = 0; i < len; ++i)
        out[i] = a[i] ^ b[i];
}

/*
 * SHAKE-256 round function.
 *
 * Domain separation ensures the four round functions are distinct.
 * Each invocation produces exactly half_len bytes.
 */
static int shake_round(
    unsigned round,
    const uint8_t *input,
    size_t half_len,
    uint8_t *output)
{
    static const char *domains[WT_ROUNDS] = {
        "wiretap/OAEP4/H1/v1",
        "wiretap/OAEP4/G1/v1",
        "wiretap/OAEP4/H2/v1",
        "wiretap/OAEP4/G2/v1"
    };

    EVP_MD_CTX *ctx = NULL;
    int ok = -1;

    if (round >= WT_ROUNDS || !input || !output ||
        half_len == 0)
        return -1;

    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1)
        goto cleanup;

    if (EVP_DigestUpdate(
            ctx, domains[round], strlen(domains[round])) != 1)
        goto cleanup;

    if (EVP_DigestUpdate(ctx, input, half_len) != 1)
        goto cleanup;

    if (EVP_DigestFinalXOF(ctx, output, half_len) != 1)
        goto cleanup;

    ok = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/*
 * OAEP4:
 *
 * L1 = L  XOR H1(R)
 * R1 = R  XOR G1(L1)
 * L2 = L1 XOR H2(R1)
 * R2 = R1 XOR G2(L2)
 *
 * output = L2 || R2
 */
int wiretap_oaep4(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    uint8_t *mem = NULL;
    uint8_t *L, *R, *L1, *R1, *L2, *R2, *tmp;
    size_t h;

    if (!input || !output || input_len == 0 ||
        input_len % 2 != 0)
        return -1;

    h = input_len / 2;

    /* Six half-block buffers. */
    if (h > SIZE_MAX / 6)
        return -1;

    mem = malloc(6 * h);
    if (!mem)
        return -1;

    L  = mem;
    R  = L  + h;
    L1 = R  + h;
    R1 = L1 + h;
    L2 = R1 + h;
    R2 = L2 + h;

    memcpy(L, input, h);
    memcpy(R, input + h, h);

    tmp = malloc(h);
    if (!tmp) {
        free(mem);
        return -1;
    }

    /* L1 = L XOR H1(R) */
    if (shake_round(0, R, h, tmp) != 0)
        goto error;
    xor_bytes(L1, L, tmp, h);

    /* R1 = R XOR G1(L1) */
    if (shake_round(1, L1, h, tmp) != 0)
        goto error;
    xor_bytes(R1, R, tmp, h);

    /* L2 = L1 XOR H2(R1) */
    if (shake_round(2, R1, h, tmp) != 0)
        goto error;
    xor_bytes(L2, L1, tmp, h);

    /* R2 = R1 XOR G2(L2) */
    if (shake_round(3, L2, h, tmp) != 0)
        goto error;
    xor_bytes(R2, R1, tmp, h);

    memcpy(output, L2, h);
    memcpy(output + h, R2, h);

    sodium_memzero(mem, 6 * h);
    sodium_memzero(tmp, h);
    free(tmp);
    free(mem);
    return 0;

error:
    sodium_memzero(mem, 6 * h);
    sodium_memzero(tmp, h);
    free(tmp);
    free(mem);
    return -1;
}

/*
 * Invert OAEP4 by undoing the rounds in reverse order.
 */
int wiretap_oaep4_inverse(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    uint8_t *mem = NULL;
    uint8_t *L2, *R2, *L1, *R1, *L, *R, *tmp;
    size_t h;

    if (!input || !output || input_len == 0 ||
        input_len % 2 != 0)
        return -1;

    h = input_len / 2;

    if (h > SIZE_MAX / 6)
        return -1;

    mem = malloc(6 * h);
    if (!mem)
        return -1;

    L2 = mem;
    R2 = L2 + h;
    L1 = R2 + h;
    R1 = L1 + h;
    L  = R1 + h;
    R  = L  + h;

    memcpy(L2, input, h);
    memcpy(R2, input + h, h);

    tmp = malloc(h);
    if (!tmp) {
        free(mem);
        return -1;
    }

    /* R1 = R2 XOR G2(L2) */
    if (shake_round(3, L2, h, tmp) != 0)
        goto error;
    xor_bytes(R1, R2, tmp, h);

    /* L1 = L2 XOR H2(R1) */
    if (shake_round(2, R1, h, tmp) != 0)
        goto error;
    xor_bytes(L1, L2, tmp, h);

    /* R = R1 XOR G1(L1) */
    if (shake_round(1, L1, h, tmp) != 0)
        goto error;
    xor_bytes(R, R1, tmp, h);

    /* L = L1 XOR H1(R) */
    if (shake_round(0, R, h, tmp) != 0)
        goto error;
    xor_bytes(L, L1, tmp, h);

    memcpy(output, L, h);
    memcpy(output + h, R, h);

    sodium_memzero(mem, 6 * h);
    sodium_memzero(tmp, h);
    free(tmp);
    free(mem);
    return 0;

error:
    sodium_memzero(mem, 6 * h);
    sodium_memzero(tmp, h);
    free(tmp);
    free(mem);
    return -1;
}

int wiretap_config_valid(const wiretap_config_t *cfg)
{
    if (!cfg || !cfg->ecc)
        return 0;

    if (cfg->K_bytes == 0 || cfg->K_bytes % 2 != 0)
        return 0;


    if (cfg->security_parameter == 0)
        return 0;

    if (!cfg->ecc->encoded_size ||
        !cfg->ecc->decoded_size ||
        !cfg->ecc->encode ||
        !cfg->ecc->decode)
        return 0;

    size_t n = cfg->ecc->encoded_size(cfg->K_bytes);

    if (n == 0)
        return 0;


    //TODO: proper validation of security parameter with K and error-correction block length

    return 1;
}

size_t wiretap_codeword_size(const wiretap_config_t *cfg)
{
    if (!wiretap_config_valid(cfg))
        return 0;

    return cfg->ecc->encoded_size(cfg->K_bytes);
}

size_t wiretap_encoded_size(
    const wiretap_config_t *cfg,
    size_t message_len)
{
    size_t q, blocks, total, n;

    if (!wiretap_config_valid(cfg) ||
        message_len == 0 ||
        message_len % cfg->K_bytes != 0)
        return 0;

    q = message_len / cfg->K_bytes;
    n = wiretap_codeword_size(cfg);

    if (mul_overflow_size(q, n, &blocks) ||
        add_overflow_size(n, blocks, &total))
        return 0;

    return total;
}

size_t wiretap_decoded_size(
    const wiretap_config_t *cfg,
    size_t ciphertext_len)
{
    size_t n, blocks;

    if (!wiretap_config_valid(cfg))
        return 0;

    n = wiretap_codeword_size(cfg);

    if (n == 0 || ciphertext_len <= n ||
        ciphertext_len % n != 0)
        return 0;

    blocks = ciphertext_len / n - 1;

    if (blocks > SIZE_MAX / cfg->K_bytes)
        return 0;

    return blocks * cfg->K_bytes;
}

static int ecc_encode_block(
    const ECC *ecc,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_capacity,
    size_t expected_len)
{
    size_t written = output_capacity;

    if (output_capacity < expected_len)
        return -1;

    if (ecc->encode(input, input_len, output, &written) != 0)
        return -1;

    return written == expected_len ? 0 : -1;
}

static int ecc_decode_block(
    const ECC *ecc,
    const uint8_t *input,
    size_t input_len,
    uint8_t *output,
    size_t output_len)
{
    if (ecc->decoded_size(input_len) != output_len)
        return -1;

    return ecc->decode(input, input_len, output, output_len);
}


int wiretap_encode_ws(
    const wiretap_config_t *cfg,
    const uint8_t *seed,
    const uint8_t *message,
    size_t message_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len)
{
    uint8_t *r_prev = NULL;
    uint8_t *s = NULL;
    uint8_t *v = NULL;
    uint8_t *r_next = NULL;
    size_t total, n, q;
    int result = -1;

    if (output_len)
        *output_len = 0;

    if (!wiretap_config_valid(cfg) || !message ||
        !output || !output_len)
        return -1;

    total = wiretap_encoded_size(cfg, message_len);
    n = wiretap_codeword_size(cfg);

    if (total == 0 || output_capacity < total)
        return -1;

    if (sodium_init() < 0)
        return -1;

    q = message_len / cfg->K_bytes;

    r_prev = malloc(cfg->K_bytes);
    s = malloc(cfg->K_bytes);
    v = malloc(cfg->K_bytes);
    r_next = malloc(cfg->K_bytes);

    if (!seed || !r_prev || !s || !v || !r_next)
        goto cleanup;


    memcpy(r_prev, seed, cfg->K_bytes);


    /* c_0 = ECC.Encode(r_0) */
    if (ecc_encode_block(
            cfg->ecc, r_prev, cfg->K_bytes,
            output, output_capacity, n) != 0)
        goto cleanup;

    for (size_t i = 0; i < q; ++i) {
        const uint8_t *m_i = message + i * cfg->K_bytes;
        uint8_t *c_i = output + (i + 1) * n;

        /* s_i = r_(i-1) XOR m_i */
        xor_bytes(s, r_prev, m_i, cfg->K_bytes);

        /* v_i = IFE(s_i) = OAEP4(s_i) */
        if (wiretap_oaep4(s, cfg->K_bytes, v) != 0)
            goto cleanup;

        /* r_i = r_(i-1) XOR v_i */
        xor_bytes(r_next, r_prev, v, cfg->K_bytes);

        /* c_i = ECC.Encode(v_i) */
        if (ecc_encode_block(
                cfg->ecc, v, cfg->K_bytes,
                c_i, n, n) != 0)
            goto cleanup;

        memcpy(r_prev, r_next, cfg->K_bytes);
    }

    *output_len = total;
    result = 0;

cleanup:
    if (r_prev) sodium_memzero(r_prev, cfg->K_bytes);
    if (s) sodium_memzero(s, cfg->K_bytes);
    if (v) sodium_memzero(v, cfg->K_bytes);
    if (r_next) sodium_memzero(r_next, cfg->K_bytes);

    free(r_prev);
    free(s);
    free(v);
    free(r_next);

    if (result != 0)
        *output_len = 0;

    return result;
}


int wiretap_encode(
    const wiretap_config_t *cfg,
    RandomnessSource *random,
    const uint8_t *message,
    size_t message_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len)
{
    uint8_t *seed;
    int result;

    if (output_len)
        *output_len = 0;

    if (!wiretap_config_valid(cfg) || !random)
        return -1;

    seed = malloc(cfg->K_bytes);
    if (!seed)
        return -1;

    random_bytes(random, seed, cfg->K_bytes);

    result = wiretap_encode_ws(
        cfg, seed, message, message_len,
        output, output_capacity, output_len);

    sodium_memzero(seed, cfg->K_bytes);
    free(seed);

    return result;
}


/* ------------------------------------------------------------------------
 * Anamorphism from randomness recoverability.
 *
 * The seed r_0 of the wiretap code is recoverable by the receiver
 * (r_0 = ECC.Decode(c_0)). The regular sender samples it uniformly; the
 * anamorphic sender instead sets
 *
 *     r_0 = Enc(akey, m_a) = nonce || (PRF(akey, nonce) XOR m_a)
 *
 * which is pseudorandom without akey. The anamorphic receiver recovers r_0
 * from the first ECC block and decrypts it.
 * ------------------------------------------------------------------------ */

/* Minimum nonce length (bytes) of the pseudorandom encryption of the seed. */
#define WT_MIN_NONCE_BYTES 16

int wiretap_ana_config_valid(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg)
{
    if (!wiretap_config_valid(cfg) || !acfg)
        return 0;

    if (acfg->ana_message_length == 0 ||
        acfg->ana_message_length > cfg->K_bytes ||
        cfg->K_bytes - acfg->ana_message_length < WT_MIN_NONCE_BYTES)
        return 0;

    return 1;
}

uint8_t *wiretap_akeygen(void)
{
    uint8_t *akey;

    if (sodium_init() < 0)
        return NULL;

    akey = malloc(crypto_generichash_KEYBYTES);
    if (akey)
        crypto_generichash_keygen(akey);

    return akey;
}

void wiretap_akey_free(uint8_t *akey)
{
    if (!akey)
        return;

    sodium_memzero(akey, crypto_generichash_KEYBYTES);
    free(akey);
}

int wiretap_aencode(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg,
    const uint8_t *akey,
    const uint8_t *message,
    size_t message_len,
    const uint8_t *amessage,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len)
{
    uint8_t *seed;
    int result = -1;

    if (output_len)
        *output_len = 0;

    if (!wiretap_ana_config_valid(cfg, acfg) || !akey || !amessage)
        return -1;

    if (sodium_init() < 0)
        return -1;

    seed = malloc(cfg->K_bytes);
    if (!seed)
        return -1;

    /* seed = nonce || (PRF(akey, nonce) XOR m_a), exactly K_bytes long */
    if (encrypt(
            akey,
            cfg->K_bytes - acfg->ana_message_length,
            amessage,
            acfg->ana_message_length,
            seed))
        goto cleanup;

    result = wiretap_encode_ws(
        cfg, seed, message, message_len,
        output, output_capacity, output_len);

cleanup:
    sodium_memzero(seed, cfg->K_bytes);
    free(seed);
    return result;
}

/* r_0 = ECC.Decode(c_0); seed_out must hold K_bytes. 0 on success, -1 on error */
int wiretap_seed_decode(
    const wiretap_config_t *cfg,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *seed_out)
{
    size_t n;

    if (!wiretap_config_valid(cfg) || !ciphertext || !seed_out)
        return -1;

    n = wiretap_codeword_size(cfg);

    if (n == 0 || ciphertext_len < n)
        return -1;

    return ecc_decode_block(cfg->ecc, ciphertext, n, seed_out, cfg->K_bytes);
}

int wiretap_adecode(
    const wiretap_config_t *cfg,
    const wiretap_ana_config_t *acfg,
    const uint8_t *akey,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *output)
{
    uint8_t *seed;
    int result = -1;

    if (!wiretap_ana_config_valid(cfg, acfg) || !akey || !output)
        return -1;

    if (sodium_init() < 0)
        return -1;

    seed = malloc(cfg->K_bytes);
    if (!seed)
        return -1;

    if (wiretap_seed_decode(cfg, ciphertext, ciphertext_len, seed) != 0)
        goto cleanup;

    result = decrypt(
        akey,
        cfg->K_bytes - acfg->ana_message_length,
        seed,
        output,
        acfg->ana_message_length);

cleanup:
    sodium_memzero(seed, cfg->K_bytes);
    free(seed);
    return result;
}


int wiretap_decode(
    const wiretap_config_t *cfg,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *output,
    size_t output_capacity,
    size_t *output_len)
{
    uint8_t *r_prev = NULL;
    uint8_t *v = NULL;
    uint8_t *s = NULL;
    uint8_t *r_next = NULL;
    size_t n, decoded_len, q;
    int result = -1;

    if (output_len)
        *output_len = 0;

    if (!wiretap_config_valid(cfg) || !ciphertext ||
        !output || !output_len)
        return -1;

    n = wiretap_codeword_size(cfg);
    decoded_len = wiretap_decoded_size(cfg, ciphertext_len);

    if (n == 0 || decoded_len == 0 ||
        output_capacity < decoded_len)
        return -1;

    q = decoded_len / cfg->K_bytes;

    r_prev = malloc(cfg->K_bytes);
    v = malloc(cfg->K_bytes);
    s = malloc(cfg->K_bytes);
    r_next = malloc(cfg->K_bytes);

    if (!r_prev || !v || !s || !r_next)
        goto cleanup;

    /* r_0 = ECC.Decode(c_0) */
    if (ecc_decode_block(
            cfg->ecc, ciphertext, n,
            r_prev, cfg->K_bytes) != 0)
        goto cleanup;


    for (size_t i = 0; i < q; ++i) {
        const uint8_t *c_i = ciphertext + (i + 1) * n;
        uint8_t *m_i = output + i * cfg->K_bytes;

        /* v_i = ECC.Decode(c_i) */
        if (ecc_decode_block(
                cfg->ecc, c_i, n, v, cfg->K_bytes) != 0)
            goto cleanup;

        /* s_i = IFE^(-1)(v_i) = OAEP4^(-1)(v_i) */
        if (wiretap_oaep4_inverse(
                v, cfg->K_bytes, s) != 0)
            goto cleanup;

        /* m_i = r_(i-1) XOR s_i */
        xor_bytes(m_i, r_prev, s, cfg->K_bytes);

        /* r_i = r_(i-1) XOR v_i */
        xor_bytes(r_next, r_prev, v, cfg->K_bytes);

        memcpy(r_prev, r_next, cfg->K_bytes);
    }

    *output_len = decoded_len;
    result = 0;

cleanup:
    if (r_prev) sodium_memzero(r_prev, cfg->K_bytes);
    if (v) sodium_memzero(v, cfg->K_bytes);
    if (s) sodium_memzero(s, cfg->K_bytes);
    if (r_next) sodium_memzero(r_next, cfg->K_bytes);

    free(r_prev);
    free(v);
    free(s);
    free(r_next);

    if (result != 0)
        *output_len = 0;

    return result;
}