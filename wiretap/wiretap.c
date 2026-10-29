/*
 * Wiretap code with an anamorphic mode.
 *
 * Encoding (q = block_count blocks m_1..m_q of block_bytes bytes, ECC = the
 * error-correcting code):
 *
 *     r_0         seed (uniform for a regular encoding)
 *     s_i = r_(i-1) XOR m_i
 *     v_i = IFE(s_i)              (IFE = OAEP4, a keyless invertible transform)
 *     r_i = r_(i-1) XOR v_i
 *     codeword  = ECC(r_0) || ECC(v_1) || ... || ECC(v_q)
 *
 * Every block is protected against channel noise by the ECC. Decoding undoes the
 * construction: r_0 = ECC^-1(c_0), v_i = ECC^-1(c_i), s_i = IFE^-1(v_i),
 * m_i = r_(i-1) XOR s_i, r_i = r_(i-1) XOR v_i. The secrecy against an eavesdropper
 * with a degraded channel is argued in the thesis (Wiretap_IFE).
 *
 * Anamorphism (randomness recovery): the seed r_0 is recoverable from the first
 * block. The anamorphic sender sets r_0 to a pseudorandom encryption of the
 * anamorphic message (ske.c) instead of a uniform string; the receiver recovers
 * r_0 and decrypts. See wiretap_aencode.
 */


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

//implemented as described in https://link.springer.com/article/10.1186/s42400-025-00419-9
/*
 * Round function of OAEP4: the first half_len bytes of
 * SHAKE-256(domain[round] || input)
 * The distinct domain strings make the four round functions independent.
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

    //Allocates and returns a digest context. (https://manpages.debian.org/testing/libssl-doc/EVP_MD_CTX_new.3ssl.en.html)
    ctx = EVP_MD_CTX_new();
    if (!ctx)
        return -1;

    /*
    Sets up digest context ctx to use a digest type. type is typically supplied by a function such as EVP_sha1(), or a value explicitly fetched with EVP_MD_fetch()
    */
    if (EVP_DigestInit_ex(ctx, EVP_shake256(), NULL) != 1)
        goto cleanup;

        /*
        Hashes cnt bytes of data at d into the digest context ctx. This function can be called several times on the same ctx to hash additional data.
        */
    if (EVP_DigestUpdate(
            ctx, domains[round], strlen(domains[round])) != 1) //domain as input to the hash
        goto cleanup;

    if (EVP_DigestUpdate(ctx, input, half_len) != 1) //input as input to the hash
        goto cleanup;

    /*
    Interfaces to extendable-output functions, XOFs, such as SHAKE128 and SHAKE256. It retrieves the digest value from ctx and places it in outlen-sized out.
    */
    if (EVP_DigestFinalXOF(ctx, output, half_len) != 1)
        goto cleanup;

    ok = 0;

cleanup:
    EVP_MD_CTX_free(ctx);
    return ok;
}

/*
 * OAEP4: an invertible transform on K bytes as defined in https://link.springer.com/article/10.1186/s42400-025-00419-9. With L || R = input:
 *
 *   L1 = L  XOR H1(R)
 *   R1 = R  XOR G1(L1)
 *   L2 = L1 XOR H2(R1)
 *   R2 = R1 XOR G2(L2)
 *
 * output = L2 || R2. Every round is its own inverse given the other half, so the
 * transform is inverted by undoing the rounds in reverse order. The round
 * functions are SHAKE-256 with a distinct domain-separation prefix
 * per round.
 */
int wiretap_oaep4(
    const uint8_t *input,
    size_t input_len,
    uint8_t *output)
{
    uint8_t *halves = NULL;
    uint8_t *L, *R, *L1, *R1, *L2, *R2, *round_output;
    size_t half;

    if (!input || !output || input_len == 0 ||
        input_len % 2 != 0)
        return -1;

    half = input_len / 2;

    /* Six half-block buffers. */
    if (half > SIZE_MAX / 6)
        return -1;

    halves = malloc(6 * half);
    if (!halves)
        return -1;

    L  = halves;
    R  = L  + half;
    L1 = R  + half;
    R1 = L1 + half;
    L2 = R1 + half;
    R2 = L2 + half;

    memcpy(L, input, half);
    memcpy(R, input + half, half);

    round_output = malloc(half);
    if (!round_output) {
        free(halves);
        return -1;
    }

    /* L1 = L XOR H1(R) */
    if (shake_round(0, R, half, round_output) != 0)
        goto error;
    xor_bytes(L1, L, round_output, half);

    /* R1 = R XOR G1(L1) */
    if (shake_round(1, L1, half, round_output) != 0)
        goto error;
    xor_bytes(R1, R, round_output, half);

    /* L2 = L1 XOR H2(R1) */
    if (shake_round(2, R1, half, round_output) != 0)
        goto error;
    xor_bytes(L2, L1, round_output, half);

    /* R2 = R1 XOR G2(L2) */
    if (shake_round(3, L2, half, round_output) != 0)
        goto error;
    xor_bytes(R2, R1, round_output, half);

    memcpy(output, L2, half);
    memcpy(output + half, R2, half);

    sodium_memzero(halves, 6 * half);
    sodium_memzero(round_output, half);
    free(round_output);
    free(halves);
    return 0;

error:
    sodium_memzero(halves, 6 * half);
    sodium_memzero(round_output, half);
    free(round_output);
    free(halves);
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
    uint8_t *halves = NULL;
    uint8_t *L2, *R2, *L1, *R1, *L, *R, *round_output;
    size_t half;

    if (!input || !output || input_len == 0 ||
        input_len % 2 != 0)
        return -1;

    half = input_len / 2;

    if (half > SIZE_MAX / 6)
        return -1;

    halves = malloc(6 * half);
    if (!halves)
        return -1;

    L2 = halves;
    R2 = L2 + half;
    L1 = R2 + half;
    R1 = L1 + half;
    L  = R1 + half;
    R  = L  + half;

    memcpy(L2, input, half);
    memcpy(R2, input + half, half);

    round_output = malloc(half);
    if (!round_output) {
        free(halves);
        return -1;
    }

    /* R1 = R2 XOR G2(L2) */
    if (shake_round(3, L2, half, round_output) != 0)
        goto error;
    xor_bytes(R1, R2, round_output, half);

    /* L1 = L2 XOR H2(R1) */
    if (shake_round(2, R1, half, round_output) != 0)
        goto error;
    xor_bytes(L1, L2, round_output, half);

    /* R = R1 XOR G1(L1) */
    if (shake_round(1, L1, half, round_output) != 0)
        goto error;
    xor_bytes(R, R1, round_output, half);

    /* L = L1 XOR H1(R) */
    if (shake_round(0, R, half, round_output) != 0)
        goto error;
    xor_bytes(L, L1, round_output, half);

    memcpy(output, L, half);
    memcpy(output + half, R, half);

    sodium_memzero(halves, 6 * half);
    sodium_memzero(round_output, half);
    free(round_output);
    free(halves);
    return 0;

error:
    sodium_memzero(halves, 6 * half);
    sodium_memzero(round_output, half);
    free(round_output);
    free(halves);
    return -1;
}

int wiretap_config_valid(const wiretap_config_t *config)
{
    if (!config || !config->ecc)
        return 0;

    if (config->block_bytes == 0 || config->block_bytes % 2 != 0)
        return 0;


    if (config->lambda == 0)
        return 0;

    if (!config->ecc->encoded_size ||
        !config->ecc->decoded_size ||
        !config->ecc->encode ||
        !config->ecc->decode)
        return 0;

    size_t codeword_bytes = config->ecc->encoded_size(config->block_bytes);

    if (codeword_bytes == 0)
        return 0;



    return 1;
}

size_t wiretap_block_codeword_size(const wiretap_config_t *config)
{
    if (!wiretap_config_valid(config))
        return 0;

    return config->ecc->encoded_size(config->block_bytes);
}

size_t wiretap_encoded_size(
    const wiretap_config_t *config,
    size_t message_len)
{
    size_t block_count, blocks, total, codeword_bytes;

    if (!wiretap_config_valid(config) ||
        message_len == 0 ||
        message_len % config->block_bytes != 0)
        return 0;

    block_count = message_len / config->block_bytes;
    codeword_bytes = wiretap_block_codeword_size(config);

    if (mul_overflow_size(block_count, codeword_bytes, &blocks) ||
        add_overflow_size(codeword_bytes, blocks, &total)) //1+blocks * codeword_bytes (the one extra is for the seed)
        return 0;

    return total;
}

size_t wiretap_decoded_size(
    const wiretap_config_t *config,
    size_t ciphertext_len)
{
    size_t codeword_bytes, blocks;

    if (!wiretap_config_valid(config))
        return 0;

    codeword_bytes = wiretap_block_codeword_size(config);

    if (codeword_bytes == 0 || ciphertext_len <= codeword_bytes ||
        ciphertext_len % codeword_bytes != 0)
        return 0;

    blocks = ciphertext_len / codeword_bytes - 1;

    if (blocks > SIZE_MAX / config->block_bytes)
        return 0;

    return blocks * config->block_bytes;
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


int wiretap_encode_with_seed(
    const wiretap_config_t *config,
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
    size_t total, codeword_bytes, block_count;
    int result = -1;

    if (output_len)
        *output_len = 0;

    if (!wiretap_config_valid(config) || !message ||
        !output || !output_len)
        return -1;

    total = wiretap_encoded_size(config, message_len);
    codeword_bytes = wiretap_block_codeword_size(config);

    if (total == 0 || output_capacity < total)
        return -1;

    if (sodium_init() < 0)
        return -1;

    block_count = message_len / config->block_bytes;

    r_prev = malloc(config->block_bytes);
    s = malloc(config->block_bytes);
    v = malloc(config->block_bytes);
    r_next = malloc(config->block_bytes);

    if (!seed || !r_prev || !s || !v || !r_next)
        goto cleanup;


    memcpy(r_prev, seed, config->block_bytes);


    /* c_0 = ECC.Encode(r_0) */
    if (ecc_encode_block(
            config->ecc, r_prev, config->block_bytes,
            output, output_capacity, codeword_bytes) != 0)
        goto cleanup;

    for (size_t i = 0; i < block_count; ++i) {
        const uint8_t *m_i = message + i * config->block_bytes;
        uint8_t *c_i = output + (i + 1) * codeword_bytes;

        /* s_i = r_(i-1) XOR m_i */
        xor_bytes(s, r_prev, m_i, config->block_bytes);

        /* v_i = IFE(s_i) = OAEP4(s_i) */
        if (wiretap_oaep4(s, config->block_bytes, v) != 0)
            goto cleanup;


        //optional TODO: instead of xor-ing using the CRE as proposed in the paper as design choice (it is not part of the security analysis) 

        /* r_i = r_(i-1) XOR v_i */
        xor_bytes(r_next, r_prev, v, config->block_bytes);

        /* c_i = ECC.Encode(v_i) */
        if (ecc_encode_block(
                config->ecc, v, config->block_bytes,
                c_i, codeword_bytes, codeword_bytes) != 0)
            goto cleanup;

        memcpy(r_prev, r_next, config->block_bytes);
    }

    *output_len = total;
    result = 0;

cleanup:
    if (r_prev) sodium_memzero(r_prev, config->block_bytes);
    if (s) sodium_memzero(s, config->block_bytes);
    if (v) sodium_memzero(v, config->block_bytes);
    if (r_next) sodium_memzero(r_next, config->block_bytes);

    free(r_prev);
    free(s);
    free(v);
    free(r_next);

    if (result != 0)
        *output_len = 0;

    return result;
}


int wiretap_encode(
    const wiretap_config_t *config,
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

    if (!wiretap_config_valid(config) || !random)
        return -1;

    seed = malloc(config->block_bytes);
    if (!seed)
        return -1;

    random_bytes(random, seed, config->block_bytes);

    result = wiretap_encode_with_seed(
        config, seed, message, message_len,
        output, output_capacity, output_len);

    sodium_memzero(seed, config->block_bytes);
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

int wiretap_aconfig_valid(
    const wiretap_config_t *config,
    const wiretap_aconfig_t *aconfig)
{
    if (!wiretap_config_valid(config) || !aconfig)
        return 0;

    if (aconfig->amessage_bytes == 0 ||
        aconfig->amessage_bytes > config->block_bytes ||
        config->block_bytes - aconfig->amessage_bytes < WT_MIN_NONCE_BYTES)
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
    const wiretap_config_t *config,
    const wiretap_aconfig_t *aconfig,
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

    if (!wiretap_aconfig_valid(config, aconfig) || !akey || !amessage)
        return -1;

    if (sodium_init() < 0)
        return -1;

    seed = malloc(config->block_bytes);
    if (!seed)
        return -1;

    /* seed = nonce || (PRF(akey, nonce) XOR m_a), exactly block_bytes long */
    if (ske_encrypt(
            akey,
            config->block_bytes - aconfig->amessage_bytes,
            amessage,
            aconfig->amessage_bytes,
            seed))
        goto cleanup;

    result = wiretap_encode_with_seed(
        config, seed, message, message_len,
        output, output_capacity, output_len);

cleanup:
    sodium_memzero(seed, config->block_bytes);
    free(seed);
    return result;
}

/* r_0 = ECC.Decode(c_0); seed_out must hold block_bytes. 0 on success, -1 on error */
int wiretap_recover_seed(
    const wiretap_config_t *config,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *seed_out)
{
    size_t codeword_bytes;

    if (!wiretap_config_valid(config) || !ciphertext || !seed_out)
        return -1;

    codeword_bytes = wiretap_block_codeword_size(config);

    if (codeword_bytes == 0 || ciphertext_len < codeword_bytes)
        return -1;

    return ecc_decode_block(config->ecc, ciphertext, codeword_bytes, seed_out, config->block_bytes);
}

int wiretap_adecode(
    const wiretap_config_t *config,
    const wiretap_aconfig_t *aconfig,
    const uint8_t *akey,
    const uint8_t *ciphertext,
    size_t ciphertext_len,
    uint8_t *output)
{
    uint8_t *seed;
    int result = -1;

    if (!wiretap_aconfig_valid(config, aconfig) || !akey || !output)
        return -1;

    if (sodium_init() < 0)
        return -1;

    seed = malloc(config->block_bytes);
    if (!seed)
        return -1;

    if (wiretap_recover_seed(config, ciphertext, ciphertext_len, seed) != 0)
        goto cleanup;

    result = ske_decrypt(
        akey,
        config->block_bytes - aconfig->amessage_bytes,
        seed,
        output,
        aconfig->amessage_bytes);

cleanup:
    sodium_memzero(seed, config->block_bytes);
    free(seed);
    return result;
}


int wiretap_decode(
    const wiretap_config_t *config,
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
    size_t codeword_bytes, decoded_len, block_count;
    int result = -1;

    if (output_len)
        *output_len = 0;

    if (!wiretap_config_valid(config) || !ciphertext ||
        !output || !output_len)
        return -1;

    codeword_bytes = wiretap_block_codeword_size(config);
    decoded_len = wiretap_decoded_size(config, ciphertext_len);

    if (codeword_bytes == 0 || decoded_len == 0 ||
        output_capacity < decoded_len)
        return -1;

    block_count = decoded_len / config->block_bytes;

    r_prev = malloc(config->block_bytes);
    v = malloc(config->block_bytes);
    s = malloc(config->block_bytes);
    r_next = malloc(config->block_bytes);

    if (!r_prev || !v || !s || !r_next)
        goto cleanup;

    /* r_0 = ECC.Decode(c_0) */
    if (ecc_decode_block(
            config->ecc, ciphertext, codeword_bytes,
            r_prev, config->block_bytes) != 0)
        goto cleanup;


    for (size_t i = 0; i < block_count; ++i) {
        const uint8_t *c_i = ciphertext + (i + 1) * codeword_bytes;
        uint8_t *m_i = output + i * config->block_bytes;

        /* v_i = ECC.Decode(c_i) */
        if (ecc_decode_block(
                config->ecc, c_i, codeword_bytes, v, config->block_bytes) != 0)
            goto cleanup;

        /* s_i = IFE^(-1)(v_i) = OAEP4^(-1)(v_i) */
        if (wiretap_oaep4_inverse(
                v, config->block_bytes, s) != 0)
            goto cleanup;

        /* m_i = r_(i-1) XOR s_i */
        xor_bytes(m_i, r_prev, s, config->block_bytes);

        /* r_i = r_(i-1) XOR v_i */
        xor_bytes(r_next, r_prev, v, config->block_bytes);

        memcpy(r_prev, r_next, config->block_bytes);
    }

    *output_len = decoded_len;
    result = 0;

cleanup:
    if (r_prev) sodium_memzero(r_prev, config->block_bytes);
    if (v) sodium_memzero(v, config->block_bytes);
    if (s) sodium_memzero(s, config->block_bytes);
    if (r_next) sodium_memzero(r_next, config->block_bytes);

    free(r_prev);
    free(v);
    free(s);
    free(r_next);

    if (result != 0)
        *output_len = 0;

    return result;
}