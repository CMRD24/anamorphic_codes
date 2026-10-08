
/* main.c */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#include "wiretap.h"
#include <sodium.h>
#include "../utils/hamming74.h"

#define K_BYTES 32
#define SECURITY_PARAMETER 128

static void print_hex(const uint8_t *data, size_t len)
{
    for (size_t i = 0; i < len; ++i)
        printf("%02x", data[i]);

    putchar('\n');
}

static int hex_value(char c)
{
    if (c >= '0' && c <= '9')
        return c - '0';
    if (c >= 'a' && c <= 'f')
        return c - 'a' + 10;
    if (c >= 'A' && c <= 'F')
        return c - 'A' + 10;
    return -1;
}

static int hex_decode(
    const char *hex,
    uint8_t **output,
    size_t *output_len)
{
    size_t len = strlen(hex);

    if (len == 0 || len % 2 != 0)
        return -1;

    size_t bytes = len / 2;
    uint8_t *buf = malloc(bytes);

    if (!buf)
        return -1;

    for (size_t i = 0; i < bytes; ++i) {
        int hi = hex_value(hex[2 * i]);
        int lo = hex_value(hex[2 * i + 1]);

        if (hi < 0 || lo < 0) {
            free(buf);
            return -1;
        }

        buf[i] = (uint8_t)((hi << 4) | lo);
    }

    *output = buf;
    *output_len = bytes;
    return 0;
}

static int encode_message(
    const wiretap_config_t *cfg,
    const char *message)
{
    size_t message_len = strlen(message);

    if (message_len == 0) {
        fprintf(stderr, "Error: message must not be empty.\n");
        return EXIT_FAILURE;
    }

    /*
     * Pad to a whole number of K-byte blocks.
     * Zero-padding is removed during text decoding.
     */
    size_t padded_len = message_len;
    size_t remainder = message_len % cfg->K_bytes;

    if (remainder != 0) {
        size_t padding = cfg->K_bytes - remainder;

        if (padded_len > SIZE_MAX - padding) {
            fprintf(stderr, "Error: message too large.\n");
            return EXIT_FAILURE;
        }

        padded_len += padding;
    }

    uint8_t *padded_message = calloc(padded_len, 1);
    if (!padded_message) {
        perror("calloc");
        return EXIT_FAILURE;
    }

    memcpy(padded_message, message, message_len);

    size_t ciphertext_capacity =
        wiretap_encoded_size(cfg, padded_len);

    if (ciphertext_capacity == 0) {
        fprintf(stderr, "Error: cannot determine ciphertext size.\n");
        sodium_memzero(padded_message, padded_len);
        free(padded_message);
        return EXIT_FAILURE;
    }

    uint8_t *ciphertext = malloc(ciphertext_capacity);
    if (!ciphertext) {
        perror("malloc");
        sodium_memzero(padded_message, padded_len);
        free(padded_message);
        return EXIT_FAILURE;
    }

    size_t ciphertext_len = 0;

    RandomnessSource random = linux_randomness();

    if (wiretap_encode(
            cfg,
            &random,
            padded_message,
            padded_len,
            ciphertext,
            ciphertext_capacity,
            &ciphertext_len) != 0) {
        fprintf(stderr, "Error: wiretap encoding failed.\n");
        sodium_memzero(padded_message, padded_len);
        sodium_memzero(ciphertext, ciphertext_capacity);
        free(padded_message);
        free(ciphertext);
        return EXIT_FAILURE;
    }

    printf("Wiretap codeword (hex):\n");
    print_hex(ciphertext, ciphertext_len);

    sodium_memzero(padded_message, padded_len);
    sodium_memzero(ciphertext, ciphertext_capacity);
    free(padded_message);
    free(ciphertext);

    return EXIT_SUCCESS;
}

static int decode_message(
    const wiretap_config_t *cfg,
    const char *hex_ciphertext)
{
    uint8_t *ciphertext = NULL;
    size_t ciphertext_len = 0;

    if (hex_decode(
            hex_ciphertext,
            &ciphertext,
            &ciphertext_len) != 0) {
        fprintf(stderr, "Error: invalid hexadecimal codeword.\n");
        return EXIT_FAILURE;
    }

    size_t plaintext_capacity =
        wiretap_decoded_size(cfg, ciphertext_len);

    if (plaintext_capacity == 0) {
        fprintf(stderr, "Error: invalid ciphertext length.\n");
        free(ciphertext);
        return EXIT_FAILURE;
    }

    uint8_t *plaintext = malloc(plaintext_capacity);
    if (!plaintext) {
        perror("malloc");
        free(ciphertext);
        return EXIT_FAILURE;
    }

    size_t plaintext_len = 0;

    if (wiretap_decode(
            cfg,
            ciphertext,
            ciphertext_len,
            plaintext,
            plaintext_capacity,
            &plaintext_len) != 0) {
        fprintf(stderr, "Error: wiretap decoding failed.\n");
        sodium_memzero(ciphertext, ciphertext_len);
        sodium_memzero(plaintext, plaintext_capacity);
        free(ciphertext);
        free(plaintext);
        return EXIT_FAILURE;
    }

    /*
     * The encoder zero-pads the last block. Remove trailing
     * zeros to recover the original text for ordinary messages.
     */
    while (plaintext_len > 0 &&
           plaintext[plaintext_len - 1] == '\0') {
        --plaintext_len;
    }

    printf("Decoded message:\n");
    if (plaintext_len > 0)
        fwrite(plaintext, 1, plaintext_len, stdout);
    putchar('\n');

    sodium_memzero(ciphertext, ciphertext_len);
    sodium_memzero(plaintext, plaintext_capacity);
    free(ciphertext);
    free(plaintext);

    return EXIT_SUCCESS;
}

int main(int argc, char **argv)
{
    if (argc != 3) {
        fprintf(stderr,
            "Usage:\n"
            "  %s enc \"message\"\n"
            "  %s dec <hex-codeword>\n",
            argv[0], argv[0]);
        return EXIT_FAILURE;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "Error: libsodium initialization failed.\n");
        return EXIT_FAILURE;
    }

    ECC ecc = hamming74_ecc();

    wiretap_config_t cfg = {
        .K_bytes = K_BYTES,
        .security_parameter = SECURITY_PARAMETER,
        .ecc = &ecc
    };

    if (!wiretap_config_valid(&cfg)) {
        fprintf(stderr, "Error: invalid wiretap configuration.\n");
        return EXIT_FAILURE;
    }

    if (strcmp(argv[1], "enc") == 0)
        return encode_message(&cfg, argv[2]);

    if (strcmp(argv[1], "dec") == 0)
        return decode_message(&cfg, argv[2]);

    fprintf(stderr, "Error: mode must be 'enc' or 'dec'.\n");
    return EXIT_FAILURE;
}