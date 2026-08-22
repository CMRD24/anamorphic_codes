#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "utils/random.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


/*
 * ================================================================
 * Parameters
 * ================================================================
 */

static const LDPCParams params = {
    .n   = 1024,
    .r   = 512,
    .g   = 256,
    .t   = 10,
    .eta = 0.01
};


/*
 * ================================================================
 * Helpers
 * ================================================================
 */

/*
 * Save a packed codeword as a textual bit string.
 */
static int
save_codeword(const char *filename,
              const uint8_t *codeword,
              size_t bits)
{
    FILE *file =
        fopen(filename, "w");

    if (file == NULL) {
        perror("fopen");
        return 0;
    }

    for (size_t i = 0;
         i < bits;
         ++i) {

        if (fputc(
                (codeword[i >> 3] &
                 (uint8_t)(1u << (i & 7)))
                ? '1'
                : '0',
                file) == EOF) {

            fclose(file);
            return 0;
        }
    }

    if (fputc('\n', file) == EOF) {
        fclose(file);
        return 0;
    }

    fclose(file);

    return 1;
}


/*
 * Read a textual codeword from a file.
 *
 * Whitespace is ignored. Every other character must be
 * either '0' or '1'.
 *
 * The buffer is grown dynamically, so there is no fixed
 * maximum ciphertext length.
 */
static uint8_t *
load_codeword(const char *filename,
              size_t *bits)
{
    if (bits == NULL)
        return NULL;

    *bits = 0;

    FILE *file =
        fopen(filename, "r");

    if (file == NULL) {
        perror("fopen");
        return NULL;
    }

    /*
     * Start with a small buffer and grow it as necessary.
     */
    size_t capacity = 1024;

    uint8_t *codeword =
        calloc((capacity + 7) / 8, 1);

    if (codeword == NULL) {
        fclose(file);
        return NULL;
    }

    int ch;

    while ((ch = fgetc(file)) != EOF) {

        /*
         * Ignore whitespace.
         */
        if (ch == ' ' ||
            ch == '\t' ||
            ch == '\n' ||
            ch == '\r')
            continue;

        /*
         * Only binary digits are allowed.
         */
        if (ch != '0' &&
            ch != '1') {

            fprintf(stderr,
                    "Invalid character in low.txt: '%c'\n",
                    ch);

            free(codeword);
            fclose(file);

            return NULL;
        }

        /*
         * Grow the bit buffer if necessary.
         */
        if (*bits == capacity) {

            size_t new_capacity;

            if (capacity > SIZE_MAX / 2) {
                free(codeword);
                fclose(file);
                return NULL;
            }

            new_capacity =
                capacity * 2;

            uint8_t *new_codeword =
                realloc(
                    codeword,
                    (new_capacity + 7) / 8
                    * sizeof(uint8_t)
                );

            if (new_codeword == NULL) {
                free(codeword);
                fclose(file);
                return NULL;
            }

            /*
             * Clear the newly allocated part.
             */
            size_t old_bytes =
                (capacity + 7) / 8;

            size_t new_bytes =
                (new_capacity + 7) / 8;

            memset(
                new_codeword + old_bytes,
                0,
                new_bytes - old_bytes
            );

            codeword = new_codeword;
            capacity = new_capacity;
        }

        if (ch == '1') {

            codeword[*bits >> 3] |=
                (uint8_t)(
                    1u << (*bits & 7)
                );
        }

        ++(*bits);
    }

    fclose(file);

    return codeword;
}


/*
 * Print available commands.
 */
static void
print_usage(void)
{
    printf(
        "Commands:\n"
        "  encode   - encode and write to low.txt\n"
        "  decode   - read from low.txt and decode\n"
        "  help\n"
        "  quit\n"
    );
}


/*
 * ================================================================
 * Main
 * ================================================================
 */

int
main(void)
{
            /*
        * ============================================================
        * Instantiate LDPC zero-bit PRC
        * ============================================================
        */

        ZBPRC underlying =
            ldpc_zbprc(&params);


        /*
        * ============================================================
        * Randomness
        * ============================================================
        */

        MBPRC_Random random = {
            .rng = linux_secure_random,
            .ctx = NULL
        };


        /*
        * ============================================================
        * Instantiate 1-bit adaptive PRC
        * ============================================================
        */

        PRCLow_Params low_params = {
            .underlying = &underlying,
            .ell = 8*5
        };

        MBPRC prc =
            prc_low_create(&low_params);


        /*
        * ============================================================
        * Key generation
        * ============================================================
        */

        MBPRC_Keys *keys =
            mbprc_keygen(
                &prc,
                &random
            );


    printf(
    "1-bit adaptive PRC initialized.\n"
    );




    print_usage();


    /*
     * ============================================================
     * Command loop
     * ============================================================
     */

    char line[256];

    for (;;) {

        printf("> ");
        fflush(stdout);

        if (fgets(line,
                  sizeof(line),
                  stdin) == NULL) {

            break;
        }

        /*
         * Remove newline.
         */
        line[strcspn(line, "\r\n")] =
            '\0';


        /*
         * Ignore empty input.
         */
        if (line[0] == '\0')
            continue;


        /*
         * --------------------------------------------------------
         * quit / exit
         * --------------------------------------------------------
         */

        if (strcmp(line, "quit") == 0 ||
            strcmp(line, "exit") == 0) {

            break;
        }


        /*
         * --------------------------------------------------------
         * help
         * --------------------------------------------------------
         */

        if (strcmp(line, "help") == 0) {

            print_usage();

            continue;
        }


        /*
 * --------------------------------------------------------
 * encode
 * --------------------------------------------------------
 */

if (strncmp(line, "encode", 6) == 0 &&
    (line[6] == ' ' || line[6] == '\0')) {

    /*
     * Skip whitespace after "encode".
     */
    char *argument = line + 6;

    while (*argument == ' ')
        ++argument;

    /*
     * Require exactly 5 ASCII characters.
     */
    if (strlen(argument) != 5) {

        fprintf(
            stderr,
            "Usage: encode <5 ASCII characters>\n"
        );

        continue;
    }

    /*
     * Convert the 5 ASCII characters to a byte array.
     */
    uint8_t message[5];

    for (size_t i = 0; i < 5; ++i) {

        if ((unsigned char)argument[i] > 127) {

            fprintf(
                stderr,
                "Error: message must contain only ASCII characters.\n"
            );

            goto encode_continue;
        }

        message[i] = (uint8_t)argument[i];
    }

    /*
     * 5 bytes = 40 message bits.
     */
    size_t message_bits = 5 * 8;
    size_t output_bits = 0;

    uint8_t *codeword =
        mbprc_encode(
            &prc,
            keys->enc,
            message,
            message_bits,
            &random,
            &output_bits
        );

    if (codeword == NULL) {

        fprintf(
            stderr,
            "Encoding failed.\n"
        );

        continue;
    }

    if (!save_codeword(
            "low.txt",
            codeword,
            output_bits)) {

        fprintf(
            stderr,
            "Failed to write low.txt.\n"
        );

    } else {

        printf(
            "Encoded message \"%s\" (%zu ciphertext bits) "
            "to low.txt.\n",
            argument,
            output_bits
        );
    }

    free(codeword);

    continue;

encode_continue:
    continue;
}


/*
 * --------------------------------------------------------
 * decode
 * --------------------------------------------------------
 */

if (strcmp(line, "decode") == 0) {

    size_t ciphertext_bits = 0;

    uint8_t *codeword =
        load_codeword(
            "low.txt",
            &ciphertext_bits
        );

    if (codeword == NULL) {

        fprintf(
            stderr,
            "Failed to read low.txt.\n"
        );

        continue;
    }

    printf(
        "Read %zu bits from low.txt.\n",
        ciphertext_bits
    );

    /*
     * The PRC has a 5-byte (40-bit) message.
     */
    uint8_t message[5] = {0};

    size_t message_bits = 0;

    int result =
        mbprc_decode(
            &prc,
            keys->dec,
            codeword,
            ciphertext_bits,
            message,
            &message_bits
        );

    if (result == 1 && message_bits == 40) {

        /*
         * Convert the 5 decoded bytes back to ASCII.
         */
        char decoded[6];

        for (size_t i = 0; i < 5; ++i)
            decoded[i] = (char)message[i];

        decoded[5] = '\0';

        printf(
            "Decoded: \"%s\"\n",
            decoded
        );

    } else {

        printf(
            "Decoding failed.\n"
        );
    }

    free(codeword);

    continue;
}
        /*
         * --------------------------------------------------------
         * Unknown command
         * --------------------------------------------------------
         */

        fprintf(stderr,
                "Unknown command: %s\n",
                line
        );

        print_usage();
    }


    /*
     * ============================================================
     * Cleanup
     * ============================================================
     */

    mbprc_free_keys(
        &prc,
        keys
    );

    return EXIT_SUCCESS;
}