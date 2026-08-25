#include "prcs/zerobit/implementations/prc_ldpc.h"
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

static void
print_codeword(const uint8_t *codeword,
               size_t bits)
{
    for (size_t i = 0;
         i < bits;
         ++i) {

        putchar(
            (codeword[i >> 3] &
             (uint8_t)(1u << (i & 7)))
            ? '1'
            : '0'
        );
    }

    putchar('\n');
}


static uint8_t *
parse_codeword(const char *string,
               size_t expected_bits)
{
    if (strlen(string) != expected_bits)
        return NULL;

    size_t bytes =
        (expected_bits + 7) / 8;

    uint8_t *codeword =
        calloc(bytes, 1);

    if (codeword == NULL)
        return NULL;

    for (size_t i = 0;
         i < expected_bits;
         ++i) {

        if (string[i] == '1') {

            codeword[i >> 3] |=
                (uint8_t)(
                    1u << (i & 7)
                );

        } else if (string[i] != '0') {

            free(codeword);

            return NULL;
        }
    }

    return codeword;
}


static void
print_usage(void)
{
    printf(
        "Commands:\n"
        "  encode\n"
        "  decode <codeword>\n"
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
     * Instantiate the LDPC zero-bit PRC.
     */
    ZBPRC prc =
        ldpc_zbprc(&params);

    /*
     * Randomness source.
     */
    RandomnessSource random = linux_randomness();

    /*
     * Generate one key pair for the lifetime of this process.
     */
    ZBPRC_Keys *keys =
        zbprc_keygen(
            &prc,
            &random
        );

    if (keys == NULL) {

        fprintf(stderr,
                "Key generation failed.\n");

        return EXIT_FAILURE;
    }


    anakey *akeys = ldpc_akeygen(&params, keys, &random);

    printf(
        "LDPC zero-bit PRC initialized.\n"
    );

    print_usage();


    /*
     * ============================================================
     * Command loop
     * ============================================================
     */

    char line[16384];

    for (;;) {

        printf("> ");
        fflush(stdout);

        if (fgets(line,
                  sizeof(line),
                  stdin) == NULL) {

            /*
             * EOF or input error.
             */
            break;
        }

        /*
         * Remove trailing newline.
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

        if (strcmp(line, "encode") == 0) {

            size_t output_bits = 0;

            uint8_t *codeword =
                zbprc_encode(
                    &prc,
                    keys->enc,
                    &random,
                    &output_bits
                );

            if (codeword == NULL) {

                fprintf(stderr,
                        "Encoding failed.\n");

                continue;
            }

            print_codeword(
                codeword,
                output_bits
            );

            free(codeword);

            continue;
        }


        /*
         * --------------------------------------------------------
         * aencode
         * --------------------------------------------------------
         */

        if (strcmp(line, "aencode") == 0) {

            size_t output_bits = 0;

            uint8_t *codeword =

                ldpc_aencode(
                    &params,
                    keys->enc,
                    akeys,
                    &random,
                    &output_bits
                );

            if (codeword == NULL) {

                fprintf(stderr,
                        "Encoding failed.\n");

                continue;
            }

            print_codeword(
                codeword,
                output_bits
            );

            free(codeword);

            continue;
        }


        /*
         * --------------------------------------------------------
         * decode <codeword>
         * --------------------------------------------------------
         */

        const char prefix[] =
            "decode ";

        size_t prefix_len =
            sizeof(prefix) - 1;

        if (strncmp(line,
                    prefix,
                    prefix_len) == 0) {

            const char *codeword_string =
                line + prefix_len;

            /*
             * Reject:
             *
             *     decode
             *
             * or
             *
             *     decode <empty>
             */
            if (*codeword_string == '\0') {

                fprintf(stderr,
                        "Missing codeword.\n");

                continue;
            }

            uint8_t *codeword =
                parse_codeword(
                    codeword_string,
                    params.n
                );

            if (codeword == NULL) {

                fprintf(stderr,
                        "Invalid codeword. "
                        "Expected exactly %zu bits "
                        "containing only 0 and 1.\n",
                        params.n);

                continue;
            }

            int result =
                zbprc_decode(
                    &prc,
                    keys->dec,
                    codeword,
                    params.n
                );

            printf("%d\n",
                   result);

            free(codeword);

            continue;
        }


        /*
         * --------------------------------------------------------
         * adecode <codeword>
         * --------------------------------------------------------
         */

        const char prefix2[] =
            "adecode ";

        size_t prefix2_len =
            sizeof(prefix2) - 1;

        if (strncmp(line,
                    prefix2,
                    prefix2_len) == 0) {

            const char *codeword_string =
                line + prefix2_len;

            /*
             * Reject:
             *
             *     decode
             *
             * or
             *
             *     decode <empty>
             */
            if (*codeword_string == '\0') {

                fprintf(stderr,
                        "Missing codeword.\n");

                continue;
            }

            uint8_t *codeword =
                parse_codeword(
                    codeword_string,
                    params.n
                );

            if (codeword == NULL) {

                fprintf(stderr,
                        "Invalid codeword. "
                        "Expected exactly %zu bits "
                        "containing only 0 and 1.\n",
                        params.n);

                continue;
            }

            int result = 
                ldpc_adecode(
                    &params,
                    keys->dec,
                    akeys,
                    codeword,
                    params.n
                );

            printf("%d\n",
                   result);

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
                line);

        print_usage();
    }


    /*
     * ============================================================
     * Cleanup
     * ============================================================
     */

    zbprc_free_keys(
        &prc,
        keys
    );

    return EXIT_SUCCESS;
}