#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/zerobit/implementations/prc_dc.h"
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
    .n   = 128,
    .r   = 64,
    .g   = 32,
    .t   = 4,
    .eta = 0.05
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
                    "Invalid character in dc.txt: '%c'\n",
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
        "  encode   - encode and write to dc.txt\n"
        "  decode   - read from dc.txt and decode\n"
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

    ZBPRC_Random random = {
        .rng = linux_secure_random,
        .ctx = NULL
    };


    /*
     * ============================================================
     * Instantiate DC zero-bit PRC
     * ============================================================
     */

    PRCDC_Params dc_params = {
        .k = params.n,
        .T = 211,
        .underlying = &underlying
    };

    ZBPRC prc =
        prc_dc_create(&dc_params);


    /*
     * ============================================================
     * Key generation
     * ============================================================
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


    printf(
        "DC zero-bit PRC initialized.\n"
    );

    printf(
        "DC ciphertext length for encode: "
        "%zu bits\n",
        dc_params.k * dc_params.T
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

            if (!save_codeword(
                    "dc.txt",
                    codeword,
                    output_bits)) {

                fprintf(stderr,
                        "Failed to write dc.txt.\n");

            } else {

                printf(
                    "Encoded %zu bits to dc.txt.\n",
                    output_bits
                );
            }

            free(codeword);

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
                    "dc.txt",
                    &ciphertext_bits
                );

            if (codeword == NULL) {

                fprintf(stderr,
                        "Failed to read dc.txt.\n");

                continue;
            }

            printf(
                "Read %zu bits from dc.txt.\n",
                ciphertext_bits
            );


            /*
             * Pass the actual number of bits in the file.
             *
             * The DC PRC supports arbitrary ciphertext lengths,
             * so we deliberately do NOT require k*T here.
             */
            int result =
                zbprc_decode(
                    &prc,
                    keys->dec,
                    codeword,
                    ciphertext_bits
                );

            printf("%d\n", result);

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

    zbprc_free_keys(
        &prc,
        keys
    );

    return EXIT_SUCCESS;
}