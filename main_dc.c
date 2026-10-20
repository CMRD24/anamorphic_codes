#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/zerobit/implementations/prc_dc.h"
#include "utils/random.h"
#include "main_utils.h"

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
        prc_ldpc(&params);


    /*
     * ============================================================
     * Randomness
     * ============================================================
     */

    RandomnessSource random = linux_randomness();


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
        prc_dc(&dc_params);


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