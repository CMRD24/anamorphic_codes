#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "prcs/multibit/implementations/prc_sharp.h"
#include "utils/hamming74.h"
#include "utils/random.h"
#include "main_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>


#define MESSAGE_SIZE 4


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
        "  encode   - encode and write to sharp.txt\n"
        "  decode   - read from sharp.txt and decode\n"
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

        static const LDPCParams params = {
    .n   = 1024,
    .r   = 512,
    .g   = 256,
    .t   = 11,
    .eta = 0.01
};

        ZBPRC underlying =
            prc_ldpc(&params);


        /*
        * ============================================================
        * Randomness
        * ============================================================
        */

        RandomnessSource random = linux_randomness();


        PRCLow_Params low_params = {
            .underlying = &underlying,
            .ell = 64
        };

        MBPRC prc_l = prc_low(&low_params);


        PRCSharp_Params high_params = {
            .prc = &prc_l,
            .lambda_bits = 16
        };

        MBPRC prc = prc_sharp(&high_params);

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

if (!keys) {
    printf("Key generation failed.\n");
    return 1;
}

printf("PRC_high initialized.\n");


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
     * Require exactly 8 ASCII characters.
     */
    if (strlen(argument) != MESSAGE_SIZE) {

        fprintf(
            stderr,
            "Usage: encode <8 ASCII characters>\n"
        );

        continue;
    }

    /*
     * Convert the MESSAGE_SIZE ASCII characters to a byte array.
     */
    uint8_t message[MESSAGE_SIZE];
    printf("m1\n");

    for (size_t i = 0; i < MESSAGE_SIZE; ++i) {

        if ((unsigned char)argument[i] > 127) {

            fprintf(
                stderr,
                "Error: message must contain only ASCII characters.\n"
            );

            goto encode_continue;
        }

        message[i] = (uint8_t)argument[i];
    }

    printf("m2\n");


    size_t message_bits = MESSAGE_SIZE * 8;
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

    printf("m3\n");

    if (codeword == NULL) {

        fprintf(
            stderr,
            "Encoding failed.\n"
        );

        continue;
    }

    if (!save_codeword(
            "sharp.txt",
            codeword,
            output_bits)) {

        fprintf(
            stderr,
            "Failed to write sharp.txt.\n"
        );

    } else {

        printf(
            "Encoded message \"%s\" (%zu ciphertext bits) "
            "to sharp.txt.\n",
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
            "sharp.txt",
            &ciphertext_bits
        );

    if (codeword == NULL) {

        fprintf(
            stderr,
            "Failed to read sharp.txt.\n"
        );

        continue;
    }

    printf(
        "Read %zu bits from sharp.txt.\n",
        ciphertext_bits
    );


    uint8_t message[MESSAGE_SIZE] = {0};

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

    if (result == 1 && message_bits == 8 * MESSAGE_SIZE) {

        /*
         * Convert the decoded bytes back to ASCII.
         */
        char decoded[MESSAGE_SIZE+1];

        for (size_t i = 0; i < MESSAGE_SIZE; ++i)
            decoded[i] = (char)message[i];

        decoded[MESSAGE_SIZE] = '\0';

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