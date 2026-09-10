#include "prcs/zerobit/implementations/prc_pp.h"
#include "utils/random.h"
#include "utils/hamming74.h"
#include "utils/none_ecc.h"
#include "prcs/anamorphism/aprc_rr.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#define AMESSAGE_SIZE 16




static void
print_usage(void)
{
    printf(
        "Commands:\n"
        "  encode\n"
        "  decode <codeword>\n"
        "  help\n"
        "  quit\n");
}

/*
 * ================================================================
 * Main
 * ================================================================
 */

int main(void)
{
    /*
     * Instantiate the LDPC zero-bit PRC.
     */

    ECC hamming_ecc = hamming74_ecc();


    PPParams params = {
        .delta = 0.0,
        .ecc = &hamming_ecc,
        .n = 16 * 8, // in bits!!!
        .q = 2,
        .message_bytes = 8,
        .symbol_bits = 1

    };

    // PPParams params = {
    //     .delta = 0,
    //     .ecc = &NONE_ECC,
    //     .n = 8 * 8, // in bits!!!
    //     .q = 2,
    //     .message_bytes = 8,
    //     .symbol_bits = 1

    // };

    ZBPRC_RR prc_rr =
        prc_pp_rr(&params);

    ZBPRC prc = prc_rr.base;

    aZBPRC_RR_Params aparams = {
        .prc_rr = &prc_rr,
        .mu = 32 + 1 + AMESSAGE_SIZE / 8, //AMESSAGE_SIZE bits / 64
        .indication_len = 32,
        .seed_len = 64};

    aZBPRC_RR aprc = aZBPRC_RR_init(&aparams);

    /*
     * Randomness source.
     */
    RandomnessSource random = linux_randomness();

    APRC_RR_Keys *dkey = aprc.akeygen(&aparams, &random);

    /*
     * Generate one key pair for the lifetime of this process.
     */
    ZBPRC_Keys *keys =
        zbprc_keygen(
            &prc,
            &random);

    if (keys == NULL)
    {

        fprintf(stderr,
                "Key generation failed.\n");

        return EXIT_FAILURE;
    }

    printf(
        "LDPC zero-bit PRC initialized.\n");

    print_usage();


     
    

    /*
     * ============================================================
     * Command loop
     * ============================================================
     */

    char line[16384];

    for (;;)
    {

        printf("> ");
        fflush(stdout);

        if (fgets(line,
                  sizeof(line),
                  stdin) == NULL)
        {

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
            strcmp(line, "exit") == 0)
        {

            break;
        }

        /*
         * --------------------------------------------------------
         * help
         * --------------------------------------------------------
         */

        if (strcmp(line, "help") == 0)
        {

            print_usage();

            continue;
        }

        /*
         * --------------------------------------------------------
         * encode
         * --------------------------------------------------------
         */

        if (strcmp(line, "encode") == 0)
        {

            size_t output_bits = 0;

            uint8_t *codeword =
                zbprc_encode(
                    &prc,
                    keys->enc,
                    &random,
                    &output_bits);

            if (codeword == NULL)
            {

                fprintf(stderr,
                        "Encoding failed.\n");

                continue;
            }

            print_codeword(
                codeword,
                output_bits);

            free(codeword);

            continue;
        }

        /*
         * --------------------------------------------------------
         * aencode
         * --------------------------------------------------------
         */

        if (strncmp(line, "aencode", 7) == 0 &&
            (line[7] == ' ' || line[7] == '\0'))
        {

            /*
             * Skip whitespace after "encode".
             */
            char *argument = line + 7;

            while (*argument == ' ')
                ++argument;

            /*
             * Require exactly AMESSAGE_SIZE ASCII characters.
             */
            if (strlen(argument) != AMESSAGE_SIZE)
            {

                fprintf(
                    stderr,
                    "Usage: encode <16 ASCII characters>\n");

                continue;
            }

            /*
             * Convert the MESSAGE_SIZE ASCII characters to a byte array.
             */
            uint8_t amessage[AMESSAGE_SIZE];

            for (size_t i = 0; i < AMESSAGE_SIZE; ++i)
            {

                if ((unsigned char)argument[i] > 127)
                {

                    fprintf(
                        stderr,
                        "Error: message must contain only ASCII characters.\n");

                    goto encode_continue;
                }

                amessage[i] = (uint8_t)argument[i];
            }

            size_t output_bits = 0;

            uint8_t **codewords = aprc.aencode(&aparams, keys->enc, dkey, amessage, &random, &output_bits);

            if (codewords == NULL)
            {

                fprintf(
                    stderr,
                    "Encoding failed.\n");

                continue;
            }

            if (!save_codewords(
                    "a_pp.txt",
                    codewords, aparams.mu,
                    output_bits))
            {

                fprintf(
                    stderr,
                    "Failed to write low.txt.\n");
            }
            else
            {

                printf(
                    "Encoded message \"%s\" (%zu ciphertext bits) "
                    "to a_pp.txt.\n",
                    argument,
                    output_bits);
            }

            free(codewords);

            continue;

        encode_continue:
            continue;
        }

        /*
         * --------------------------------------------------------
         * adecode
         * --------------------------------------------------------
         */

        if (strcmp(line, "adecode") == 0)
        {

            size_t num_codewords = 0;
            size_t codeword_bits = 0;

            uint8_t **codewords =
                load_codewords(
                    "a_pp.txt",
                    &num_codewords, &codeword_bits);

            if (codewords == NULL)
            {

                fprintf(
                    stderr,
                    "Failed to read a_pp.txt.\n");

                continue;
            }

            uint8_t amessage[AMESSAGE_SIZE] = {0};

            int result = aprc.adecode(&aparams, keys->dec, dkey, (const uint8_t *const *)codewords, codeword_bits, amessage);

            if (result == 1)
            {

                /*
                 * Convert the decoded bytes back to ASCII.
                 */
                char decoded[AMESSAGE_SIZE + 1];

                for (size_t i = 0; i < AMESSAGE_SIZE; ++i)
                    decoded[i] = (char)amessage[i];

                decoded[AMESSAGE_SIZE] = '\0';

                printf(
                    "Decoded: \"%s\"\n",
                    decoded);
            }
            else
            {

                printf(
                    "Decoding failed.\n");
            }

            free(codewords);

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
                    prefix_len) == 0)
        {

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
            if (*codeword_string == '\0')
            {

                fprintf(stderr,
                        "Missing codeword.\n");

                continue;
            }

            uint8_t *codeword =
                parse_codeword(
                    codeword_string,
                    params.n);

            if (codeword == NULL)
            {

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
                    params.n);

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
        keys);

    return EXIT_SUCCESS;
}