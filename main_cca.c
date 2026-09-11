#include "prcs/zerobit/implementations/prc_ldpc.h"
#include "prcs/multibit/implementations/prc_low.h"
#include "prcs/multibit/implementations/prc_cca.h"
#include "utils/hamming74.h"
#include "utils/random.h"
#include "prcs/anamorphism/aprc_rr.h"

#include "main_utils.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>




#define MESSAGE_SIZE 4
#define AMESSAGE_SIZE 8


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


uint8_t **readlines(const char *filename, size_t l, size_t k)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
        return NULL;

    uint8_t **lines = malloc(l * sizeof(uint8_t *));
    if (lines == NULL) {
        fclose(file);
        return NULL;
    }

    for (size_t i = 0; i < l; i++) {
        lines[i] = malloc(k * sizeof(uint8_t));
        if (lines[i] == NULL) {
            for (size_t j = 0; j < i; j++)
                free(lines[j]);

            free(lines);
            fclose(file);
            return NULL;
        }

        size_t j = 0;
        int c;

        while (j < k && (c = fgetc(file)) != EOF && c != '\n') {
            lines[i][j++] = (uint8_t)c;
        }

        /* If the line is shorter than k, zero-pad it */
        while (j < k)
            lines[i][j++] = 0;

        if (c == EOF && i + 1 < l) {
            /* Not enough lines */
            for (size_t x = 0; x <= i; x++)
                free(lines[x]);

            free(lines);
            fclose(file);
            return NULL;
        }
    }

    fclose(file);
    return lines;
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
                    "Invalid character in cca.txt: '%c'\n",
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
        "  encode   - encode and write to cca.txt\n"
        "  decode   - read from cca.txt and decode\n"
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

        MBPRC prc_l =
            prc_low(&low_params);

        
        PRC_CCA_Params high_params = {
            .prc = &prc_l,
            .lambda_bits = 16,
            .delta = 0.05
        };
        
        MBPRC_RR prc_rr = prc_cca_rr(&high_params);



        MBPRC prc = prc_rr.base;

        aMBPRC_RR_Params aparams = {
            .prc_rr = &prc_rr,
            .mu = 32 + 1 + AMESSAGE_SIZE / 2, //AMESSAGE_SIZE bits / 16
            .indication_len = 32,
            .seed_len = 16};

        aMBPRC_RR aprc = aMBPRC_RR_init(&aparams);

/*
 * ============================================================
 * Key generation
 * ============================================================
 */

 APRC_RR_Keys *dkey = aprc.akeygen(&aparams, &random);

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
            "cca.txt",
            codeword,
            output_bits)) {

        fprintf(
            stderr,
            "Failed to write cca.txt.\n"
        );

    } else {

        printf(
            "Encoded message \"%s\" (%zu ciphertext bits) "
            "to cca.txt.\n",
            argument,
            output_bits
        );
    }

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


            uint8_t **reg_messages = readlines("cca_reg_msgs.txt", aparams.mu, MESSAGE_SIZE);

            uint8_t **codewords = aprc.aencode(&aparams, keys->enc, dkey, reg_messages, MESSAGE_SIZE*8, amessage, &random, &output_bits);

            if (codewords == NULL)
            {

                fprintf(
                    stderr,
                    "Encoding failed.\n");

                continue;
            }

            if (!save_codewords(
                    "a_cca.txt",
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
                    "to a_cca.txt.\n",
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
                    "a_cca.txt",
                    &num_codewords, &codeword_bits);


            if (codewords == NULL)
            {

                fprintf(
                    stderr,
                    "Failed to read a_cca.txt.\n");

                continue;
            }

            uint8_t amessage[AMESSAGE_SIZE] = {0};

            int result = aprc.adecode(&aparams, keys->dec, dkey, (const uint8_t *const *)codewords, codeword_bits, amessage, MESSAGE_SIZE*8);

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
 * decode
 * --------------------------------------------------------
 */

if (strcmp(line, "decode") == 0) {

    size_t ciphertext_bits = 0;

    uint8_t *codeword =
        load_codeword(
            "cca.txt",
            &ciphertext_bits
        );

    if (codeword == NULL) {

        fprintf(
            stderr,
            "Failed to read cca.txt.\n"
        );

        continue;
    }

    printf(
        "Read %zu bits from cca.txt.\n",
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