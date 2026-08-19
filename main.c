#include "prc_ldpc.h"

#include <stdio.h>
#include <stdlib.h>

/*
 * Linux-specific secure RNG.
 */
extern int linux_secure_random(void *ctx,
                               uint8_t *out,
                               size_t len);


int main(void)
{
    /*
     * PRC parameters.
     */
    PRCParams params = {
        .n   = 512,
        .r   = 256,
        .g   = 128,
        .t   = 8,
        .eta = 0.01
    };

    /*
     * Connect the PRC to Linux's CSPRNG.
     */
    PRCRandom random = {
        .rng = linux_secure_random,
        .ctx = NULL
    };

    /*
     * KeyGen(1^lambda)
     */
    PRCKeys *keys =
        prc_keygen(&params,
                   &random);

    if (keys == NULL) {
        fprintf(stderr,
                "Key generation failed.\n");
        return EXIT_FAILURE;
    }

    printf("Key generation successful.\n\n");

    /*
     * Print encryption key.
     */
    //prc_print_enc_key(&params,
    //                  keys->enc);

    putchar('\n');

    /*
     * Print decryption key.
     */
    //prc_print_dec_key(&params,
    //                  keys->dec);

    putchar('\n');

    /*
     * Encode(1^lambda, EncKey, 1)
     */
    uint8_t *c =
        prc_encode(&params,
                   keys->enc,
                   &random);

    if (c == NULL) {
        fprintf(stderr,
                "Encoding failed.\n");

        prc_free_keys(keys);
        return EXIT_FAILURE;
    }

    printf("Encoding successful.\n\n");

    /*
     * Print ciphertext.
     */
    prc_print_codeword(&params,
                       c);

    putchar('\n');

    /*
     * Decode(1^lambda, DecKey, c)
     */
    int result =
        prc_decode(&params,
                   keys->dec,
                   c);

    printf("Decode result: %s\n",
           result ? "1" : "bottom");

    free(c);
    prc_free_keys(keys);


    

    return EXIT_SUCCESS;
}