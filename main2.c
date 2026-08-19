#include "prc_0_pp.h"
#include "folded_rs.h"

#include <stdio.h>
#include <stdlib.h>

extern int linux_secure_random(
    void *ctx,
    uint8_t *out,
    size_t len
);

int main(void)
{
    PRC0PPRandom random = {
        .rng = linux_secure_random,
        .ctx = NULL
    };

    /*
     * ------------------------------------------------------------
     * Folded Reed–Solomon parameters
     * ------------------------------------------------------------
     *
     * Base field:
     *
     *     GF(2^8)
     *
     * Folding factor:
     *
     *     s = 2
     *
     * Thus:
     *
     *     q = 2^(8*2) = 65536
     */
    FoldedRSParams rs_params;

    if (!folded_rs_params_init(
            &rs_params,
            8,      /* field bits */
            2,      /* folding factor */
            64,     /* n */
            16)) {  /* k */
        fprintf(stderr,
                "Invalid Reed-Solomon parameters.\n");
        return EXIT_FAILURE;
    }

    /*
     * Construct the generic PRCCode interface.
     */
    PRCCode code;

    if (!folded_rs_init(
            &rs_params,
            &code)) {

        fprintf(stderr,
                "Failed to initialize folded RS code.\n");
        return EXIT_FAILURE;
    }

    /*
     * ------------------------------------------------------------
     * PRC^{0,PP} parameters
     * ------------------------------------------------------------
     */

    PRC0PPParams params = {
        .code = code,

        .eta = 0.01,

        .p_dec = 0.10,
        .epsilon_dec = 0.05,

        .L_max = 16,

        .t_rec = 48,

        .m = 128
    };

    /*
     * ------------------------------------------------------------
     * PRC KeyGen
     * ------------------------------------------------------------
     */

    PRC0PPKey *key =
        prc_0_pp_keygen(
            &params,
            &random
        );

    if (key == NULL) {
        fprintf(stderr,
                "PRC key generation failed.\n");
        return EXIT_FAILURE;
    }

    printf("PRC^{0,PP} key generation successful.\n");

    /*
     * ------------------------------------------------------------
     * Encode
     * ------------------------------------------------------------
     */

    size_t ciphertext_bits;

    uint8_t *ciphertext =
        prc_0_pp_encode(
            &params,
            key,
            &random,
            &ciphertext_bits
        );

    if (ciphertext == NULL) {
        fprintf(stderr,
                "Encoding failed.\n");

        prc_0_pp_free_key(key);
        return EXIT_FAILURE;
    }

    printf(
        "Encoded %zu bits.\n",
        ciphertext_bits
    );

    /*
     * ------------------------------------------------------------
     * Decode
     * ------------------------------------------------------------
     */

    printf("decoding started");

    int result =
        prc_0_pp_decode(
            &params,
            key,
            ciphertext,
            ciphertext_bits
        );

    printf(
        "Decode result: %s\n",
        result ? "1" : "bottom"
    );

    free(ciphertext);
    prc_0_pp_free_key(key);

    return EXIT_SUCCESS;
}