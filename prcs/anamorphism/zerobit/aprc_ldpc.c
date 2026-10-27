/*
 * Anamorphic mode of the LDPC zero-bit PRC (prc_ldpc.c): a second set of parity
 * checks (the construction for PRC_ldpc in the thesis).
 *
 * aKeyGen samples a second sparse parity-check matrix P' <- S_{t,r',n} until
 * P'G has full row rank r', and computes a matrix B (g x kappa, kappa = g - r')
 * whose columns are a basis of ker(P'G). The double key is dk = B, the trapdoor
 * key tk = P'. Only the matrix P'G enters the basis computation, not P'.
 *
 * aEncode is the regular encoding with the secret restricted to that subspace:
 * c = G B s + z + e with s uniform in F_2^kappa. Then P'G B s = 0, so the syndrome
 *     P'(c + z) = P'G B s + P'e = P'e
 * is sparse noise only, and aDecode accepts iff its weight is below
 * (1/2 - r'^(-1/4)) r'. The codeword is still of the form G x + z + e, so the
 * regular decoder accepts it. For a regular codeword (x uniform) P'G x is uniform
 * because P'G has full row rank, so the weight is about r'/2 and the codeword is
 * rejected (anamorphic robustness); the same holds for fixed strings, since z is
 * uniform.
 *
 * Security: given G and P, the product P'G is pseudorandom under a planted-XOR
 * assumption (lemma "hidden sparse rows"), so B hides the subspace. Only kappa
 * independent secrets fit into it, so the security claim covers
 * Q = kappa - log2(n)^2 anamorphic codewords per key (3840 for the default
 * instance n = 2^16, kappa = 4096 of the LDPC demo).
 */

#include "aprc_ldpc.h"
#include "a_zerobit_prc.h"
#include "../../zerobit/implementations/prc_ldpc.h"
#include "../../zerobit/implementations/prc_ldpc_internal.h"

#include <math.h>
#include <stdio.h>
#include <stdlib.h>

#include "../../../utils/matrix.h"
#include "../../../utils/random_utils.h"


struct AZBPRC_DoubleKey {
    ColumnMatrix B;          /* g x kappa, columns a basis of ker(P'G) */
};

struct AZBPRC_TrapdoorKey {
    SparseMatrix P_prime;    /* r' x n, t ones per row */
};


int ldpc_admissible_choice(size_t n, double epsilon, double delta, double eta,
                           LDPCParams *params, A_LDPCParams *aparams)
{
    if (params == NULL || n < 2 || !(epsilon > 0.0 && epsilon < 1.0) ||
        !(delta > 0.0) || !(eta > 0.0 && eta < 0.5))
        return -1;

    const double block_length = (double)n;
    const size_t r = (size_t)ceil(pow(block_length, epsilon / 2.0));
    const size_t kappa = (size_t)ceil(pow(block_length, epsilon));

    *params = (LDPCParams){
        .n = n,
        .g = kappa + r,
        .t = (size_t)floor(delta * log2(block_length)),
        .r = r,
        .eta = eta,
    };

    if (aparams != NULL)
        *aparams = (A_LDPCParams){.r_prime = r};

    return 0;
}

/* (1/2 - r^(-1/4)) r > 0 iff r > 16: with fewer checks every string is rejected */
#define MIN_PARITY_CHECKS 16

static int requirement_failed(const char *requirement)
{
    fprintf(stderr, "LDPC parameters violate %s\n", requirement);
    return -1;
}

/* n^exponent, rounded up like the admissible choice (tolerating rounding errors of pow) */
static double power_bound(size_t n, double exponent)
{
    return ceil(pow((double)n, exponent) - 1e-9);
}

int ldpc_check_requirements(const LDPCParams *params, const A_LDPCParams *aparams,
                            double epsilon)
{
    if (params == NULL || params->n < 2)
        return requirement_failed("n >= 2");

    const double n = (double)params->n;
    const double log_n = log2(n);
    const double log_n_squared = log_n * log_n;

    if (params->t < 1 || (double)params->t > log_n)
        return requirement_failed("(R1): 1 <= t <= log2 n");

    if ((double)params->r < power_bound(params->n, epsilon / 2.0))
        return requirement_failed("(R2): r >= n^(epsilon/2)");

    if (params->r <= MIN_PARITY_CHECKS)
        return requirement_failed("r > 16 (otherwise the threshold (1/2 - r^(-1/4)) r is not positive)");

    if ((double)(params->g + params->r) > n - log_n_squared)
        return requirement_failed("(R4): g + r <= n - log2(n)^2");

    if (!(params->eta > 0.0 && params->eta < 0.5))
        return requirement_failed("(R5): 0 < eta < 1/2");

    if ((double)params->g < power_bound(params->n, epsilon))
        return requirement_failed("(A1): g >= n^epsilon");

    if (aparams == NULL)
        return 0;

    if (aparams->r_prime <= MIN_PARITY_CHECKS)
        return requirement_failed("r' > 16 (otherwise the threshold (1/2 - r'^(-1/4)) r' is not positive)");

    if ((double)aparams->r_prime < power_bound(params->n, epsilon / 2.0) ||
        (double)(params->r + aparams->r_prime) > 0.99 * n)
        return requirement_failed("(R2): r' >= n^(epsilon/2) and r + r' <= 0.99 n");

    if (aparams->r_prime >= params->g ||
        (double)(params->g - aparams->r_prime) <= log_n_squared)
        return requirement_failed("(R3): r' < g and kappa = g - r' > log2(n)^2");

    if ((double)(params->g - aparams->r_prime) < power_bound(params->n, epsilon))
        return requirement_failed("(R6): kappa >= n^epsilon");

    return 0;
}


static void ldpc_free_double_key(const void *params, const void *aparams,
                                 AZBPRC_DoubleKey *double_key)
{
    (void)params;
    (void)aparams;

    if (double_key == NULL)
        return;

    column_matrix_free(&double_key->B);
    free(double_key);
}

static void ldpc_free_trapdoor_key(const void *params, const void *aparams,
                                   AZBPRC_TrapdoorKey *trapdoor_key)
{
    (void)params;
    (void)aparams;

    if (trapdoor_key == NULL)
        return;

    sparse_matrix_free(&trapdoor_key->P_prime);
    free(trapdoor_key);
}

/*
 * aKeyGen: samples P' <- S_{t,r',n} until rk(P'G) = r', i.e. until
 * dim ker(P'G) = g - r' (an r' x g matrix with uniform columns has full rank
 * except with probability below 2^-kappa); gives up after lambda = n attempts.
 * Returns dk = B and tk = P'; of the regular keys only G is read.
 */
static AZBPRC_Keys *ldpc_akeygen(const void *params_ptr, const void *aparams_ptr,
                                 ZBPRC_Keys *regular_keys, RandomnessSource *random)
{
    const LDPCParams *params = params_ptr;
    const A_LDPCParams *aparams = aparams_ptr;

    if (params == NULL || aparams == NULL || regular_keys == NULL ||
        regular_keys->enc == NULL || random == NULL || random->rng == NULL ||
        aparams->r_prime == 0 || aparams->r_prime >= params->g)
        return NULL;

    const ColumnMatrix *G = &regular_keys->enc->G;
    const size_t kappa = params->g - aparams->r_prime;
    SparseMatrix P_prime = {0};
    ColumnMatrix B = {0};
    int full_rank = 0;

    for (size_t attempt = 0; attempt < params->n && !full_rank; ++attempt) {
        P_prime = sparse_matrix_alloc(aparams->r_prime, params->n, params->t);
        sparse_matrix_sample(&P_prime, random);

        ColumnMatrix P_prime_G = sparse_matrix_mul_column_matrix(&P_prime, G);

        B = column_matrix_kernel(&P_prime_G);
        column_matrix_free(&P_prime_G);

        full_rank = B.cols == kappa;

        if (!full_rank) {
            column_matrix_free(&B);
            sparse_matrix_free(&P_prime);
        }
    }

    if (!full_rank)
        return NULL;

    AZBPRC_Keys *akeys = calloc(1, sizeof(*akeys));

    if (akeys != NULL) {
        akeys->double_key = malloc(sizeof(*akeys->double_key));
        akeys->trapdoor_key = malloc(sizeof(*akeys->trapdoor_key));
    }

    if (akeys == NULL || akeys->double_key == NULL || akeys->trapdoor_key == NULL) {
        if (akeys != NULL) {
            free(akeys->double_key);
            free(akeys->trapdoor_key);
        }
        free(akeys);
        column_matrix_free(&B);
        sparse_matrix_free(&P_prime);
        return NULL;
    }

    akeys->double_key->B = B;
    akeys->trapdoor_key->P_prime = P_prime;

    return akeys;
}

/* aEncode: c = G B s + z + e with s uniform in F_2^kappa and e <- Ber(n, eta). */
static uint8_t *ldpc_aencode(const void *params_ptr,
                             const void *aparams_ptr,
                             const ZBPRC_EncKey *enc_key,
                             const AZBPRC_DoubleKey *double_key,
                             RandomnessSource *random,
                             size_t *codeword_bits)
{
    const LDPCParams *params = params_ptr;

    (void)aparams_ptr;

    if (params == NULL || enc_key == NULL || double_key == NULL ||
        random == NULL || codeword_bits == NULL)
        return NULL;

    BitVector s = bitvector_alloc(double_key->B.cols);
    BitVector Bs = bitvector_alloc(params->g);

    random_bitvector(random, &s);
    column_matrix_mul_vector(&double_key->B, &s, &Bs);

    uint8_t *codeword = ldpc_encode_seed(params, enc_key, &Bs, random, codeword_bits);

    bitvector_free(&Bs);
    bitvector_free(&s);

    return codeword;
}

/* aDecode: accepts iff c has n bits and wgt(P'(c + z)) < (1/2 - r'^(-1/4)) r'. */
static int ldpc_adecode(const void *params_ptr,
                        const void *aparams_ptr,
                        const ZBPRC_DecKey *dec_key,
                        const AZBPRC_TrapdoorKey *trapdoor_key,
                        const uint8_t *codeword,
                        size_t codeword_bits)
{
    (void)aparams_ptr;

    if (params_ptr == NULL || dec_key == NULL || trapdoor_key == NULL)
        return 0;

    return ldpc_syndrome_test(&trapdoor_key->P_prime, &dec_key->z, codeword, codeword_bits);
}

aZBPRC aprc_ldpc(const A_LDPCParams *aparams)
{
    return (aZBPRC){
        .aparams = aparams,
        .akeygen = ldpc_akeygen,
        .aencode = ldpc_aencode,
        .adecode = ldpc_adecode,
        .free_double_key = ldpc_free_double_key,
        .free_trapdoor_key = ldpc_free_trapdoor_key,
    };
}
