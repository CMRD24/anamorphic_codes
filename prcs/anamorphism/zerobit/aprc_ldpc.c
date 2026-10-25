/*
 * Anamorphic mode of the LDPC zero-bit PRC (prc_ldpc.c): a second set of parity
 * checks.
 *
 * Anamorphic key generation samples a second sparse parity-check matrix P'
 * (r' x n, t ones per row) as the trapdoor key and computes a basis B of the
 * kernel of P'G (G is the generator matrix of the regular key). The double key is
 * B (dimension g - r').
 *
 * Anamorphic encoding is the regular encoding with the secret s restricted to
 * the subspace: c = G (B s') + z + e. Then P' G B s' = 0, so the syndrome
 *     P'(c + z) = P' G B s' + P' e = P' e
 * is sparse noise only, and the anamorphic decoder accepts iff its weight is
 * below (1/2 - r'^(-1/4)) r'. The codeword is still of the form G s + z + e, so
 * the regular decoder accepts it. For a regular codeword with s uniform,
 * P' G s is uniform when P'G has full row rank r', so the weight is about r'/2
 * and it is rejected (anamorphic robustness); the same holds for random strings.
 *
 * Security: P'G B hides the subspace B, since given G and P the products P' G are
 * pseudorandom under a planted-XOR assumption (so a regular observer cannot tell
 * that s is confined to a subspace); only g - r' vectors lie in the subspace, so
 * the claim is limited to about g - r' codewords per key (see the thesis).
 */

#include "a_zerobit_prc.h"
#include "aprc_ldpc.h"
#include "../../zerobit/zerobit_prc.h"
#include "../../zerobit/implementations/prc_ldpc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <limits.h>
#include <stdint.h>

#include "../../../utils/matrix.h"
#include "../../../utils/random_utils.h"


struct APRC_EncKey {
    PackedG *Subspace;

};


struct APRC_DecKey {
    SparseP *P_prime;
};


struct ZBPRC_EncKey {
    PackedG G;
    BitVector z;
};


struct ZBPRC_DecKey {
    SparseP P;
    BitVector z;
};


void free_enc_akey(const void *params, const void *aparams, APRC_EncKey *key)
{
    (void)params;
    (void)aparams;

    if (key == NULL)
        return;

    packed_g_free(key->Subspace);

    free(key);
}


void free_dec_akey(const void *params, const void *aparams, APRC_DecKey *key)
{
    (void)params;
    (void)aparams;
    if (key == NULL)
        return;

    sparse_p_free(key->P_prime);

    free(key);
}


/*
 * Number r' of anamorphic parity checks P'. The anamorphic subspace ker(P'G) then
 * has dimension g - r' (rank-nullity), which must be positive and large enough
 * for the number of codewords that are to look regular.
 */
static size_t
ldpc_num_anamorphic_checks(const LDPCParams *params)
{
    return params->g / 2;
}


/*
 * Anamorphic key generation. Samples P' (r' = g/2 rows) until P'G has full row
 * rank r' (an r' x g matrix with independent random columns has full rank except
 * with probability about 2^(r' - g), so a few attempts suffice), then computes a
 * basis B of ker(P'G) (packed_g_kernel). Returns the
 * double key B and the trapdoor key P'; the regular keys are only read (G).
 */
APRC_Keys *
ldpc_akeygen(const void *params_ptr, const void *aparams_ptr, ZBPRC_Keys *reg_keys,
            RandomnessSource *random)
{
    (void)aparams_ptr;

    const LDPCParams *params =
        (const LDPCParams *)params_ptr;


    if (params == NULL ||
        random == NULL ||
        random->rng == NULL)
        return NULL;

    if (params->n == 0 ||
        params->r == 0 ||
        params->g == 0 ||
        params->t > params->n ||
        params->g > params->n)
        return NULL;

    APRC_Keys *dk =
        calloc(1, sizeof(APRC_Keys));

    if (dk == NULL)
        return NULL;

    dk->enc =
        calloc(1, sizeof(APRC_EncKey));

    dk->dec =
        calloc(1, sizeof(APRC_DecKey));

    if (dk->enc == NULL ||
    dk->dec == NULL) {

        free_enc_akey(params_ptr, aparams_ptr, dk->enc);
        free_dec_akey(params_ptr, aparams_ptr, dk->dec);
        free(dk);

        return NULL;
    }

    size_t r_prime = ldpc_num_anamorphic_checks(params);

    /*
     * Sample P' until P'G has full row rank r'. Since
     * dim ker(P'G) = g - rk(P'G), this is the case iff the kernel has
     * dimension g - r'. For r' < g this fails with probability <= 2^-(g-r'),
     * so a bounded number of attempts suffices.
     */
    enum { MAX_ATTEMPTS = 128 };

    SparseP P_prime = {0};
    KernelBasis kerPpG = {0};
    int full_rank = 0;

    for (int attempt = 0; attempt < MAX_ATTEMPTS && !full_rank; ++attempt) {
        P_prime =
            sparse_p_alloc(r_prime,
                           params->n,
                           params->t);

        sample_sparse_p(random, &P_prime);

        PackedG PpG = sparse_p_mul_packed_g(&P_prime, &reg_keys->enc->G);

        kerPpG = packed_g_kernel(&PpG);
        packed_g_free(&PpG);

        full_rank = (kerPpG.dimension + r_prime == params->g);

        if (!full_rank) {
            kernel_basis_free(&kerPpG);
            sparse_p_free(&P_prime);
        }
    }

    if (!full_rank) {
        free_enc_akey(params_ptr, aparams_ptr, dk->enc);
        free_dec_akey(params_ptr, aparams_ptr, dk->dec);
        free(dk);

        return NULL;
    }

    PackedG B = kernel_basis_to_packed_g(&kerPpG, params->g);

    kernel_basis_free(&kerPpG);

    dk->enc->Subspace = malloc(sizeof(PackedG));
    if (dk->enc->Subspace == NULL) {
        packed_g_free(&B);
        free(dk);
        return NULL;
    }

    *dk->enc->Subspace = B;

    dk->dec->P_prime = malloc(sizeof(SparseP));
    if (dk->dec->P_prime == NULL) {
        packed_g_free(&B);
        free(dk);
        return NULL;
    }

    *dk->dec->P_prime = P_prime;


    return dk;


}


/*
 * Anamorphic encoding: c = G (B s') + z + e with s' uniform in F_2^(g - r') and
 * e ~ Ber(n, eta), i.e. a regular encoding whose secret lies in ker(P'G).
 */
uint8_t *
ldpc_aencode(const void *params_ptr,
            const void *aparams_ptr,
            const ZBPRC_EncKey *key,
            const APRC_EncKey *dk,
            RandomnessSource *random,
            size_t *output_bits)
{
    (void)aparams_ptr;

    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    if (params == NULL ||
        key == NULL ||
        random == NULL ||
        output_bits == NULL)
        return NULL;


    /* dimension of ker(P'G) */
    size_t k = params->g - ldpc_num_anamorphic_checks(params);
    /*
     * s <- F_2^k
     */
    BitVector s_prime =
        bitvector_alloc(k);

    random_bitvector(random, &s_prime);


    /* s = B s' lives in F_2^g, the column space of G */
    BitVector s =
        bitvector_alloc(params->g);


    packed_g_mul(dk->Subspace, &s_prime, &s);



    /*
     * e <- Ber(n, eta)
     */
    BitVector e =
        bitvector_alloc(params->n);

    random_bernoulli_vector(random,
                            &e,
                            params->eta);

    /*
     * Gs.
     */
    BitVector Gs =
        bitvector_alloc(params->n);

    packed_g_mul(&key->G,
                 &s,
                 &Gs);

    /*
     * c = Gs + z + e.
     */
    BitVector c =
        bitvector_alloc(params->n);

    for (size_t w = 0;
         w < c.words;
         ++w) {

        c.data[w] =
            Gs.data[w] ^
            key->z.data[w] ^
            e.data[w];
    }

    /*
     * Convert to packed byte representation.
     */
    size_t bytes =
        (params->n + 7) / 8;

    uint8_t *result =
        calloc(bytes, 1);

    if (result == NULL) {

        bitvector_free(&s);
        bitvector_free(&e);
        bitvector_free(&Gs);
        bitvector_free(&c);

        return NULL;
    }

    for (size_t i = 0;
         i < params->n;
         ++i) {

        if (bit_get(&c, i)) {

            result[i >> 3] |=
                (uint8_t)(
                    1u << (i & 7)
                );
        }
    }

    *output_bits = params->n;

    bitvector_free(&s);
    bitvector_free(&e);
    bitvector_free(&Gs);
    bitvector_free(&c);

    return result;
}


/*
 * Anamorphic decoding: accepts iff wgt(P'(c + z)) < (1/2 - r'^(-1/4)) r', where
 * P'(c + z) = P' e for an anamorphic codeword (see the comment at the top of the file).
 */
int
ldpc_adecode(const void *params_ptr,
    const void *aparams_ptr,
            const ZBPRC_DecKey *key,
            const APRC_DecKey *dk,
            const uint8_t *ciphertext,
            size_t ciphertext_bits)
{

    (void)aparams_ptr;


    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    size_t r_prime = ldpc_num_anamorphic_checks(params);

    if (params == NULL ||
        key == NULL ||
        ciphertext == NULL)
        return 0;

    /*
     * size of ciphertext must have size n
     */
    if (ciphertext_bits != params->n)
        return 0;


    /*
     * Convert byte representation to BitVector.
     */
    BitVector c =
        bitvector_alloc(params->n);

    for (size_t i = 0;
         i < params->n;
         ++i) {

        if (ciphertext[i >> 3] &
            (uint8_t)(
                1u << (i & 7)
            )) {

            bit_set(&c, i, 1);
        }
    }

    /*
     * P'c.
     */
    BitVector Pc =
        bitvector_alloc(r_prime);

    sparse_p_mul(dk->P_prime,
                 &c,
                 &Pc);

    /*
     * Pz.
     */
    BitVector Pz =
        bitvector_alloc(r_prime);

    sparse_p_mul(dk->P_prime,
                 &key->z,
                 &Pz);

    /*
     * Pc + Pz.
     */
    for (size_t w = 0;
         w < Pc.words;
         ++w) {

        Pc.data[w] ^=
            Pz.data[w];
    }

    /*
     * wt(Pc + Pz)
     */
    size_t weight =
        bitvector_weight(&Pc);


    /*
     * Threshold:
     *
     *     (1/2 - r^(-1/4)) r
     */
    double threshold =
        (0.5 -
         pow((double)r_prime,
             -0.25))
        * (double)r_prime;

    int result =
        ((double)weight < threshold);

    bitvector_free(&c);
    bitvector_free(&Pc);
    bitvector_free(&Pz);

    return result;
}


aZBPRC
aprc_ldpc(const A_LDPCParams *aparams)
{
    aZBPRC aprc = {
        .aparams = aparams,


        .akeygen =
            ldpc_akeygen,

        .aencode =
            ldpc_aencode,

        .adecode =
            ldpc_adecode,

        .free_adec_key =
            free_dec_akey,

        .free_aenc_key =
            free_enc_akey
    };

    return aprc;
}

