

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



APRC_Keys *
ldpc_akeygen(const void *params_ptr, const void *aparams_ptr, ZBPRC_Keys *reg_keys,
            RandomnessSource *random)
{
    const A_LDPCParams *aparams =
        (const A_LDPCParams *)aparams_ptr;

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

    
    size_t k = params->g/2;
    size_t g_prime_dim = aparams->g_prime; //params->n-params->r+k;//params->n-k;

    if (params->r <= params->g/2 && params->g <= params->n-params->r){
        printf("Setting 2\n");
        g_prime_dim = params->n-k;
    }
    
    /*
     * Sample P'.
     */
    SparseP P_prime =
        sparse_p_alloc(params->r,
                       params->n,
                       params->t);

    sample_sparse_p(random, &P_prime);

    printf("ak1\n");
    /*
     * Compute ker(P').
     */
    PackedMatrix A =
        sparse_p_to_packed(&P_prime);
    KernelBasis kerP =
        kernel_basis(&A);

    

    

    printf("ak2\n");

    /*
     * Sample G' uniformly from ker(P').
     */
    PackedG G_prime =
        packed_g_alloc(params->n,
                       g_prime_dim);

    for (size_t j = 0;
         j < g_prime_dim;
         ++j) {

        for (size_t k = 0;
             k < kerP.dimension;
             ++k) {

            if (random_bit(random)) {

                for (size_t w = 0;
                     w < G_prime.columns[j].words;
                     ++w) {

                    G_prime.columns[j].data[w] ^=
                        kerP.vectors[k].data[w];
                }
            }
        }
    }

    printf("ak3\n");

    kernel_basis_free(&kerP);

    //create G|G'

    PackedMatrix GG = concat_g_matrices(&reg_keys->enc->G, &G_prime);

    printf("gg' dim %zu x %zu\n", GG.rows, GG.cols);
    /*
     * Compute ker(G|G').
     */
    KernelBasis K_prime =
        kernel_basis(&GG);

     printf("k dim %zu\n", K_prime.dimension);

    printf("ak5\n");

    

    printf("ak6\n");


    printf("ak6a\n");
    PackedMatrix mtemp0 = packed_g_to_matrix(&reg_keys->enc->G);
    
    printf("dim ker G       = %zu\n", kernel_basis(&mtemp0).dimension);
    printf("G is  %zu x %zu\n", reg_keys->enc->G.n, reg_keys->enc->G.g);
    PackedMatrix mtemp = packed_g_to_matrix(&G_prime);
    
    printf("dim ker G'       = %zu\n", kernel_basis(&mtemp).dimension);
    printf("G' is  %zu x %zu\n", G_prime.n, G_prime.g);
    printf("dim kern GG'       = %zu\n", kernel_basis(&GG).dimension);
    


    printf("k dim %zu\n", K_prime.dimension);

    PackedG B = kernel_basis_to_packed_g(&K_prime, reg_keys->enc->G.g);

    printf("b %zu x %zu\n", B.n, B.g);
    
    printf("ak6b\n");

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


    printf("ak7\n");

    //packed_matrix_free(A);

    return dk;


}



uint8_t *
ldpc_aencode(const void *params_ptr,
            const void *aparams_ptr, 
            const ZBPRC_EncKey *key,
            const APRC_EncKey *dk,
            RandomnessSource *random,
            size_t *output_bits)
{
    (void)aparams_ptr;

    printf("here\n");
    const LDPCParams *params =
        (const LDPCParams *)params_ptr;

    if (params == NULL ||
        key == NULL ||
        random == NULL ||
        output_bits == NULL)
        return NULL;
    
    printf("ae1\n");

    size_t k = params->g/2;
    /*
     * s <- F_2^k
     */
    BitVector s_prime =
        bitvector_alloc(k);

    random_bitvector(random, &s_prime);

    printf("ae2\n");

    BitVector s =
        bitvector_alloc(params->n);

    printf("ae3\n");

    packed_g_mul(dk->Subspace, &s_prime, &s);

    printf("ae4\n");

    //rest the same as regular encode

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
        bitvector_alloc(params->r);

    sparse_p_mul(dk->P_prime,
                 &c,
                 &Pc);

    /*
     * Pz.
     */
    BitVector Pz =
        bitvector_alloc(params->r);

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
         pow((double)params->r,
             -0.25))
        * (double)params->r;

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

