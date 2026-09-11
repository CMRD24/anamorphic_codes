

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
    //TODO get r_prime from aparams
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

    size_t r_prime = params->g/2;
    
    /*
     * Sample P'.
     */
    SparseP P_prime =
        sparse_p_alloc(r_prime,
                       params->n,
                       params->t);

    sample_sparse_p(random, &P_prime);

    printf("ak1\n");

    //compute P'G

    PackedG PpG = sparse_p_mul_packed_g(&P_prime, &reg_keys->enc->G);

    

    /*
     * Compute ker(P'G).
     */
    PackedMatrix temp = packed_g_to_matrix(&PpG);

    KernelBasis kerPpG =
        kernel_basis(&temp);

    
    printf("ker P'G dim %zu\n", kerPpG.dimension);


    PackedG B = kernel_basis_to_packed_g(&kerPpG, params->g);

    
    
    


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

    size_t r_prime = params->g/2;

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

    printf("weight %zu\n", weight);

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

