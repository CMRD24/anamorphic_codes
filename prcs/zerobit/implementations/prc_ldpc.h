#ifndef PRC_LDPC_H
#define PRC_LDPC_H

/*
 * The zero-bit PRC PRC_ldpc = LDPC-PRC_0[n, g, t, r, eta, r^(-1/4)] of Christ and
 * Gunn (see prc_ldpc.c). Parameters satisfying the requirements of the thesis are
 * computed by ldpc_admissible_choice (aprc_ldpc.h).
 */

#include <stddef.h>

#include "../zerobit_prc.h"

typedef struct {
    size_t n;      /* block length (the security parameter lambda = n) */
    size_t g;      /* columns of the generator matrix G (length of the LPN secret) */
    size_t t;      /* sparsity: ones per row of the parity-check matrix P */
    size_t r;      /* rows of P (parity checks) */
    double eta;    /* noise rate of the encoder, e <- Ber(n, eta) */
} LDPCParams;

/* The LDPC zero-bit PRC (the parameters must outlive it). */
ZBPRC prc_ldpc(const LDPCParams *params);

#endif /* PRC_LDPC_H */
