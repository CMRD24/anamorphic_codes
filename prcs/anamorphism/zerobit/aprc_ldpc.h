#ifndef APRC_LDPC_H
#define APRC_LDPC_H

/* Anamorphic mode of the LDPC zero-bit PRC (see aprc_ldpc.c). */

#include <stddef.h>

#include "a_zerobit_prc.h"
#include "../../zerobit/implementations/prc_ldpc.h"

typedef struct {
    size_t r_prime;    /* r': rows of the anamorphic parity-check matrix P'; kappa = g - r' */
} A_LDPCParams;

/*
 * The admissible choice of the thesis for block length n:
 *     r = r' = ceil(n^(epsilon/2)),  kappa = ceil(n^epsilon),  g = kappa + r',
 *     t = floor(delta log2 n),
 * where epsilon is the constant of the LPN assumption (Set II of Christ and Gunn)
 * and delta the constant of the sparsity; eta is the encoder noise rate. aparams
 * may be NULL if only the regular parameters are needed. Returns 0, or -1 if a
 * value is out of range (n < 2, epsilon not in (0, 1), delta <= 0, eta not in
 * (0, 1/2)).
 */
int ldpc_admissible_choice(size_t n, double epsilon, double delta, double eta,
                           LDPCParams *params, A_LDPCParams *aparams);

/*
 * Checks the requirements (R1)-(R6) of the thesis in a concrete form; the
 * asymptotic conditions are read with omega(log n) as "more than log2(n)^2":
 *   (R1) 1 <= t <= log2 n                (t = delta log n with delta <= 1)
 *   (R2) r, r' >= n^(epsilon/2) and r + r' <= 0.99 n; in addition r, r' > 16,
 *        since otherwise the decoding threshold (1/2 - r^(-1/4)) r is not positive
 *   (R3) r' < g and kappa = g - r' > log2(n)^2
 *   (R4) g + r <= n - log2(n)^2
 *   (R5) 0 < eta < 1/2
 *   (R6) kappa >= n^epsilon, and g >= n^epsilon for LPN_g (A1)
 * With aparams == NULL only the requirements of the regular PRC are checked.
 * Returns 0 if all hold; otherwise prints the first violated one to stderr and
 * returns -1.
 */
int ldpc_check_requirements(const LDPCParams *params, const A_LDPCParams *aparams,
                            double epsilon);

/* The anamorphic mode for the LDPC PRC (the parameters must outlive it). */
aZBPRC aprc_ldpc(const A_LDPCParams *aparams);

#endif /* APRC_LDPC_H */
