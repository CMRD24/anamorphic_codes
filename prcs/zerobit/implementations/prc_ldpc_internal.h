#ifndef PRC_LDPC_INTERNAL_H
#define PRC_LDPC_INTERNAL_H

/*
 * Key layout and shared steps of the LDPC PRC, used by its regular mode
 * (prc_ldpc.c) and its anamorphic mode (aprc_ldpc.c) only.
 */

#include <stddef.h>
#include <stdint.h>

#include "prc_ldpc.h"
#include "../../../utils/matrix.h"
#include "../../../utils/random.h"

struct ZBPRC_EncKey {
    ColumnMatrix G;      /* n x g generator matrix, columns uniform in ker P */
    BitVector z;         /* one-time pad in F_2^n */
};

struct ZBPRC_DecKey {
    SparseMatrix P;      /* r x n parity-check matrix, t ones per row */
    BitVector z;
};

/*
 * c = G x + z + e with e <- Ber(n, eta), packed LSB first; x in F_2^g is the secret
 * (uniform for a regular codeword, B s for an anamorphic one). Returns NULL on
 * allocation failure.
 */
uint8_t *ldpc_encode_secret(const LDPCParams *params,
                            const ZBPRC_EncKey *enc_key,
                            const BitVector *x,
                            RandomnessSource *random,
                            size_t *codeword_bits);

/*
 * The syndrome test of both decoders: 1 iff the codeword has P.cols bits and
 * wgt(P (c + z)) < (1/2 - rows^(-1/4)) rows for the rows x n parity-check matrix P.
 */
int ldpc_syndrome_test(const SparseMatrix *P,
                       const BitVector *z,
                       const uint8_t *codeword,
                       size_t codeword_bits);

#endif /* PRC_LDPC_INTERNAL_H */
