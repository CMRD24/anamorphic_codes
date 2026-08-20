#ifndef FOLDED_RS_H
#define FOLDED_RS_H

#include <stddef.h>
#include <stdint.h>

#include "prc_code.h"

/*
 * Folded Reed-Solomon code over GF(2^w).
 *
 * A message is a polynomial f(X) of degree < k over GF(2^w).
 * The underlying RS word evaluates f at
 *
 *   alpha^0, alpha^1, ..., alpha^(n*folding_factor-1)
 *
 * and folds every `folding_factor` consecutive base-field symbols
 * into one q-ary symbol. Hence
 *
 *   Q = 2^w,
 *   q = Q^folding_factor = 2^(w*folding_factor).
 *
 * The packed q-ary symbol stores the first evaluation in the least
 * significant field slot, the second in the next slot, etc.
 *
 * This implementation deliberately uses exhaustive list recovery:
 * it enumerates message polynomials until it finds one agreeing with
 * the input coordinate lists in at least t_rec positions. This is an
 * exact reference implementation, but is exponential in k.
 */

typedef struct {
    /* Base field GF(2^field_bits), 2 <= field_bits <= 16. */
    unsigned field_bits;

    /* Number of base-field evaluations folded into one symbol. */
    size_t folding_factor;

    /* Folded code block length. */
    size_t n;

    /* Message dimension over the base field. */
    size_t k;

    /* Primitive polynomial, including the x^field_bits term. */
    uint32_t primitive_polynomial;

    /* Generator alpha of the multiplicative group. */
    uint32_t alpha;

} FoldedRSParams;

/*
 * Validate parameters and derive the PRCCode interface.
 *
 * code->n = params->n
 * code->q = (2^field_bits)^folding_factor
 *
 * The returned interface owns no memory and remains valid as long as
 * params remains valid.
 */
int folded_rs_init(
    FoldedRSParams *params,
    PRCCode *code);

/* Convenience constructor for common primitive polynomials. */
int folded_rs_params_init(
    FoldedRSParams *params,
    unsigned field_bits,
    size_t folding_factor,
    size_t n,
    size_t k);

/*
 * Returns the q-ary alphabet size q = Q^folding_factor, or 0 on an
 * invalid parameter set / overflow.
 */
uint64_t folded_rs_alphabet_size(
    const FoldedRSParams *params);

/*
 * Human-readable parameter validation helper.
 * Returns 1 if valid, 0 otherwise.
 */
int folded_rs_validate(
    const FoldedRSParams *params);

#endif /* FOLDED_RS_H */
