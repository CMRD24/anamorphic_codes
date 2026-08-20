#ifndef PRC_CODE_H
#define PRC_CODE_H

#include <stddef.h>
#include <stdint.h>

/*
 * Abstract q-ary code interface used by PRC^{0,PP}.
 *
 * Symbols are represented as integers in [0,q).
 *
 * The concrete code implementation owns code_ctx and is responsible
 * for:
 *   - sampling a uniform codeword from C,
 *   - applying substitution noise,
 *   - list recovery.
 *
 * ListRecovery must return non-zero iff its output list is non-empty.
 */
typedef struct {
    size_t n;
    uint64_t q;
    void *code_ctx;

    /*
     * Sample c <- C uniformly.
     * Returns n symbols in [0,q), or NULL on failure.
     * Caller owns the returned array.
     */
    uint64_t *(*sample)(
        void *code_ctx,
        size_t n,
        uint64_t q,
        void *rng);

    /*
     * Return SC_eta(word).
     * The returned array has n symbols and is owned by the caller.
     */
    uint64_t *(*substitute)(
        void *code_ctx,
        const uint64_t *word,
        size_t n,
        uint64_t q,
        double eta,
        void *rng);

    /*
     * List recovery.
     *
     * lists[i] contains list_lengths[i] symbols in [0,q).
     * Each list has already been truncated to L_max.
     *
     * Return non-zero iff ListRecovery(t_rec, lists) is non-empty.
     */
    int (*list_recovery)(
        void *code_ctx,
        size_t n,
        uint64_t q,
        size_t t_rec,
        const uint64_t *const *lists,
        const size_t *list_lengths,
        size_t L_max);

} PRCCode;

#endif /* PRC_CODE_H */
