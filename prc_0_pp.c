#include "prc_0_pp.h"

#include <limits.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ================================================================
 * Basic utilities
 * ================================================================ */

size_t prc_0_pp_log2_power_of_two(uint64_t x)
{
    size_t r = 0;

    if (x == 0)
        return 0;

    while (x > 1) {
        if ((x & 1u) != 0)
            return 0; /* not a power of two */
        x >>= 1;
        ++r;
    }

    return r;
}

size_t prc_0_pp_bytes_for_bits(size_t bits)
{
    return (bits + 7u) / 8u;
}

static int valid_power_of_two(uint64_t x)
{
    return x != 0 && (x & (x - 1u)) == 0;
}


/* ================================================================
 * Randomness
 * ================================================================ */

static int rng_bytes(
    PRC0PPRandom *random,
    void *out,
    size_t len)
{
    if (random == NULL ||
        random->rng == NULL)
        return 0;

    return random->rng(
        random->ctx,
        (uint8_t *)out,
        len);
}

static uint64_t random_u64(PRC0PPRandom *random)
{
    uint64_t x = 0;

    if (!rng_bytes(random, &x, sizeof(x)))
        return 0;

    return x;
}

/*
 * Uniform integer in [0,bound).
 *
 * Rejection sampling is used for non-power-of-two bounds.
 */
static int random_bounded(
    PRC0PPRandom *random,
    uint64_t bound,
    uint64_t *result)
{
    if (bound == 0 || result == NULL)
        return 0;

    /*
     * For a power of two, masking is exact and avoids rejection.
     */
    if ((bound & (bound - 1u)) == 0) {
        const size_t bits =
            prc_0_pp_log2_power_of_two(bound);

        if (bits == 64) {
            *result = random_u64(random);
        } else {
            *result =
                random_u64(random) &
                ((UINT64_C(1) << bits) - 1u);
        }

        return 1;
    }

    const uint64_t limit =
        UINT64_MAX -
        (UINT64_MAX % bound);

    uint64_t x;

    do {
        x = random_u64(random);
    } while (x >= limit);

    *result = x % bound;
    return 1;
}

static int random_bernoulli(
    PRC0PPRandom *random,
    double p)
{
    if (p <= 0.0)
        return 0;

    if (p >= 1.0)
        return 1;

    /*
     * 53 uniformly random bits, matching binary64 precision.
     */
    const uint64_t x =
        random_u64(random) >> 11;

    const double u =
        (double)x * (1.0 / 9007199254740992.0);

    return u < p;
}


/* ================================================================
 * Permutations
 * ================================================================ */

static size_t *sample_permutation_n(
    size_t n,
    PRC0PPRandom *random)
{
    size_t *p = malloc(n * sizeof(*p));

    if (p == NULL && n != 0)
        return NULL;

    for (size_t i = 0; i < n; ++i)
        p[i] = i;

    /*
     * Fisher-Yates.
     */
    for (size_t i = n; i > 1; --i) {
        uint64_t j64;

        if (!random_bounded(
                random,
                (uint64_t)i,
                &j64)) {
            free(p);
            return NULL;
        }

        const size_t j = (size_t)j64;

        size_t tmp = p[i - 1];
        p[i - 1] = p[j];
        p[j] = tmp;
    }

    return p;
}

static int sample_alphabet_permutation(
    uint64_t q,
    uint64_t **forward_out,
    uint64_t **inverse_out,
    PRC0PPRandom *random)
{
    if (q == 0 ||
        forward_out == NULL ||
        inverse_out == NULL)
        return 0;

    /*
     * This implementation stores a complete permutation for each
     * coordinate, so q must fit in SIZE_MAX and be allocatable.
     */
    if (q > SIZE_MAX / sizeof(uint64_t))
        return 0;

    uint64_t *forward =
        malloc((size_t)q * sizeof(*forward));

    uint64_t *inverse =
        malloc((size_t)q * sizeof(*inverse));

    if (forward == NULL ||
        inverse == NULL) {
        free(forward);
        free(inverse);
        return 0;
    }

    for (uint64_t i = 0; i < q; ++i)
        forward[i] = i;

    /*
     * Fisher-Yates.
     */
    for (uint64_t i = q; i > 1; --i) {
        uint64_t j;

        if (!random_bounded(
                random,
                i,
                &j)) {
            free(forward);
            free(inverse);
            return 0;
        }

        uint64_t tmp = forward[i - 1];
        forward[i - 1] = forward[j];
        forward[j] = tmp;
    }

    for (uint64_t i = 0; i < q; ++i)
        inverse[forward[i]] = i;

    *forward_out = forward;
    *inverse_out = inverse;

    return 1;
}


/* ================================================================
 * Key generation
 * ================================================================ */

PRC0PPKey *prc_0_pp_keygen(
    const PRC0PPParams *params,
    PRC0PPRandom *random)
{
    if (params == NULL ||
        random == NULL ||
        params->code.n == 0 ||
        params->code.q == 0 ||
        !valid_power_of_two(
            (uint64_t)params->code.n) ||
        !valid_power_of_two(
            params->code.q) ||
        params->code.sample == NULL ||
        params->code.substitute == NULL ||
        params->code.list_recovery == NULL) {
        return NULL;
    }

    if (params->code.q > SIZE_MAX)
        return NULL;

    const size_t n = params->code.n;
    const uint64_t q = params->code.q;

    PRC0PPKey *key =
        calloc(1, sizeof(*key));

    if (key == NULL)
        return NULL;

    key->n = n;
    key->q = q;

    key->sigma =
        sample_permutation_n(n, random);

    if (key->sigma == NULL) {
        prc_0_pp_free_key(key);
        return NULL;
    }

    key->pi =
        calloc(n, sizeof(*key->pi));

    key->pi_inv =
        calloc(n, sizeof(*key->pi_inv));

    key->otp =
        malloc(n * sizeof(*key->otp));

    if (key->pi == NULL ||
        key->pi_inv == NULL ||
        (key->otp == NULL && n != 0)) {
        prc_0_pp_free_key(key);
        return NULL;
    }

    for (size_t i = 0; i < n; ++i) {
        if (!sample_alphabet_permutation(
                q,
                &key->pi[i],
                &key->pi_inv[i],
                random)) {

            prc_0_pp_free_key(key);
            return NULL;
        }

        uint64_t o;

        if (!random_bounded(
                random,
                q,
                &o)) {

            prc_0_pp_free_key(key);
            return NULL;
        }

        key->otp[i] = o;
    }

    return key;
}


/* ================================================================
 * Packed bitstring helpers
 *
 * Bits are stored LSB-first within bytes:
 *
 *   bit 0 -> byte 0, bit 0
 *   bit 1 -> byte 0, bit 1
 *
 * The binary representation emitted by Encode is nevertheless
 * conventional MSB-first within each fixed-width field.
 * ================================================================ */

static uint8_t get_packed_bit(
    const uint8_t *data,
    size_t bit)
{
    return (uint8_t)(
        (data[bit >> 3] >>
         (bit & 7u)) & 1u);
}

static void set_packed_bit(
    uint8_t *data,
    size_t bit,
    uint8_t value)
{
    const uint8_t mask =
        (uint8_t)(1u << (bit & 7u));

    if (value)
        data[bit >> 3] |= mask;
    else
        data[bit >> 3] &= (uint8_t)~mask;
}

/*
 * Append an integer in fixed-width binary, MSB first.
 */
static void append_bits(
    uint8_t *out,
    size_t *position,
    uint64_t value,
    size_t width)
{
    for (size_t j = 0; j < width; ++j) {
        const size_t shift =
            width - 1u - j;

        const uint8_t bit =
            (uint8_t)((value >> shift) & 1u);

        set_packed_bit(
            out,
            *position,
            bit);

        ++(*position);
    }
}


/* ================================================================
 * Encode
 * ================================================================ */

uint8_t *prc_0_pp_encode(
    const PRC0PPParams *params,
    const PRC0PPKey *key,
    PRC0PPRandom *random,
    size_t *output_bits)
{
    if (output_bits == NULL)
        return NULL;

    *output_bits = 0;

    if (params == NULL ||
        key == NULL ||
        random == NULL ||
        key->n != params->code.n ||
        key->q != params->code.q ||
        params->m == 0 ||
        params->code.sample == NULL ||
        params->code.substitute == NULL) {
        return NULL;
    }

    const size_t n = key->n;
    const uint64_t q = key->q;

    const size_t log_n =
        prc_0_pp_log2_power_of_two((uint64_t)n);

    const size_t log_q =
        prc_0_pp_log2_power_of_two(q);

    if (log_n == 0 && n != 1)
        return NULL;

    if (log_q == 0 && q != 1)
        return NULL;

    const size_t ell =
        log_n + log_q;

    if (params->m >
        SIZE_MAX / ell)
        return NULL;

    const size_t total_bits =
        params->m * ell;

    const size_t total_bytes =
        prc_0_pp_bytes_for_bits(total_bits);

    uint8_t *output =
        calloc(total_bytes, 1);

    if (output == NULL && total_bytes != 0)
        return NULL;

    /*
     * c_r <- C
     */
    uint64_t *cr =
        params->code.sample(
            params->code.code_ctx,
            n,
            q,
            random);

    if (cr == NULL) {
        free(output);
        return NULL;
    }

    /*
     * c'_r <- SC_eta(c_r)
     */
    uint64_t *cr_noisy =
        params->code.substitute(
            params->code.code_ctx,
            cr,
            n,
            q,
            params->eta,
            random);

    free(cr);

    if (cr_noisy == NULL) {
        free(output);
        return NULL;
    }

    /*
     * z = c'_r + o (mod q).
     */
    uint64_t *z =
        malloc(n * sizeof(*z));

    if (z == NULL && n != 0) {
        free(cr_noisy);
        free(output);
        return NULL;
    }

    for (size_t i = 0; i < n; ++i) {
        /*
         * q is a power of two. For q <= 2^63, this mask is exact.
         * For q == 2^64, unsigned uint64_t overflow itself gives
         * modulo 2^64 arithmetic, but q cannot be represented as a
         * uint64_t value. We therefore reject that case below.
         */
        if (q > UINT64_C(0x8000000000000000)) {
            free(cr_noisy);
            free(z);
            free(output);
            return NULL;
        }

        const uint64_t mask = q - 1u;

        z[i] =
            (cr_noisy[i] + key->otp[i]) &
            mask;
    }

    free(cr_noisy);

    /*
     * Sample m indices independently and uniformly from [n].
     *
     * If an index is fresh:
     *
     *     z'_j = pi_i(z_sigma(i))
     *
     * Otherwise:
     *
     *     z'_j <- [q].
     */
    uint8_t *seen =
        calloc(n, 1);

    if (seen == NULL && n != 0) {
        free(z);
        free(output);
        return NULL;
    }

    size_t position = 0;

    for (size_t j = 0; j < params->m; ++j) {
        uint64_t i64;

        if (!random_bounded(
                random,
                (uint64_t)n,
                &i64)) {

            free(seen);
            free(z);
            free(output);
            return NULL;
        }

        const size_t i =
            (size_t)i64;

        uint64_t zp;

        if (!seen[i]) {
            seen[i] = 1;

            zp =
                key->pi[i][
                    z[key->sigma[i]]
                ];
        } else {
            if (!random_bounded(
                    random,
                    q,
                    &zp)) {

                free(seen);
                free(z);
                free(output);
                return NULL;
            }
        }

        append_bits(
            output,
            &position,
            i,
            log_n);

        append_bits(
            output,
            &position,
            zp,
            log_q);
    }

    free(seen);
    free(z);

    *output_bits = total_bits;
    return output;
}


/* ================================================================
 * Distance calculations
 * ================================================================ */

/*
 * Get the j-th bit of bin(i)||bin(z), MSB first.
 */
static uint8_t candidate_bit(
    uint64_t i,
    uint64_t z,
    size_t log_n,
    size_t log_q,
    size_t j)
{
    if (j < log_n) {
        return (uint8_t)(
            (i >> (log_n - 1u - j)) & 1u);
    }

    j -= log_n;

    return (uint8_t)(
        (z >> (log_q - 1u - j)) & 1u);
}


/*
 * Hamming distance between received[pos..pos+ell) and
 * bin(i)||bin(z).
 */
static size_t candidate_hamming_distance(
    const uint8_t *received,
    size_t pos,
    uint64_t i,
    uint64_t z,
    size_t log_n,
    size_t log_q)
{
    const size_t ell =
        log_n + log_q;

    size_t d = 0;

    for (size_t j = 0; j < ell; ++j) {
        if (get_packed_bit(
                received,
                pos + j) !=
            candidate_bit(
                i,
                z,
                log_n,
                log_q,
                j)) {
            ++d;
        }
    }

    return d;
}


/*
 * Standard Levenshtein edit distance between the fixed-width
 * candidate string and the received substring.
 *
 * Both strings have length ell, but insertions/deletions are
 * still allowed inside the distance computation.
 *
 * Only two rows of the DP matrix are retained.
 */
static size_t candidate_edit_distance(
    const uint8_t *received,
    size_t pos,
    uint64_t i,
    uint64_t z,
    size_t log_n,
    size_t log_q)
{
    const size_t ell =
        log_n + log_q;

    size_t *prev =
        malloc((ell + 1u) * sizeof(*prev));

    size_t *curr =
        malloc((ell + 1u) * sizeof(*curr));

    if (prev == NULL || curr == NULL) {
        free(prev);
        free(curr);

        /*
         * Allocation failure is treated conservatively as
         * "not in the ball".
         */
        return SIZE_MAX;
    }

    for (size_t j = 0; j <= ell; ++j)
        prev[j] = j;

    for (size_t a = 1; a <= ell; ++a) {
        curr[0] = a;

        const uint8_t ca =
            candidate_bit(
                i,
                z,
                log_n,
                log_q,
                a - 1u);

        for (size_t b = 1; b <= ell; ++b) {
            const uint8_t cb =
                get_packed_bit(
                    received,
                    pos + b - 1u);

            const size_t deletion =
                prev[b] + 1u;

            const size_t insertion =
                curr[b - 1u] + 1u;

            const size_t substitution =
                prev[b - 1u] +
                (ca != cb);

            size_t best = deletion;

            if (insertion < best)
                best = insertion;

            if (substitution < best)
                best = substitution;

            curr[b] = best;
        }

        size_t *tmp = prev;
        prev = curr;
        curr = tmp;
    }

    const size_t distance = prev[ell];

    free(prev);
    free(curr);

    return distance;
}


/*
 * Test membership in
 *
 * B_H,E(x, alpha, epsilon)
 *
 * using the natural interpretation
 *
 *     d_H(x,y) <= alpha * ell
 *     d_E(x,y) <= epsilon * ell.
 */
static int candidate_in_ball(
    const uint8_t *received,
    size_t pos,
    uint64_t i,
    uint64_t z,
    size_t log_n,
    size_t log_q,
    double hamming_radius,
    double edit_radius)
{
    const size_t ell =
        log_n + log_q;

    const size_t max_hamming =
        (size_t)floor(
            hamming_radius * (double)ell);

    const size_t max_edit =
        (size_t)floor(
            edit_radius * (double)ell);

    const size_t hamming =
        candidate_hamming_distance(
            received,
            pos,
            i,
            z,
            log_n,
            log_q);

    if (hamming > max_hamming)
        return 0;

    const size_t edit =
        candidate_edit_distance(
            received,
            pos,
            i,
            z,
            log_n,
            log_q);

    if (edit > max_edit)
        return 0;

    return 1;
}


/* ================================================================
 * Decoder
 * ================================================================ */

int prc_0_pp_decode(
    const PRC0PPParams *params,
    const PRC0PPKey *key,
    const uint8_t *received,
    size_t received_bits)
{

    printf("p0a");

    if (params == NULL ||
        key == NULL ||
        (received == NULL && received_bits != 0) ||
        key->n != params->code.n ||
        key->q != params->code.q ||
        params->code.list_recovery == NULL ||
        params->L_max == 0) {
        return 0;
    }

    const size_t n = key->n;
    const uint64_t q = key->q;

    printf("p0b");

    const size_t log_n =
        prc_0_pp_log2_power_of_two((uint64_t)n);

    const size_t log_q =
        prc_0_pp_log2_power_of_two(q);

    const size_t ell =
        log_n + log_q;

    if (ell == 0 ||
        received_bits < ell)
        return 0;

    printf("p0c");
    /*
     * Allocate n lists. Each list has capacity L_max.
     *
     * We deliberately keep duplicates, matching the paper's
     * "add ... and truncate arbitrary elements" formulation.
     */
    if (n > SIZE_MAX / sizeof(uint64_t *))
        return 0;

    uint64_t **lists =
        calloc(n, sizeof(*lists));

    size_t *list_lengths =
        calloc(n, sizeof(*list_lengths));

    if (lists == NULL ||
        list_lengths == NULL) {
        free(lists);
        free(list_lengths);
        return 0;
    }

    printf("p1");

    for (size_t i = 0; i < n; ++i) {
        if (params->L_max >
            SIZE_MAX / sizeof(uint64_t)) {

            for (size_t j = 0; j < i; ++j)
                free(lists[j]);

            free(lists);
            free(list_lengths);
            return 0;
        }

        lists[i] =
            malloc(
                params->L_max *
                sizeof(uint64_t));

        if (lists[i] == NULL) {
            for (size_t j = 0; j < i; ++j)
                free(lists[j]);

            free(lists);
            free(list_lengths);
            return 0;
        }
    }

    printf("p2");

    /*
     * The decoder in Algorithm 1 scans every contiguous
     * length-ell substring and checks every (i,z).
     */
    for (size_t pos = 0;
         pos + ell <= received_bits;
         ++pos) {

        for (size_t i = 0; i < n; ++i) {

            for (uint64_t z = 0;
                 z < q;
                 ++z) {

                if (!candidate_in_ball(
                        received,
                        pos,
                        (uint64_t)i,
                        z,
                        log_n,
                        log_q,
                        0.5 - params->p_dec,
                        params->epsilon_dec)) {

                    continue;
                }

                /*
                 * The candidate is bin(i)||bin(z), where z is
                 * pi_i(a). Therefore recover
                 *
                 *     a = pi_i^{-1}(z)
                 *
                 * and put it in L_sigma(i).
                 */
                const size_t target =
                    key->sigma[i];

                if (list_lengths[target] <
                    params->L_max) {

                    lists[target][
                        list_lengths[target]++
                    ] =
                        key->pi_inv[i][z];
                }
            }
        }
    }

    printf("p3");

    /*
     * Apply the OTP:
     *
     *     (L_i - o_i) mod q.
     */
    if (q > UINT64_C(0x8000000000000000)) {
        for (size_t i = 0; i < n; ++i)
            free(lists[i]);

        free(lists);
        free(list_lengths);
        return 0;
    }

    const uint64_t mask =
        q - 1u;


    printf("p3");

    for (size_t i = 0; i < n; ++i) {
        for (size_t j = 0;
             j < list_lengths[i];
             ++j) {

            lists[i][j] =
                (lists[i][j] -
                 key->otp[i]) &
                mask;
        }
    }

    printf("p4");

    /*
     * Call the concrete code's list-recovery algorithm.
     */
    const int recovered =
        params->code.list_recovery(
            params->code.code_ctx,
            n,
            q,
            params->t_rec,
            (const uint64_t *const *)lists,
            list_lengths,
            params->L_max);

    for (size_t i = 0; i < n; ++i)
        free(lists[i]);

    printf("p5");

    free(lists);
    free(list_lengths);

    return recovered ? 1 : 0;
}


/* ================================================================
 * Cleanup
 * ================================================================ */

void prc_0_pp_free_key(PRC0PPKey *key)
{
    if (key == NULL)
        return;

    if (key->pi != NULL) {
        for (size_t i = 0; i < key->n; ++i)
            free(key->pi[i]);
    }

    if (key->pi_inv != NULL) {
        for (size_t i = 0; i < key->n; ++i)
            free(key->pi_inv[i]);
    }

    free(key->pi);
    free(key->pi_inv);
    free(key->sigma);
    free(key->otp);
    free(key);
}
