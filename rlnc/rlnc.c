/*
 * Random linear network coding (RLNC) over GF(q), q = 2^m <= 256.
 *
 * A generation consists of K source packets w_1..w_K, each a vector of GF(q)
 * symbols. A coded symbol carries a global encoding vector gamma in GF(q)^K (the
 * "header") and the payload u = sum_k gamma_k w_k. Any node can create new symbols
 * as random linear combinations of the symbols it holds; the global vector of the
 * result is the same combination of the global vectors. A receiver that holds K
 * symbols whose global vectors are linearly independent recovers the generation
 * by solving a linear system. See T. Ho et al., "A random linear network coding
 * approach to multicast", IEEE Trans. Inf. Theory 52(10), 2006, and P. A. Chou,
 * Y. Wu, K. Jain, "Practical network coding", Allerton 2003 (generations and
 * global encoding vectors in the packet headers).
 *
 * The anamorphic mode is in arlnc.c; it uses encode_with_vector below.
 */

#include "rlnc.h"

#include <stdlib.h>
#include <string.h>
#include "../utils/random_utils.h"

/*
 * Field polynomial of GF(q) = GF(2)[x] / (f), bit i = coefficient of x^i, with
 * the x^m term included (0x11D = x^8 + x^4 + x^3 + x^2 + 1, the polynomial of
 * the usual GF(256) of Reed-Solomon codes, e.g. in AES it would be 0x11B).
 * The polynomials are irreducible, in fact primitive, so x generates the
 * multiplicative group:
 *   GF(2): x + 1             GF(4): x^2 + x + 1        GF(8): x^3 + x + 1
 *   GF(16): x^4 + x + 1      GF(32): x^5 + x^2 + 1     GF(64): x^6 + x + 1
 *   GF(128): x^7 + x + 1     GF(256): x^8 + x^4 + x^3 + x^2 + 1
 */
static uint32_t gf_polynomial(uint32_t q)
{
    switch (q) {
        case 2:   return 0x03;
        case 4:   return 0x07;
        case 8:   return 0x0B;
        case 16:  return 0x13;
        case 32:  return 0x25;
        case 64:  return 0x43;
        case 128: return 0x83;
        case 256: return 0x11D;
        default:  return 0;
    }
}

static int is_power_of_two(uint32_t q)
{
    return q >= 2 && (q & (q - 1)) == 0;
}

static unsigned field_bits(uint32_t q)
{
    unsigned m = 0;

    while (q > 1) {
        q >>= 1;
        ++m;
    }

    return m;
}

/*
 * Number of GF(q) symbols of a payload of packet_size bytes (m bits each).
 */
static size_t symbol_count(const rlnc_config_t *cfg)
{
    const size_t bits = cfg->packet_size * 8;
    const size_t m = field_bits(cfg->q);

    return (bits + m - 1) / m;
}


/* -------------------------------------------------------------------------
 * GF(2^m)
 * ------------------------------------------------------------------------- */

static uint32_t gf_add(uint32_t a, uint32_t b)
{
    /* addition in characteristic 2 is the XOR of the coefficient vectors */
    return a ^ b;
}

/*
 * a * b in GF(q): polynomial product modulo the field polynomial.
 */
static uint32_t gf_mul(
    uint32_t a,
    uint32_t b,
    uint32_t q)
{
    const unsigned m = field_bits(q);
    const uint32_t polynomial = gf_polynomial(q);

    uint32_t result = 0;

    /*
     * Shift-and-add ("Russian peasant") multiplication: for every bit b_i of b
     * add a * x^i to the result, where a * x is a shift of a by one position
     * followed by a reduction modulo the field polynomial if the coefficient of
     * x^(m-1) was shifted out.
     */
    for (unsigned i = 0; i < m; ++i) {
        if (b & 1u)
            result ^= a;

        b >>= 1;

        const uint32_t carry = a & (1u << (m - 1));

        a <<= 1;

        if (carry)
            a ^= polynomial;
    }

    return result & (q - 1);
}

/*
 * a^exponent in GF(q) by square-and-multiply (binary exponentiation), O(log exponent) multiplications.
 */
static uint32_t gf_pow(
    uint32_t a,
    uint32_t exponent,
    uint32_t q)
{
    uint32_t result = 1;

    while (exponent != 0) {
        if (exponent & 1u)
            result = gf_mul(result, a, q);

        a = gf_mul(a, a, q);
        exponent >>= 1;
    }

    return result;
}

/*
 * 1/a in GF(q) (0 for a = 0).
 */
static uint32_t gf_inv(uint32_t a, uint32_t q)
{
    if (a == 0)
        return 0;

    /* Fermat: a^(q-1) = 1 for a != 0 in GF(q), hence a^(-1) = a^(q-2) */
    return gf_pow(a, q - 2, q);
}


/* -------------------------------------------------------------------------
 * Packing/unpacking arbitrary bytes into GF(q) symbols
 * ------------------------------------------------------------------------- */

/*
 * Extract symbol number `index` from a byte array.
 *
 * The byte array is interpreted as a continuous little-endian bit stream:
 *
 *   byte 0: b0 b1 b2 ...
 *
 * The exact bit ordering does not matter for RLNC as long as encoding
 * and decoding use the same representation.
 */
static uint32_t get_symbol(
    const uint8_t *data,
    size_t index,
    unsigned m)
{
    const size_t bit_offset = index * m;
    const size_t byte_offset = bit_offset / 8;
    const unsigned shift = bit_offset % 8;

    uint32_t value = data[byte_offset] >> shift;

    if (shift + m > 8) {
        value |= (uint32_t)data[byte_offset + 1] << (8 - shift);
    }

    return value & ((1u << m) - 1u);
}


/*
 * Write a GF(q) symbol into the byte array.
 *
 * The destination must have been zero-initialized before writing.
 */
static void set_symbol(
    uint8_t *data,
    size_t index,
    unsigned m,
    uint32_t value)
{
    const size_t bit_offset = index * m;
    const size_t byte_offset = bit_offset / 8;
    const unsigned shift = bit_offset % 8;
    const uint32_t mask = (1u << m) - 1u;

    value &= mask;

    /*
     * First part.
     */
    data[byte_offset] |= (uint8_t)(value << shift);

    /*
     * If the symbol crosses a byte boundary, write the remaining bits.
     */
    if (shift + m > 8) {
        data[byte_offset + 1] |=
            (uint8_t)(value >> (8 - shift));
    }
}


/* -------------------------------------------------------------------------
 * Configuration / packet management
 * ------------------------------------------------------------------------- */

int rlnc_config_valid(const rlnc_config_t *cfg)
{
    if (cfg == NULL)
        return 0;

    /* the arithmetic is that of GF(2^m): q must be a power of two */
    if (!is_power_of_two(cfg->q))
        return 0;

    /*
     * This implementation currently supports GF(2^m), m <= 8.
     */
    if (cfg->q > 256)
        return 0;

    if (gf_polynomial(cfg->q) == 0)
        return 0;

    if (cfg->packet_size == 0)
        return 0;

    if (cfg->generation_size == 0)
        return 0;

    return 1;
}

int rlnc_packet_alloc(
    const rlnc_config_t *cfg,
    rlnc_packet_t *packet)
{
    if (!rlnc_config_valid(cfg) || packet == NULL)
        return -1;

    packet->payload = calloc(cfg->packet_size, sizeof(uint8_t));
    packet->global = calloc(cfg->generation_size, sizeof(uint8_t));

    if (packet->payload == NULL || packet->global == NULL) {
        rlnc_packet_free(packet);
        return -1;
    }

    return 0;
}

void rlnc_packet_free(rlnc_packet_t *packet)
{
    if (packet == NULL)
        return;

    free(packet->payload);
    free(packet->global);

    packet->payload = NULL;
    packet->global = NULL;
}


/* -------------------------------------------------------------------------
 * Encoding
 * ------------------------------------------------------------------------- */


/*
 * Samples a local encoding vector: input_count coefficients, each uniform in GF(q).
 * A symbol is the combination sum_j alpha_j * (packet j) with these coefficients.
 */
 int rlnc_sample_local_encoding_vector(
    const rlnc_config_t *cfg,
    size_t input_count,
    RandomnessSource *rng,
    uint8_t *local_vector)
{
    if (!rlnc_config_valid(cfg) ||
        input_count == 0 ||
        rng == NULL ||
        local_vector == NULL)
        return -1;

    for (size_t i = 0; i < input_count; ++i) {
        local_vector[i] =
            (uint8_t)random_bounded(rng, cfg->q);
    }

    return 0;
}


/*
 * Creates one coded symbol as the linear combination
 *     out = sum_j alpha_j * packets[j]
 * of the input symbols with the given local coefficients alpha, applied both to the
 * global encoding vectors and to the payloads (a matrix-vector product over GF(q)).
 * If the inputs are the source packets (global vectors e_1..e_K), the global vector of
 * the output is alpha itself. The anamorphic encoder uses this with a chosen alpha.
 */
int rlnc_encode_with_vector(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    const uint8_t *local_vector,
    rlnc_packet_t *out)
{
    if (!rlnc_config_valid(cfg) ||
        packets == NULL ||
        local_vector == NULL ||
        out == NULL)
        return -1;

    if (packet_count == 0)
        return -1;

    const unsigned m = field_bits(cfg->q);
    const size_t symbols = symbol_count(cfg);

    memset(out->payload, 0, cfg->packet_size);
    memset(out->global, 0, cfg->generation_size);

    /*
     * Accumulate the coded payload as GF(q) symbols.
     *
     * We cannot accumulate directly into the byte array because
     * GF(q) symbols may cross byte boundaries when m does not
     * divide 8.
     */
    uint32_t *coded_symbols =
        calloc(symbols, sizeof(uint32_t));

    if (coded_symbols == NULL)
        return -1;

    /*
     * u' = sum_j alpha_j * u_j
     *
     * gamma' = sum_j alpha_j * gamma_j
     */
    for (size_t j = 0; j < packet_count; ++j) {
        const uint32_t alpha = local_vector[j];

        /*
         * Compute the global encoding vector:
         *
         * gamma' = sum_j alpha_j * gamma_j
         */
        for (size_t k = 0; k < cfg->generation_size; ++k) {
            const uint32_t product =
                gf_mul(
                    alpha,
                    packets[j].global[k],
                    cfg->q);

            out->global[k] =
                (uint8_t)gf_add(
                    out->global[k],
                    product);
        }

        /*
         * Compute the coded payload:
         *
         * u' = sum_j alpha_j * u_j
         */
        for (size_t i = 0; i < symbols; ++i) {
            const uint32_t value =
                get_symbol(
                    packets[j].payload,
                    i,
                    m);

            const uint32_t product =
                gf_mul(
                    alpha,
                    value,
                    cfg->q);

            coded_symbols[i] =
                gf_add(
                    coded_symbols[i],
                    product);
        }
    }

    /*
     * Pack the resulting GF(q) symbols back into bytes.
     */
    for (size_t i = 0; i < symbols; ++i) {
        set_symbol(
            out->payload,
            i,
            m,
            coded_symbols[i]);
    }

    free(coded_symbols);

    return 0;
}


/*
 * Creates one coded symbol from fresh random coefficients: a random linear combination of the input symbols.
 */
int rlnc_encode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *rng)
{
    if (!rlnc_config_valid(cfg) ||
        packets == NULL ||
        out == NULL ||
        rng == NULL)
        return -1;

    if (packet_count == 0)
        return -1;

    /*
     * The local encoding vector belongs to this node and therefore
     * has one coefficient for every packet available to this node.
     */
    uint8_t *local_vector =
        malloc(packet_count * sizeof(uint8_t));

    if (local_vector == NULL)
        return -1;

    /*
     * Sample the local encoding vector.
     */
    if (rlnc_sample_local_encoding_vector(
            cfg,
            packet_count,
            rng,
            local_vector) != 0) {

        free(local_vector);
        return -1;
    }

    /*
     * Encode using the sampled local encoding vector.
     *
     * rlnc_encode_with_vector() derives the outgoing global
     * encoding vector from the incoming global vectors.
     */
    const int result =
        rlnc_encode_with_vector(
            cfg,
            packets,
            packet_count,
            local_vector,
            out);

    free(local_vector);

    return result;
}


/* -------------------------------------------------------------------------
 * Decoding
 * ------------------------------------------------------------------------- */


/*
 * Recovers the K source packets from received symbols (at least K).
 *
 * Solves the linear system [gamma_j | u_j] over GF(q) by Gauss-Jordan elimination
 * on the augmented matrix whose rows are the received global vectors followed by
 * the payloads: for each column find a row with a non-zero entry, normalise it with
 * the inverse of the pivot, and eliminate the column from all other rows. When the
 * left part is the identity the right part holds w_1..w_K. All received rows
 * are used, so a surplus of symbols compensates for dependent ones. Returns -1 if
 * the global vectors do not have rank K. Cost O(R K (K + D)) field operations for
 * R received symbols and D payload symbols.
 */
int rlnc_decode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *received,
    size_t received_count,
    rlnc_packet_t *out)
{
    if (!rlnc_config_valid(cfg) ||
        received == NULL ||
        out == NULL)
        return -1;

    if (received_count < cfg->generation_size)
        return -1;

    const size_t K = cfg->generation_size;
    const size_t R = received_count;
    const unsigned m = field_bits(cfg->q);
    const size_t symbols = symbol_count(cfg);

    /*
     * Work on all received packets: the first K need not be independent.
     *
     * Each row consists of:
     *
     *     [ global vector | payload symbols ]
     */
    uint32_t **matrix =
        calloc(R, sizeof(uint32_t *));

    if (matrix == NULL)
        return -1;

    for (size_t r = 0; r < R; ++r) {
        matrix[r] =
            calloc(K + symbols, sizeof(uint32_t));

        if (matrix[r] == NULL) {
            for (size_t i = 0; i < r; ++i)
                free(matrix[i]);

            free(matrix);
            return -1;
        }

        /*
         * Global encoding vector.
         */
        for (size_t c = 0; c < K; ++c)
            matrix[r][c] = received[r].global[c];

        /*
         * Payload represented as GF(q) symbols.
         */
        for (size_t i = 0; i < symbols; ++i)
            matrix[r][K + i] =
                get_symbol(received[r].payload, i, m);
    }

    /*
     * Gauss-Jordan elimination.
     *
     * We never swap columns. Instead, we search for a row containing
     * a non-zero value in the current pivot column and swap rows.
     */
    for (size_t col = 0; col < K; ++col) {
        size_t pivot = col;

        while (pivot < R && matrix[pivot][col] == 0)
            ++pivot;

        if (pivot == R) {
            /*
             * The received global vectors are not linearly independent.
             */
            for (size_t i = 0; i < R; ++i)
                free(matrix[i]);

            free(matrix);
            return -1;
        }

        if (pivot != col) {
            uint32_t *tmp = matrix[col];
            matrix[col] = matrix[pivot];
            matrix[pivot] = tmp;
        }

        /*
         * Normalize pivot to 1.
         */
        const uint32_t inverse =
            gf_inv(matrix[col][col], cfg->q);

        for (size_t j = col; j < K + symbols; ++j) {
            matrix[col][j] =
                gf_mul(matrix[col][j], inverse, cfg->q);
        }

        /*
         * Eliminate this column from all other rows.
         */
        for (size_t row = 0; row < R; ++row) {
            if (row == col)
                continue;

            const uint32_t factor = matrix[row][col];

            if (factor == 0)
                continue;

            for (size_t j = col; j < K + symbols; ++j) {
                const uint32_t product =
                    gf_mul(factor, matrix[col][j], cfg->q);

                matrix[row][j] =
                    gf_add(matrix[row][j], product);
            }
        }
    }

    for (size_t row = 0; row < K; ++row) {
    memset(out[row].payload, 0, cfg->packet_size);

    for (size_t i = 0; i < symbols; ++i) {
        set_symbol(
            out[row].payload,
            i,
            m,
            matrix[row][K + i]);
    }

    memset(out[row].global, 0, K);
    out[row].global[row] = 1;
    }

    for (size_t i = 0; i < R; ++i)
        free(matrix[i]);

    free(matrix);

    return 0;
}