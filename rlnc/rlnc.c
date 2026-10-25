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
#include <threads.h>
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
 * GF(2^m) by table lookup
 *
 * For q <= 256 the full multiplication table has q^2 <= 65536 entries, so every
 * product is a single lookup (the classic table method for small binary fields,
 * cf. J. S. Plank, "A tutorial on Reed-Solomon coding for fault-tolerance in
 * RAID-like systems", Software: Practice and Experience 27(9), 1997). The tables
 * are built once from logarithm / antilogarithm tables: the field polynomials are
 * primitive, so every non-zero element is a power x^i of the generator x, and
 * x^i * x^j = x^((i + j) mod (q - 1)).
 * ------------------------------------------------------------------------- */

static uint8_t *mul_tables[9];        /* [m][a * 2^m + b] = a * b in GF(2^m) */
static uint8_t inv_tables[9][256];    /* [m][a] = 1 / a (0 for a = 0) */
static once_flag tables_once = ONCE_FLAG_INIT;

static void build_tables(void)
{
    for (unsigned m = 1; m <= 8; ++m) {
        const uint32_t q = 1u << m, poly = gf_polynomial(q);
        uint8_t exp[2 * 256], log[256] = {0};
        uint32_t x = 1;

        /* exp[i] = x^i, log[x^i] = i, by repeated multiplication with x */
        for (uint32_t i = 0; i < q - 1; ++i) {
            exp[i] = (uint8_t)x;
            log[x] = (uint8_t)i;
            x <<= 1;
            if (x & q)
                x ^= poly;
        }
        for (uint32_t i = q - 1; i < 2 * (q - 1); ++i)
            exp[i] = exp[i - (q - 1)];

        mul_tables[m] = calloc(q * q, 1);
        if (mul_tables[m] == NULL)
            abort();

        for (uint32_t u = 1; u < q; ++u) {
            for (uint32_t v = 1; v < q; ++v)
                mul_tables[m][u * q + v] = exp[log[u] + log[v]];

            inv_tables[m][u] = exp[(q - 1 - log[u]) % (q - 1)];
        }
    }
}

/* row a of the multiplication table: row[b] = a * b */
static const uint8_t *gf_mul_row(uint32_t a, uint32_t q)
{
    call_once(&tables_once, build_tables);

    return mul_tables[field_bits(q)] + a * q;
}

static uint32_t gf_inv(uint32_t a, uint32_t q)
{
    call_once(&tables_once, build_tables);

    return inv_tables[field_bits(q)][a];
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


/* dst[i] += a * src[i] over GF(q) (the row operation of encoding and elimination) */
static void gf_axpy(uint8_t *dst, const uint8_t *src, size_t len, uint32_t a, uint32_t q)
{
    if (a == 0)
        return;

    if (a == 1) {
        for (size_t i = 0; i < len; ++i)
            dst[i] ^= src[i];
        return;
    }

    const uint8_t *mul = gf_mul_row(a, q);

    for (size_t i = 0; i < len; ++i)
        dst[i] ^= mul[src[i]];
}

/* v[i] = a * v[i] over GF(q) */
static void gf_scale(uint8_t *v, size_t len, uint32_t a, uint32_t q)
{
    const uint8_t *mul = gf_mul_row(a, q);

    for (size_t i = 0; i < len; ++i)
        v[i] = mul[v[i]];
}

/* the symbols of a payload, one GF(q) element per byte */
static void unpack_symbols(const uint8_t *payload, unsigned m, size_t symbols, uint8_t *out)
{
    if (m == 8) {
        memcpy(out, payload, symbols);
        return;
    }

    for (size_t i = 0; i < symbols; ++i)
        out[i] = (uint8_t)get_symbol(payload, i, m);
}

/* inverse of unpack_symbols; payload must be zeroed */
static void pack_symbols(const uint8_t *in, unsigned m, size_t symbols, uint8_t *payload)
{
    if (m == 8) {
        memcpy(payload, in, symbols);
        return;
    }

    for (size_t i = 0; i < symbols; ++i)
        set_symbol(payload, i, m, in[i]);
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
    if (!rlnc_config_valid(cfg) || packets == NULL || local_vector == NULL ||
        out == NULL || packet_count == 0)
        return -1;

    const unsigned m = field_bits(cfg->q);
    const size_t symbols = symbol_count(cfg);
    uint8_t *acc = NULL, *tmp = NULL;

    memset(out->payload, 0, cfg->packet_size);
    memset(out->global, 0, cfg->generation_size);

    /* symbols of fewer than 8 bits are combined unpacked, one per byte */
    if (m != 8) {
        acc = calloc(symbols, 1);
        tmp = malloc(symbols);

        if (acc == NULL || tmp == NULL) {
            free(acc);
            free(tmp);
            return -1;
        }
    }

    /* gamma' = sum_j alpha_j gamma_j,  u' = sum_j alpha_j u_j */
    for (size_t j = 0; j < packet_count; ++j) {
        const uint32_t alpha = local_vector[j];

        gf_axpy(out->global, packets[j].global, cfg->generation_size, alpha, cfg->q);

        if (m == 8) {
            gf_axpy(out->payload, packets[j].payload, cfg->packet_size, alpha, cfg->q);
        } else {
            unpack_symbols(packets[j].payload, m, symbols, tmp);
            gf_axpy(acc, tmp, symbols, alpha, cfg->q);
        }
    }

    if (m != 8)
        pack_symbols(acc, m, symbols, out->payload);

    free(acc);
    free(tmp);

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
 * the payload symbols: for each column find a row with a non-zero entry, normalise it with
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
    if (!rlnc_config_valid(cfg) || received == NULL || out == NULL ||
        received_count < cfg->generation_size)
        return -1;

    const size_t K = cfg->generation_size;
    const size_t R = received_count;
    const unsigned m = field_bits(cfg->q);
    const size_t symbols = symbol_count(cfg);
    const size_t width = K + symbols;
    int rc = -1;

    /*
     * Augmented matrix, one row per received symbol (all of them: the first K
     * need not be independent): [ global vector | payload symbols ], one GF(q)
     * element per byte.
     */
    uint8_t *data = malloc(R * width);
    uint8_t **row = malloc(R * sizeof(*row));

    if (data == NULL || row == NULL)
        goto done;

    for (size_t r = 0; r < R; ++r) {
        row[r] = data + r * width;
        memcpy(row[r], received[r].global, K);
        unpack_symbols(received[r].payload, m, symbols, row[r] + K);
    }

    /* Gauss-Jordan elimination; rows are swapped, columns never */
    for (size_t col = 0; col < K; ++col) {
        size_t pivot = col;

        while (pivot < R && row[pivot][col] == 0)
            ++pivot;

        if (pivot == R)
            goto done;      /* the global vectors do not have rank K */

        uint8_t *tmp = row[col];
        row[col] = row[pivot];
        row[pivot] = tmp;

        /* normalise the pivot to 1 */
        gf_scale(row[col] + col, width - col, gf_inv(row[col][col], cfg->q), cfg->q);

        /* eliminate the column from all other rows */
        for (size_t r = 0; r < R; ++r) {
            if (r != col && row[r][col] != 0)
                gf_axpy(row[r] + col, row[col] + col, width - col, row[r][col], cfg->q);
        }
    }

    /* row k now reads [ e_k | w_k ] */
    for (size_t k = 0; k < K; ++k) {
        memset(out[k].payload, 0, cfg->packet_size);
        pack_symbols(row[k] + K, m, symbols, out[k].payload);

        memset(out[k].global, 0, K);
        out[k].global[k] = 1;
    }

    rc = 0;

done:
    free(row);
    free(data);

    return rc;
}