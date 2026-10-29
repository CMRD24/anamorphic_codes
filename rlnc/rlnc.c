/*
 * Random linear network coding (RLNC) over GF(q), q = 2^m <= 256.
 *
 * A generation consists of K source packets w_1..w_K, each a vector of GF(q)
 * symbols. A coded symbol carries a global encoding vector gamma in GF(q)^K 
 * and the payload u = sum_k gamma_k w_k. Any node can create new symbols
 * as random linear combinations of the symbols it holds; the global vector of the
 * result is the same combination of the global vectors. A receiver that holds K
 * symbols whose global vectors are linearly independent recovers the generation
 * by solving a linear system. See T. Ho et al., "A random linear network coding
 * approach to multicast", IEEE Trans. Inf. Theory 52(10), 2006, and P. A. Chou,
 * Y. Wu, K. Jain, "Practical network coding", Allerton 2003 (generations and
 * global encoding vectors in the packets).
 *
 * The anamorphic mode is in arlnc.c; it uses rlnc_encode_with_vector below.
 */

#include "rlnc.h"

#include <stdlib.h>
#include <string.h>
#include <threads.h>
#include "../utils/random_utils.h"

/*
 * Field polynomial of GF(q) = GF(2)[x] / (f), bit i = coefficient of x^i, with
 * the x^m term included (0x11D = x^8 + x^4 + x^3 + x^2 + 1, the polynomial of
 * the usual GF(256) of Reed-Solomon codes.
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

/* m = log2 q for q = 2^m */
static unsigned field_bits(uint32_t q)
{
    unsigned m = 0;

    while (q > 1) {
        q >>= 1;
        ++m;
    }

    return m;
}

/* D: the number of GF(q) symbols of a payload of payload_bytes bytes (m bits each) */
static size_t payload_symbol_count(const rlnc_config_t *config)
{
    const size_t bits = config->payload_bytes * 8;
    const size_t m = field_bits(config->q);

    return (bits + m - 1) / m;
}


/* -------------------------------------------------------------------------
 * GF(2^m) by table lookup
 *
 * For q <= 256 the full multiplication table has q^2 <= 65536 entries, so every
 * product is a single lookup (the classic table method for small binary fields,
 * cf. J. S. Plank, "A tutorial on Reed-Solomon coding for fault-tolerance in
 * RAID-like systems"). The tables
 * are built once from logarithm / antilogarithm tables: the field polynomials are
 * primitive, so every non-zero element is a power x^i of the generator x, and
 * x^i * x^j = x^((i + j) mod (q - 1)).
 * ------------------------------------------------------------------------- */

static uint8_t *mul_tables[9];        /* storage: [m][a * 2^m + b] = a * b in GF(2^m) */
static uint8_t inv_tables[9][256];    /* storage: [m][a] = 1 / a (0 for a = 0) */
static once_flag tables_once = ONCE_FLAG_INIT;

static void build_tables(void)
{
    //possible future improvement: only load tables for the specific q (not for all 8 possible choices of q)
    for (unsigned m = 1; m <= 8; ++m) {
        const uint32_t q = 1u << m, polynomial = gf_polynomial(q);
        uint8_t exp[2 * 256], log[256] = {0};
        uint32_t x = 1;

        /* exp[i] = x^i, log[x^i] = i, by repeated multiplication with x */
        for (uint32_t i = 0; i < q - 1; ++i) {
            exp[i] = (uint8_t)x; //store current power
            log[x] = (uint8_t)i; //store logarithm
            x <<= 1; //multiply with the polynomial (monomial) "x" 
            if (x & q)
                x ^= polynomial; //reduction modulo polynomial
        }
        for (uint32_t i = q - 1; i < 2 * (q - 1); ++i)
            exp[i] = exp[i - (q - 1)]; //because the multiplicative group has q-1 elements x^(q-1)=x^0=1

        //build the table for the specific m resp. q
        mul_tables[m] = calloc(q * q, 1);
        if (mul_tables[m] == NULL)
            abort();

        for (uint32_t a = 1; a < q; ++a) {
            for (uint32_t b = 1; b < q; ++b)
                mul_tables[m][a * q + b] = exp[log[a] + log[b]]; //x^i * x^j = x^((i + j) mod (q - 1))

            inv_tables[m][a] = exp[(q - 1 - log[a]) % (q - 1)]; //a:=x^i -> x^-i = x^(q-1)-i
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


/* -------------------------------------------------------------------------
 * Payloads as GF(q) symbols
 *
 * A payload is a continuous little-endian bit stream (byte 0: b0 b1 b2 ...)
 * cut into symbols of m bits. For m < 8 the arithmetic works on the unpacked
 * symbols, one per byte.
 * ------------------------------------------------------------------------- */

static uint32_t get_symbol(const uint8_t *payload, size_t index, unsigned m)
{
    const size_t bit_offset = index * m;
    const size_t byte_offset = bit_offset / 8;
    const unsigned shift = bit_offset % 8;
    uint32_t value = payload[byte_offset] >> shift;

    if (shift + m > 8) //reaches into next byte of payload
        value |= (uint32_t)payload[byte_offset + 1] << (8 - shift);

    return value & ((1u << m) - 1u); //mask to set MSBs to 0 (so only value in 2^m is returned)
}

/* writes symbol `index`; IMPORTANT: the payload must be zeroed */
static void set_symbol(uint8_t *payload, size_t index, unsigned m, uint32_t value)
{
    const size_t bit_offset = index * m;
    const size_t byte_offset = bit_offset / 8;
    const unsigned shift = bit_offset % 8;

    value &= (1u << m) - 1u; //mask value, e.g. with 0000 1111 for m=4
    payload[byte_offset] |= (uint8_t)(value << shift); //need to correct by shift to hit exactly the right symbol

    /* the symbol crosses a byte boundary */
    if (shift + m > 8)
        payload[byte_offset + 1] |= (uint8_t)(value >> (8 - shift)); //need to only take the highest bits of value for the next byte
}

static void unpack_symbols(const uint8_t *payload, unsigned m, size_t count, uint8_t *symbols)
{
    if (m == 8) {
        memcpy(symbols, payload, count);
        return;
    }

    for (size_t i = 0; i < count; ++i)
        symbols[i] = (uint8_t)get_symbol(payload, i, m);
}

/* inverse of unpack_symbols; payload must be zeroed */
static void pack_symbols(const uint8_t *symbols, unsigned m, size_t count, uint8_t *payload)
{
    if (m == 8) {
        memcpy(payload, symbols, count);
        return;
    }

    for (size_t i = 0; i < count; ++i)
        set_symbol(payload, i, m, symbols[i]);
}


/* -------------------------------------------------------------------------
 * Configuration / packets
 * ------------------------------------------------------------------------- */

int rlnc_config_valid(const rlnc_config_t *config)
{
    /* the arithmetic is that of GF(2^m), m <= 8 */
    return config != NULL && gf_polynomial(config->q) != 0 &&
           config->payload_bytes > 0 && config->generation_size > 0;
}

int rlnc_packet_alloc(const rlnc_config_t *config, rlnc_packet_t *packet)
{
    if (!rlnc_config_valid(config) || packet == NULL)
        return -1;

    packet->payload = calloc(config->payload_bytes, 1);
    packet->global_vector = calloc(config->generation_size, 1);

    if (packet->payload == NULL || packet->global_vector == NULL) {
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
    free(packet->global_vector);

    packet->payload = NULL;
    packet->global_vector = NULL;
}


/* -------------------------------------------------------------------------
 * Encoding
 * ------------------------------------------------------------------------- */

/*
 * Creates one coded symbol as the linear combination
 *     out = sum_j alpha_j * packets[j]
 * of the input symbols with the local coefficients alpha = local_vector, applied
 * both to the global encoding vectors and to the payloads (a matrix-vector product
 * over GF(q)). If the inputs are the source packets (global vectors e_1..e_K), the
 * global vector of the output is alpha itself. The anamorphic encoder uses this
 * with a chosen alpha.
 */
int rlnc_encode_with_vector(
    const rlnc_config_t *config,
    const rlnc_packet_t *packets,
    size_t packet_count,
    const uint8_t *local_vector,
    rlnc_packet_t *out)
{
    if (!rlnc_config_valid(config) || packets == NULL || local_vector == NULL ||
        out == NULL || packet_count == 0)
        return -1;

    const unsigned m = field_bits(config->q);
    const size_t symbol_count = payload_symbol_count(config);
    uint8_t *combination = NULL, *unpacked = NULL;

    //out must already be allocated (by convention) and zeroed
    memset(out->payload, 0, config->payload_bytes);
    memset(out->global_vector, 0, config->generation_size);

    /* symbols of fewer than 8 bits are combined unpacked, one per byte */
    if (m != 8) {
        combination = calloc(symbol_count, 1);
        unpacked = malloc(symbol_count);

        if (combination == NULL || unpacked == NULL) {
            free(combination);
            free(unpacked);
            return -1;
        }
    }

    /* gamma' = sum_j alpha_j gamma_j,  u' = sum_j alpha_j u_j */
    for (size_t j = 0; j < packet_count; ++j) {
        const uint32_t alpha = local_vector[j];

        gf_axpy(out->global_vector, packets[j].global_vector, config->generation_size,
                alpha, config->q); //update out->global_vector in each iteration

        if (m == 8) {
            gf_axpy(out->payload, packets[j].payload, config->payload_bytes, alpha, config->q);
        } else {
            unpack_symbols(packets[j].payload, m, symbol_count, unpacked);
            gf_axpy(combination, unpacked, symbol_count, alpha, config->q);
        } //same for the xor-ed payload
    }

    if (m != 8)
        pack_symbols(combination, m, symbol_count, out->payload);

    free(combination);
    free(unpacked);

    return 0;
}

/*
 * Creates one coded symbol with a fresh local encoding vector: one uniform GF(q)
 * coefficient for every packet available to this node.
 */
int rlnc_encode(
    const rlnc_config_t *config,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *random)
{
    if (!rlnc_config_valid(config) || packets == NULL || out == NULL || random == NULL ||
        packet_count == 0)
        return -1;

    uint8_t *local_vector = malloc(packet_count);

    if (local_vector == NULL)
        return -1;

    for (size_t j = 0; j < packet_count; ++j)
        local_vector[j] = (uint8_t)random_bounded(random, config->q);

    const int result = rlnc_encode_with_vector(config, packets, packet_count, local_vector, out);

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
 * the payload symbols: for each column find a row with a non-zero entry, normalise
 * it with the inverse of the pivot, and eliminate the column from all other rows.
 * When the left part is the identity the right part holds w_1..w_K. All received
 * rows are used, so a surplus of symbols compensates for dependent ones. Returns
 * -1 if the global vectors do not have rank K.
 */
int rlnc_decode(
    const rlnc_config_t *config,
    const rlnc_packet_t *received,
    size_t received_count,
    rlnc_packet_t *out)
{
    if (!rlnc_config_valid(config) || received == NULL || out == NULL ||
        received_count < config->generation_size)
        return -1;

    const size_t K = config->generation_size;
    const unsigned m = field_bits(config->q);
    const size_t symbol_count = payload_symbol_count(config);
    const size_t width = K + symbol_count;
    int result = -1;

    /*
     * Augmented matrix, one row per received packet (all of them: the first K
     * need not be independent): [ global vector | payload symbols ], one GF(q)
     * element per byte.
     */
    uint8_t *matrix = malloc(received_count * width);
    uint8_t **rows = malloc(received_count * sizeof(*rows));

    if (matrix == NULL || rows == NULL)
        goto done;

    for (size_t r = 0; r < received_count; ++r) {
        rows[r] = matrix + r * width; //offset into the matrix
        memcpy(rows[r], received[r].global_vector, K); //copy global encoding vector into first part of the row
        unpack_symbols(received[r].payload, m, symbol_count, rows[r] + K); //write symbols into second part of the row
    }

    /* Gauss-Jordan elimination; rows are swapped, columns never */
    for (size_t col = 0; col < K; ++col) {
        size_t pivot = col;

        while (pivot < received_count && rows[pivot][col] == 0) //choose the first row for which the column entry is not 0
            ++pivot;

        if (pivot == received_count)
            goto done;      /* the global vectors do not have rank K */

        uint8_t *swap = rows[col];
        rows[col] = rows[pivot];
        rows[pivot] = swap; //by swapping to the col position the sub-matrix with the encoding vectors becomes an identity matrix

        /* normalise the pivot to 1 */
        gf_scale(rows[col] + col, width - col, gf_inv(rows[col][col], config->q), config->q); //only starting at rows[col] + col because the values before it in the row are already 0 (nothing to scale)

        /* eliminate the column from all other rows */
        for (size_t r = 0; r < received_count; ++r) {
            if (r != col && rows[r][col] != 0)
                gf_axpy(rows[r] + col, rows[col] + col, width - col, rows[r][col], config->q);
        }
    }

    /* row k now reads [ e_k | w_k ] */
    for (size_t k = 0; k < K; ++k) {
        memset(out[k].payload, 0, config->payload_bytes);
        pack_symbols(rows[k] + K, m, symbol_count, out[k].payload);

        memset(out[k].global_vector, 0, K);
        out[k].global_vector[k] = 1; //set the global encoding vector accordingly (only 1 at position k)
    }

    result = 0;

done:
    free(rows);
    free(matrix);

    return result;
}
