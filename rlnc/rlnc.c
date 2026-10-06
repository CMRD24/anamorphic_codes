#include "rlnc.h"

#include <stdlib.h>
#include <string.h>
#include "../utils/random_utils.h"
#include <sodium.h>

/*
 * Primitive / irreducible polynomials for GF(2^m).
 *
 * The polynomial is represented with the x^m term included.
 *
 * Examples:
 *   GF(2):    x + 1
 *   GF(4):    x^2 + x + 1
 *   GF(8):    x^3 + x + 1
 *   GF(16):   x^4 + x + 1
 *   GF(32):   x^5 + x^2 + 1
 *   GF(64):   x^6 + x + 1
 *   GF(128):  x^7 + x + 1
 *   GF(256):  x^8 + x^4 + x^3 + x^2 + 1
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
    /*
     * Addition in characteristic 2 is XOR.
     */
    return a ^ b;
}

static uint32_t gf_mul(
    uint32_t a,
    uint32_t b,
    uint32_t q)
{
    const unsigned m = field_bits(q);
    const uint32_t polynomial = gf_polynomial(q);

    uint32_t result = 0;

    /*
     * Russian-peasant multiplication in GF(2^m).
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

static uint32_t gf_inv(uint32_t a, uint32_t q)
{
    if (a == 0)
        return 0;

    /*
     * In GF(q), a^(q-1) = 1 for a != 0,
     * hence a^(-1) = a^(q-2).
     */
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

    /*
     * XOR addition is only possible for fields of characteristic 2.
     *
     * Therefore q must be 2^m.
     */
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


// anamorphic:

uint8_t prf_bit(const unsigned char *key,
                const unsigned char *input,
                size_t input_len)
{
    unsigned char output[crypto_generichash_BYTES];

    crypto_generichash(
        output,
        sizeof(output),
        input,
        input_len,
        key,
        crypto_generichash_KEYBYTES
    );

    return output[0] & 1;
}

//todo: free akey method

uint8_t *rlnc_akeygen(){
    uint8_t *akey = malloc(crypto_generichash_KEYBYTES);
    
    crypto_generichash_keygen(akey);
    return akey;
}

int rlnc_source_aencode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *rng,
    const unsigned char *akey,
    uint8_t amessage

)
{
    if (!rlnc_config_valid(cfg) ||
        packets == NULL ||
        out == NULL ||
        rng == NULL)
        return -1;

    if (packet_count == 0)
        return -1;

    if (packet_count != cfg->generation_size){
        //only source can encode anamorphic message.
        return -1;
    }

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
    do {
        if (rlnc_sample_local_encoding_vector(
            cfg,
            packet_count,
            rng,
            local_vector) != 0) {

        free(local_vector);
        return -1;
    }
    }

    while(prf_bit(akey, local_vector, packet_count)!=amessage);
    

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

int rlnc_adecode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *received,
    size_t received_count,
    const unsigned char *akey)
{



    if (!rlnc_config_valid(cfg) ||
        received == NULL ||
        received_count == 0 ||
        akey == NULL)
        return -1;

    int ana_bit = -1;

    for (size_t i = 0; i < received_count; ++i) {
        uint8_t current_bit =
            prf_bit(akey, received[i].global, cfg->generation_size);


        if (ana_bit == -1) {
            ana_bit = current_bit;
        } else if (current_bit != ana_bit) {
            return -1;
        }
    }

    return ana_bit;

    
}


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
    const unsigned m = field_bits(cfg->q);
    const size_t symbols = symbol_count(cfg);

    /*
     * Work on K independent packets.
     *
     * Each row consists of:
     *
     *     [ global vector | payload symbols ]
     */
    uint32_t **matrix =
        calloc(K, sizeof(uint32_t *));

    if (matrix == NULL)
        return -1;

    for (size_t r = 0; r < K; ++r) {
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

        while (pivot < K && matrix[pivot][col] == 0)
            ++pivot;

        if (pivot == K) {
            /*
             * The received global vectors are not linearly independent.
             */
            for (size_t i = 0; i < K; ++i)
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
        for (size_t row = 0; row < K; ++row) {
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

    for (size_t i = 0; i < K; ++i)
        free(matrix[i]);

    free(matrix);

    return 0;
}