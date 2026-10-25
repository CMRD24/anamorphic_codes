#ifndef RLNC_H
#define RLNC_H

/*
 * Random linear network coding over GF(q), q = 2^m <= 256 (rlnc.c), and its
 * anamorphic mode aRLNC (arlnc.c). Notation of the thesis: generation size K,
 * payload length D, T sent and S received symbols; a symbol is a global
 * encoding vector gamma in F_q^K and a payload u in F_q^D.
 */

#include <stddef.h>
#include <stdint.h>
#include "../utils/random.h"

typedef struct {
    uint32_t q;               /* field size, a power of two <= 256 */
    size_t payload_bytes;     /* bytes of a payload (D = 8 payload_bytes / log2 q symbols) */
    size_t generation_size;   /* K: number of source packets of a generation */
} rlnc_config_t;

/* a symbol (or source packet) */
typedef struct {
    uint8_t *payload;         /* payload_bytes bytes */
    uint8_t *global_vector;   /* gamma: generation_size GF(q) symbols, one per byte */
} rlnc_packet_t;

int rlnc_config_valid(const rlnc_config_t *config);

/* 0, or -1 on invalid parameters or allocation failure */
int rlnc_packet_alloc(const rlnc_config_t *config, rlnc_packet_t *packet);
void rlnc_packet_free(rlnc_packet_t *packet);

/*
 * out = sum_j local_vector[j] * packets[j] (global vectors and payloads). Returns
 * 0, or -1 on invalid parameters.
 */
int rlnc_encode_with_vector(
    const rlnc_config_t *config,
    const rlnc_packet_t *packets,
    size_t packet_count,
    const uint8_t *local_vector,
    rlnc_packet_t *out);

/* a random linear combination of the packets; 0 or -1 */
int rlnc_encode(
    const rlnc_config_t *config,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *random);

/* the K source packets from received_count >= K symbols; 0, or -1 if rank < K */
int rlnc_decode(
    const rlnc_config_t *config,
    const rlnc_packet_t *received,
    size_t received_count,
    rlnc_packet_t *out);


/*
 * Anamorphic RLNC (arlnc.c).
 *
 * Reed-Solomon points over E = GF(q^{K-a}) are hidden in the global encoding
 * vectors, masked by a PRF. a = ceil(lambda / log2 q) is the label length,
 * K >= 2a is required, and the receiver collects exactly S >= K symbols. The
 * anamorphic message consists of (S-1)*(K-a) GF(q) symbols (one per byte).
 */
typedef struct {
    size_t lambda;              /* security parameter in bits */
    size_t received_symbols;    /* S */
} rlnc_aconfig_t;

/* number of GF(q) symbols of the anamorphic message, 0 if the parameters are invalid */
size_t rlnc_amessage_symbols(const rlnc_config_t *config, const rlnc_aconfig_t *aconfig);

/* the PRF key s (dk = tk); free with rlnc_akey_free */
uint8_t *rlnc_akeygen(void);
void rlnc_akey_free(uint8_t *akey);

/*
 * Encodes the generation `source` (K packets with global vectors e_1..e_K) into
 * sent_count = T >= S allocated symbols whose global vectors carry amessage.
 * Returns 0, or -1 on invalid parameters.
 */
int rlnc_aencode(
    const rlnc_config_t *config,
    const rlnc_aconfig_t *aconfig,
    const rlnc_packet_t *source,
    rlnc_packet_t *sent,
    size_t sent_count,
    RandomnessSource *random,
    const uint8_t *akey,
    const uint8_t *amessage);

/* 0 and the message in amessage_out on success, -1 (bottom) otherwise */
int rlnc_adecode(
    const rlnc_config_t *config,
    const rlnc_aconfig_t *aconfig,
    const rlnc_packet_t *received,
    size_t received_count,
    const uint8_t *akey,
    uint8_t *amessage_out);

#endif /* RLNC_H */
