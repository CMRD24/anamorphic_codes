#ifndef RLNC_H
#define RLNC_H

#include <stddef.h>
#include <stdint.h>
#include "../utils/random.h"

typedef struct {
    uint32_t q;
    size_t packet_size;       // bytes
    size_t generation_size;  // number of source packets
} rlnc_config_t;

typedef struct {
    uint8_t *payload;   // packet_size bytes
    uint8_t *global;    // generation_size GF(q) symbols
} rlnc_packet_t;


int rlnc_config_valid(const rlnc_config_t *cfg);

int rlnc_packet_alloc(
    const rlnc_config_t *cfg,
    rlnc_packet_t *packet);

void rlnc_packet_free(
    rlnc_packet_t *packet);

int rlnc_sample_local_encoding_vector(
    const rlnc_config_t *cfg,
    size_t input_count,
    RandomnessSource *rng,
    uint8_t *local_vector);

int rlnc_encode_with_vector(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    const uint8_t *local_vector,
    rlnc_packet_t *out);

int rlnc_encode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *rng);

int rlnc_decode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *received,
    size_t received_count,
    rlnc_packet_t *out);


/*
 * Anamorphic RLNC (arlnc.c).
 *
 * Reed-Solomon points over E = GF(q^{K-a}) are hidden in the headers, masked by
 * a PRF. a = ceil(lambda / log2 q) is the label length, K >= 2a is required, and
 * the receiver collects exactly `received` = S >= K symbols. The anamorphic
 * message consists of (S-1)*(K-a) GF(q) symbols (one per byte).
 */
typedef struct {
    size_t lambda;     /* security parameter in bits */
    size_t received;   /* S */
} rlnc_aconfig_t;

/* number of GF(q) symbols of the anamorphic message, 0 if parameters invalid */
size_t rlnc_amsg_len(const rlnc_config_t *cfg, const rlnc_aconfig_t *acfg);

uint8_t *rlnc_akeygen(void);
void rlnc_akey_free(uint8_t *akey);

/*
 * Encodes the generation `source` (K packets with global vectors e_1..e_K) into
 * out_count >= S allocated symbols whose headers carry amessage.
 */
int rlnc_aencode(
    const rlnc_config_t *cfg,
    const rlnc_aconfig_t *acfg,
    const rlnc_packet_t *source,
    rlnc_packet_t *out,
    size_t out_count,
    RandomnessSource *rng,
    const uint8_t *akey,
    const uint8_t *amessage);

/* 0 and the message in amessage on success, -1 (bottom) otherwise */
int rlnc_adecode(
    const rlnc_config_t *cfg,
    const rlnc_aconfig_t *acfg,
    const rlnc_packet_t *received,
    size_t received_count,
    const uint8_t *akey,
    uint8_t *amessage);

#endif /* RLNC_H */
