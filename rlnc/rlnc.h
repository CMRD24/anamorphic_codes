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


//anamorphic:

uint8_t *rlnc_akeygen();

int rlnc_source_aencode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *packets,
    size_t packet_count,
    rlnc_packet_t *out,
    RandomnessSource *rng,
    const unsigned char *akey,
    uint8_t amessage

);

int rlnc_adecode(
    const rlnc_config_t *cfg,
    const rlnc_packet_t *received,
    size_t received_count,
    const unsigned char *akey);

#endif /* RLNC_H */