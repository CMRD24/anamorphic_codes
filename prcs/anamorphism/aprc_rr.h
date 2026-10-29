#ifndef APRC_RR_H
#define APRC_RR_H

/*
 * Anamorphism from randomness recoverability (construction "rr" of the thesis)
 * for seed-recoverable zero-bit and multibit PRCs.
 *
 * The anamorphic message m_a is encrypted with a pseudorandom symmetric
 * encryption, Enc(sk, m_a) = nonce || (PRF(sk, nonce) xor m_a) (utils/ske.h),
 * and the ciphertext is used as the seeds rho of mu regular codewords; the
 * anamorphic decoder recovers the seeds with RecDecode and decrypts them.
 *
 * Extension for robustness (remark "robust_rand"): the first z of the mu seeds
 * are indication seeds with PRF(indication_key, rho) = 0. They make the decoder
 * reject codewords that are not anamorphic except with probability 2^-z, at the
 * price of z extra codewords; z = 0 is allowed. The remaining mu - z seeds carry
 * the ciphertext, which therefore has exactly (mu - z) * k / 8 bytes; its nonce
 * fills what the message leaves free and must have at least RR_MIN_NONCE_BYTES
 * bytes. With mu = 1 and z = 0 a single codeword carries the message.
 */

#include <stddef.h>
#include <stdint.h>

#include "../../utils/random.h"
#include "../zerobit/zerobit_prc_rr.h"
#include "../multibit/multibit_prc_rr.h"

/* The nonce of the encryption has at least this many bytes. */
#define RR_MIN_NONCE_BYTES 8

#define RR_KEY_BYTES 32

typedef struct {
    size_t seed_bits;          /* k: bits of a seed rho, a positive multiple of 8 */
    size_t indication_seeds;   /* z */
    size_t codeword_count;     /* mu: regular codewords per anamorphic message, > z */
    size_t amessage_bytes;     /* length of the anamorphic message m_a */
} RR_Shape;

/* dk = tk = (indication_key, sk), so the construction is symmetric */
typedef struct {
    uint8_t indication_key[RR_KEY_BYTES];
    uint8_t encryption_key[RR_KEY_BYTES];
} RR_AKeys;

typedef struct {
    RR_Shape shape;
    const ZBPRC_RR *prc;
} aZBPRC_RR;

typedef struct {
    RR_Shape shape;
    const MBPRC_RR *prc;
} aMBPRC_RR;

/*
 * Smallest number mu - z of ciphertext seeds that carries an anamorphic message
 * of amessage_bytes bytes together with a nonce of RR_MIN_NONCE_BYTES bytes.
 */
size_t rr_min_ciphertext_seeds(size_t seed_bits, size_t amessage_bytes);

/* aKeyGen: independent of the regular keys. Keys are drawn from random, so a
 * deterministic source gives reproducible keys. NULL on error. */
RR_AKeys *rr_akeygen(RandomnessSource *random);
void rr_free_akeys(RR_AKeys *akeys);

/* frees an array of count codewords returned by an aencode function */
void rr_free_codewords(uint8_t **codewords, size_t count);

/*
 * aEncode for zero-bit PRCs: returns mu codewords of *codeword_bits bits each,
 * every one an encoding of 1 with one of the seeds; NULL on error.
 */
uint8_t **azbprc_rr_aencode(const aZBPRC_RR *aprc,
                            const ZBPRC_EncKey *enc_key,
                            const RR_AKeys *akeys,
                            const uint8_t *amessage,
                            RandomnessSource *random,
                            size_t *codeword_bits);

/* aDecode for zero-bit PRCs: returns 1 and m_a, or 0 */
int azbprc_rr_adecode(const aZBPRC_RR *aprc,
                      const ZBPRC_DecKey *dec_key,
                      const RR_AKeys *akeys,
                      const uint8_t *const *codewords,
                      size_t codeword_bits,
                      uint8_t *amessage_out);

/*
 * aEncode for multibit PRCs: codeword i encodes messages[i] (message_bits bits)
 * with seed i; NULL on error.
 */
uint8_t **ambprc_rr_aencode(const aMBPRC_RR *aprc,
                            const MBPRC_EncKey *enc_key,
                            const RR_AKeys *akeys,
                            const uint8_t *const *messages,
                            size_t message_bits,
                            const uint8_t *amessage,
                            RandomnessSource *random,
                            size_t *codeword_bits);

/*
 * aDecode for multibit PRCs: returns 1 and m_a, or 0. message_bits is the
 * length of the regular messages, which are decoded and discarded.
 */
int ambprc_rr_adecode(const aMBPRC_RR *aprc,
                      const MBPRC_DecKey *dec_key,
                      const RR_AKeys *akeys,
                      const uint8_t *const *codewords,
                      size_t codeword_bits,
                      size_t message_bits,
                      uint8_t *amessage_out);

#endif /* APRC_RR_H */
