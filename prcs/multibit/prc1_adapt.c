#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

/*
 * PRC^0_adapt interface.
 *
 * Replace these types/functions with your existing PRC^0 implementation.
 */

typedef struct {
    /* PRC^0 encryption key */
    void *key;
} PRC0_EncKey;

typedef struct {
    /* PRC^0 decryption key */
    void *key;
} PRC0_DecKey;

/*
 * Decode returns:
 *   0  -> decoded zero
 *   1  -> decoded one
 *  -1  -> ⊥
 */
typedef int PRC0_DecodeResult;


/* Your existing PRC^0 functions. */
PRC0_EncKey prc0_keygen(size_t lambda);
uint8_t *prc0_encode(
    size_t lambda,
    const PRC0_EncKey *key,
    int message,
    size_t *ciphertext_len
);

PRC0_DecodeResult prc0_decode(
    size_t lambda,
    const PRC0_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_len
);


/*
 * ============================================================
 * PRC^1_adapt
 * ============================================================
 */

typedef struct {
    PRC0_EncKey key0;
    PRC0_EncKey key1;
} PRC1_EncKey;

typedef struct {
    PRC0_DecKey key0;
    PRC0_DecKey key1;
} PRC1_DecKey;

typedef struct {
    PRC1_EncKey enc_key;
    PRC1_DecKey dec_key;
} PRC1_KeyPair;


/*
 * KeyGen(1^lambda)
 *
 * Generate two independent PRC^0 keys.
 */
PRC1_KeyPair prc1_keygen(size_t lambda)
{
    PRC1_KeyPair keys;

    keys.enc_key.key0 = prc0_keygen(lambda);
    keys.enc_key.key1 = prc0_keygen(lambda);

    /*
     * If your PRC^0 key generation returns separate encryption
     * and decryption keys, store those here accordingly.
     */
    keys.dec_key.key0.key = keys.enc_key.key0.key;
    keys.dec_key.key1.key = keys.enc_key.key1.key;

    return keys;
}


/*
 * Encode(1^lambda, PRCEncKey, m)
 *
 * m = 0 -> encode 1 under key 0
 * m = 1 -> encode 1 under key 1
 */
uint8_t *prc1_encode(
    size_t lambda,
    const PRC1_EncKey *key,
    int message,
    size_t *ciphertext_len
)
{
    if (message == 0) {
        return prc0_encode(
            lambda,
            &key->key0,
            1,
            ciphertext_len
        );
    }

    return prc0_encode(
        lambda,
        &key->key1,
        1,
        ciphertext_len
    );
}


/*
 * Decode(1^lambda, PRCDecKey, c)
 *
 * m0 = Decode(key0, c)
 * m1 = Decode(key1, c)
 *
 *     m0 = 1, m1 = ⊥  -> 0
 *     m0 = ⊥, m1 = 1  -> 1
 *     otherwise       -> ⊥
 */
int prc1_decode(
    size_t lambda,
    const PRC1_DecKey *key,
    const uint8_t *ciphertext,
    size_t ciphertext_len
)
{
    PRC0_DecodeResult m0 =
        prc0_decode(
            lambda,
            &key->key0,
            ciphertext,
            ciphertext_len
        );

    PRC0_DecodeResult m1 =
        prc0_decode(
            lambda,
            &key->key1,
            ciphertext,
            ciphertext_len
        );

    if (m0 == 1 && m1 == -1) {
        return 0;
    }

    if (m0 == -1 && m1 == 1) {
        return 1;
    }

    return -1;  /* ⊥ */
}