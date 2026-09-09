
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sodium.h>



unsigned char key[crypto_generichash_KEYBYTES];

crypto_generichash_keygen(key);



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

