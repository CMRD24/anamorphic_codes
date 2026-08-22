#ifndef CSPRG_H
#define CSPRG_H

#include <stddef.h>
#include <stdint.h>


typedef struct {

    


    int (*generate)(
        const uint8_t *seed,
        size_t seed_bits,
        uint8_t *output,
        size_t output_len
    );

} CSPRG;


//convenience




static inline int
csprg_generate(
    const CSPRG *csprg, const uint8_t *seed,
        size_t seed_bits,
        uint8_t *output,
        size_t output_len)
{
    return csprg->generate(
        seed, seed_bits, output, output_len
    );
}


#endif /* CSPRG_H */