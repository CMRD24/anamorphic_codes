#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>


typedef struct {

    void *ctx;

    /*
    return 1 on success, 0 on failue
    */
    int (*rng)(
        void *ctx,
    uint8_t *out,
    size_t len);


} RandomnessSource;



RandomnessSource linux_randomness(void);


#endif /* RANDOM_H */