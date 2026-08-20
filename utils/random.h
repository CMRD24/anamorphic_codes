#ifndef RANDOM_H
#define RANDOM_H

#include <stddef.h>
#include <stdint.h>

int linux_secure_random(
    void *ctx,
    uint8_t *out,
    size_t len
);

#endif /* RANDOM_H */