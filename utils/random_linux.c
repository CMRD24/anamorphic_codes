#define _GNU_SOURCE

#include "random.h"

#include <sys/random.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>


/*
 * Secure randomness using Linux getrandom(2).
 *
 * Returns:
 *     1  success
 *     0  failure
 */
int linux_secure_random(void *ctx,
                        uint8_t *out,
                        size_t len)
{
    (void)ctx;

    size_t offset = 0;

    while (offset < len) {

        ssize_t ret =
            getrandom(out + offset,
                       len - offset,
                       0);

        if (ret > 0) {
            offset += (size_t)ret;
            continue;
        }

        if (ret < 0 && errno == EINTR)
            continue;

        return 0;
    }

    return 1;
}


RandomnessSource linux_randomness(){
    RandomnessSource rand = {
        .ctx = NULL,
        .rng = linux_secure_random
    };
    return rand;
}