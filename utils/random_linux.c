#define _GNU_SOURCE

#include "random.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <sys/random.h>

/*
 * Secure randomness from the Linux kernel CSPRNG via getrandom(2).
 *
 * The constructions draw many small values (single words for bounded integers,
 * Bernoulli bits, permutations), and one system call per draw dominated their
 * running time. Small requests are therefore served from a per-thread buffer that
 * is refilled with one getrandom call (the same approach as arc4random); bytes
 * are wiped from the buffer once they have been handed out. Large requests go to
 * getrandom directly.
 */

#define BUFFER_BYTES 4096

static int fill(uint8_t *out, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t ret = getrandom(out + offset, len - offset, 0);

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

/* Returns 1 on success, 0 on failure. */
int linux_secure_random(void *ctx, uint8_t *out, size_t len)
{
    static _Thread_local uint8_t buffer[BUFFER_BYTES];
    static _Thread_local size_t available;     /* unused bytes at the end of buffer */

    (void)ctx;

    if (len >= BUFFER_BYTES / 4)
        return fill(out, len);

    while (len > 0) {
        if (available == 0) {
            if (!fill(buffer, BUFFER_BYTES))
                return 0;
            available = BUFFER_BYTES;
        }

        size_t take = len < available ? len : available;
        uint8_t *src = buffer + BUFFER_BYTES - available;

        memcpy(out, src, take);
        memset(src, 0, take);

        out += take;
        len -= take;
        available -= take;
    }

    return 1;
}

RandomnessSource linux_randomness(void)
{
    return (RandomnessSource){.ctx = NULL, .rng = linux_secure_random};
}
