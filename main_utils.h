#ifndef MAIN_UTILS_H
#define MAIN_UTILS_H

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>


void
print_codeword(const uint8_t *codeword,
               size_t bits);

uint8_t *
parse_codeword(const char *string,
               size_t expected_bits);

int
save_codewords(const char *filename,
                uint8_t *codewords[],
               size_t num_codewords,
               size_t bits);

uint8_t **load_codewords(const char *filename, size_t *num_codewords, size_t *max_bits);

#endif /* MAIN_UTILS_H */