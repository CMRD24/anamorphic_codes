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

/* Saves a packed codeword as a textual bit string. 1 on success, 0 on failure. */
int
save_codeword(const char *filename,
              const uint8_t *codeword,
              size_t bits);

/* Reads a textual bit string (whitespace ignored). NULL on failure. */
uint8_t *
load_codeword(const char *filename,
              size_t *bits);

#endif /* MAIN_UTILS_H */