

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>











/*
 * ================================================================
 * Helpers
 * ================================================================
 */

static void
print_codeword(const uint8_t *codeword,
               size_t bits)
{
    for (size_t i = 0;
         i < bits;
         ++i)
    {

        putchar(
            (codeword[i >> 3] &
             (uint8_t)(1u << (i & 7)))
                ? '1'
                : '0');
    }

    putchar('\n');
}

static uint8_t *
parse_codeword(const char *string,
               size_t expected_bits)
{
    if (strlen(string) != expected_bits)
        return NULL;

    size_t bytes =
        (expected_bits + 7) / 8;

    uint8_t *codeword =
        calloc(bytes, 1);

    if (codeword == NULL)
        return NULL;

    for (size_t i = 0;
         i < expected_bits;
         ++i)
    {

        if (string[i] == '1')
        {

            codeword[i >> 3] |=
                (uint8_t)(1u << (i & 7));
        }
        else if (string[i] != '0')
        {

            free(codeword);

            return NULL;
        }
    }

    return codeword;
}

static int
save_codewords(const char *filename,
                uint8_t *codewords[],
               size_t num_codewords,
               size_t bits)
{
    FILE *file = fopen(filename, "w");

    if (file == NULL)
    {
        perror("fopen");
        return 0;
    }

    for (size_t j = 0; j < num_codewords; ++j)
    {

        const uint8_t *codeword = codewords[j];

        for (size_t i = 0; i < bits; ++i)
        {

            if (fputc(
                    (codeword[i >> 3] &
                     (uint8_t)(1u << (i & 7)))
                        ? '1'
                        : '0',
                    file) == EOF)
            {

                fclose(file);
                return 0;
            }
        }

        // Separate codewords with a comma
        if (j + 1 < num_codewords)
        {
            if (fputc(',', file) == EOF)
            {
                fclose(file);
                return 0;
            }
        }
    }

    if (fputc('\n', file) == EOF)
    {
        fclose(file);
        return 0;
    }

    fclose(file);
    return 1;
}

static uint8_t **load_codewords(const char *filename, size_t *num_codewords, size_t *max_bits)
{
    FILE *file = fopen(filename, "r");
    if (file == NULL)
        return NULL;
    uint8_t **codewords = NULL;
    size_t count = 0;
    size_t capacity = 4;
    size_t max_length = 0;
    codewords = malloc(capacity * sizeof(uint8_t *));
    if (codewords == NULL)
    {
        fclose(file);
        return NULL;
    }
    char buffer[10000];
    while (fscanf(file, "%9999[^,\n]%*[, \n]", buffer) == 1)
    {
        size_t bits = strlen(buffer);
        if (bits > max_length)
            max_length = bits;
        if (count == capacity)
        {
            capacity *= 2;
            uint8_t **tmp = realloc(codewords, capacity * sizeof(uint8_t *));
            if (tmp == NULL)
                goto error;
            codewords = tmp;
        }
        size_t bytes = (bits + 7) / 8;
        codewords[count] = calloc(bytes, sizeof(uint8_t));
        if (codewords[count] == NULL)
            goto error;
        for (size_t i = 0; i < bits; ++i)
        {
            if (buffer[i] == '1')
                codewords[count][i >> 3] |= (uint8_t)(1u << (i & 7));
            else if (buffer[i] != '0')
                goto error;
        }
        count++;
    }
    fclose(file);
    *num_codewords = count;
    *max_bits = max_length;
    return codewords;
error:
    for (size_t i = 0; i < count; ++i)
        free(codewords[i]);
    free(codewords);
    fclose(file);
    return NULL;
}
