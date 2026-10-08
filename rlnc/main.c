#include "rlnc.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "../utils/random.h"


static void print_packet(
    const rlnc_packet_t *packet,
    const rlnc_config_t *cfg)
{
    printf("vector: ");

    for (size_t i = 0; i < cfg->generation_size; ++i) {
        printf("%02x", packet->global[i]);

        //if (i + 1 < cfg->generation_size)
          //  printf(" ");
    }

    printf(" payload: ");

    for (size_t i = 0; i < cfg->packet_size; ++i) {
        printf("%02x", packet->payload[i]);

        //if (i + 1 < cfg->packet_size)
           // printf(" ");
    }

    putchar('\n');
}

/*
 * Split a string at ';'.
 *
 * The returned array and its strings must be freed by the caller.
 */
static char **split_content(
    const char *content,
    size_t *count)
{
    char *copy;
    char **packets = NULL;
    size_t packet_count = 0;

    if (content == NULL || count == NULL)
        return NULL;

    copy = malloc(strlen(content) + 1);

    if (copy == NULL)
        return NULL;

    strcpy(copy, content);

    /*
     * First determine the number of packets.
     */
    char *p = copy;

    packet_count = 1;

    while (*p != '\0') {
        if (*p == ';')
            packet_count++;

        p++;
    }

    packets = calloc(packet_count, sizeof(char *));

    if (packets == NULL) {
        free(copy);
        return NULL;
    }

    /*
     * Split the string.
     */
    size_t index = 0;
    char *token = strtok(copy, ";");

    while (token != NULL && index < packet_count) {

        packets[index] = malloc(strlen(token) + 1);

        if (packets[index] == NULL) {
            for (size_t i = 0; i < index; ++i)
                free(packets[i]);

            free(packets);
            free(copy);

            return NULL;
        }

        strcpy(packets[index], token);

        index++;
        token = strtok(NULL, ";");
    }

    free(copy);

    *count = index;

    return packets;
}


static void free_content(
    char **content,
    size_t count)
{
    if (content == NULL)
        return;

    for (size_t i = 0; i < count; ++i)
        free(content[i]);

    free(content);
}


/*
 * Shuffle an array using Fisher-Yates.
 */
static void shuffle(
    size_t *array,
    size_t n)
{
    if (n <= 1)
        return;

    for (size_t i = n - 1; i > 0; --i) {

        size_t j =
            (size_t)(rand() % (i + 1));

        size_t tmp = array[i];
        array[i] = array[j];
        array[j] = tmp;
    }
}


/*
 * Print a decoded packet as a string.
 *
 * The packet payload contains ASCII characters followed by
 * zero padding.
 */
static void print_packet_payload(
    const rlnc_packet_t *packet,
    size_t packet_size)
{
    size_t length = 0;

    while (length < packet_size &&
           packet->payload[length] != 0) {
        length++;
    }

    for (size_t i = 0; i < length; ++i)
        putchar((char)packet->payload[i]);

    putchar('\n');
}


static int command_test(
    const char *content,
    size_t generated_packets, int ana_msg)
{
    /*
     * --------------------------------------------------------
     * RLNC configuration
     * --------------------------------------------------------
     *
     * We use F_251 here because the RLNC implementation
     * operates on prime fields.
     */
    rlnc_config_t cfg = {
        .q = 8,
        .packet_size = 64,
        .generation_size = 5
    };

    

    uint8_t *akey = rlnc_akeygen();

    /*
     * Parse source packet contents.
     */
    size_t source_count = 0;

    char **source_content =
        split_content(content, &source_count);

    if (source_content == NULL || source_count == 0) {
        fprintf(stderr, "Failed to parse content.\n");
        return 1;
    }

    if (source_count != cfg.generation_size) {
        fprintf(
            stderr,
            "Error: expected exactly %zu source packets, "
            "but got %zu.\n",
            cfg.generation_size,
            source_count
        );
        
        free_content(source_content, source_count);
        return 1;
    }


    /*
     * We need at least K generated packets so that we can
     * select K packets for decoding.
     */
    if (generated_packets < cfg.generation_size) {
        fprintf(
            stderr,
            "Error: x must be at least %zu.\n",
            cfg.generation_size
        );

        free_content(source_content, source_count);
        return 1;
    }


    /*
     * --------------------------------------------------------
     * Create source packets
     * --------------------------------------------------------
     */
    rlnc_packet_t *source =
        calloc(cfg.generation_size,
               sizeof(rlnc_packet_t));

    if (source == NULL) {
        free_content(source_content, source_count);
        return 1;
    }

    for (size_t i = 0;
         i < cfg.generation_size;
         ++i) {

        if (rlnc_packet_alloc(&cfg, &source[i]) != 0) {
            fprintf(
                stderr,
                "Failed to allocate source packet.\n"
            );

            for (size_t j = 0; j < i; ++j)
                rlnc_packet_free(&source[j]);

            free(source);
            free_content(source_content, source_count);

            return 1;
        }

        /*
         * Copy string into payload.
         */
        size_t length =
            strlen(source_content[i]);

        if (length > cfg.packet_size) {
            fprintf(
                stderr,
                "Error: source packet %zu is too large "
                "(maximum %zu bytes).\n",
                i,
                cfg.packet_size
            );

            for (size_t j = 0;
                 j <= i;
                 ++j)
                rlnc_packet_free(&source[j]);

            free(source);
            free_content(source_content, source_count);

            return 1;
        }

        for (size_t j = 0; j < length; ++j)
            source[i].payload[j] =
                (uint32_t)(unsigned char)source_content[i][j];

        /*
         * Source packet i gets the canonical global
         * encoding vector e_i.
         */
        source[i].global[i] = 1;
    }


    /*
     * --------------------------------------------------------
     * Generate x coded packets.
     * --------------------------------------------------------
     */
    rlnc_packet_t *generated =
        calloc(
            generated_packets,
            sizeof(rlnc_packet_t));

    if (generated == NULL) {
        for (size_t i = 0;
             i < cfg.generation_size;
             ++i)
            rlnc_packet_free(&source[i]);

        free(source);
        free_content(source_content, source_count);

        return 1;
    }


    for (size_t i = 0;
         i < generated_packets;
         ++i) {

        if (rlnc_packet_alloc(&cfg, &generated[i]) != 0) {
            fprintf(
                stderr,
                "Failed to allocate generated packet.\n"
            );

            for (size_t j = 0; j < i; ++j)
                rlnc_packet_free(&generated[j]);

            free(generated);

            for (size_t j = 0;
                 j < cfg.generation_size;
                 ++j)
                rlnc_packet_free(&source[j]);

            free(source);
            free_content(source_content, source_count);

            return 1;
        }

        RandomnessSource rand = linux_randomness();

        
        int encoding_result = 0;
        
        if(ana_msg != -1){
            encoding_result = rlnc_source_aencode(
                &cfg,
                source,
                cfg.generation_size,
                &generated[i],
                &rand, akey, ana_msg);
        }
        else{
            encoding_result = rlnc_encode(
                &cfg,
                source,
                cfg.generation_size,
                &generated[i],
                &rand);
        }
        

        /*
         * Encode the entire generation.
         */
        if (encoding_result != 0) {

            fprintf(
                stderr,
                "Encoding failed for packet %zu.\n",
                i
            );

            for (size_t j = 0;
                 j < generated_packets;
                 ++j)
                rlnc_packet_free(&generated[j]);

            free(generated);

            for (size_t j = 0;
                 j < cfg.generation_size;
                 ++j)
                rlnc_packet_free(&source[j]);

            free(source);
            free_content(source_content, source_count);

            return 1;
        }
    }


    printf(
        "Generated %zu coded packets.\n",
        generated_packets
    );


    /*
     * --------------------------------------------------------
     * Randomly select K generated packets.
     * --------------------------------------------------------
     */
    size_t *indices =
        malloc(generated_packets * sizeof(size_t));

    if (indices == NULL) {
        fprintf(stderr, "Failed to allocate indices.\n");
        return 1;
    }

    for (size_t i = 0;
         i < generated_packets;
         ++i)
        indices[i] = i;

    shuffle(indices, generated_packets);


    printf("\nEncoded packets:\n");

    for (size_t i = 0; i < generated_packets; ++i) {
        printf("[%zu] ", i);
        print_packet(&generated[i], &cfg);
    }


    /*
     * --------------------------------------------------------
     * Prepare received packets.
     *
     * We only pass the first K randomly selected packets
     * to the decoder.
     * --------------------------------------------------------
     */
    size_t K = cfg.generation_size;

    rlnc_packet_t *received =
        calloc(K, sizeof(rlnc_packet_t));

    rlnc_packet_t *decoded =
        calloc(K, sizeof(rlnc_packet_t));

    if (received == NULL || decoded == NULL) {
        fprintf(stderr, "Allocation failed.\n");

        free(received);
        free(decoded);
        free(indices);

        return 1;
    }


    /*
     * We don't need to allocate new payloads for received
     * packets. They can directly point to the generated
     * packets.
     */
    for (size_t i = 0; i < K; ++i) {

        size_t selected =
            indices[i];

        received[i].payload =
            generated[selected].payload;

        received[i].global =
            generated[selected].global;

        /*
         * Allocate output packets for decoding.
         */
        if (rlnc_packet_alloc(
                &cfg,
                &decoded[i]) != 0) {

            fprintf(
                stderr,
                "Failed to allocate decoded packet.\n"
            );

            free(received);
            free(decoded);
            free(indices);

            return 1;
        }

        printf(
            "Selected generated packet %zu\n",
            selected
        );
    }


    /*
     * --------------------------------------------------------
     * Decode.
     * --------------------------------------------------------
     */
    int result =
        rlnc_decode(
            &cfg,
            received,
            K,
            decoded
        );


    int aresult =
        rlnc_adecode(
            &cfg,
            received,
            K,
            akey
        );


    /*
     * --------------------------------------------------------
     * Print result.
     * --------------------------------------------------------
     */
    if(aresult != -1){
        printf("\nAnam. decode result: %d\n", aresult);
    }
    else{
         printf("\nNo anamorphic message present\n");
    }
    
    printf("\nDecode result: ");

    switch (result) {

        case 0:
            printf("SUCCESS\n");

            printf("Decoded packets:\n");

            for (size_t i = 0; i < K; ++i) {
                printf(
                    "  [%zu] ",
                    i
                );

                print_packet_payload(
                    &decoded[i],
                    cfg.packet_size
                );
            }

            break;

        case 1:
            printf(
                "FAILURE - insufficient rank\n"
            );
            break;

        default:
            printf(
                "ERROR - invalid arguments or "
                "allocation failure\n"
            );
            break;
    }


    /*
     * --------------------------------------------------------
     * Cleanup.
     * --------------------------------------------------------
     */
    for (size_t i = 0; i < K; ++i)
        rlnc_packet_free(&decoded[i]);

    free(received);
    free(decoded);
    free(indices);

    for (size_t i = 0;
         i < generated_packets;
         ++i)
        rlnc_packet_free(&generated[i]);

    free(generated);

    for (size_t i = 0;
         i < cfg.generation_size;
         ++i)
        rlnc_packet_free(&source[i]);

    free(source);

    free_content(
        source_content,
        source_count
    );

    return result == 0 ? 0 : 1;
}


/*
 * ============================================================
 * Main
 * ============================================================
 */

int main(int argc, char **argv)
{
    /*
     * Seed the test RNG.
     */
    srand((unsigned int)time(NULL));


    /*
     * Usage:
     *
     *     ./rlnc test "first packet;second packet" 10
     */
    if (argc < 4 || argc > 5) {

        fprintf(
            stderr,
            "Usage: %s reg #received \"packet1;packet2;...\"\nOR ana #received \"packet1;packet2;...\" 0/1\n",
            argv[0]
        );

        return 1;
    }


    int ana_msg = -1;


    if (strcmp(argv[1], "reg") == 0) {

        ana_msg = -1;
    }
    else if (strcmp(argv[1], "ana") == 0) {

        ana_msg =  strtoul(argv[4], NULL, 10);
        printf("%d\n", ana_msg);
    }
    else{
        fprintf(
            stderr,
            "Unknown command: %s\n",
            argv[1]
        );

        fprintf(
            stderr,
            "Available commands: reg,ana\n"
        );

        return 1;
    }


    /*
     * Parse x.
     */
    char *endptr = NULL;

    unsigned long x =
        strtoul(argv[2], &endptr, 10);

    if (*argv[2] == '\0' ||
        *endptr != '\0' ||
        x == 0) {

        fprintf(
            stderr,
            "Error: x must be a positive integer.\n"
        );

        return 1;
    }

    return command_test(
        argv[3],
        (size_t)x, ana_msg
    );
    
}