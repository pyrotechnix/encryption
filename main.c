#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Implementation of chacha20 encryption
#include "chacha.h"

#define INPUT_FLAG "-i"
#define OUTPUT_FLAG "-o"


void parse_commands(int argc, char *argv[]) {
    uint8_t example_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t example_nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    char *input = NULL;
    char *output = NULL;
    char *mode = NULL;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], OUTPUT_FLAG) == 0) {
            if (i + 1 >= argc) {
                printf("Incorrect usage: Use -e followed by file to encrypt\n");
                return;
            }
            output = argv[i + 1];
            i++;
        } else {
            input = argv[i];
        }
    }
    if (input == NULL) {
        printf("Input not specified\n");
        return;
    } else if (output == NULL) {
        printf("Output not specified\n");
        return;
    }
    chacha20_encrypt(example_key, 1, example_nonce, input, output);
}

int main(int argc, char *argv[]) {
    parse_commands(argc, argv);
    FILE *fp = fopen("example_key", "w");
    for (int i = 0; i < 32; i++) {
        fputc((uint8_t)i, fp);
    }
}
