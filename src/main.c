#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Implementation of chacha20 encryption
#include "sha256.h"
#include "chacha.h"

#define INPUT_FLAG "-i"
#define OUTPUT_FLAG "-o"
#define KEY_FLAG "-k"
#define NONCE_FLAG "-n"
#define KEYFILE_FLAG "-f"
#define WRITE_KEYFILE_FLAG "-w"
#define PASSWORD_FLAG "-p"


uint8_t convert_to_hex(char first_char, char second_char) {
    uint8_t res = 0;
    if (first_char >= '0' && first_char <= '9') {
        res |= (first_char - '0') << 4;
    } else {
        res |= (first_char - 'a' + 10) << 4;
    }
    if (second_char >= '0' && second_char <= '9') {
        res |= (second_char - '0') & 0b1111;
    } else {
        res |= (second_char - 'a' + 10) & 0b1111;
    }
    return res;
}

int parse_hex_string(char *string, uint8_t *output, int len) {
    if (strlen(string) != len * 2) {
        printf("Error: incorrect length\n");
        return -1;
    }
    for (int i = 0; i < len; i++) {
        output[i] = convert_to_hex(string[i * 2], string[i * 2 + 1]);
    }
}

void write_keyfile(char *filename, uint8_t key[32], uint8_t nonce[12]) {
    FILE *fp = fopen(filename, "w");
    for (int i = 0; i < 32; i++) {
        fputc(key[i], fp); 
    }
    for (int i = 0; i < 12; i++) {
        fputc(nonce[i], fp); 
    }
    fclose(fp);
}

int read_keyfile(char *filename, uint8_t key[32], uint8_t nonce[12]) {
    struct stat statbuf;
    if (stat(filename, &statbuf) == -1) {
        perror("Could not read keyfile");
        return -1;
    }
    FILE *fp = fopen(filename, "r");
    uint8_t ch;
    for (int i = 0; i < 32; i++) {
        ch = fgetc(fp); 
        key[i] = ch;
    }
    for (int i = 0; i < 12; i++) {
        fputc(nonce[i], fp); 
        ch = fgetc(fp); 
        nonce[i] = ch;
    }
    fclose(fp);
    return 0;
}

void parse_commands(int argc, char *argv[]) {
    uint8_t key[32] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
    };
    char *input = NULL;
    char *output = NULL;

    int should_write_keyfile = false;
    int should_get_password = false;
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], OUTPUT_FLAG) == 0) {
            if (i + 1 >= argc) {
                printf("Incorrect usage: Use -o followed by output to set output\n");
                return;
            }
            output = argv[i + 1];
            i++;
        } else if (strcmp(argv[i], KEY_FLAG) == 0) {
            if (i + 1 >= argc) {
                printf("Incorrect usage: Use -k followed by key to specify key\n");
                return;
            }
            printf("Specified key: %s\n", argv[i + 1]);
            parse_hex_string(argv[i + 1], key, 32);
            i++;
        } else if (strcmp(argv[i], NONCE_FLAG) == 0) {
            if (i + 1 >= argc) {
                printf("Incorrect usage: Use -n followed by nonce to specify nonce\n");
                return;
            }
            printf("Specified nonce: %s\n", argv[i + 1]);
            parse_hex_string(argv[i + 1], nonce, 12);
            i++;
        } else if (strcmp(argv[i], KEYFILE_FLAG) == 0) {
            if (i + 1 >= argc) {
                printf("Incorrect usage: Use -f followed by keyfile path to specify key file\n");
                return;
            }
            printf("Specified keyfile: %s\n", argv[i + 1]);
            if (read_keyfile(argv[i + 1], key, nonce) == -1) {
                return;
            }
            i++;
        } else if (strcmp(argv[i], WRITE_KEYFILE_FLAG) == 0) {
            should_write_keyfile = true;
        } else if (strcmp(argv[i], PASSWORD_FLAG) == 0) {
            should_get_password = true;
        } else {
            input = argv[i];
        }
    }
    if (input == NULL) {
        printf("Input not specified\n");
        return;
    }
    if (output == NULL) {
        char output_buf[2048] = "output_";
        strcat(output_buf, input);
        output = strdup(output_buf);
        printf("Output not specified. Defaulted to %s\n" ,output);
    }
    if (should_get_password) {
        printf("Please enter the password: ");
        char buf[1024];
        fgets(buf, 1024, stdin);
        printf("%s\n", sha256(buf));
        parse_hex_string(sha256(buf), key, 32);
    }
    chacha20_encrypt(key, 1, nonce, input, output);
    if (should_write_keyfile) {
        printf("Writing keyfile to %s\n", "keyfile");
        write_keyfile("keyfile", key, nonce);
        printf("Done\n");
    }
}

int main(int argc, char *argv[]) {
    parse_commands(argc, argv);
}
