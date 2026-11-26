#include "chacha.h"

void rotate_bits_left(uint32_t *num, int amount) {
    uint32_t new_num = 0;
    new_num |= *num << amount;
    new_num |= *num >> (32 - amount);
    *num = new_num;
}

// Takes 4 32 bit integer adresses and applies the quarter round to them
void apply_quarter_round(uint32_t *a, uint32_t *b, uint32_t *c, uint32_t *d) {
    *a += *b;
    *d ^= *a;
    rotate_bits_left(d, 16);
    *c += *d;
    *b ^= *c;
    rotate_bits_left(b, 12);
    *a += *b;
    *d ^= *a;
    rotate_bits_left(d, 8);
    *c += *d;
    *b ^= *c;
    rotate_bits_left(b, 7);
}

uint32_t *get_chacha_adress(uint32_t state[4][4], int pos) {
    int y_pos = pos / 4;
    int x_pos = pos % 4;
    return &(state[y_pos][x_pos]);
}

// Takes a state array and pos a, b, c, and d and applies the shi to them
void quarter_round(uint32_t state[4][4], int pa, int pb, int pc, int pd) {
    uint32_t *ad_a = get_chacha_adress(state, pa);
    uint32_t *ad_b = get_chacha_adress(state, pb);
    uint32_t *ad_c = get_chacha_adress(state, pc);
    uint32_t *ad_d = get_chacha_adress(state, pd);
    apply_quarter_round(ad_a, ad_b, ad_c, ad_d);
    
}

// Sets the appropriate blocks in the state to the key
// also ensures that it is little endian like it is meant to be
void set_key_state(uint32_t state[4][4], uint8_t key[32]) {
    for (int i = 0; i < 8; i++) {
        uint32_t next_val = 0;
        int pos = i * 4;
        next_val |= (uint32_t)key[pos];
        next_val |= (uint32_t)key[pos + 1] << 8;
        next_val |= (uint32_t)key[pos + 2] << 16;
        next_val |= (uint32_t)key[pos + 3] << 24;
        uint32_t *val_adress = get_chacha_adress(state, i + 4);
        *val_adress = next_val;
    }
}

void set_nonce_state(uint32_t state[4][4], uint8_t nonce[12]) {
    for (int i = 0; i < 3; i++) {
        uint32_t next_val = 0;
        int pos = i * 4;
        next_val |= (uint32_t)nonce[pos];
        next_val |= (uint32_t)nonce[pos + 1] << 8;
        next_val |= (uint32_t)nonce[pos + 2] << 16;
        next_val |= (uint32_t)nonce[pos + 3] << 24;
        uint32_t *val_adress = get_chacha_adress(state, i + 13);
        *val_adress = next_val;
    }
}

// As input, this takes:
// An array with the state
// A 256 bit key (The thing that we use to actually encrypt/decrypt)
// A 32 bit block counter (The number of blocks)
// A 48 bit nonce (Something to ensure that the output is not always the same)
void init_chacha_state(uint32_t state[4][4], uint8_t key[32], uint32_t block, uint8_t nonce[12]) {
    // Init the first 4 as constants 0x61707865, 0x3320646e, 0x79622d32, 0x6b206574
    state[0][0] = 0x61707865;
    state[0][1] = 0x3320646e;
    state[0][2] = 0x79622d32;
    state[0][3] = 0x6b206574;
    set_key_state(state, key);
    state[3][0] = block;
    set_nonce_state(state, nonce);
}

void column_round(uint32_t state[4][4]) {
    quarter_round(state, 0, 4, 8, 12);
    quarter_round(state, 1, 5, 9, 13);
    quarter_round(state, 2, 6, 10, 14);
    quarter_round(state, 3, 7, 11, 15);
}

void diagonal_round(uint32_t state[4][4]) {
    quarter_round(state, 0, 5, 10, 15);
    quarter_round(state, 1, 6, 11, 12);
    quarter_round(state, 2, 7, 8, 13);
    quarter_round(state, 3, 4, 9, 14);
}

uint8_t *serialize(uint32_t state[4][4]) {
    uint8_t *keystring = malloc(sizeof(uint8_t) * 64);
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            keystring[i * 16 + j * 4] = (state[i][j]) & 0b11111111;
            keystring[i * 16 + j * 4 + 1] = (state[i][j] >> 8) & 0b11111111;
            keystring[i * 16 + j * 4 + 2] = (state[i][j] >> 16) & 0b11111111;
            keystring[i * 16 + j * 4 + 3] = (state[i][j] >> 24) & 0b11111111;
        }
    }
    return keystring;
}

uint8_t *chacha_block_function(uint32_t state[4][4]) {
    // Saving the original array so that we can add it later
    uint32_t original_array[4][4];
    memcpy(original_array, state, sizeof(uint32_t) * 4 * 4);

    // Applying column and diagonal rounds
    for (int i = 0; i < 10; i++) {
        column_round(state);
        diagonal_round(state);
    }

    // Adding original array
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            state[i][j] += original_array[i][j];
        }
    }
    return serialize(state);
}

void pinfo(uint8_t key[32], uint32_t counter, uint8_t nonce[12], char *input_filename, char *output_filename) {
    printf("Done: encrypted file %s -> %s\n", input_filename, output_filename);

    printf("├── Key: ");
    for (int i = 0; i < 32; i++) {
        printf("%02x", key[i]);
    }
    printf("\n");
    printf("└── Nonce: ");
    for (int i = 0; i < 12; i++) {
        printf("%02x", nonce[i]);
    }
    printf("\n");
    // Cool char
    // └── 
    // ├
}

void chacha20_encrypt(uint8_t key[32], uint32_t counter, uint8_t nonce[12], char *input_filename, char *output_filename) {
    struct stat stats;
    int status = stat(input_filename, &stats);
    if (status == -1) {
        perror("Failed");
        return;
    }
    off_t size = stats.st_size;
    printf("This file is %d bytes (%d blocks)\n", size, size / 64 + ((size % 64) != 0));

    FILE *fp_read = fopen(input_filename, "r");
    FILE *fp_write = fopen(output_filename, "w");
    for (int i = 0; i < (size / 64); i++) {
        printf("\rWriting block %d", i);
        // Init and process the state
        uint32_t state[4][4];
        init_chacha_state(state, key, counter + i, nonce);
        uint8_t *keystream = chacha_block_function(state);

        // Getting the next 64 chars
        uint8_t buf[64];
        fread(buf, 1, 64, fp_read);
        
        // Xoring them
        for (int j = 0; j < 64; j++) {
            buf[j] ^= keystream[j];
            fputc(buf[j], fp_write);
        }
        free(keystream);
    }
    if (size % 64 != 0) {
        // Init and process the state
        int i = size / 64;
        printf("\rWriting block %d", i);
        int chars_left = size % 64;
        uint32_t state[4][4];
        init_chacha_state(state, key, counter + i, nonce);
        uint8_t *keystream = chacha_block_function(state);

        uint8_t buf[64];
        fread(buf, 1, chars_left, fp_read);

        for (int j = 0; j < chars_left; j++) {
            buf[j] ^= keystream[j];
            fputc(buf[j], fp_write);
        }
        free(keystream);
    }
    printf("\n");
    fclose(fp_read);
    fclose(fp_write);
    pinfo(key, counter, nonce, input_filename, output_filename);
}
