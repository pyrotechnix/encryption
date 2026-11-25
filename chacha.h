#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/stat.h>

/* PARAMATERS
 *  key:
 *      This is a 32 byte (256 bit) encryption key. This is what is used to actually encrypt the file
 *
 *  counter:
 *      This is where the counter should start. In main, it is set to 1 by default
 *
 *  nonce:
 *      The nonce (number used once) is a unique 12 byte (96 bit) number that is used to make sure that the 
 *
 *  input_filename:
 *      The filename of the file that you want to encrypt/decrypt
 *
 *  output_filename:
 *      The filename of the output, i.e. where you want the encrypted/decrypted contents to go
 */
void chacha20_encrypt(uint8_t key[32], uint32_t counter, uint8_t nonce[12], char *input_filename, char *output_filename);
