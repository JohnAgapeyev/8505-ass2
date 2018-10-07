#include <assert.h>
#include <getopt.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#define STB_IMAGE_IMPLEMENTATION
#include "stb_image.h"
#define STB_IMAGE_WRITE_IMPLEMENTATION
#include "shared.h"
#include "stb_image_write.h"


/*
 * function:
 *    read_stego
 *
 * return:
 *    unsigned char*
 *
 * parameters:
 *    const char* in_filename file to read
 *    const char* data_filename file to extract
 *    const char* password password to use
 *
 * notes:
 *    decrypt and read the data from the files
 * */

unsigned char* read_stego( const char* in_filename, const char* data_filename, const char* password) {
    unsigned char* key = password_key_derive(password);

    size_t byte_count = 0;
    size_t bit_count = 0;

    unsigned char* buffer = calloc(1ul << 20, 1);

    uint32_t data_len = 0;

    int x, y, n;
    unsigned char* data = stbi_load(in_filename, &x, &y, &n, 3);
    if (!data) {
        fprintf(stderr, "Failed to open image\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < x * y * n; ++i) {
        if (!!(data[i] & (1 << bit_setting))) {
            //Pixel is 1
            buffer[byte_count] |= (1 << bit_count);
        } else {
            //Pixel is 0
            buffer[byte_count] &= ~(1 << bit_count);
        }

        if (bit_count == 7) {
            ++byte_count;
            if (byte_count > 3 && data_len == 0) {
                memcpy(&data_len, buffer, sizeof(uint32_t));
                if ((int) data_len * 8 > x * y * n) {
                    //Image is corrupted or does not have a message embedded
                    exit(EXIT_FAILURE);
                }
            }
            if (byte_count > 3 && byte_count >= data_len + 4) {
                break;
            }
        }
        bit_count = (bit_count + 1) % 8;
    }

    unsigned char* message
            = decrypt_data(buffer + sizeof(uint32_t), data_len, key, (unsigned char*) &use_aes, 1);
    if (!message) {
        goto cleanup;
    }

    FILE* f = fopen(data_filename, "wb");
    fwrite(message, data_len - OVERHEAD_LEN - 16 - 12, 1, f);
    fclose(f);

cleanup:
    stbi_image_free(data);
    free(key);
    return message;
}


/*
 * function:
 *    write_stego
 *
 * return:
 *    void
 *
 * parameters:
 *    const char* in_filename carrier file
 *    const char* out_filename output file
 *    const char* data_filename data to add file
 *    const char* password password to use
 *
 * notes:
 *    encrypts the data in the data file and adds it to the output file
 * */

void write_stego(const char* in_filename, const char* out_filename, const char* data_filename, const char* password) {
    FILE* f = fopen(data_filename, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char* mesg = malloc(fsize);
    fread(mesg, fsize, 1, f);
    fclose(f);

    size_t mesg_len = fsize;

    unsigned char* key = password_key_derive(password);

    size_t byte_count = 0;
    size_t bit_count = 0;

    unsigned char* ciphertext = encrypt_data(mesg, mesg_len, key, (unsigned char*) &use_aes, 1);

    int x, y, n;
    unsigned char* data = stbi_load(in_filename, &x, &y, &n, 3);
    if (!data) {
        fprintf(stderr, "Failed to open image\n");
        exit(EXIT_FAILURE);
    }

    if ((int) (mesg_len * 8) > (x * y * n)) {
        fprintf(stderr, "Message too big for carrier image\n");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < x * y * n; ++i) {
        if (!!(ciphertext[byte_count] & (1 << bit_count)) ^ (!!(data[i] & (1 << bit_setting)))) {
            data[i] ^= (1 << bit_setting);
        }

        if (bit_count == 7) {
            ++byte_count;
            if (byte_count >= mesg_len + OVERHEAD_LEN) {
                break;
            }
        }
        bit_count = (bit_count + 1) % 8;
    }

    if (out_bmp) {
        stbi_write_bmp(out_filename, x, y, n, data);
    } else {
        stbi_write_png(out_filename, x, y, n, data, x * n);
    }

    stbi_image_free(data);

    free(ciphertext);
    free(key);
}
