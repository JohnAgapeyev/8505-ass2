#include <assert.h>
#include <getopt.h>
#include <math.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
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
#include "stb_image_write.h"

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32

#define OVERHEAD_LEN TAG_LEN + NONCE_LEN + sizeof(uint32_t)

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* aad, const size_t aad_len) {
    unsigned char nonce[NONCE_LEN];
    RAND_bytes(nonce, NONCE_LEN);

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_chacha20_poly1305(), NULL, key, nonce);

    int len;
    EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len);

    //Allocate enough for the message and the tag
    unsigned char* ciphertext = malloc(mesg_len + TAG_LEN + NONCE_LEN + sizeof(uint32_t));

    EVP_EncryptUpdate(ctx, ciphertext, &len, message, mesg_len);

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);

    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, ciphertext + mesg_len);

    memcpy(ciphertext + mesg_len + TAG_LEN, nonce, NONCE_LEN);

    //Shift ciphertext over and prepend length to it
    memmove(ciphertext + sizeof(uint32_t), ciphertext, mesg_len + TAG_LEN + NONCE_LEN);

    uint32_t cipher_len = mesg_len + TAG_LEN + NONCE_LEN;

    memcpy(ciphertext, &cipher_len, sizeof(uint32_t));

    printf("Nonce:\n");
    for (int i = 0; i < NONCE_LEN; ++i) {
        printf("%02x", ciphertext[mesg_len + TAG_LEN + i]);
    }
    printf("\n");

    EVP_CIPHER_CTX_free(ctx);

    printf("Message:\n");
    for (unsigned long i = 0; i < mesg_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Tag:\n");
    for (unsigned long i = 0; i < TAG_LEN; ++i) {
        printf("%02x", ciphertext[mesg_len + i]);
    }
    printf("\n");

    return ciphertext;
}

unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
        const unsigned char* aad, const size_t aad_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    printf("Nonce:\n");
    for (int i = 0; i < NONCE_LEN; ++i) {
        printf("%02x", message[mesg_len - NONCE_LEN + i]);
    }
    printf("\n");

    if (!EVP_DecryptInit_ex(
                ctx, EVP_chacha20_poly1305(), NULL, key, message + mesg_len - NONCE_LEN)) {
        puts("Init failure");
        return NULL;
    }

    int len;
    if (!EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len)) {
        puts("AAD set failure");
        return NULL;
    }

    if (mesg_len <= TAG_LEN + NONCE_LEN) {
        puts("Invalid message length");
        return NULL;
    }

    unsigned char* plaintext = malloc(mesg_len - TAG_LEN - NONCE_LEN);

    printf("Message:\n");
    for (unsigned long i = 0; i < mesg_len - TAG_LEN - NONCE_LEN; ++i) {
        printf("%02x", message[i]);
    }
    printf("\n");

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, message, mesg_len - TAG_LEN - NONCE_LEN)) {
        puts("decrypt update failure");
        return NULL;
    }

    printf("Tag:\n");
    for (unsigned long i = 0; i < TAG_LEN; ++i) {
        printf("%02x", message[mesg_len - TAG_LEN - NONCE_LEN + i]);
    }
    printf("\n");

    if (!EVP_CIPHER_CTX_ctrl(
                ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, message + mesg_len - TAG_LEN - NONCE_LEN)) {
        puts("Set tag failure");
        return NULL;
    }

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) {
        puts("Decrypt call failure");
        return NULL;
    }

    EVP_CIPHER_CTX_free(ctx);

    return plaintext;
}

unsigned char* read_stego(const char* in_filename, const char* data_filename) {
    unsigned char key[KEY_LEN];

    memset(key, 0xab, KEY_LEN);

    size_t byte_count = 0;
    size_t bit_count = 0;

    unsigned char *buffer = calloc(1ul << 20, 1);

    uint32_t data_len = 0;

    int x, y, n;
    unsigned char* data = stbi_load(in_filename, &x, &y, &n, 3);

    for (int i = 0; i < x * y * n; ++i) {
        if (data[i] % 2) {
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
            }
            if (byte_count > 3 && byte_count >= data_len + 4) {
                break;
            }
        }
        bit_count = (bit_count + 1) % 8;
    }

    unsigned char* message = decrypt_data(buffer + sizeof(uint32_t), data_len, key, NULL, 0);
    printf("Data message: ");
    for (size_t i = 0; i < data_len - OVERHEAD_LEN - 16 - 12; ++i) {
        printf("%c", message[i]);
    }
    printf("\n");

    stbi_image_free(data);

    return message;
}

void write_stego(const char* in_filename, const char* out_filename, const char* data_filename) {
    FILE* f = fopen(data_filename, "rb");
    fseek(f, 0, SEEK_END);
    long fsize = ftell(f);
    rewind(f);

    unsigned char* mesg = malloc(fsize);
    fread(mesg, fsize, 1, f);
    fclose(f);

    size_t mesg_len = fsize;

    unsigned char key[KEY_LEN];

    memset(key, 0xab, KEY_LEN);

    size_t byte_count = 0;
    size_t bit_count = 0;

    unsigned char* ciphertext = encrypt_data(mesg, mesg_len, key, NULL, 0);

    int x, y, n;
    unsigned char* data = stbi_load(in_filename, &x, &y, &n, 3);

    for (int i = 0; i < x * y * n; ++i) {
        if (!!(ciphertext[byte_count] & (1 << bit_count)) ^ (data[i] % 2)) {
            ++data[i];
        }

        if (bit_count == 7) {
            ++byte_count;
            if (byte_count >= mesg_len + OVERHEAD_LEN) {
                break;
            }
        }
        bit_count = (bit_count + 1) % 8;
    }
    printf("Data message: ");
    for (size_t i = 0; i < mesg_len + OVERHEAD_LEN; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    stbi_write_png(out_filename, x, y, n, data, x * n);
    stbi_image_free(data);

    free(ciphertext);
}

#define usage() \
    do { \
        printf("Usage: 8505-ass2 input-file output-file mode [cipher]\n"); \
    } while (0)

int main(int argc, char** argv) {
    int choice;
    const char* input_filename = NULL;
    const char* output_filename = NULL;
    const char* data_filename = NULL;
    const char* mode = NULL;
    bool is_encrypt = false;
    for (;;) {
        static struct option long_options[]
                = {{"help", no_argument, 0, 'h'}, {"input", required_argument, 0, 'i'},
                        {"output", required_argument, 0, 'o'}, {"mode", required_argument, 0, 'm'},
                        {"data", required_argument, 0, 'd'}, {0, 0, 0, 0}};

        int option_index = 0;
        if ((choice = getopt_long(argc, argv, "hi:o:m:d:", long_options, &option_index)) == -1) {
            break;
        }

        switch (choice) {
            case 'i':
                input_filename = optarg;
                break;
            case 'o':
                output_filename = optarg;
                break;
            case 'm':
                mode = optarg;
                break;
            case 'd':
                data_filename = optarg;
                break;
            case 'h':
            case '?':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    if (!input_filename || !mode || !data_filename) {
        usage();
        return EXIT_FAILURE;
    }
    if (strcmp(mode, "e") == 0) {
        is_encrypt = true;
    } else if (strcmp(mode, "d") == 0) {
        is_encrypt = false;
    } else {
        usage();
        return EXIT_FAILURE;
    }
    if (is_encrypt && !output_filename) {
        usage();
        return EXIT_FAILURE;
    }

    if (is_encrypt) {
        write_stego(input_filename, output_filename, data_filename);
    } else {
        read_stego(input_filename, data_filename);
    }
    return EXIT_SUCCESS;
}
