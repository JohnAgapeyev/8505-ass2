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

#define libcrypto_error() \
    do { \
        fprintf(stderr, "Libcrypto error %s at %s, line %d in function %s\n", \
                ERR_error_string(ERR_get_error(), NULL), __FILE__, __LINE__, __func__); \
        exit(EXIT_FAILURE); \
    } while (0)

#define checkCryptoAPICall(pred) \
    do { \
        if ((pred) != 1) { \
            libcrypto_error(); \
        } \
    } while (0)

#define nullCheckCryptoAPICall(pred) \
    do { \
        if ((pred) == NULL) { \
            libcrypto_error(); \
        } \
    } while (0)

bool use_aes = false;

size_t encrypt_aead(const unsigned char* plaintext, size_t plain_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag) {
    EVP_CIPHER_CTX* ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL));

    checkCryptoAPICall(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_EncryptUpdate(ctx, NULL, &len, aad, aad_len));

    len = 0;
    checkCryptoAPICall(EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plain_len));

    int ciphertextlen = len;
    checkCryptoAPICall(EVP_EncryptFinal_ex(ctx, ciphertext + len, &len));

    ciphertextlen += len;

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag));

    EVP_CIPHER_CTX_free(ctx);

    assert(ciphertextlen >= 0);

    return ciphertextlen;
}

ssize_t decrypt_aead(const unsigned char* ciphertext, size_t cipher_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        const unsigned char* tag, unsigned char* plaintext) {
    printf("Nonce:\n");
    for (int i = 0; i < NONCE_LEN; ++i) {
        printf("%02x", iv[i]);
    }
    printf("\n");
    printf("Message:\n");
    for (unsigned long i = 0; i < cipher_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
    printf("Tag:\n");
    for (unsigned long i = 0; i < TAG_LEN; ++i) {
        printf("%02x", tag[i]);
    }
    printf("\n");
    printf("AAD:\n");
    for (unsigned long i = 0; i < aad_len; ++i) {
        printf("%02x", aad[i]);
    }
    printf("\n");

    EVP_CIPHER_CTX* ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL));

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len));

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (unsigned char*) tag)) {
        libcrypto_error();
    }

    ssize_t ret = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    plaintextlen += len;

    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0) {
        assert(plaintextlen >= 0);
        return plaintextlen;
    }
    return -1;
}

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* aad, const size_t aad_len) {
    unsigned char nonce[NONCE_LEN];
    RAND_bytes(nonce, NONCE_LEN);

    if (use_aes) {
        unsigned char* ciphertext = malloc(mesg_len + TAG_LEN + NONCE_LEN + sizeof(uint32_t));
        size_t total_len = encrypt_aead(
                message, mesg_len, aad, aad_len, key, nonce, ciphertext, ciphertext + mesg_len);
        //Append nonce
        memcpy(ciphertext + mesg_len + TAG_LEN, nonce, NONCE_LEN);

        //Shift ciphertext over and prepend length to it
        memmove(ciphertext + sizeof(uint32_t), ciphertext, mesg_len + TAG_LEN + NONCE_LEN);
        uint32_t cipher_len = mesg_len + TAG_LEN + NONCE_LEN;

        memcpy(ciphertext, &cipher_len, sizeof(uint32_t));

        printf("Total len %lu\n", total_len);

        printf("Nonce:\n");
        for (int i = 0; i < NONCE_LEN; ++i) {
            printf("%02x", ciphertext[mesg_len + TAG_LEN + i + 4]);
        }
        printf("\n");

        printf("Message:\n");
        for (unsigned long i = 0; i < mesg_len; ++i) {
            printf("%02x", ciphertext[i + 4]);
        }
        printf("\n");
        printf("Tag:\n");
        for (unsigned long i = 0; i < TAG_LEN; ++i) {
            printf("%02x", ciphertext[mesg_len + i + 4]);
        }
        printf("\n");
        printf("AAD:\n");
        for (unsigned long i = 0; i < aad_len; ++i) {
            printf("%02x", aad[i]);
        }
        printf("\n");

        return ciphertext;
    }

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

    EVP_CIPHER_CTX_free(ctx);

    printf("Nonce:\n");
    for (int i = 0; i < NONCE_LEN; ++i) {
        printf("%02x", ciphertext[mesg_len + TAG_LEN + i]);
    }
    printf("\n");

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

    if (use_aes) {
        unsigned char* plaintext = malloc(mesg_len + TAG_LEN + NONCE_LEN + sizeof(uint32_t));
        ssize_t res = decrypt_aead(message, mesg_len - TAG_LEN - NONCE_LEN, aad, aad_len, key,
                message + mesg_len - NONCE_LEN, message + mesg_len - TAG_LEN - NONCE_LEN,
                plaintext);
        if (res == -1) {
            printf("Bad decrypt\n");
            free(plaintext);
            return NULL;
        }
        return plaintext;
    }

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

unsigned char* password_key_derive(const char* password) {
    unsigned char* key = malloc(KEY_LEN);
    PKCS5_PBKDF2_HMAC(password, strlen(password), NULL, 0, 100000, EVP_sha256(), KEY_LEN, key);
    return key;
}

unsigned char* read_stego(
        const char* in_filename, const char* data_filename, const char* password) {
    unsigned char* key = password_key_derive(password);

    size_t byte_count = 0;
    size_t bit_count = 0;

    unsigned char* buffer = calloc(1ul << 20, 1);

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
    printf("Read buffer: ");
    for (size_t i = 0; i < data_len + 4; ++i) {
        printf("%02x", buffer[i]);
    }
    printf("\n");

    unsigned char* message
            = decrypt_data(buffer + sizeof(uint32_t), data_len, key, (unsigned char*) &use_aes, 1);
    if (!message) {
        goto cleanup;
    }

    if (data_filename) {
        FILE* f = fopen(data_filename, "wb");
        fwrite(message, data_len - OVERHEAD_LEN - 16 - 12, 1, f);
        fclose(f);
    } else {
        printf("Data message: ");
        for (size_t i = 0; i < data_len - OVERHEAD_LEN - 16 - 12; ++i) {
            printf("%c", message[i]);
        }
        printf("\n");
    }

cleanup:
    stbi_image_free(data);
    free(key);
    return message;
}

void write_stego(const char* in_filename, const char* out_filename, const char* data_filename,
        const char* password) {
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
    free(key);
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
    const char* password = NULL;
    bool is_encrypt = false;
    for (;;) {
        static struct option long_options[] = {{"help", no_argument, 0, 'h'},
                {"input", required_argument, 0, 'i'}, {"output", required_argument, 0, 'o'},
                {"mode", required_argument, 0, 'm'}, {"data", required_argument, 0, 'd'},
                {"password", required_argument, 0, 'p'}, {"aes", no_argument, 0, 'a'},
                {0, 0, 0, 0}};

        int option_index = 0;
        if ((choice = getopt_long(argc, argv, "hi:o:m:d:p:a", long_options, &option_index)) == -1) {
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
            case 'p':
                password = optarg;
                break;
            case 'a':
                use_aes = true;
                break;
            case 'h':
            case '?':
            default:
                usage();
                return EXIT_FAILURE;
        }
    }
    if (!input_filename || !mode || !password) {
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
    if (is_encrypt && !output_filename && !data_filename) {
        usage();
        return EXIT_FAILURE;
    }

    if (is_encrypt) {
        write_stego(input_filename, output_filename, data_filename, password);
    } else {
        if (!read_stego(input_filename, data_filename, password)) {
            return EXIT_FAILURE;
        }
    }
    return EXIT_SUCCESS;
}
