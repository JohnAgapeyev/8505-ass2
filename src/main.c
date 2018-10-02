#include <MagickWand/MagickWand.h>
#include <assert.h>
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

#define TAG_LEN 16
#define NONCE_LEN 12
#define KEY_LEN 32

#define OVERHEAD_LEN TAG_LEN + NONCE_LEN + sizeof(uint32_t)
//#define OVERHEAD_LEN 4

#define MAX_PAYLOAD 512
#define MAX_USER_DATA MAX_PAYLOAD - OVERHEAD_LEN

#define ThrowWandException(wand) \
    { \
        char* description; \
\
        ExceptionType severity; \
\
        description = MagickGetException(wand, &severity); \
        (void) fprintf(stderr, "%s %s %lu %s\n", GetMagickModule(), description); \
        description = (char*) MagickRelinquishMemory(description); \
        exit(-1); \
    }

#define SigmoidalContrast(x) \
    (QuantumRange * (1.0 / (1 + exp(10.0 * (0.5 - QuantumScale * x))) - 0.0066928509) * 1.0092503)

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

unsigned char* read_stego(const char* in_filename) {
    unsigned char key[KEY_LEN];

    memset(key, 0xab, KEY_LEN);

    size_t byte_count = 0;
    size_t bit_count = 0;

    bool data_done = false;
    unsigned char buffer[900];
    memset(buffer, 0, 100);

    MagickWandGenesis();
    MagickWand* magick_wand = NewMagickWand();
    if (!magick_wand) {
        ThrowWandException(magick_wand);
    }
    MagickBooleanType status = MagickReadImage(magick_wand, in_filename);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }

    PixelIterator* iterator = NewPixelIterator(magick_wand);
    if (!iterator) {
        ThrowWandException(magick_wand);
    }
    int x;
    int y;
    PixelWand** pixels;
    PixelInfo pixel;
    uint32_t data_len = 0;
    for (y = 0; y < (long) MagickGetImageHeight(magick_wand); y++) {
        size_t width;
        pixels = PixelGetNextIteratorRow(iterator, &width);
        if (!pixels) {
            break;
        }
        if (data_done) {
            break;
        }
        for (x = 0; x < (long) width; x++) {
            PixelGetMagickColor(pixels[x], &pixel);

            if (((int) pixel.red) % 2) {
                //Pixel is 1
                buffer[byte_count] |= (1 << bit_count);
            } else {
                //Pixel is 0
                buffer[byte_count] &= ~(1 << bit_count);
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", buffer[byte_count]);
                ++byte_count;
                if (byte_count > 3 && data_len == 0) {
                    memcpy(&data_len, buffer, sizeof(uint32_t));
                }
                if (byte_count > 3 && byte_count >= data_len + 4) {
                    data_done = true;
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;

            if (((int) pixel.blue) % 2) {
                //Pixel is 1
                buffer[byte_count] |= (1 << bit_count);
            } else {
                //Pixel is 0
                buffer[byte_count] &= ~(1 << bit_count);
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", buffer[byte_count]);
                ++byte_count;
                if (byte_count > 3 && data_len == 0) {
                    memcpy(&data_len, buffer, sizeof(uint32_t));
                }
                if (byte_count > 3 && byte_count >= data_len + 4) {
                    data_done = true;
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;

            if (((int) pixel.green) % 2) {
                //Pixel is 1
                buffer[byte_count] |= (1 << bit_count);
            } else {
                //Pixel is 0
                buffer[byte_count] &= ~(1 << bit_count);
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", buffer[byte_count]);
                ++byte_count;
                if (byte_count > 3 && data_len == 0) {
                    memcpy(&data_len, buffer, sizeof(uint32_t));
                }
                if (byte_count > 3 && byte_count >= data_len + 4) {
                    data_done = true;
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;
        }
        PixelSyncIterator(iterator);
    }

    iterator = DestroyPixelIterator(iterator);
    magick_wand = DestroyMagickWand(magick_wand);

    unsigned char* message = decrypt_data(buffer + sizeof(uint32_t), data_len, key, NULL, 0);
    printf("Data message: ");
    for (size_t i = 0; i < data_len - OVERHEAD_LEN - 16 - 12; ++i) {
        printf("%c", message[i]);
    }
    printf("\n");

    MagickWandTerminus();

    return message;
}

void write_stego(const char* in_filename, const char* out_filename) {
    unsigned char key[KEY_LEN];

    memset(key, 0xab, KEY_LEN);

    size_t byte_count = 0;
    size_t bit_count = 0;

    bool data_done = false;

    const char* test_message
            = "This is a test of the stegonography application with extra special sauce!";
    unsigned char* ciphertext
            = encrypt_data((const unsigned char*) test_message, strlen(test_message), key, NULL, 0);

    MagickWandGenesis();
    MagickWand* magick_wand = NewMagickWand();
    if (!magick_wand) {
        ThrowWandException(magick_wand);
    }
    MagickBooleanType status = MagickReadImage(magick_wand, in_filename);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }

    PixelIterator* iterator = NewPixelIterator(magick_wand);
    if (!iterator) {
        ThrowWandException(magick_wand);
    }
    int x;
    int y;
    PixelWand** pixels;
    PixelInfo pixel;
    for (y = 0; y < (long) MagickGetImageHeight(magick_wand); y++) {
        size_t width;
        pixels = PixelGetNextIteratorRow(iterator, &width);
        if (!pixels) {
            break;
        }
        if (data_done) {
            PixelSyncIterator(iterator);
            break;
        }
        for (x = 0; x < (long) width; x++) {
            PixelGetMagickColor(pixels[x], &pixel);

            if (!!(ciphertext[byte_count] & (1 << bit_count)) ^ (((int) pixel.red) % 2)) {
                ++pixel.red;
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", ciphertext[byte_count]);
                ++byte_count;
                if (byte_count >= strlen(test_message) + OVERHEAD_LEN) {
                    data_done = true;
                    PixelSetPixelColor(pixels[x], &pixel);
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;

            if (!!(ciphertext[byte_count] & (1 << bit_count)) ^ ((int) pixel.blue) % 2) {
                ++pixel.blue;
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", ciphertext[byte_count]);
                ++byte_count;
                if (byte_count >= strlen(test_message) + OVERHEAD_LEN) {
                    data_done = true;
                    PixelSetPixelColor(pixels[x], &pixel);
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;
            if (!!(ciphertext[byte_count] & (1 << bit_count)) ^ ((int) pixel.green) % 2) {
                ++pixel.green;
            }

            if (bit_count == 7) {
                printf("Full byte %02x\n", ciphertext[byte_count]);
                ++byte_count;
                if (byte_count >= strlen(test_message) + OVERHEAD_LEN) {
                    data_done = true;
                    PixelSetPixelColor(pixels[x], &pixel);
                    break;
                }
            }
            bit_count = (bit_count + 1) % 8;
            PixelSetPixelColor(pixels[x], &pixel);
        }
        PixelSyncIterator(iterator);
    }
    printf("Data message: ");
    for (size_t i = 0; i < strlen(test_message) + OVERHEAD_LEN; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    status = MagickWriteImages(magick_wand, out_filename, MagickTrue);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }

    iterator = DestroyPixelIterator(iterator);
    magick_wand = DestroyMagickWand(magick_wand);

    MagickWandTerminus();
}

int main(int argc, char** argv) {
    if (argc != 4) {
        printf("Usage: %s image thumbnail\n", argv[0]);
        exit(EXIT_SUCCESS);
    }
    if (strcmp(argv[3], "d") == 0) {
        read_stego(argv[2]);
    } else {
        write_stego(argv[1], argv[2]);
    }
    return EXIT_SUCCESS;
}
