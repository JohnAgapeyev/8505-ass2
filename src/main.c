#include <MagickWand/MagickWand.h>
#include <assert.h>
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

#define OVERHEAD_LEN TAG_LEN + NONCE_LEN

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

int main(int argc, char** argv) {
    if (argc != 3) {
        printf("Usage: %s image thumbnail\n", argv[0]);
        exit(EXIT_SUCCESS);
    }
    MagickWandGenesis();
    MagickWand* magick_wand = NewMagickWand();
    if (!magick_wand) {
        ThrowWandException(magick_wand);
    }
    MagickBooleanType status = MagickReadImage(magick_wand, argv[1]);
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
        for (x = 0; x < (long) width; x++) {
            PixelGetMagickColor(pixels[x], &pixel);
            pixel.red = SigmoidalContrast(pixel.red);
            pixel.green = SigmoidalContrast(pixel.green);
            pixel.blue = SigmoidalContrast(pixel.blue);
            pixel.index = SigmoidalContrast(pixel.index);
            PixelSetPixelColor(pixels[x], &pixel);
        }
        PixelSyncIterator(iterator);
    }
    if (y < (long) MagickGetImageHeight(magick_wand)) {
        ThrowWandException(magick_wand);
    }
    status = MagickWriteImages(magick_wand, argv[2], MagickTrue);
    if (status == MagickFalse) {
        ThrowWandException(magick_wand);
    }

    iterator = DestroyPixelIterator(iterator);
    magick_wand = DestroyMagickWand(magick_wand);

    MagickWandTerminus();

    return EXIT_SUCCESS;
}
