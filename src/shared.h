#ifndef SHARED_H
#define SHARED_H

#include <openssl/err.h>
#include <stdint.h>
#include <stdbool.h>
#include <unistd.h>

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

extern bool use_aes;
extern bool out_bmp;
extern int bit_setting;

size_t encrypt_aead(const unsigned char* plaintext, size_t plain_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        unsigned char* ciphertext, unsigned char* tag);

ssize_t decrypt_aead(const unsigned char* ciphertext, size_t cipher_len, const unsigned char* aad,
        const size_t aad_len, const unsigned char* key, const unsigned char* iv,
        const unsigned char* tag, unsigned char* plaintext);

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
        const unsigned char* key, const unsigned char* aad, const size_t aad_len);

unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
        const unsigned char* aad, const size_t aad_len);

unsigned char* password_key_derive(const char* password);

unsigned char* read_stego(const char* in_filename, const char* data_filename, const char* password);

void write_stego(const char* in_filename, const char* out_filename, const char* data_filename,
        const char* password);

#endif /* end of include guard: SHARED_H */
