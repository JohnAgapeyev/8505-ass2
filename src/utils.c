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

#include "shared.h"

/*
 * function:
 *    encrypt_aead
 *
 * return:
 *    size_t text len
 *
 * parameters:
 *    const unsigned char* plaintext the plaintext
 *    size_t plain_len the length of the plaintext
 *    const unsigned char* aad additional authenticated data
 *    const size_t aad_len length of the add
 *    const unsigned char* key the key to use
 *    const unsigned char* iv the initialization vector
 *    unsigned char* ciphertext the cyphertext
 *    unsigned char* tag the tag to use
 *
 * notes:
 *    encrypts the data with aes
 * */

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

/*
 * function:
 *    decrypt_aead
 *
 * return:
 *    ssize_t text len
 *
 * parameters:
 *    const unsigned char* ciphertext the cyphertext
 *    size_t cipher_len the length of the cyphertext
 *    const unsigned char* plaintext the plaintext
 *    const unsigned char* aad additional authenticated data
 *    const size_t aad_len length of the add
 *    const unsigned char* key the key to use
 *    const unsigned char* iv the initialization vector
 *    unsigned char* ciphertext the cyphertext
 *    unsigned char* tag the tag to use
 *
 * notes:
 *    decrypt the data with aes
 * */

ssize_t decrypt_aead(const unsigned char* ciphertext, size_t cipher_len, const unsigned char* aad,
    const size_t aad_len, const unsigned char* key, const unsigned char* iv,
    const unsigned char* tag, unsigned char* plaintext) {
    EVP_CIPHER_CTX* ctx;
    nullCheckCryptoAPICall(ctx = EVP_CIPHER_CTX_new());

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL));

    checkCryptoAPICall(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv));

    int len;
    checkCryptoAPICall(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

    checkCryptoAPICall(EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, cipher_len));

    int plaintextlen = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, (unsigned char*)tag)) {
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

/*
 * function:
 *    encrypt_data
 *
 * return:
 *    unsigned char* the cyphertext
 *
 * parameters:
 *    const unsigned char* message message to encrypt
 *    const size_t mesg_len the length of the message
 *    const unsigned char* key the key to use
 *    const unsigned char* aad the additional authenticated data
 *    const size_t aad_len the length of the aad
 *
 * notes:
 *   encrypt the data with chacha20 poly1305
 * */

unsigned char* encrypt_data(const unsigned char* message, const size_t mesg_len,
    const unsigned char* key, const unsigned char* aad, const size_t aad_len) {
    unsigned char nonce[NONCE_LEN];
    RAND_bytes(nonce, NONCE_LEN);

    if (use_aes) {
        unsigned char* ciphertext = malloc(mesg_len + TAG_LEN + NONCE_LEN + sizeof(uint32_t));
        encrypt_aead(
            message, mesg_len, aad, aad_len, key, nonce, ciphertext, ciphertext + mesg_len);
        //Append nonce
        memcpy(ciphertext + mesg_len + TAG_LEN, nonce, NONCE_LEN);

        //Shift ciphertext over and prepend length to it
        memmove(ciphertext + sizeof(uint32_t), ciphertext, mesg_len + TAG_LEN + NONCE_LEN);
        uint32_t cipher_len = mesg_len + TAG_LEN + NONCE_LEN;

        memcpy(ciphertext, &cipher_len, sizeof(uint32_t));

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

    return ciphertext;
}

/*
 * function:
 *    decrypt_data
 *
 * return:
 *    unsigned char* the plaintext
 *
 * parameters:
 *    unsigned char* message the cyphertext
 *    const size_t mesg_len the length of the cyphertext
 *    const unsigned char* key the key to use
 *    const unsigned char* aad the additional authenticated data
 *    const size_t aad_len the length of the add
 *
 * notes:
 *   decrypts the cyphertext with chacha20 poly1305
 * */

unsigned char* decrypt_data(unsigned char* message, const size_t mesg_len, const unsigned char* key,
    const unsigned char* aad, const size_t aad_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();

    if (use_aes) {
        unsigned char* plaintext = malloc(mesg_len + TAG_LEN + NONCE_LEN + sizeof(uint32_t));
        ssize_t res = decrypt_aead(message, mesg_len - TAG_LEN - NONCE_LEN, aad, aad_len, key,
            message + mesg_len - NONCE_LEN, message + mesg_len - TAG_LEN - NONCE_LEN, plaintext);
        if (res == -1) {
            printf("Bad decrypt\n");
            free(plaintext);
            return NULL;
        }
        return plaintext;
    }

    checkCryptoAPICall(EVP_DecryptInit_ex(
        ctx, EVP_chacha20_poly1305(), NULL, key, message + mesg_len - NONCE_LEN));

    int len;
    checkCryptoAPICall(EVP_DecryptUpdate(ctx, NULL, &len, aad, aad_len));

    if (mesg_len <= TAG_LEN + NONCE_LEN) {
        puts("Invalid message length");
        return NULL;
    }

    unsigned char* plaintext = malloc(mesg_len - TAG_LEN - NONCE_LEN);

    checkCryptoAPICall(
        EVP_DecryptUpdate(ctx, plaintext, &len, message, mesg_len - TAG_LEN - NONCE_LEN));

    checkCryptoAPICall(EVP_CIPHER_CTX_ctrl(
        ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN, message + mesg_len - TAG_LEN - NONCE_LEN));

    int res = EVP_DecryptFinal_ex(ctx, plaintext + len, &len);

    EVP_CIPHER_CTX_free(ctx);

    if (res == 0) {
        printf("Bad decrypt\n");
        free(plaintext);
        return NULL;
    }
    return plaintext;
}

/*
 * function:
 *    password_key_derive
 *
 * return:
 *    unsigned char* the derived password
 *
 * parameters:
 *    const char* password the plaintext password
 *
 * notes:
 *    derives the password key fro mthe plaintext
 * */

unsigned char* password_key_derive(const char* password) {
    unsigned char* key = malloc(KEY_LEN);
    PKCS5_PBKDF2_HMAC(password, strlen(password), NULL, 0, 100000, EVP_sha256(), KEY_LEN, key);
    return key;
}
