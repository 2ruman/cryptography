/*
 * aes_gcm.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */
#include "aes.h"

//#include <stddef.h>
//#include <stdint.h>

#include <openssl/evp.h>
#include <openssl/err.h>

static const EVP_CIPHER *select_cipher(int key_len) {
    switch(key_len) {
        case 16:
            return EVP_aes_128_gcm();
        case 24:
            return EVP_aes_192_gcm();
        case 32:
            return EVP_aes_256_gcm();
        default:
            return NULL;
    }
}

static void handle_errors(const char *err_msg) {
    ERR_print_errors_fp(stderr);
#ifdef DIAGNOSTICS
    printf("%s\n", err_msg);
#endif
    // abort();
}

int aes_gcm_encrypt(uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *ciphertext) {

    EVP_CIPHER_CTX *ctx;

    int updated_len, ciphertext_len, ret = -1;

    if (plaintext == NULL || key == NULL
            || iv == NULL || aad == NULL || tag == NULL) {
        return ret;
    }

    do {
        /* Create cipher context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            handle_errors("Error occurred while create cipher context");
            break;
        }

        /* Set up cipher context with cipher type */
        if (!EVP_EncryptInit_ex(ctx, select_cipher(key_len), NULL, NULL, NULL)) {
            handle_errors("Error occurred while set cipher type");
            break;
        }

        /* Set IV length(12 bytes by default) */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
            handle_errors("Error occurred while set IV length");
            break;
        }

        /* Set up cipher context with key and IV */
        if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
            handle_errors("Error occurred while set key and IV");
            break;
        }

        /* Update AAD */
        if (!EVP_EncryptUpdate(ctx, NULL, &updated_len, aad, aad_len)) {
            handle_errors("Error occurred while update AAD");
            break;
        }
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Encrypt plaintext */
        if (!EVP_EncryptUpdate(ctx, ciphertext, &updated_len, plaintext, plaintext_len)) {
            handle_errors("Error occurred while encryption");
            break;
        }
        ciphertext_len = updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Finalize encryption */
        if (!EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &updated_len)) {
            handle_errors("Error occurred while finalization");
            break;
        }
        ciphertext_len += updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Extract authentication tag */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
            handle_errors("Error occurred while extract auth tag");
            break;
        }

        /* Return value is the length of ciphertext */
        ret = ciphertext_len;
    } while(0);

    if (ctx) {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext) {

    EVP_CIPHER_CTX *ctx;

    int updated_len, plaintext_len, ret = -1;

    if (plaintext == NULL || key == NULL
            || iv == NULL || aad == NULL || tag == NULL) {
        return ret;
    }

    do {
        /* Create cipher context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            handle_errors("Error occurred while create cipher context");
            break;
        }

        /* Set up cipher context with cipher type */
        if (!EVP_DecryptInit_ex(ctx, select_cipher(key_len), NULL, NULL, NULL)) {
            handle_errors("Error occurred while set cipher type");
            break;
        }

        /* Set IV length(12 bytes by default) */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
            handle_errors("Error occurred while set IV length");
            break;
        }

        /* Set up cipher context with key and IV */
        if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
            handle_errors("Error occurred while set key and IV");
            break;
        }

        /* Update AAD */
        if (!EVP_DecryptUpdate(ctx, NULL, &updated_len, aad, aad_len)) {
            handle_errors("Error occurred while update AAD");
            break;
        }
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Decrypt ciphertext */
        if (!EVP_DecryptUpdate(ctx, plaintext, &updated_len, ciphertext, ciphertext_len)) {
            handle_errors("Error occurred while encryption");
            break;
        }
        plaintext_len = updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Set authentication tag */
        if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
            handle_errors("Error occurred while set auth tag");
            break;
        }

        /* Finalize decryption */
        if (!EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &updated_len)) {
            handle_errors("Error occurred while finalization");
            break;
        }
        plaintext_len += updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        ret = plaintext_len;
    } while(0);

    if (ctx) {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}
