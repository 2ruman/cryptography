/*
 * aes_gcm.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : accords with "aes.h"
 */
#include "aes.h"

//#include <stddef.h>
//#include <stdint.h>

#include <openssl/evp.h>

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
        ERROR("Invalid parameters");
        return ret;
    }

    do {
        /* Create cipher context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERROR("Failed while create cipher context");
            break;
        }

        /* Set up cipher context with cipher type */
        IS_FAILED(EVP_EncryptInit_ex(ctx, select_cipher(key_len), NULL, NULL, NULL)) {
            ERROR("Failed while set cipher type");
            break;
        }

        /* Set IV length(12 bytes by default) */
        IS_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
            ERROR("Failed while set IV length");
            break;
        }

        /* Set up cipher context with key and IV */
        IS_FAILED(EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv)) {
            ERROR("Failed while set key and IV");
            break;
        }

        /* Update AAD */
        IS_FAILED(EVP_EncryptUpdate(ctx, NULL, &updated_len, aad, aad_len)) {
            ERROR("Failed while update AAD");
            break;
        }
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Encrypt plaintext */
        IS_FAILED(EVP_EncryptUpdate(ctx, ciphertext, &updated_len, plaintext, plaintext_len)) {
            ERROR("Failed while encryption");
            break;
        }
        ciphertext_len = updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Finalise encryption */
        IS_FAILED(EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &updated_len)) {
            ERROR("Failed while finalisation");
            break;
        }
        ciphertext_len += updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Get authentication tag */
        IS_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, tag_len, tag)) {
            ERROR("Failed while get authentication tag");
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
        ERROR("Invalid parameters");
        return ret;
    }

    do {
        /* Create cipher context */
        if (!(ctx = EVP_CIPHER_CTX_new())) {
            ERROR("Failed while create cipher context");
            break;
        }

        /* Set up cipher context with cipher type */
        IS_FAILED(EVP_DecryptInit_ex(ctx, select_cipher(key_len), NULL, NULL, NULL)) {
            ERROR("Failed while set cipher type");
            break;
        }

        /* Set IV length(12 bytes by default) */
        IS_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv_len, NULL)) {
            ERROR("Failed while set IV length");
            break;
        }

        /* Set up cipher context with key and IV */
        IS_FAILED(EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv)) {
            ERROR("Failed while set key and IV");
            break;
        }

        /* Update AAD */
        IS_FAILED(EVP_DecryptUpdate(ctx, NULL, &updated_len, aad, aad_len)) {
            ERROR("Failed while update AAD");
            break;
        }
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Decrypt ciphertext */
        IS_FAILED(EVP_DecryptUpdate(ctx, plaintext, &updated_len, ciphertext, ciphertext_len)) {
            ERROR("Failed while decryption");
            break;
        }
        plaintext_len = updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Set authentication tag */
        IS_FAILED(EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag_len, tag)) {
            ERROR("Failed while set authentication tag");
            break;
        }

        /* Finalise decryption */
        IS_FAILED(EVP_DecryptFinal_ex(ctx, plaintext + plaintext_len, &updated_len)) {
            ERROR("Failed while finalisation");
            break;
        }
        plaintext_len += updated_len;
#ifdef DIAGNOSTICS
        printf("updated_len : %d\n", updated_len);
#endif
        /* Return value is the length of plaintext */
        ret = plaintext_len;
    } while(0);

    if (ctx) {
        /* Clean up */
        EVP_CIPHER_CTX_free(ctx);
    }
    return ret;
}
