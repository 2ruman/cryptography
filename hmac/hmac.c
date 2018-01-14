/*
 * hmac.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */
#include "hmac.h"

//#include <stddef.h>
//#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>

int hmac(uint8_t *out, size_t out_len,
         uint8_t *key, size_t key_len,
         uint8_t *msg, size_t msg_len,
         const EVP_MD *digest);

int hmac_sha256(uint8_t *out, size_t out_len,
                uint8_t *key, size_t key_len,
                uint8_t *msg, size_t msg_len) {
    return hmac(out, out_len, key, key_len, msg, msg_len, EVP_sha256());
}

int hmac_sha512(uint8_t *out, size_t out_len,
                uint8_t *key, size_t key_len,
                uint8_t *msg, size_t msg_len) {
    return hmac(out, out_len, key, key_len, msg, msg_len, EVP_sha512());
}

int hmac(uint8_t *out, size_t out_len,
         uint8_t *key, size_t key_len,
         uint8_t *msg, size_t msg_len,
         const EVP_MD *digest) {

    int rc = OPENSSL_FAILURE;
    if (out == NULL || out_len == 0
            || key == NULL || key_len == 0
            || msg == NULL || msg_len == 0) {
       return rc;
    }

    unsigned int digest_len = EVP_MD_size(digest);
    size_t result_len = (size_t)digest_len;
    uint8_t *result = (uint8_t *)malloc(result_len);
    if (result == NULL) {
        return rc;
    }

    HMAC_CTX hctx;
    HMAC_CTX_init(&hctx);

    if (!HMAC_Init_ex(&hctx, key, key_len, digest, NULL)) {
        printf("Failed to initialize hmac context\n");
        goto out;
    }
    if (!HMAC_Update(&hctx, msg, msg_len)) {
        printf("Failed to update message to hamc context\n");
        goto out;
    }
    if (!HMAC_Final(&hctx, result, &digest_len)) {
        printf("Failed to finalize hmac calculation\n");
        goto out;
    }
    printf("HMAC :: %d bytes digested\n", digest_len);

    memcpy(out, result,
           (out_len >= result_len) ?
                   result_len : out_len);
    rc = OPENSSL_SUCCESS;
out:
    HMAC_CTX_cleanup(&hctx);
    free(result);
    return rc;
}
