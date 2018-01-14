/*
 * pbkdf2.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#include "pbkdf2.h"

//#include <stddef.h>
//#include <stdint.h>

#include <openssl/evp.h>

int PBKDF2(uint8_t *out, size_t out_len,
           uint8_t *password, size_t password_len,
           uint8_t *salt, size_t salt_len, uint32_t iter,
           const EVP_MD *digest);

int PBKDF2_HMAC_SHA256(uint8_t *out, size_t out_len,
                       uint8_t *password, size_t password_len,
                       uint8_t *salt, size_t salt_len, uint32_t iter) {
    return PBKDF2(out, out_len,
                  password, password_len,
                  salt, salt_len,
                  iter, EVP_sha256());
}

int PBKDF2_HMAC_SHA512(uint8_t *out, size_t out_len,
                       uint8_t *password, size_t password_len,
                       uint8_t *salt, size_t salt_len, uint32_t iter) {
    return PBKDF2(out, out_len,
                  password, password_len,
                  salt, salt_len,
                  iter, EVP_sha512());
}

int PBKDF2(uint8_t *out, size_t out_len,
           uint8_t *password, size_t password_len,
           uint8_t *salt, size_t salt_len, uint32_t iter,
           const EVP_MD *digest) {
    int rc = OPENSSL_FAILURE;
    if (out == NULL || out_len == 0
            || password == NULL || password_len == 0
            || salt == NULL || salt_len == 0) {
            return rc;
    }
    rc = PKCS5_PBKDF2_HMAC((const char *)password, password_len,
                           (const unsigned char *)salt, salt_len, iter, digest,
                           out_len, out);
    return rc;
}
// int PKCS5_PBKDF2_HMAC(const char *pass, int passlen,
//                       const unsigned char *salt, int saltlen, int iter,
//                       const EVP_MD *digest,
//                       int keylen, unsigned char *out);
