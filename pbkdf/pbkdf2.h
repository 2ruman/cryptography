/*
 * pbkdf2.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#ifndef PBKDF2_H_
#define PBKDF2_H_

#include <stddef.h>
#include <stdint.h>

#ifndef OPENSSL_SUCCESS
#define OPENSSL_SUCCESS 1
#endif

#ifndef OPENSSL_FAILURE
#define OPENSSL_FAILURE 0
#endif

int PBKDF2_HMAC_SHA256(uint8_t *out, size_t out_len,
                       uint8_t *password, size_t password_len,
                       uint8_t *salt, size_t salt_len, uint32_t iter);

int PBKDF2_HMAC_SHA512(uint8_t *out, size_t out_len,
                       uint8_t *password, size_t password_len,
                       uint8_t *salt, size_t salt_len, uint32_t iter);

#endif /* PBKDF2_H_ */
