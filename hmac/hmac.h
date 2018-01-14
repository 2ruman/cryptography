/*
 * hmac.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#ifndef HMAC_H_
#define HMAC_H_

#include <stddef.h>
#include <stdint.h>

#ifndef OPENSSL_SUCCESS
#define OPENSSL_SUCCESS 1
#endif

#ifndef OPENSSL_FAILURE
#define OPENSSL_FAILURE 0
#endif

int hmac_sha256(uint8_t *out, size_t out_len,
                uint8_t *key, size_t key_len,
                uint8_t *msg, size_t msg_len);

int hmac_sha512(uint8_t *out, size_t out_len,
                uint8_t *key, size_t key_len,
                uint8_t *msg, size_t msg_len);

#endif /* HMAC_H_ */
