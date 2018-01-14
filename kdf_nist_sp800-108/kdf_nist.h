/*
 * kdf_nist.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#ifndef KDF_NIST_H_
#define KDF_NIST_H_

#include <stddef.h>
#include <stdint.h>

#ifndef OPENSSL_SUCCESS
#define OPENSSL_SUCCESS 1
#endif

#ifndef OPENSSL_FAILURE
#define OPENSSL_FAILURE 0
#endif

// #define DIAGNOSTICS

int KDF_CTR_HAMC_SHA256(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len);

int KDF_CTR_HAMC_SHA512(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len);

#endif /* KDF_NIST_H_ */
