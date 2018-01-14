/*
 * crypto_util.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#ifndef CRYPTO_UTIL_H_
#define CRYPTO_UTIL_H_

/*
 * Note that not all of the libcrypto functions return 0 for error
 * and 1 for success.
 */
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define OPENSSL_SUCCESS 1
#define OPENSSL_FAILURE 0

#define DEFAULT_KEY_LEN 32

#define IS_FAILED(x)  if (OPENSSL_SUCCESS != (x))
#define IS_NULL(x) if (NULL == (x))
#define LOG(...) printf(__VA_ARGS__);

static const uint8_t asc_32_bytes[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D,
        0x1E, 0x1F };

const uint8_t *get_asc_32();
int generate_rand_bytes(uint8_t *buf, size_t buf_len);
void *secure_memset(void *v, int c, size_t n);
void print_hex(const char* tag, uint8_t *data, size_t data_len);

#endif /* CRYPTO_UTIL_H_ */
