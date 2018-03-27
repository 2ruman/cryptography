/*
 * crypto_util.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.2
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

#define TRUE            1
#define FALSE           0
#define OPENSSL_SUCCESS 1
#define OPENSSL_FAILURE 0

#define ROUND_UPX(i, x) (((i)+((x)-1))&~((x)-1))
#define ROUND_DWX(i, x) ((i)&~((x)-1))
#define ROUND_UP8(x)    (((x)+7)&~7)
#define ROUND_DW8(x)    ((x)&~7)
#define IN_BYTES(x)     ((x)>>3)
#define IN_BITS(x)      ((x)<<3)
#define IS_ODD(x)       (((x)&0x1)==0x1)

#define SET_XYZW(x,y,z,w) ((x) | ((y) << 0x08) | ((z) << 0x10) | ((w) << 0x18))
#define GET_X(xyzw)       (((xyzw) >> 0x00) & 0xFF)
#define GET_Y(xyzw)       (((xyzw) >> 0x08) & 0xFF)
#define GET_Z(xyzw)       (((xyzw) >> 0x10) & 0xFF)
#define GET_W(xyzw)       (((xyzw) >> 0x18) & 0xFF)

#define IS_FAILED(x)  if (OPENSSL_SUCCESS != (x))
#define IS_NULL(x) if (NULL == (x))

#define LOG(...) printf(__VA_ARGS__);

#define SINGLE_HEXLEN   2
#define DEFAULT_KEY_LEN 32
/*
 * Byte arrays of constant values in ascending order.
 * The arrays are provided as forms of 12, 16, 24 and 32 bytes.
 */
static const uint8_t asc_12_bytes[12] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B,
};

static const uint8_t asc_16_bytes[16] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
};

static const uint8_t asc_24_bytes[24] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
};

static const uint8_t asc_32_bytes[] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
};

const uint8_t *get_asc_12();
const uint8_t *get_asc_16();
const uint8_t *get_asc_24();
const uint8_t *get_asc_32();
int generate_rand_bytes(uint8_t *buf, size_t buf_len);
void *secure_memset(void *v, int c, size_t n);
void print_hex(const char* tag, uint8_t *data, size_t data_len);
void hex_to_bytes(char *src, size_t src_len, uint8_t *dst, size_t dst_len);
void bytes_to_hex(uint8_t *src, size_t src_len, char *dst, size_t dst_len);
void reverse_hex(char *hex, size_t hex_len);
void reverse_bytes(uint8_t *bytes, size_t bytes_len);
#endif /* CRYPTO_UTIL_H_ */
