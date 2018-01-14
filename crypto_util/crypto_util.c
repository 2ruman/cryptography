/*
 * crypto_util.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#include "crypto_util.h"

//#include <stddef.h>
//#include <stdint.h>
//#include <stdio.h>
#include <stdlib.h>

#include <openssl/rand.h>

const uint8_t *get_asc_32() {
    return asc_32_bytes;
}

int generate_rand_bytes(uint8_t *buf, size_t buf_len) {
    int rc = OPENSSL_FAILURE;
    if (buf == NULL || buf_len == 0) {
        return rc;
    }
    IS_FAILED(
            rc = RAND_bytes(buf, buf_len)) {
        LOG("Failed to generate random bytes\n");
    }
    return rc;
}

void *secure_memset(void *v, int c, size_t n) {
    volatile unsigned char *p = v;
    while (n--) *p++ = c;
    return v;
}

void print_hex(const char* tag, uint8_t *data, size_t data_len) {
    static const char *hex = "0123456789ABCDEF";
    static const char delimiter = ' ';

    if (tag == NULL || data == NULL || data_len <= 0) {
        return;
    }

    int i;
    size_t buf_len = data_len * 3;
    char *buf = (char *)malloc(buf_len);
    if (buf == NULL) {
        return;
    }
    for (i= 0 ; i < data_len ; i++) {
        buf[i*3 + 0] = hex[(data[i] >> 4) & 0x0F];
        buf[i*3 + 1] = hex[(data[i]) & 0x0F];
        buf[i*3 + 2] = delimiter;
    }
    buf[buf_len - 1] = '\0';
    LOG("%s : %s\n", tag, buf);
    free(buf);
}
