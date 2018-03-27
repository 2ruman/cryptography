/*
 * crypto_util.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.2
 */

#include "crypto_util.h"

//#include <stddef.h>
//#include <stdint.h>
//#include <stdio.h>
#include <stdlib.h>

#include <openssl/rand.h>

const uint8_t *get_asc_12() {
    return asc_12_bytes;
}

const uint8_t *get_asc_16() {
    return asc_16_bytes;
}

const uint8_t *get_asc_24() {
    return asc_24_bytes;
}

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

void hex_to_bytes(char *src, size_t src_len, uint8_t *dst, size_t dst_len) {
    uint8_t *p_dst;
    int i;

    if (src == NULL || dst == NULL
            || IS_ODD(src_len)
            || dst_len < (src_len / SINGLE_HEXLEN)) {
        return;
    }

    p_dst = dst;

    for (i = 0 ; i < (src_len / SINGLE_HEXLEN) ; i++, p_dst++) {
        sscanf(src + (i * 2), "%2hhx", p_dst);
    }
    return;
}

void bytes_to_hex(uint8_t *src, size_t src_len, char *dst, size_t dst_len) {
    const char *hex = "0123456789abcdef";
    char *p_dst;
    int i;

    if (src == NULL || dst == NULL
            || src_len == 0
            || dst_len < (src_len * SINGLE_HEXLEN)) {
        return;
    }

    p_dst = dst;

    for (i = 0 ; i < src_len ; i++) {
        *(p_dst++) = hex[(src[i] >> 4) & 0x0F];
        *(p_dst++) = hex[(src[i] & 0x0F)];
    }
    return;
}

void reverse_hex(char *hex, size_t hex_len) {
    int head, navel, tail;
    char buff[2];

    if (IS_ODD(hex_len)
            || hex_len < (SINGLE_HEXLEN * 2)) {
        return;
    }
    for (head = 0, navel = hex_len/SINGLE_HEXLEN, tail =  hex_len - SINGLE_HEXLEN ;
            head < navel ; head+=SINGLE_HEXLEN, tail-=SINGLE_HEXLEN) {
        buff[0]     = hex[head+0];
        buff[1]     = hex[head+1];
        hex[head+0] = hex[tail+0];
        hex[head+1] = hex[tail+1];
        hex[tail+0] = buff[0];
        hex[tail+1] = buff[1];
    }
    return;
}

void reverse_bytes(uint8_t *bytes, size_t bytes_len) {
    int head, navel, tail;
    uint8_t buff;

    if (bytes_len < 2) {
        return;
    }
    for (head = 0, navel = bytes_len/2, tail =  bytes_len - 1 ;
            head < navel ; head++, tail--) {
        buff        = bytes[head];
        bytes[head] = bytes[tail];
        bytes[tail] = buff;
    }
    return;
}
