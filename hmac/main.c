/*
 * main.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *
 *      This is a test program to verify normal operation of the functions implemented,
 *      at the same time, is a sample program to present how to make use of them.
 */

#include "hmac.h"
#include "crypto_util.h"

#include <stdlib.h>
#include <string.h>

int main() {
    puts("======================================================================");
    LOG("               [ HMAC Functional Verification ]\n");
    puts("======================================================================");

    int rc ,ret;
    uint8_t *out;
    size_t out_len;

    char *msg = "@Hello, everyone~! Hope you enjoy~! Thank you~!@";
    size_t msg_len = strlen(msg);
    LOG("Message        : %s\n", msg);
    LOG("Message length : %zu\n", msg_len);

    size_t key_len = DEFAULT_KEY_LEN;
    uint8_t *key = (uint8_t*)malloc(key_len);
    IS_FAILED(
            rc = generate_rand_bytes(key, key_len)) {
        goto error;
    }
    print_hex("Input Key     ", key, key_len);

    /* Use of hmac_sha256() function */
    out_len = 256 / 8;
    out = (uint8_t*)malloc(out_len);
    IS_FAILED(
            rc = hmac_sha256(out, out_len, key, key_len, (uint8_t *)msg, msg_len)) {
        goto error;
    }
    print_hex("HMAC256 out   ", out, out_len);
    free(out);

    /* Use of hmac_sha512() function */
    out_len = 512 / 8;
    out = (uint8_t*)malloc(out_len);
    IS_FAILED(
            rc = hmac_sha512(out, out_len, key, key_len, (uint8_t *)msg, msg_len)) {
        goto error;
    }
    print_hex("HMAC512 out   ", out, out_len);
    free(out);
    goto end;

error:
    ret = 1;
end:
    ret = 0;
    if (key != NULL) {
        free(key);
    }
    return ret;
}
