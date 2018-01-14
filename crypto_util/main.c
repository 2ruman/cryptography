/*
 * main.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *
 *      This is a test program to verify normal operation of the functions implemented,
 *      at the same time, is a sample program to present how to make use of them.
 */

#include "crypto_util.h"

#include <stdlib.h>

int main() {
    int rc;
    LOG("[ CryptoUtil Functional Verification ]\n");

    /* Use of generate_rand_bytes() function */
    size_t key_len = DEFAULT_KEY_LEN;
    uint8_t *key = (uint8_t*)malloc(key_len);
    rc = generate_rand_bytes(key, key_len);
    LOG("generate_rand_bytes() - [ rc : %d ]\n", rc);
    if (rc == OPENSSL_SUCCESS) {
        print_hex("generate_rand_bytes() --> Key", key, key_len);
    }

    /* Use of secure_memset() function */
    secure_memset(key, 0, key_len);
    LOG("secure_memset() - [ rc : %s ]\n", "N/A");
    print_hex("secure_memset() --> Key", key, key_len);
    free(key);

    /* Use of get_asc_32 function */
    size_t salt_len = 32;
    uint8_t *salt = (uint8_t *)get_asc_32();
    LOG("get_asc_32() - [ rc : %p ]\n", salt);
    print_hex("get_asc_32() --> Salt", salt, salt_len);

    puts("See you~! :-)");
    return 0;
}
