/*
 * main.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *
 *      This is a test program to verify normal operation of the functions implemented,
 *      at the same time, is a sample program to present how to make use of them.
 */

#include "pbkdf2.h"
#include "crypto_util.h"

#include <stdlib.h>
#include <string.h>

int main() {
    puts("====================================================================================================");
    LOG("                             [ PBKDF Functional Verification ]\n");
    puts("====================================================================================================");

    int rc ,ret;
    int interation = 10000;
    const char *password = "Don't forget your passcode!";
    uint8_t *salt;
    uint8_t *out;

    size_t password_len = strlen(password);
    size_t salt_len = DEFAULT_KEY_LEN;
    size_t out_len = DEFAULT_KEY_LEN;

    LOG("password : %s ( Length : %zu )\n", password, password_len);
    print_hex("password", (uint8_t*)password, password_len);

//  salt = get_asc_32();
    salt = (uint8_t*)malloc(salt_len);
    IS_FAILED(
            rc = generate_rand_bytes(salt, salt_len)) {
        goto error;
    }
    print_hex("salt    ", salt, salt_len);

    out = (uint8_t*)malloc(out_len);
    IS_NULL(out) {
        goto error;
    }
    memset(out, 0, out_len);
    print_hex("out     ", out, out_len);

    IS_FAILED(
            rc = PBKDF2_HMAC_SHA256(out, out_len,
                                    (uint8_t *)password, password_len,
                                    salt, salt_len, interation)) {
        goto error;
    }
    print_hex("out     ", out, out_len);

    goto end;

error:
    ret = 1;
end:
    ret = 0;
    if (salt != NULL) {
        free(salt);
    }
    if (out!= NULL) {
        free(out);
    }
    return ret;
}
