/*
 * main.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *
 *      This is a test program to verify normal operation of the functions implemented,
 *      at the same time, is a sample program to present how to make use of them.
 */

#include "kdf_nist.h"
#include "crypto_util.h"

#include <stdlib.h>
#include <string.h>

int main() {
    puts("====================================================================================================");
    LOG("                           [ KDF(SP800-108) Functional Verification ]\n");
    puts("====================================================================================================");

    int rc ,ret;
    uint8_t *Ko;
    uint8_t *Ki;
    const char *Label = "KeyEncryptionKey";
    const char *Context = "KDF(SP800-108)";
    size_t Ko_len = DEFAULT_KEY_LEN;
    size_t Ki_len = DEFAULT_KEY_LEN;
    size_t Label_len = strlen(Label);
    size_t Context_len = strlen(Context);

    Ki = (uint8_t*)malloc(Ki_len);
    IS_FAILED(
            rc = generate_rand_bytes(Ki, Ki_len)) {
        goto error;
    }
    print_hex("Ki", Ki, Ki_len);

    Ko = (uint8_t*)malloc(Ko_len);
    IS_NULL(Ko) {
        goto error;
    }

    /* Clean up */
    memset(Ko, 0, Ko_len);
    print_hex("Ko", Ko, Ko_len);

    /* Use of KDF_CTR_HAMC_SHA256() function */
    IS_FAILED(
            rc = KDF_CTR_HAMC_SHA256(Ko, Ko_len, Ki, Ki_len,
                                     (uint8_t *)Label, Label_len,
                                     (uint8_t *)Context, Context_len)) {
        goto error;
    }
    print_hex("Ko", Ko, Ko_len);

    /* Clean up */
    memset(Ko, 0, Ko_len);
    print_hex("Ko", Ko, Ko_len);

    /* Use of KDF_CTR_HAMC_SHA512() function */
    IS_FAILED(
            rc = KDF_CTR_HAMC_SHA512(Ko, Ko_len, Ki, Ki_len,
                                     (uint8_t *)Label, Label_len,
                                     (uint8_t *)Context, Context_len)) {
        goto error;
    }
    print_hex("Ko", Ko, Ko_len);
    goto end;

error:
    ret = 1;
end:
    ret = 0;
    if (Ki != NULL) {
        free(Ki);
    }
    if (Ko!= NULL) {
        free(Ko);
    }
    return ret;
}
