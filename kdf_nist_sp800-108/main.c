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
#include "kdf_nist.h"

#include <stdlib.h>
#include <string.h>

int main() {
    puts("====================================================================================================");
    LOG("                           [ KDF(SP800-108) Functional Verification ]\n");
    puts("====================================================================================================");

    int rc ,ret;
    uint8_t Ko[1024];
    uint8_t *Ki;
    size_t Ki_len = DEFAULT_KEY_LEN;
    const char *Label = "KeyEncryptionKey";
    const char *Context = "KDF(SP800-108)";
    size_t Label_len = strlen(Label);
    size_t Context_len = strlen(Context);
    size_t L = 257;

    Ki = (uint8_t*)malloc(Ki_len);
    IS_FAILED(
            rc = generate_rand_bytes(Ki, Ki_len)) {
        goto error;
    }
    print_hex("Ki", Ki, Ki_len);

    /* Clean up */
    memset(Ko, 0, 1024);

    /* Use of KDF_CTR_HMAC_SHA256() function */
    IS_FAILED(
            rc = KDF_CTR_HMAC_SHA256(Ko, L,
                                     Ki, Ki_len,
                                     (uint8_t *)Label, Label_len,
                                     (uint8_t *)Context, Context_len)) {
        goto error;
    }
    print_hex("Ko", Ko, CALC_KO_LEN(L));

    /* Clean up */
    memset(Ko, 0, 1024);

    /* Use of KDF_CTR_HMAC_SHA512() function */
    IS_FAILED(
            rc = KDF_CTR_HMAC_SHA512(Ko, L,
                                     Ki, Ki_len,
                                     (uint8_t *)Label, Label_len,
                                     (uint8_t *)Context, Context_len)) {
        goto error;
    }
    print_hex("Ko", Ko, CALC_KO_LEN(L));
    goto end;

error:
    ret = 1;
end:
    ret = 0;
    if (Ki) {
        free(Ki);
        Ki = NULL;
    }
    return ret;
}
