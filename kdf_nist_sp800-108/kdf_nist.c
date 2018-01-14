/*
 * kdf_nist.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */
#include "kdf_nist.h"

//#include <stddef.h>
//#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>

int KDF_CTR_HAMC(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len,
                        const EVP_MD *digest);

int KDF_CTR_HAMC_SHA256(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len) {
    return KDF_CTR_HAMC(Ko, Ko_len, Ki, Ki_len,
                        Label, Label_len, Context, Context_len,
                        EVP_sha256());
}

int KDF_CTR_HAMC_SHA512(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len) {
    return KDF_CTR_HAMC(Ko, Ko_len, Ki, Ki_len,
                        Label, Label_len, Context, Context_len,
                        EVP_sha512());
}

int KDF_CTR_HAMC(uint8_t *Ko, size_t Ko_len,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len,
                        const EVP_MD *digest) {
    int rc = OPENSSL_FAILURE;
    if (Ko == NULL || Ko_len == 0
            || Ki == NULL || Ki_len == 0
            || Label == NULL || Label_len == 0
            || Context == NULL || Context_len == 0) {
       return rc;
    }

    HMAC_CTX hctx, hctx_tpl;

    size_t fixed_input_data_len;
    size_t input_data_len;
    size_t K_i_len;
    size_t result_i_len;

    uint8_t *fixed_input_data;
    uint8_t *input_data;
    uint8_t *K_i;
    uint8_t *result_i;
    uint8_t *i_ptr;

    uint32_t digest_len = (uint32_t)EVP_MD_size(digest);
    uint32_t i = 0;
    uint32_t h = digest_len * 8;
    uint32_t L = Ko_len * 8;
    uint32_t n = (L < h) ? 1 : L/h;
    uint32_t r = sizeof(i);

    /* Fixed Input Data : Label || 0x00 || Context || [L] */
    fixed_input_data_len = Label_len + 1 + Context_len + sizeof(L);
    fixed_input_data = (uint8_t *)malloc(fixed_input_data_len);
    if (fixed_input_data == NULL) {
        goto error;
    }
    memset(fixed_input_data, 0, fixed_input_data_len);

    /* Input Data : [i] || Label || 0x00 || Context || [L] */
    input_data_len = r + fixed_input_data_len;
    input_data = (uint8_t *)malloc(input_data_len);
    if (input_data == NULL) {
        goto error;
    }
    memset(input_data, 0, input_data_len);

    /* K(i) := PRF(Ki, input_data) */
    K_i_len = digest_len;
    K_i = (uint8_t *)malloc(K_i_len);
    if (K_i == NULL) {
        goto error;
    }
    memset(K_i, 0, K_i_len);

    /* result(0) := Empty */
    /* result(i) := result(i-1) || K(i) */
    result_i_len = K_i_len * n;
    result_i = (uint8_t *)malloc(result_i_len);
    if (result_i == NULL) {
        goto error;
    }
    memset(result_i, 0, result_i_len);

#ifdef DIAGNOSTICS
    printf("i              : %d\n", i);
    printf("h              : %d\n", h);
    printf("L              : %d\n", L);
    printf("n              : %d\n", n);
    printf("r              : %d\n", r);
    printf("Ki_len         : %zu\n", Ki_len);
    printf("Ko_len         : %zu\n", Ko_len);
    printf("Label_len      : %zu\n", Label_len);
    printf("Context_len    : %zu\n", Context_len);
    printf("digest_len     : %d\n", digest_len);
    printf("fixed_data_len : %zu\n", fixed_input_data_len);
    printf("input_data_len : %zu\n", input_data_len);
    printf("result_i_len   : %zu\n", result_i_len);
#endif

    memcpy(input_data+r, fixed_input_data, fixed_input_data_len);

    HMAC_CTX_init(&hctx);
    if (!HMAC_Init_ex(&hctx, Ki, Ki_len, digest, NULL)) {
        printf("Failed to initialize hmac context\n");
        goto error;
    }
    for (i_ptr = result_i ; i <= n ; i++) {
        if (i == 0) {
            // memset(result_i, 0, result_i_len);
            continue;
        }
        HMAC_CTX_copy(&hctx_tpl, &hctx);

        memcpy(input_data, &i, r);
        if (!HMAC_Update(&hctx_tpl, input_data, input_data_len)) {
            printf("Failed to update message to hamc context\n");
            goto error;
        }
        if (!HMAC_Final(&hctx_tpl, K_i, &digest_len)) {
            printf("Failed to finalize hmac calculation\n");
            goto error;
        }
#ifdef DIAGNOSTICS
        printf("HMAC(%d) :: %d bytes digested\n", i, digest_len);
#endif
        memcpy(i_ptr, K_i, K_i_len); // K_i_len should be same with digest_len
        memset(K_i, 0, K_i_len);
        i_ptr += K_i_len;

        HMAC_CTX_cleanup(&hctx_tpl);
    }

    memcpy(Ko, result_i, Ko_len);
    rc = OPENSSL_SUCCESS;
    goto end;

error:
    rc = OPENSSL_FAILURE;
    // TODO : Handle opeenssl error just happened
    HMAC_CTX_cleanup(&hctx_tpl);
end:
    if (fixed_input_data != NULL) {
        free(fixed_input_data);
    }
    if (input_data != NULL) {
        free(input_data);
    }
    if (K_i != NULL) {
        free(K_i);
    }
    if (result_i != NULL) {
        memset(result_i, 0, result_i_len);
        free(result_i);
    }
    HMAC_CTX_cleanup(&hctx);
    return rc;
}
