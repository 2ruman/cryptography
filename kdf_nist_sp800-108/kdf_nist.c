/*
 * kdf_nist.c
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.2.0
 */
#include "kdf_nist.h"

//#include <stddef.h>
//#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/hmac.h>

int KDF_CTR_HMAC_SHA256(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len) {
    return KDF_CTR_HMAC(Ko, L,
                        Ki, Ki_len,
                        Label, Label_len, Context, Context_len,
                        SET_CFG(DEFAULT_KDF_MODE, DEFAULT_KDF_RLEN,
                                KDF_PRF_HMAC_SHA256, KDF_NONE));
}

int KDF_CTR_HMAC_SHA512(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len) {
    return KDF_CTR_HMAC(Ko, L,
                        Ki, Ki_len,
                        Label, Label_len, Context, Context_len,
                        SET_CFG(DEFAULT_KDF_MODE, DEFAULT_KDF_RLEN,
                                KDF_PRF_HMAC_SHA512, KDF_NONE));
}

int KDF_CTR_HMAC(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len,
                        uint32_t cfg) {
    int rc = OPENSSL_FAILURE;
    int mode = GET_CFG_MODE(cfg);
    int rlen = GET_CFG_RLEN(cfg);
    int prf  = GET_CFG_PRF(cfg);
    int ext, cloc = ext
             = GET_CFG_EXT(cfg);
#ifdef DIAGNOSTICS
    KDF_LOGD("L               : %zu\n", L);
    KDF_LOGD("Ki_len          : %zu\n", Ki_len);
    KDF_LOGD("Label_len       : %zu\n", Label_len);
    KDF_LOGD("Context_len     : %zu\n", Context_len);
    KDF_LOGD("mode            : %d\n", mode);
    KDF_LOGD("rlen            : %d\n", rlen);
    KDF_LOGD("prf             : %d\n", prf);
    KDF_LOGD("ext(=cloc)      : %d\n", ext);
#endif
    if (Ko == NULL || Ki == NULL || Ki_len == 0 || L == 0) {
        KDF_LOGE("Invalid input parameters...\n");
        return rc;
    }
    if (!CHECK_KDF_MODE(mode)) {
        KDF_LOGE("Invalid mode...\n");
        return rc;
    }
    if (!CHECK_KDF_RLEN(rlen)) {
        KDF_LOGE("Invalid r length...\n");
        return rc;
    }
    if (!CHECK_KDF_PRF(prf)) {
        KDF_LOGE("Invalid PRF...\n");
        return rc;
    }
    if (IS_KBKDFVS(mode)
            && !CHECK_KBKDFVS_CTRLOC(cloc)) {
        KDF_LOGE("Invalid counter location...\n");
        return rc;
    }

    HMAC_CTX hctx, hctx_tpl;
    size_t fixed_input_data_len;
    size_t input_data_len;
    size_t Ko_len;
    size_t K_i_len;
    size_t result_i_len;

    uint8_t *input_data;
    uint8_t *K_i;
    uint8_t *result_i;
    uint8_t *i_ptr;

    uint32_t digest_len;
    uint32_t h;
    uint32_t n;
    uint32_t r;
    uint32_t i;
    uint32_t rev_i;

    const EVP_MD *digest = GET_PRF(prf);
    digest_len = (uint32_t)EVP_MD_size(digest);

    h = IN_BITS(digest_len); // PRF block length in bits
    n = ROUND_UPX(L, h)/h;   // n := ROUNDUP(L/h) = (L divisible by h)/h
    r = IN_BITS(rlen);       // Length of counter i, smaller or equal to 32
#ifdef DIAGNOSTICS
    KDF_LOGD("digest_len      : %d\n", digest_len);
    KDF_LOGD("h               : %d\n", h);
    KDF_LOGD("n               : %d\n", n);
    KDF_LOGD("r               : %d\n", r);
#endif
    if (!CHECK_KDF_PRF_BLOCK_LEN(digest_len)) {
        KDF_LOGE("Invalid PRF block length...\n");
        return rc;
    }

    // If n > 2^r-1, then indicate an error and stop.
    if (n > GET_MAX_ITER_CNT(rlen)) {
        KDF_LOGE("Invalid iteration count...\n");
        return rc;
    }

    input_data = K_i = result_i = NULL;

    if (IS_KBKDFVS(mode)) {
        /* Fixed Input Data : Label || Context */
        fixed_input_data_len = Label_len + Context_len;

        /*
         * Input Data(Before) : [i] || Label || Context
         * Input Data(Middle) : Label || [i] || Context
         * Input Data(After)  : Label || Context || [i]
         */
        input_data_len = rlen + fixed_input_data_len;
        input_data = (uint8_t *)malloc(input_data_len);
        if (input_data == NULL) {
            goto error;
        }
        memset(input_data, 0, input_data_len);

        switch(cloc) {
            case KBKDFVS_CTRLOC_BEFORE_FIXED:
                if (Label_len > 0) {
                    memcpy(input_data + rlen, Label, Label_len);
                }
                if (Context_len > 0) {
                    memcpy(input_data + rlen + Label_len, Context, Context_len);
                }
                break;
            case KBKDFVS_CTRLOC_MIDDLE_FIXED:
                if (Label_len > 0) {
                    memcpy(input_data, Label, Label_len);
                }
                if (Context_len > 0) {
                    memcpy(input_data + Label_len + rlen, Context, Context_len);
                }
                break;
            case KBKDFVS_CTRLOC_AFTER_FIXED:
                if (Label_len > 0) {
                    memcpy(input_data, Label, Label_len);
                }
                if (Context_len > 0) {
                    memcpy(input_data + Label_len, Context, Context_len);
                }
                break;
            default:
                goto error;
        }
    } else {
        /* Fixed Input Data : Label || 0x00 || Context || [L] */
        fixed_input_data_len = Label_len + 1 + Context_len + sizeof(L);

        /* Input Data : [i] || Label || 0x00 || Context || [L] */
        input_data_len = rlen + fixed_input_data_len;
        input_data = (uint8_t *)malloc(input_data_len);
        if (input_data == NULL) {
            goto error;
        }
        memset(input_data, 0, input_data_len);

        if (Label_len > 0) {
            memcpy(input_data + rlen, Label, Label_len);
        }
        if (Context_len > 0) {
            memcpy(input_data + rlen + Label_len + 1, Context, Context_len);
        }
        memcpy(input_data + rlen + Label_len + 1 + Context_len, &L, sizeof(L));
    }

    /* K(i) := PRF(Ki, input_data) */
    /* K(i)_len = h in bytes(=digest_len) */
    K_i_len = IN_BYTES(h);
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
    KDF_LOGD("fixed_data_len  : %zu\n", fixed_input_data_len);
    KDF_LOGD("input_data_len  : %zu\n", input_data_len);
    KDF_LOGD("K_i_len         : %zu\n", K_i_len);
    KDF_LOGD("result_i_len    : %zu\n", result_i_len);
#endif

    HMAC_CTX_init(&hctx);
    if (!HMAC_Init_ex(&hctx, Ki, Ki_len, digest, NULL)) {
        KDF_LOGE("Failed to initialize hmac context\n");
        goto error;
    }
    for (i = 0, i_ptr = result_i ; i <= n ; i++) {
        if (i == 0) {
            // memset(result_i, 0, result_i_len);
            continue;
        }
        HMAC_CTX_copy(&hctx_tpl, &hctx);

        if (IS_KBKDFVS(mode)) {
            rev_i = i;
            REVERSE_ENDIAN((uint8_t *)&rev_i, rlen);

            switch(cloc) {
                case KBKDFVS_CTRLOC_BEFORE_FIXED:
                    memcpy(input_data, &rev_i, rlen);
                    break;
                case KBKDFVS_CTRLOC_MIDDLE_FIXED:
                    memcpy(input_data+Label_len, &rev_i, rlen);
                    break;
                case KBKDFVS_CTRLOC_AFTER_FIXED:
                    memcpy(input_data+fixed_input_data_len, &rev_i, rlen);
                    break;
                default:
                    goto error;
            }
        } else {
            memcpy(input_data, &i, r);
        }
        if (!HMAC_Update(&hctx_tpl, input_data, input_data_len)) {
            KDF_LOGE("Failed to update message to hamc context\n");
            goto error;
        }
        if (!HMAC_Final(&hctx_tpl, K_i, &digest_len)) {
            KDF_LOGE("Failed to finalize hmac calculation\n");
            goto error;
        }
#ifdef DIAGNOSTICS
        KDF_LOGD("HMAC(%d) :: %d bytes digested\n", i, digest_len);
#endif
        memcpy(i_ptr, K_i, K_i_len); // K(i) len should be same with digest_len
        memset(K_i, 0, K_i_len);
        i_ptr += K_i_len;

        HMAC_CTX_cleanup(&hctx_tpl);
    }

    Ko_len = CALC_KO_LEN(L); // Length of final output
#ifdef DIAGNOSTICS
    KDF_LOGD("Ko_len          : %zu\n", Ko_len);
#endif
    memcpy(Ko, result_i, Ko_len);
    rc = OPENSSL_SUCCESS;
    goto end;

error:
    rc = OPENSSL_FAILURE;
    // TODO : Handle opeenssl error just happened
    HMAC_CTX_cleanup(&hctx_tpl);
end:
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
