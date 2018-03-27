/*
 * kdf_nist.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.2.0
 */

#ifndef KDF_NIST_H_
#define KDF_NIST_H_

#include <stddef.h>
#include <stdint.h>

#include <openssl/evp.h>
/*
 * [ KDF Utilities ]
 *
 */
#ifndef CRYPTO_UTIL_H_
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

#define SET_XYZW(x,y,z,w) ((x) | ((y) << 0x08) | ((z) << 0x10) | ((w) << 0x18))
#define GET_X(xyzw)       (((xyzw) >> 0x00) & 0xFF)
#define GET_Y(xyzw)       (((xyzw) >> 0x08) & 0xFF)
#define GET_Z(xyzw)       (((xyzw) >> 0x10) & 0xFF)
#define GET_W(xyzw)       (((xyzw) >> 0x18) & 0xFF)
#endif

#ifdef __ANDROID__
# define KDF_LOGD(...)
# define KDF_LOGE(...)
#else
# define KDF_LOGD(...) fprintf(stdout, __VA_ARGS__)
# define KDF_LOGE(...) fprintf(stderr, __VA_ARGS__)
#endif

#define CALC_KO_LEN(L) IN_BYTES(ROUND_UP8((L)))

#define UINT24_MAX              16777215

/*
 * [ KDF Configuration ]
 *
 *    Field Format:
 *        | EXT | PRF | RLEN | MODE |
 *    Field Size:
 *        |  1  |  1  |  1  |  1  |
 *
 *    In KBKDFVS(Key-based KDF Validation System) mode,
 *        the extension field should represent counter location.
 */
#define SET_CFG(m,r,p,e)   SET_XYZW(m,r,p,e)
#define GET_CFG_MODE(c)    GET_X(c)
#define GET_CFG_RLEN(c)    GET_Y(c)
#define GET_CFG_PRF(c)     GET_Z(c)
#define GET_CFG_EXT(c)     GET_W(c)
#define GET_CFG_CTRLOC(c)  GET_EXT(c)

#define KDF_NONE           0

#define KDF_MODE_USER      0
#define KDF_MODE_KBKDFVS   1
#define MIN_KDF_MODE       KDF_MODE_USER
#define MAX_KDF_MODE       KDF_MODE_KBKDFVS
#define DEFAULT_KDF_MODE   KDF_MODE_USER
#define CHECK_KDF_MODE(m)  (((m) >= MIN_KDF_MODE && (m) <= MAX_KDF_MODE) \
                               ? TRUE : FALSE)
#define IS_KBKDFVS(c)      (GET_CFG_MODE(c) == KDF_MODE_KBKDFVS)

#define KDF_RLEN_08        1
#define KDF_RLEN_16        2
#define KDF_RLEN_24        3
#define KDF_RLEN_32        4
#define MIN_KDF_RLEN       KDF_RLEN_08
#define MAX_KDF_RLEN       KDF_RLEN_32
#define DEFAULT_KDF_RLEN   KDF_RLEN_32
#define CHECK_KDF_RLEN(l)  (((l) >= MIN_KDF_RLEN && (l) <= MAX_KDF_RLEN) \
                               ? TRUE : FALSE)

#define KDF_PRF_HMAC_SHA1              1
#define KDF_PRF_HMAC_SHA224            2
#define KDF_PRF_HMAC_SHA256            3
#define KDF_PRF_HMAC_SHA384            4
#define KDF_PRF_HMAC_SHA512            5
#define MIN_KDF_PRF                    KDF_PRF_HMAC_SHA1
#define MAX_KDF_PRF                    KDF_PRF_HMAC_SHA512
#define DEFAULT_KDF_PRF                KDF_PRF_HMAC_SHA512
#define CHECK_KDF_PRF(p)               (((p) >= MIN_KDF_PRF && \
                                           (p) <= MAX_KDF_PRF) \
                                               ? TRUE : FALSE)

#define KDF_PRF_BLOCK_LEN_HMAC_SHA1    160
#define KDF_PRF_BLOCK_LEN_HMAC_SHA224  224
#define KDF_PRF_BLOCK_LEN_HMAC_SHA256  256
#define KDF_PRF_BLOCK_LEN_HMAC_SHA384  384
#define KDF_PRF_BLOCK_LEN_HMAC_SHA512  512
#define MIN_PRF_BLOCK_LEN_BITS         KDF_PRF_BLOCK_LEN_HMAC_SHA1
#define MAX_PRF_BLOCK_LEN_BITS         KDF_PRF_BLOCK_LEN_HMAC_SHA512
#define MIN_PRF_BLOCK_LEN              IN_BYTES(MIN_PRF_BLOCK_LEN_BITS)
#define MAX_PRF_BLOCK_LEN              IN_BYTES(MAX_PRF_BLOCK_LEN_BITS)
#define CHECK_KDF_PRF_BLOCK_LEN(l)     (((l) >= MIN_PRF_BLOCK_LEN && \
                                           (l) <= MAX_PRF_BLOCK_LEN) \
                                               ? TRUE : FALSE)

#define KBKDFVS_CTRLOC_BEFORE_FIXED    1
#define KBKDFVS_CTRLOC_MIDDLE_FIXED    2
#define KBKDFVS_CTRLOC_AFTER_FIXED     3
#define MIN_KBKDFVS_CTRLOC             KBKDFVS_CTRLOC_BEFORE_FIXED
#define MAX_KBKDFVS_CTRLOC             KBKDFVS_CTRLOC_AFTER_FIXED
#define CHECK_KBKDFVS_CTRLOC(c)        (((c) >= MIN_KBKDFVS_CTRLOC && \
                                           (c) <= MAX_KBKDFVS_CTRLOC) \
                                               ? TRUE : FALSE)

#define DIAGNOSTICS

int KDF_CTR_HMAC(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len,
                        uint32_t cfg);

int KDF_CTR_HMAC_SHA256(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len);

int KDF_CTR_HMAC_SHA512(uint8_t *Ko, size_t L,
                        uint8_t *Ki, size_t Ki_len,
                        uint8_t *Label, size_t Label_len,
                        uint8_t *Context, size_t Context_len);

static __inline__ const EVP_MD *GET_PRF(int prf) {
    switch(prf) {
        case KDF_PRF_HMAC_SHA1:
            return EVP_sha1();
        case KDF_PRF_HMAC_SHA224:
            return EVP_sha224();
        case KDF_PRF_HMAC_SHA256:
            return EVP_sha256();
        case KDF_PRF_HMAC_SHA384:
            return EVP_sha384();
        case KDF_PRF_HMAC_SHA512:
        default:
            return EVP_sha512();
    }
}

static __inline__  uint32_t GET_MAX_ITER_CNT(int rlen) {
    switch(rlen) {
        case KDF_RLEN_08:
            return UINT8_MAX;
        case KDF_RLEN_16:
            return UINT16_MAX;
        case KDF_RLEN_24:
            return UINT24_MAX;
        case KDF_RLEN_32:
            return UINT32_MAX;
        default:
            return 0;
    }
}

static __inline__ void REVERSE_ENDIAN(uint8_t *bytes, size_t bytes_len) {
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

#endif /* KDF_NIST_H_ */
