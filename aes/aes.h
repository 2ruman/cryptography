/*
 * aes.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.2
 */

#ifndef AES_H_
#define AES_H_

#include <stddef.h>
#include <stdint.h>

#include <openssl/err.h>

#define AES_API
#define AES_PRIVATE static
#define AES_BLOCK_SIZE 16

#define MAX_AUTH_TAG_SIZE 16

AES_API int aes_gcm_encrypt(uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *ciphertext);

AES_API int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext);

#ifndef IS_FAILED
# define IS_FAILED(x) if (1 != (x))
#endif

#define DIAGNOSTICS
#define SET_TXT_RED  "\x1b[31m"
#define SET_NO_COLOR "\x1b[0m"
#define ERROR(m) handle_errors(m, __FILE__, __LINE__);

AES_PRIVATE __inline__ void handle_errors(const char *err_msg, char *file, int line) {
#ifdef DIAGNOSTICS
    printf(SET_TXT_RED "ERROR(%s, %d) :: %s\n" SET_NO_COLOR, file, line, err_msg);
#else
    ERR_print_errors_fp(stderr);
    abort();
#endif
}

#endif /* AES_H_ */
