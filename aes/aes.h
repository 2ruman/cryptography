/*
 * aes.h
 *
 *      Author  : Truman
 *      Contact : truman.t.kim@gmail.com
 *      Version : 0.1.0
 */

#ifndef AES_H_
#define AES_H_

#include <stddef.h>
#include <stdint.h>

#define DIAGNOSTICS

int aes_gcm_encrypt(uint8_t *plaintext, size_t plaintext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *ciphertext);

int aes_gcm_decrypt(uint8_t *ciphertext, size_t ciphertext_len,
                    uint8_t *key, size_t key_len,
                    uint8_t *iv,  size_t iv_len,
                    uint8_t *aad, size_t aad_len,
                    uint8_t *tag, size_t tag_len,
                    uint8_t *plaintext);

#endif /* AES_H_ */
