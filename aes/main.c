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
#include "aes.h"

#include <stdlib.h>
#include <string.h>

int main() {
    puts("===========================================================================================");
    puts("                              [ AES Functional Verification ]");
    puts("===========================================================================================");
    puts("");

    const char *msg = "@Hello, everyone~! Hope you enjoy~! Thank you~!@";
    int res;

    uint8_t *key = (uint8_t *)get_asc_32();
    size_t key_len = sizeof(asc_32_bytes);

    uint8_t *iv = (uint8_t *)get_asc_12();
    size_t iv_len = sizeof(asc_12_bytes);

    uint8_t *aad = (uint8_t *)get_asc_16();
    size_t aad_len = sizeof(asc_16_bytes);

    uint8_t *plaintext = (uint8_t *)msg;
    size_t plaintext_len = strlen(msg);

    uint8_t ciphertext[plaintext_len];
    size_t ciphertext_len = sizeof(ciphertext);

    uint8_t restored[plaintext_len];
    size_t restored_len = sizeof(restored);

    uint8_t tag[MAX_AUTH_TAG_SIZE] = { 0 };
    size_t tag_len = sizeof(tag);

    char str_buf[100] = { 0 };

    printf("Message    : %s (Length = %zu)\n", plaintext, plaintext_len);
    print_hex("Key       ", key, key_len);
    print_hex("IV        ", iv, iv_len);
    print_hex("AAD       ", aad, aad_len);

    res = aes_gcm_encrypt(plaintext, plaintext_len, key, key_len, iv, iv_len, aad, aad_len, tag, tag_len, ciphertext);
    printf("\nResult of AES-GCM encryption : %d\n",res);
    if (res < 0) {
        goto end;
    }
    print_hex("Plaintext ", plaintext, plaintext_len);
    print_hex("Ciphertext", ciphertext, ciphertext_len);
    print_hex("Auth Tag  ", tag, tag_len);

    res = aes_gcm_decrypt(ciphertext, ciphertext_len, key, key_len, iv, iv_len, aad, aad_len, tag, tag_len, restored);
    printf("\nResult of AES-GCM decryption : %d\n",res);
    if (res < 0) {
        goto end;
    }
    print_hex("Ciphertext", ciphertext, ciphertext_len);
    print_hex("Restored  ", restored, restored_len);
    memcpy(str_buf, restored, restored_len);
    printf("Message    : %s\n", str_buf);

end:
    return 0;
}
