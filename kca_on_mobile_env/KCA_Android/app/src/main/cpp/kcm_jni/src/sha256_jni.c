#include <stdlib.h>
#include <string.h>
#include <jni.h>

#include "sha256.h"

KISA_SHA256 sha256;

JNIEXPORT jint JNICALL
Java_com_truman_android_kca_internal_NativeCryptoJNI_sha256Update(JNIEnv* env, jclass thiz, jlongArray l1, jintArray l2, jintArray data,
                                                jbyteArray buf, jbyteArray inputText, jint inputOffset, jint inputTextLen)
{
    unsigned char *pInputText = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, inputText, 0);
    pInputText += inputOffset;

    uint64_t *pl1Array = (uint64_t *)(*env)->GetPrimitiveArrayCritical(env, l1, 0);
    unsigned int *pl2Array = (unsigned int *)(*env)->GetPrimitiveArrayCritical(env, l2, 0);

    sha256.l1 = pl1Array[0];
    sha256.l2 = pl2Array[0];

    unsigned long *tmp_data = (unsigned long *)(*env)->GetPrimitiveArrayCritical(env, data, 0);
    memcpy(sha256.data, tmp_data, sizeof(unsigned long) * 8);

    unsigned char *tmp_buf = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, buf, 0);
    memcpy(sha256.buf, tmp_buf, SHA256_BLOCK_SIZE);

    int result = KISA_SHA256_update(&sha256, pInputText, inputTextLen);

    pl1Array[0] = sha256.l1;
    pl2Array[0] = sha256.l2;

    memcpy(tmp_data, sha256.data, sizeof(unsigned long) * 8);
    memcpy(tmp_buf, sha256.buf, SHA256_BLOCK_SIZE);

    (*env)->ReleasePrimitiveArrayCritical(env, inputText, pInputText, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, l1, pl1Array, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, l2, pl2Array, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, data, (jint *)tmp_data, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, buf, tmp_buf, 0);

    return result;
}

JNIEXPORT jint JNICALL
Java_com_truman_android_kca_internal_NativeCryptoJNI_sha256Final(JNIEnv* env, jclass thiz, jlongArray l1, jintArray l2, jintArray data,
                                               jbyteArray buf, jbyteArray outputText)
{
    unsigned char *pOutputText = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, outputText, 0);

    uint64_t *pl1Array = (uint64_t *)(*env)->GetPrimitiveArrayCritical(env, l1, 0);
    unsigned int *pl2Array = (unsigned int *)(*env)->GetPrimitiveArrayCritical(env, l2, 0);

    sha256.l1 = pl1Array[0];
    sha256.l2 = pl2Array[0];

    unsigned long *tmp_data = (unsigned long *)(*env)->GetPrimitiveArrayCritical(env, data, 0);
    memcpy(sha256.data, tmp_data, sizeof(unsigned long) * 8);

    unsigned char *tmp_buf = (unsigned char *)(*env)->GetPrimitiveArrayCritical(env, buf, 0);
    memcpy(sha256.buf, tmp_buf, SHA256_BLOCK_SIZE);

    int result = KISA_SHA256_final(&sha256, pOutputText);

    (*env)->ReleasePrimitiveArrayCritical(env, outputText, pOutputText, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, l1, pl1Array, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, l2, pl2Array, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, data, (jint *)tmp_data, 0);
    (*env)->ReleasePrimitiveArrayCritical(env, buf, tmp_buf, 0);

    return result;
}