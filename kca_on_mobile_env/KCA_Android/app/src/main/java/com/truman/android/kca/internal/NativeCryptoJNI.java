package com.truman.android.kca.internal;

public final class NativeCryptoJNI {
    static {
        System.loadLibrary("kcm-jni");
    }

    // SHA256 {
    static native int sha256Update(long[] l1, int[] l2, int[] data, byte[] buf,
                                    byte[] inputText, int inputOffset, int inputTextLen);

    static native int sha256Final(long[] l1, int[] l2, int[] data, byte[] buf, byte[] outputText);
    // } SHA256
}
