package com.truman.android.kca.internal;

public class SHA256 {

    public static final int SHA256_BLOCK_SIZE = 64;
    public static final int SHA256_BLOCK_SIZEx8 = 512;
    public static final int SHA256_DIGEST_LENGTH = 32;

    private long l1;
    private int l2;
    private int[] data;
    private byte[] buf;

    public SHA256() {
        this.data = new int[8];
        this.buf = new byte[SHA256_BLOCK_SIZE];
    }

    public void init() {
        this.l1 = 0;
        this.l2 = 0;
        this.data[0] = 0x6A09E667;
        this.data[1] = 0xBB67AE85;
        this.data[2] = 0x3C6EF372;
        this.data[3] = 0xA54FF53A;
        this.data[4] = 0x510E527F;
        this.data[5] = 0x9B05688C;
        this.data[6] = 0x1F83D9AB;
        this.data[7] = 0x5BE0CD19;
    }

    public int update(byte[] inputText, int inputOffset, int inputTextLen) {
        if (inputText == null) {
            return 0;
        }

        if (inputTextLen < 0) {
            return 0;
        }

        long[] l1Array = { this.l1 };
        int[] l2Array = { this.l2 };

        int result = NativeCryptoJNI.sha256Update(l1Array, l2Array, this.data, this.buf, inputText, inputOffset, inputTextLen);

        this.l1 = l1Array[0];
        this.l2 = l2Array[0];

        l1Array = null;
        l2Array = null;

        return result;
    }

    public int doFinal(byte[] outputText) {
        if (outputText == null) {
            return 0;
        }

        long[] l1Array = { this.l1 };
        int[] l2Array = { this.l2 };

        int result = NativeCryptoJNI.sha256Final(l1Array, l2Array, this.data, this.buf, outputText);

        l1Array = null;
        l2Array = null;

        return result;
    }

    public int MD(byte[] inputText, int inputOffset, int inputTextLen, byte[] outputText) {
        this.init();

        if (this.update(inputText, inputOffset, inputTextLen) == 0) {
            return 0;
        }

        if (this.doFinal(outputText) == 0) {
            return 0;
        }

        return SHA256_DIGEST_LENGTH;
    }

    public int getDigestSize() {
        return SHA256_DIGEST_LENGTH;
    }
}