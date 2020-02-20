package com.truman.android.kca;

import com.truman.android.kca.internal.SHA256;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;

public final class NativeCrypto {

    private static int KCA_SUCCESS = 1;
    private static int KCA_FAILURE = 0;

    public static byte[] DEFAULT_KEY = "This is my 32 bytes master key!!".getBytes();
    public static byte[] DEFAULT_IV = "Do RNG next time".getBytes();

    public static byte[] SHA256(byte[] ...messages) {
        if (messages == null) {
            return null;
        }

        SHA256 sha256 = new SHA256();
        sha256.init();
        for (byte[] message : messages) {
            if (message == null || message.length == 0
                    || sha256.update(message, 0, message.length) != KCA_SUCCESS) {
                return null;
            }
        }

        byte[] out = new byte[SHA256.SHA256_DIGEST_LENGTH];
        if (sha256.doFinal(out) != KCA_SUCCESS) {
            return null;
        }
        return out;
    }

    /**
     * Temporary function - It's not from KCM
     */
    public static byte[] encrypt(byte[] pt, byte[] key, byte[] iv) {
        return streamCipher(pt, key);
    }

    /**
     * Temporary function - It's not from KCM
     */
    public static byte[] decrypt(byte[] ct, byte[] key, byte[] iv) {
        return streamCipher(ct, key);
    }

    /**
     * Temporary function - It's not from KCM
     */
    private static byte[] streamCipher(byte[] stream, byte[] key)
            throws IllegalArgumentException {
        if (stream == null || stream.length == 0
                || key == null || key.length == 0) {
            throw new IllegalArgumentException("Invalid parameter");
        }

        byte[] res = new byte[stream.length];
        if (stream.length > key.length) {
            for (int i = 0, kI = 0 ; i < stream.length ; i++, kI = i % key.length) {
                res[i] = (byte) (stream[i] ^ key[kI]);
            }
        } else {
            for (int i = 0 ; i < stream.length ; i++) {
                res[i] = (byte) (stream[i] ^ key[i]);
            }
        }
        return res;
    }

    /**
     * Temporary function - It's not from KCM
     */
    public static byte[] generateRandom(int length) {
        try {
            return SecureRandom.getInstance("SHA1PRNG").generateSeed(length);
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
            return new byte[length];
        }
    }
}
