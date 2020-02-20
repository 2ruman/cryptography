package com.truman.android.kca;

public class BytesUtil {
    private static final String DEFAULT_HEX_PREFIX = ""; // Alternative, "0x";
    private static final String DEFAULT_HEX_DELIMITER = ""; // Alternative, " ";
    private static final HexCase DEFAULT_HEX_CASE = HexCase.UPPER_CASE;

    public enum HexCase {
        UPPER_CASE, LOWER_CASE
    }

    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, DEFAULT_HEX_PREFIX, DEFAULT_HEX_DELIMITER, DEFAULT_HEX_CASE);
    }

    public static String bytesToHex(byte[] bytes, String prefix, String delimiter,
                                    HexCase hexCase) {
        String ret = "";
        if (bytes == null) {
            ret = "null";
        } else {
            final String hex = (hexCase == HexCase.UPPER_CASE)
                    ? "0123456789ABCDEF" : "0123456789abcdef";
            final boolean hasDel = (delimiter != null && !delimiter.isEmpty());
            final boolean hasPrf = (prefix != null && !prefix.isEmpty());

            StringBuilder sb = new StringBuilder();
            for(byte b : bytes) {
                if (hasPrf) {
                    sb.append(prefix);
                }
                sb.append(hex.charAt((b >>> 4) & 0xF));
                sb.append(hex.charAt(b & 0xF));
                if (hasDel) {
                    sb.append(delimiter);
                }
            }
            if (sb.length() > 0 && hasDel) {
                sb.deleteCharAt(sb.length() -1);
            }
            ret = sb.toString();
        }
        return ret;
    }

    public static byte[] hexToBytes(String hex) throws IllegalArgumentException {
        return hexToBytes(hex, DEFAULT_HEX_PREFIX, DEFAULT_HEX_DELIMITER);
    }

    public static byte[] hexToBytes(String hex, String prefix, String delimiter)
            throws IllegalArgumentException {
        if (hex == null) return null;
        if (hex.isEmpty()) return new byte[0];

        int prfLen = (prefix == null || prefix.isEmpty()) ? 0 : prefix.length();
        int delLen = (delimiter == null || delimiter.isEmpty()) ? 0 : delimiter.length();
        int hexLen = hex.length();

        if ((hexLen + delLen) % (prfLen + delLen + 2) != 0) {
            throw new IllegalArgumentException("Invalid hex length");
        }

        int resIdx = 0;
        int resLen = (hexLen + delLen) / (prfLen + delLen + 2);
        byte[] res = new byte[resLen];
        int i = 0;
        while(i < hexLen) {
            i += prfLen;
            res[resIdx++] = (byte) (charToDigit(hex.charAt(i)) << 4 | charToDigit(hex.charAt(i + 1)));
            i += 2;
            i += delLen;
        }
        return res;
    }

    private static int charToDigit(char c) {
        if ('0' <= c && c <= '9') {
            return c - '0';
        } else if ('a' <= c && c <= 'f') {
            return 10 + (c - 'a');
        } else if ('A' <= c && c <= 'F') {
            return 10 + (c - 'A');
        }

        throw new IllegalArgumentException("Invalid hex char");
    }
}
