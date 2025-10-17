package com.trackwize.cloud.authentication.util;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

public final class EncryptUtil {

    private static final String HEX_CHARS = "0123456789ABCDEF";
    private static final String ALPHABET = "abcdefghijklmnopqrstuvwxyz";
    private static final SecureRandom RANDOM = new SecureRandom();

    private EncryptUtil() {
        throw new UnsupportedOperationException("This is a utility class and cannot be instantiated");
    }

    // Convert hex string ("0A1F35") -> byte[]
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] data = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            data[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return data;
    }

    // Convert byte[] -> hex string ("0A1F35")
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder(bytes.length * 2);
        for (byte b : bytes) {
            sb.append(HEX_CHARS.charAt((b >> 4) & 0x0F))
                    .append(HEX_CHARS.charAt(b & 0x0F));
        }
        return sb.toString();
    }

    // XOR operation between two byte arrays
    private static byte[] xor(byte[] a, byte[] b) {
        byte[] result = new byte[a.length];
        for (int i = 0; i < a.length; i++) {
            byte b2 = (i < b.length) ? b[i] : 0;
            result[i] = (byte) (a[i] ^ b2);
        }
        return result;
    }

    // Encrypt plain text with key
    public static String encrypt(String plainText, String key) {
        byte[] textBytes = plainText.getBytes(StandardCharsets.UTF_8);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] encrypted = xor(textBytes, keyBytes);
        return bytesToHex(encrypted);
    }

    // Decrypt hex text with key
    public static String decrypt(String hexCipher, String key) {
        byte[] cipherBytes = hexToBytes(hexCipher);
        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
        byte[] decrypted = xor(cipherBytes, keyBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // Generate random lowercase string
    public static String generateRandomKey(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(ALPHABET.charAt(RANDOM.nextInt(ALPHABET.length())));
        }
        return sb.toString();
    }
}
