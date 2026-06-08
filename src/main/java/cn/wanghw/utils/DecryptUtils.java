package cn.wanghw.utils;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.*;
import java.util.regex.Pattern;

public class DecryptUtils {

    private static final String[] WEAK_PASSWORDS = {
            "", "123456", "password", "admin", "root", "secret", "jasypt",
            "encrypt", "default", "test", "abc123", "key", "passw0rd",
            "P@ssw0rd", "qwerty", "12345678", "111111", "1234",
            "password123", "admin123", "root123", "test123"
    };

    private static final Pattern ENC_PATTERN = Pattern.compile("^ENC\\((.+?)\\)$");
    private static final Pattern CIPHER_PATTERN = Pattern.compile("^\\{cipher\\}(.+)$");
    private static final Pattern BASE64_PATTERN = Pattern.compile("^[A-Za-z0-9+/=]{16,}$");
    private static final Pattern HEX_PATTERN = Pattern.compile("^[0-9a-fA-F]{16,}$");

    public static String[] getWeakPasswords() {
        return WEAK_PASSWORDS;
    }

    // ============ 格式判断 ============

    public static boolean isJasyptFormat(String value) {
        return value != null && ENC_PATTERN.matcher(value.trim()).matches();
    }

    public static boolean isCipherPrefixFormat(String value) {
        return value != null && CIPHER_PATTERN.matcher(value.trim()).matches();
    }

    public static boolean isBase64Format(String value) {
        return value != null && BASE64_PATTERN.matcher(value.trim()).matches();
    }

    public static boolean isHexFormat(String value) {
        return value != null && HEX_PATTERN.matcher(value.trim()).matches();
    }

    public static String extractEncValue(String value) {
        if (value == null) return null;
        java.util.regex.Matcher m = ENC_PATTERN.matcher(value.trim());
        if (m.matches()) return m.group(1);
        m = CIPHER_PATTERN.matcher(value.trim());
        if (m.matches()) return m.group(1);
        return null;
    }

    // ============ Base64 解码 ============

    public static String tryBase64Decode(String encoded) {
        try {
            byte[] decoded = Base64.decode(encoded.trim());
            if (decoded == null) return null;
            String result = new String(decoded, StandardCharsets.UTF_8);
            if (isPrintable(result)) {
                return result;
            }
        } catch (Exception e) {
            // not valid base64
        }
        return null;
    }

    // ============ Hex 解码 ============

    public static String tryHexDecode(String hex) {
        try {
            hex = hex.trim();
            if (hex.length() % 2 != 0) return null;
            byte[] bytes = hexToBytes(hex);
            String result = new String(bytes, StandardCharsets.UTF_8);
            if (isPrintable(result)) {
                return result;
            }
        } catch (Exception e) {
            // not valid hex
        }
        return null;
    }

    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    // ============ jasypt 解密 (PBEWithMD5AndDES) ============

    public static String tryJasyptDecrypt(String encrypted, String password) {
        try {
            byte[] salt = "0123456789abcdef".getBytes(StandardCharsets.UTF_8);
            return jasyptDecrypt(encrypted, password, salt, "PBEWithMD5AndDES", 1000);
        } catch (Exception e) {
            return null;
        }
    }

    public static String tryJasyptDecryptWithSalt(String encrypted, String password, byte[] salt) {
        try {
            return jasyptDecrypt(encrypted, password, salt, "PBEWithMD5AndDES", 1000);
        } catch (Exception e) {
            return null;
        }
    }

    private static String jasyptDecrypt(String encrypted, String password, byte[] salt, String algorithm, int iterations) throws Exception {
        PBEKeySpec keySpec = new PBEKeySpec(password.toCharArray());
        SecretKeyFactory factory = SecretKeyFactory.getInstance(algorithm);
        SecretKey key = factory.generateSecret(keySpec);
        IvParameterSpec ivSpec = new IvParameterSpec(salt);

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, ivSpec);

        byte[] decoded = Base64.decode(encrypted);
        if (decoded == null) return null;
        byte[] decrypted = cipher.doFinal(decoded);
        String result = new String(decrypted, StandardCharsets.UTF_8);
        if (isPrintable(result)) {
            return result;
        }
        return null;
    }

    // ============ druid ConfigTools 解密 ============

    public static String tryDruidDecrypt(String encrypted, String publicKey) {
        try {
            return druidDecrypt(encrypted, publicKey);
        } catch (Exception e) {
            return null;
        }
    }

    private static String druidDecrypt(String encrypted, String publicKey) throws Exception {
        // druid ConfigTools uses RSA/ECB/PKCS1Padding
        byte[] encryptedBytes = Base64.decode(encrypted);
        if (encryptedBytes == null) return null;

        // construct public key from base64
        byte[] keyBytes = Base64.decode(publicKey);
        if (keyBytes == null) return null;
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(spec);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decrypted = cipher.doFinal(encryptedBytes);
        return new String(decrypted, StandardCharsets.UTF_8);
    }

    // ============ 自动尝试解密 ============

    public static DecryptResult autoDecrypt(String value) {
        if (value == null || value.isEmpty()) return null;

        // 1. try Base64
        if (isBase64Format(value)) {
            String decoded = tryBase64Decode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Base64", null);
            }
        }

        // 2. try Hex
        if (isHexFormat(value)) {
            String decoded = tryHexDecode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Hex", null);
            }
        }

        // 3. try jasypt ENC() or {cipher}
        String encValue = extractEncValue(value);
        if (encValue != null) {
            return tryJasyptWithDictionary(encValue);
        }

        return null;
    }

    public static DecryptResult autoDecryptWithKey(String value, String key) {
        if (value == null || value.isEmpty()) return null;

        // 1. try Base64
        if (isBase64Format(value)) {
            String decoded = tryBase64Decode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Base64", null);
            }
        }

        // 2. try Hex
        if (isHexFormat(value)) {
            String decoded = tryHexDecode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Hex", null);
            }
        }

        // 3. try jasypt with user key
        String encValue = extractEncValue(value);
        if (encValue != null && key != null) {
            String decrypted = tryJasyptDecrypt(encValue, key);
            if (decrypted != null) {
                return new DecryptResult(value, decrypted, "jasypt", key);
            }
        }

        // 4. try jasypt with dictionary
        if (encValue != null) {
            return tryJasyptWithDictionary(encValue);
        }

        return null;
    }

    private static DecryptResult tryJasyptWithDictionary(String encValue) {
        // try with jasypt default salt first
        for (String pwd : WEAK_PASSWORDS) {
            String decrypted = tryJasyptDecrypt(encValue, pwd);
            if (decrypted != null) {
                return new DecryptResult("ENC(" + encValue + ")", decrypted, "jasypt", pwd.isEmpty() ? "(empty)" : pwd);
            }
        }
        // try with different salt (some jasypt versions use different default salt)
        try {
            byte[] altSalt = "0123456789ABCDEF".getBytes(StandardCharsets.UTF_8);
            for (String pwd : WEAK_PASSWORDS) {
                String decrypted = tryJasyptDecryptWithSalt(encValue, pwd, altSalt);
                if (decrypted != null) {
                    return new DecryptResult("ENC(" + encValue + ")", decrypted, "jasypt(salt-alt)", pwd.isEmpty() ? "(empty)" : pwd);
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    // ============ 工具方法 ============

    private static boolean isPrintable(String s) {
        if (s == null || s.isEmpty()) return false;
        int printable = 0;
        for (char c : s.toCharArray()) {
            if (c >= 0x20 && c <= 0x7E) {
                printable++;
            } else if (c == '\n' || c == '\r' || c == '\t') {
                printable++;
            }
        }
        // at least 80% printable characters
        return (double) printable / s.length() >= 0.8;
    }

    // ============ 解密结果 ============

    public static class DecryptResult {
        private final String ciphertext;
        private final String plaintext;
        private final String method;
        private final String key;

        public DecryptResult(String ciphertext, String plaintext, String method, String key) {
            this.ciphertext = ciphertext;
            this.plaintext = plaintext;
            this.method = method;
            this.key = key;
        }

        public String getCiphertext() { return ciphertext; }
        public String getPlaintext() { return plaintext; }
        public String getMethod() { return method; }
        public String getKey() { return key; }

        @Override
        public String toString() {
            if (key != null) {
                return ciphertext + " -> " + plaintext + " (" + method + ", key: " + key + ")";
            }
            return ciphertext + " -> " + plaintext + " (" + method + ")";
        }
    }
}
