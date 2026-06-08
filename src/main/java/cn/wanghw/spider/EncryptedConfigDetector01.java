package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.Main;
import cn.wanghw.utils.DecryptUtils;
import cn.wanghw.utils.DecryptUtils.DecryptResult;
import cn.wanghw.utils.HashMapUtils;

import java.util.*;
import java.util.regex.Pattern;

public class EncryptedConfigDetector01 implements ISpider {

    private static final Pattern ENC_PATTERN = Pattern.compile("ENC\\([^)]+\\)");
    private static final Pattern CIPHER_PATTERN = Pattern.compile("\\{cipher\\}.+");
    private static final Pattern VAULT_PATTERN = Pattern.compile("vault:.*");

    // config keys that typically hold encrypted values
    private static final String[] SENSITIVE_KEY_PATTERNS = {
            "password", "passwd", "pwd", "secret", "token", "credential",
            "accesskey", "secretkey", "apikey", "privatekey",
            "encrypt", "decrypt", "cipher"
    };

    // known encrypted framework classes
    private static final String[][] FRAMEWORK_CLASSES = {
            {"com.ulisesbocchi.jasypt.encryptor.StringEncryptor", "encrypt"},
            {"org.jasypt.encryption.StringEncryptor", "encrypt"},
            {"com.alibaba.druid.filter.config.ConfigFilter", "decryptKey"},
            {"org.springframework.security.crypto.encrypt.BytesEncryptor", "key"},
            {"org.springframework.security.crypto.encrypt.TextEncryptor", "key"},
    };

    public String getName() {
        return "EncryptedConfigDetector";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        String userKey = Main.getDecryptKey();
        String dictPath = Main.getDecryptDictPath();

        // Load dictionary if specified
        List<String> dictPasswords = new ArrayList<String>();
        if (dictPath != null && !dictPath.isEmpty()) {
            dictPasswords = DecryptUtils.loadDictFile(dictPath);
        }

        try {
            List<EncryptedItem> encryptedItems = new ArrayList<EncryptedItem>();

            // 1. scan Map entries for encrypted config values
            scanMapEntries(heapHolder, encryptedItems);

            // 2. scan known framework classes
            scanFrameworkClasses(heapHolder, encryptedItems);

            // 3. scan Properties objects
            scanProperties(heapHolder, encryptedItems);

            if (encryptedItems.isEmpty()) return null;

            // 4. categorize and output
            List<EncryptedItem> jasyptItems = new ArrayList<EncryptedItem>();
            List<EncryptedItem> cipherItems = new ArrayList<EncryptedItem>();
            List<EncryptedItem> base64Items = new ArrayList<EncryptedItem>();
            List<EncryptedItem> hexItems = new ArrayList<EncryptedItem>();
            List<EncryptedItem> otherItems = new ArrayList<EncryptedItem>();

            for (EncryptedItem item : encryptedItems) {
                if (item.format.contains("ENC")) {
                    jasyptItems.add(item);
                } else if (item.format.contains("{cipher}")) {
                    cipherItems.add(item);
                } else if (item.format.contains("Base64")) {
                    base64Items.add(item);
                } else if (item.format.contains("Hex")) {
                    hexItems.add(item);
                } else {
                    otherItems.add(item);
                }
            }

            // output by category
            if (!jasyptItems.isEmpty()) {
                result.append("[jasypt ENC]\r\n");
                for (EncryptedItem item : jasyptItems) {
                    result.append("  ").append(item.key).append(" = ").append(item.value).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!cipherItems.isEmpty()) {
                result.append("[Spring Cloud {cipher}]\r\n");
                for (EncryptedItem item : cipherItems) {
                    result.append("  ").append(item.key).append(" = ").append(item.value).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!base64Items.isEmpty()) {
                result.append("[Base64 Encoded]\r\n");
                for (EncryptedItem item : base64Items) {
                    result.append("  ").append(item.key).append(" = ").append(item.value).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!hexItems.isEmpty()) {
                result.append("[Hex Encoded]\r\n");
                for (EncryptedItem item : hexItems) {
                    result.append("  ").append(item.key).append(" = ").append(item.value).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!otherItems.isEmpty()) {
                result.append("[Other Encrypted]\r\n");
                for (EncryptedItem item : otherItems) {
                    result.append("  ").append(item.key).append(" = ").append(item.value).append("\r\n");
                }
                result.append("\r\n");
            }

            // 5. try to decrypt
            List<DecryptResult> decryptResults = new ArrayList<DecryptResult>();
            for (EncryptedItem item : encryptedItems) {
                DecryptResult dr = null;

                // Try user-specified key first
                if (userKey != null) {
                    dr = DecryptUtils.autoDecryptWithKey(item.value, userKey);
                }

                // Try dictionary file
                if (dr == null && !dictPasswords.isEmpty()) {
                    dr = tryDecryptWithDict(item.value, dictPasswords);
                }

                // Try built-in weak passwords
                if (dr == null) {
                    dr = DecryptUtils.autoDecrypt(item.value);
                }

                if (dr != null) {
                    decryptResults.add(dr);
                }
            }

            if (!decryptResults.isEmpty()) {
                result.append("[Decryption Results]\r\n");
                for (DecryptResult dr : decryptResults) {
                    result.append("  ").append(dr.toString()).append("\r\n");
                }
            }

        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }

    private void scanMapEntries(IHeapHolder heapHolder, List<EncryptedItem> items) {
        List<Object> mapEntryClasses = new ArrayList<Object>();
        for (Iterator it = heapHolder.getClasses(); it.hasNext(); ) {
            Object clazz = it.next();
            String clazzName = heapHolder.getClassName(clazz).toLowerCase();
            if (clazzName.contains("$")) {
                String innerName = clazzName.split("\\$")[1];
                if (innerName.endsWith("entry") || innerName.equals("node") || innerName.equals("treenode")) {
                    mapEntryClasses.add(clazz);
                }
            }
        }

        for (Object clazz : mapEntryClasses) {
            scanEntryClass(heapHolder, items, clazz);
            Object[] subClasses = heapHolder.getSubClasses(clazz);
            if (subClasses != null) {
                for (Object subClazz : subClasses) {
                    scanEntryClass(heapHolder, items, subClazz);
                }
            }
        }
    }

    private void scanEntryClass(IHeapHolder heapHolder, List<EncryptedItem> items, Object clazz) {
        for (Object instance : heapHolder.getInstances(clazz)) {
            try {
                String key = heapHolder.getFieldStringValue(instance, "key");
                if (key == null || !isSensitiveKey(key)) continue;

                String value = heapHolder.getFieldStringValue(instance, "value");
                if (value == null || value.isEmpty()) continue;

                String format = detectEncryptedFormat(value);
                if (format != null) {
                    items.add(new EncryptedItem(key, value, format));
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    private void scanFrameworkClasses(IHeapHolder heapHolder, List<EncryptedItem> items) {
        for (String[] classInfo : FRAMEWORK_CLASSES) {
            Object clazz = heapHolder.findClass(classInfo[0]);
            if (clazz == null) continue;

            for (Object instance : heapHolder.getInstances(clazz)) {
                try {
                    HashMap<String, String> values = new HashMap<String, String>();
                    values.put("class", classInfo[0]);

                    String keyVal = heapHolder.getFieldStringValue(instance, classInfo[1]);
                    if (keyVal != null && !keyVal.isEmpty()) {
                        values.put(classInfo[1], keyVal);
                    }

                    // try to get algorithm
                    String alg = heapHolder.getFieldStringValue(instance, "algorithm");
                    if (alg == null) alg = heapHolder.getFieldStringValue(instance, "algorithmName");
                    if (alg != null) values.put("algorithm", alg);

                    if (values.size() > 1) {
                        items.add(new EncryptedItem(classInfo[0], values.toString(), "Framework"));
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    private void scanProperties(IHeapHolder heapHolder, List<EncryptedItem> items) {
        Object propsClass = heapHolder.findClass("java.util.Properties");
        if (propsClass == null) return;

        for (Object instance : heapHolder.getInstances(propsClass)) {
            try {
                if (!heapHolder.isMap(instance)) continue;
                HashMap<String, String> props = heapHolder.arrayDump(heapHolder.getMap(instance));
                if (props == null) continue;

                for (Map.Entry<String, String> entry : props.entrySet()) {
                    String key = entry.getKey();
                    if (key == null || !isSensitiveKey(key)) continue;

                    String value = entry.getValue();
                    if (value == null || value.isEmpty()) continue;

                    String format = detectEncryptedFormat(value);
                    if (format != null) {
                        items.add(new EncryptedItem(key, value, format));
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    private boolean isSensitiveKey(String key) {
        String lower = key.toLowerCase();
        for (String pattern : SENSITIVE_KEY_PATTERNS) {
            if (lower.contains(pattern)) return true;
        }
        return false;
    }

    private DecryptResult tryDecryptWithDict(String value, List<String> dictPasswords) {
        // Extract ENC value if needed
        String encValue = DecryptUtils.extractEncValue(value);
        if (encValue == null) encValue = value;

        // Try each password in dictionary
        for (String pwd : dictPasswords) {
            // Try jasypt decrypt
            String decrypted = DecryptUtils.tryJasyptDecrypt(encValue, pwd);
            if (decrypted != null) {
                return new DecryptResult(value, decrypted, "jasypt(dict)", pwd);
            }
        }

        // Try base64 decode
        if (DecryptUtils.isBase64Format(value)) {
            String decoded = DecryptUtils.tryBase64Decode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Base64", null);
            }
        }

        // Try hex decode
        if (DecryptUtils.isHexFormat(value)) {
            String decoded = DecryptUtils.tryHexDecode(value);
            if (decoded != null) {
                return new DecryptResult(value, decoded, "Hex", null);
            }
        }

        return null;
    }

    private String detectEncryptedFormat(String value) {
        if (value == null || value.isEmpty()) return null;

        // jasypt ENC()
        if (ENC_PATTERN.matcher(value).find()) return "ENC(jasypt)";

        // Spring Cloud {cipher}
        if (CIPHER_PATTERN.matcher(value).find()) return "{cipher}";

        // vault reference
        if (VAULT_PATTERN.matcher(value).find()) return "vault";

        // Base64 (long enough and looks like base64)
        if (value.length() >= 16 && DecryptUtils.isBase64Format(value)) {
            // check if it's likely encrypted (not just a regular base64 string)
            if (value.length() >= 24) return "Base64(encrypted)";
        }

        // Hex (long enough and looks like hex)
        if (value.length() >= 32 && DecryptUtils.isHexFormat(value)) {
            return "Hex(encrypted)";
        }

        return null;
    }

    private static class EncryptedItem {
        final String key;
        final String value;
        final String format;

        EncryptedItem(String key, String value, String format) {
            this.key = key;
            this.value = value;
            this.format = format;
        }
    }
}
