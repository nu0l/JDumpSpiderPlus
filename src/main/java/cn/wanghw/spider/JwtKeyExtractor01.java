package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class JwtKeyExtractor01 implements ISpider {

    private static final Pattern JWT_PATTERN = Pattern.compile(
            "(eyJ[A-Za-z0-9_-]{10,}\\.[A-Za-z0-9._-]{10,})");

    private static final Pattern PRIVATE_KEY_PATTERN = Pattern.compile(
            "-----BEGIN (RSA )?PRIVATE KEY-----");

    // known JWT-related classes and their key fields
    private static final String[][] JWT_CLASSES = {
            {"io.jsonwebtoken.impl.DefaultJwtBuilder", "key"},
            {"io.jsonwebtoken.impl.DefaultJwtParser", "signingKey"},
            {"org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter", "signingKey"},
            {"org.springframework.security.oauth2.provider.token.store.JwtAccessTokenConverter", "verifierKey"},
            {"org.springframework.security.oauth2.jwt.JwtEncoder", "jwsKey"},
            {"com.auth0.jwt.algorithms.Algorithm", "secret"},
            {"io.jsonwebtoken.impl.DefaultJwtBuilder", "keyBytes"},
    };

    public String getName() {
        return "JwtKeyExtractor";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        try {
            // 1. extract from known classes
            boolean foundKnownClass = false;
            for (String[] classInfo : JWT_CLASSES) {
                Object clazz = heapHolder.findClass(classInfo[0]);
                if (clazz == null) continue;

                for (Object instance : heapHolder.getInstances(clazz)) {
                    HashMap<String, String> values = new HashMap<String, String>();
                    values.put("class", classInfo[0]);
                    try {
                        String keyValue = heapHolder.getFieldStringValue(instance, classInfo[1]);
                        if (keyValue != null && !keyValue.isEmpty()) {
                            values.put(classInfo[1], keyValue);
                        }
                    } catch (Exception e) {
                        // field not found
                    }
                    // try to get algorithm field
                    try {
                        String alg = heapHolder.getFieldStringValue(instance, "algorithm");
                        if (alg == null) alg = heapHolder.getFieldStringValue(instance, "algName");
                        if (alg != null && !alg.isEmpty()) {
                            values.put("algorithm", alg);
                        }
                    } catch (Exception e) {
                        // ignore
                    }

                    if (values.size() > 1) {
                        result.append(HashMapUtils.dumpString(values, false));
                        foundKnownClass = true;
                    }
                }
            }

            // 2. scan all strings for JWT tokens
            LinkedHashSet<String> jwtTokens = new LinkedHashSet<String>();
            LinkedHashSet<String> privateKeys = new LinkedHashSet<String>();

            Object stringClass = heapHolder.findClass("java.lang.String");
            if (stringClass != null) {
                int count = 0;
                for (Object instance : heapHolder.getInstances(stringClass)) {
                    String text = heapHolder.toString(instance);
                    if (text == null || text.isEmpty()) continue;

                    // JWT tokens
                    Matcher m = JWT_PATTERN.matcher(text);
                    while (m.find()) {
                        jwtTokens.add(m.group(1));
                    }

                    // private keys
                    if (PRIVATE_KEY_PATTERN.matcher(text).find()) {
                        // truncate long PEM keys
                        if (text.length() > 200) {
                            privateKeys.add(text.substring(0, 200) + "...");
                        } else {
                            privateKeys.add(text);
                        }
                    }

                    count++;
                    if (count >= 500000) break;
                }
            }

            if (!jwtTokens.isEmpty()) {
                if (result.length() > 0) result.append("\r\n");
                result.append("[JWT Tokens] (").append(jwtTokens.size()).append(")\r\n");
                for (String token : jwtTokens) {
                    result.append("  ").append(token).append("\r\n");
                }
            }

            if (!privateKeys.isEmpty()) {
                if (result.length() > 0) result.append("\r\n");
                result.append("[Private Keys] (").append(privateKeys.size()).append(")\r\n");
                for (String key : privateKeys) {
                    result.append("  ").append(key).append("\r\n");
                }
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
