package org.apache.commons.dbutils;

/**
 * 场景3：Bypass 内存马
 * 类名伪装为知名开源库，使用自定义 ClassLoader 加载
 * 字段中包含 XOR 编码的危险关键词
 */
public class Handler {
    // XOR 编码的 "java.lang.Runtime" (key=0x42)
    public byte[] xorEncoded = xorEncode("java.lang.Runtime", 0x42);
    // Base64 编码的 "ProcessBuilder"
    public String base64Payload = "UHJvY2Vzc0J1aWxkZXI=";
    // 危险方法名
    public String methodName = "getRuntime";
    // 解密密钥
    public int xorKey = 0x42;
    // 看似正常的配置
    public String configName = "db-query-config";

    private static byte[] xorEncode(String input, int key) {
        byte[] data = input.getBytes();
        byte[] encoded = new byte[data.length];
        for (int i = 0; i < data.length; i++) {
            encoded[i] = (byte) (data[i] ^ key);
        }
        return encoded;
    }
}
