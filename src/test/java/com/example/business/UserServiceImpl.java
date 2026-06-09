package com.example.business;

/**
 * 场景2：反射内存马
 * 类名伪装为正常业务类，但字段中引用了危险类
 */
public class UserServiceImpl {
    // 危险引用 - 命令执行
    public Runtime runtime = Runtime.getRuntime();
    public String dangerousField = "java.lang.Runtime.getRuntime().exec()";
    public String encodedPayload = "amF2YS5sYW5nLlJ1bnRpbWU=";  // Base64: java.lang.Runtime
    public ProcessBuilder processBuilder;

    public UserServiceImpl() {
        try {
            this.processBuilder = new ProcessBuilder("whoami");
        } catch (Exception e) {
            // ignore
        }
    }
}
