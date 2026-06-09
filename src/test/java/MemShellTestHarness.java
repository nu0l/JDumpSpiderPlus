import com.sun.management.HotSpotDiagnosticMXBean;
import org.apache.catalina.core.ApplicationFilterConfig;
import org.apache.catalina.core.StandardContext;
import org.apache.catalina.core.StandardWrapper;
import org.apache.commons.dbutils.Handler;
import org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping;
import com.example.business.UserServiceImpl;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import javax.management.MBeanServer;
import java.io.File;
import java.lang.management.ManagementFactory;
import java.lang.reflect.InvocationHandler;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;

/**
 * 内存马检测测试程序
 * 生成 3 种不同场景的 heapdump 文件，用于验证 MemShellDetector 的检测能力
 *
 * 场景1 (normal):   普通内存马 - 类名 "evil"，无包名
 * 场景2 (reflect):  反射内存马 - 类名伪装，字段中引用危险类
 * 场景3 (bypass):   Bypass 内存马 - 类名伪装 + 自定义 ClassLoader + 编码字段
 */
public class MemShellTestHarness {

    // 保持引用，防止 GC 回收
    private static Object scenario1Ref;
    private static Object scenario2Ref;
    private static Object scenario3Ref;
    private static Object scenario4Ref;
    private static Object scenario5Ref;
    private static Object scenario6Ref;
    private static Object scenario7Ref;

    public static void main(String[] args) throws Exception {
        String outputDir = args.length > 0 ? args[0] : ".";
        System.out.println("[*] MemShell Test Harness - Bypass Edition");
        System.out.println("[*] Output directory: " + outputDir);

        // 场景1: 普通内存马
        setupScenario1();
        dumpHeap(outputDir + "/memshell-test-normal.hprof");
        System.out.println("[+] Scenario 1: Normal memshell heapdump created");

        // 场景2: 反射内存马
        setupScenario2();
        dumpHeap(outputDir + "/memshell-test-reflect.hprof");
        System.out.println("[+] Scenario 2: Reflection memshell heapdump created");

        // 场景3: Bypass 内存马 (XOR + 自定义ClassLoader)
        setupScenario3();
        dumpHeap(outputDir + "/memshell-test-bypass.hprof");
        System.out.println("[+] Scenario 3: Bypass memshell heapdump created");

        // 场景4: 动态代理内存马
        setupScenario4();
        dumpHeap(outputDir + "/memshell-test-proxy.hprof");
        System.out.println("[+] Scenario 4: Dynamic proxy memshell heapdump created");

        // 场景5: ScriptEngine 脚本内存马
        setupScenario5();
        dumpHeap(outputDir + "/memshell-test-script.hprof");
        System.out.println("[+] Scenario 5: ScriptEngine memshell heapdump created");

        // 场景6: Cipher 加密 bypass
        setupScenario6();
        dumpHeap(outputDir + "/memshell-test-cipher.hprof");
        System.out.println("[+] Scenario 6: Cipher bypass heapdump created");

        // 场景7: 反射链 bypass
        setupScenario7();
        dumpHeap(outputDir + "/memshell-test-reflchain.hprof");
        System.out.println("[+] Scenario 7: Reflection chain bypass heapdump created");

        // 综合 heapdump
        setupScenario1();
        setupScenario2();
        setupScenario3();
        setupScenario4();
        setupScenario5();
        setupScenario6();
        setupScenario7();
        dumpHeap(outputDir + "/memshell-test-all.hprof");
        System.out.println("[+] All scenarios combined heapdump created");

        // 导出字节码（模拟）
        exportBytecode(outputDir);

        System.out.println("[*] Done. Run JDumpSpiderPlus against the .hprof files to test detection.");
    }

    /**
     * 场景1: 普通内存马
     * - 类名 "evil"，无包名
     * - 注册到 ApplicationFilterConfig
     * - 使用系统 ClassLoader
     */
    private static void setupScenario1() {
        System.out.println("[*] Setting up Scenario 1: Normal memshell (class name: 'evil')");

        // 使用自定义 ClassLoader 加载一个无包名的类
        // 由于编译限制，我们模拟一个无包名类的行为
        // 实际检测时，检测器会检查 ApplicationFilterConfig 中的 filterClass 字段

        // 创建一个 Filter 实例（使用 Handler 作为代理，检测器检查的是 filterClass 字段字符串）
        Object filterInstance = new Object();

        // 注册到 ApplicationFilterConfig
        // filterClass 设为 "evil" - 无包名，会被检测为可疑
        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "evilFilter",      // filter name
                "evil",            // filter class - 无包名，可疑！
                filterInstance     // filter instance
        );

        // 注册到 StandardContext
        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario1Ref = ctx;
    }

    /**
     * 场景2: 反射内存马
     * - 类名伪装为 "com.example.business.UserServiceImpl"
     * - 实例字段中引用 Runtime、ProcessBuilder
     * - 字符串字段中包含危险关键词
     */
    private static void setupScenario2() {
        System.out.println("[*] Setting up Scenario 2: Reflection memshell");

        // 创建 UserServiceImpl 实例（包含危险引用）
        UserServiceImpl evilService = new UserServiceImpl();

        // 注册为 Spring Controller
        RequestMappingHandlerMapping mapping = new RequestMappingHandlerMapping();
        mapping.registerHandler("/api/user/**", "com.example.business.UserServiceImpl#handle");

        // 同时注册为 Servlet
        StandardWrapper wrapper = new StandardWrapper(
                "UserServlet",
                "com.example.business.UserServiceImpl",  // 伪装的类名
                evilService
        );

        scenario2Ref = new Object[]{mapping, wrapper, evilService};
    }

    /**
     * 场景3: Bypass 内存马
     * - 类名伪装为 "org.apache.commons.dbutils.Handler"
     * - 使用自定义 ClassLoader 加载
     * - 字段中包含 XOR 编码的危险关键词
     * - 包含 Base64 编码的 payload
     */
    private static void setupScenario3() {
        System.out.println("[*] Setting up Scenario 3: Bypass memshell");

        // 使用自定义 ClassLoader 加载（模拟攻击者注入）
        CustomClassLoader loader = new CustomClassLoader(MemShellTestHarness.class.getClassLoader());
        Class<?> handlerClass;
        Object handlerInstance;
        try {
            handlerClass = loader.loadClass("org.apache.commons.dbutils.Handler");
            handlerInstance = handlerClass.newInstance();
        } catch (Exception e) {
            // fallback
            handlerInstance = new Handler();
            handlerClass = Handler.class;
        }

        // 注册到 ApplicationFilterConfig
        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "dbQueryFilter",
                handlerClass.getName(),
                handlerInstance
        );

        // 注册到 StandardContext
        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario3Ref = new Object[]{ctx, handlerInstance, loader};
    }

    /**
     * 场景4: 动态代理内存马
     * - 使用 Proxy.newProxyInstance 创建代理
     * - InvocationHandler 中包含危险操作
     */
    private static void setupScenario4() {
        System.out.println("[*] Setting up Scenario 4: Dynamic proxy memshell");

        // 创建一个恶意的 InvocationHandler
        InvocationHandler evilHandler = new EvilInvocationHandler();

        // 创建动态代理
        Object proxyInstance = Proxy.newProxyInstance(
                MemShellTestHarness.class.getClassLoader(),
                new Class[]{Runnable.class},
                evilHandler
        );

        // 注册为 Filter
        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "proxyFilter",
                "com.sun.proxy.$Proxy0",  // 代理类名
                proxyInstance
        );

        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario4Ref = new Object[]{ctx, evilHandler, proxyInstance};
    }

    /**
     * 场景5: ScriptEngine 脚本内存马
     * - 类名伪装，但字段中包含 ScriptEngine 引用和脚本内容
     */
    private static void setupScenario5() {
        System.out.println("[*] Setting up Scenario 5: ScriptEngine memshell");

        // 创建一个包含 ScriptEngine 引用的对象
        ScriptEngineHolder holder = new ScriptEngineHolder();

        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "scriptFilter",
                "com.example.filter.ScriptFilter",  // 伪装类名
                holder
        );

        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario5Ref = new Object[]{ctx, holder};
    }

    /**
     * 场景6: Cipher 加密 bypass
     * - 使用 AES 加密存储 payload
     * - 字段中包含 Cipher、SecretKey、加密后的字节数组
     */
    private static void setupScenario6() {
        System.out.println("[*] Setting up Scenario 6: Cipher encryption bypass");

        EncryptedPayloadHolder holder = new EncryptedPayloadHolder();

        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "cryptoFilter",
                "com.example.filter.CryptoFilter",  // 伪装类名
                holder
        );

        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario6Ref = new Object[]{ctx, holder};
    }

    /**
     * 场景7: 反射链 bypass
     * - 使用 Class.forName + getDeclaredMethod + invoke 反射链
     * - 字段中包含反射相关的字符串
     */
    private static void setupScenario7() {
        System.out.println("[*] Setting up Scenario 7: Reflection chain bypass");

        ReflectionChainHolder holder = new ReflectionChainHolder();

        ApplicationFilterConfig config = new ApplicationFilterConfig(
                "reflectFilter",
                "com.example.filter.ReflectFilter",  // 伪装类名
                holder
        );

        StandardContext ctx = new StandardContext();
        ctx.addFilterConfig(config);

        scenario7Ref = new Object[]{ctx, holder};
    }

    // ========== 场景辅助类 ==========

    /**
     * 恶意 InvocationHandler - 场景4
     */
    static class EvilInvocationHandler implements InvocationHandler {
        public String command = "whoami";
        public String runtimeClass = "java.lang.Runtime";
        public String method = "exec";
        public Method execMethod;
        public Runtime runtime;

        public EvilInvocationHandler() {
            try {
                this.runtime = Runtime.getRuntime();
                this.execMethod = Runtime.class.getMethod("exec", String.class);
            } catch (Exception e) {
                // ignore
            }
        }

        @Override
        public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
            return null;
        }
    }

    /**
     * ScriptEngine 持有者 - 场景5
     */
    static class ScriptEngineHolder {
        public String engineName = "javascript";
        public String script = "java.lang.Runtime.getRuntime().exec('whoami')";
        public String evalMethod = "eval";
        public String dangerousPayload = "var p=new ProcessBuilder(['cmd','/c','calc']);p.start();";
        // Base64 encoded "java.lang.Runtime"
        public String encodedClass = "amF2YS5sYW5nLlJ1bnRpbWU=";
    }

    /**
     * 加密 Payload 持有者 - 场景6
     */
    static class EncryptedPayloadHolder {
        public Cipher cipher;
        public SecretKeySpec secretKey;
        public byte[] encryptedPayload;
        public String algorithm = "AES";
        public String mode = "AES/CBC/PKCS5Padding";
        public String keySpec = "0123456789abcdef";

        public EncryptedPayloadHolder() {
            try {
                this.cipher = Cipher.getInstance("AES");
                this.secretKey = new SecretKeySpec("0123456789abcdef".getBytes(), "AES");
                // 模拟加密后的 payload
                this.encryptedPayload = "java.lang.Runtime".getBytes();
            } catch (Exception e) {
                // ignore
            }
        }
    }

    /**
     * 反射链持有者 - 场景7
     */
    static class ReflectionChainHolder {
        public String className = "java.lang.Runtime";
        public String methodName = "getRuntime";
        public String execMethod = "exec";
        public String forName = "Class.forName";
        public String getDeclaredMethod = "getDeclaredMethod";
        public String setAccessible = "setAccessible";
        public String invoke = "invoke";
        public Method method;
        public Object target;

        public ReflectionChainHolder() {
            try {
                Class<?> rtClass = Class.forName("java.lang.Runtime");
                this.method = rtClass.getDeclaredMethod("getRuntime");
                this.target = rtClass.getMethod("exec", String.class);
            } catch (Exception e) {
                // ignore
            }
        }
    }

    /**
     * 导出字节码（模拟）
     * 在实际场景中，可以通过 ClassLoader.getResourceAsStream 获取字节码
     * 对于 heapdump 分析，只能导出元数据
     */
    private static void exportBytecode(String outputDir) {
        String memshellDir = outputDir + "/memshell";
        new File(memshellDir).mkdirs();

        // 导出场景信息
        try {
            java.io.FileWriter fw = new java.io.FileWriter(memshellDir + "/detection-summary.txt");
            fw.write("=== MemShell Detection Test Summary ===\n\n");
            fw.write("Scenario 1 - Normal Memshell:\n");
            fw.write("  Class: evil (no package)\n");
            fw.write("  Type: Filter\n");
            fw.write("  Expected: HIGH - no package name\n\n");
            fw.write("Scenario 2 - Reflection Memshell:\n");
            fw.write("  Class: com.example.business.UserServiceImpl\n");
            fw.write("  Type: Controller/Servlet\n");
            fw.write("  Expected: HIGH - references Runtime, contains dangerous patterns\n\n");
            fw.write("Scenario 3 - Bypass Memshell:\n");
            fw.write("  Class: org.apache.commons.dbutils.Handler\n");
            fw.write("  Type: Filter\n");
            fw.write("  Expected: HIGH/MEDIUM - non-system ClassLoader, XOR-encoded fields\n\n");
            fw.write("Note: HPROF format does not contain class bytecode.\n");
            fw.write("Bytecode export is only possible from a live JVM.\n");
            fw.close();
            System.out.println("[+] Detection summary saved to: " + memshellDir + "/detection-summary.txt");
        } catch (Exception e) {
            System.out.println("[-] Failed to write summary: " + e.getMessage());
        }
    }

    /**
     * 生成 heapdump 文件
     */
    private static void dumpHeap(String filePath) throws Exception {
        MBeanServer server = ManagementFactory.getPlatformMBeanServer();
        HotSpotDiagnosticMXBean bean = ManagementFactory.newPlatformMXBeanProxy(
                server,
                "com.sun.management:type=HotSpotDiagnostic",
                HotSpotDiagnosticMXBean.class
        );
        bean.dumpHeap(filePath, true);
        System.out.println("[+] Heapdump saved: " + filePath);
    }

    /**
     * 自定义 ClassLoader - 模拟攻击者使用的自定义类加载器
     */
    static class CustomClassLoader extends ClassLoader {
        public CustomClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        public Class<?> loadClass(String name) throws ClassNotFoundException {
            // 对目标类使用自定义加载
            if (name.equals("org.apache.commons.dbutils.Handler")) {
                try {
                    // 读取类字节码
                    String path = name.replace('.', '/') + ".class";
                    java.io.InputStream is = getParent().getResourceAsStream(path);
                    if (is != null) {
                        java.io.ByteArrayOutputStream bos = new java.io.ByteArrayOutputStream();
                        byte[] buf = new byte[4096];
                        int len;
                        while ((len = is.read(buf)) != -1) {
                            bos.write(buf, 0, len);
                        }
                        is.close();
                        byte[] bytecode = bos.toByteArray();
                        return defineClass(name, bytecode, 0, bytecode.length);
                    }
                } catch (Exception e) {
                    // fallback
                }
            }
            return super.loadClass(name);
        }
    }
}
