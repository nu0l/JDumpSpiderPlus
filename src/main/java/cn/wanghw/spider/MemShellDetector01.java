package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import org.yaml.snakeyaml.Yaml;

import java.io.InputStream;
import java.util.*;
import java.util.regex.Pattern;

public class MemShellDetector01 implements ISpider {

    private static final Pattern SUSPICIOUS_CLASS_PATTERN = Pattern.compile(
            "(shell|evil|inject|memshell|backdoor|behinder|godzilla|ant|冰蝎|哥斯拉|蚁剑|neoreg|rebeyond)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern RANDOM_NAME_PATTERN = Pattern.compile(
            "^[a-zA-Z]{1,3}[0-9a-f]{8,}$|^[A-Z][a-z]+[A-Z][a-z]+[0-9]{4,}$|^[a-z]{1,2}[0-9]{10,}$");

    private static final String[] SYSTEM_CLASSLOADERS = {
            "sun.misc.Launcher$AppClassLoader",
            "sun.misc.Launcher$ExtClassLoader",
            "jdk.internal.loader.ClassLoaders$AppClassLoader",
            "jdk.internal.loader.ClassLoaders$PlatformClassLoader",
            "jdk.internal.loader.BuiltinClassLoader",
            "java.lang.ClassLoader",
            "java.net.URLClassLoader",
            "java.security.SecureClassLoader",
            "org.apache.catalina.loader.WebappClassLoader",
            "org.apache.catalina.loader.WebappClassLoaderBase",
            "org.springframework.boot.loader.LaunchedURLClassLoader"
    };

    private static final String[] FILTER_DETECTOR_CLASSES = {
            "org.apache.catalina.core.ApplicationFilterConfig",
            "org.apache.catalina.core.ApplicationFilterChain"
    };

    private static final String[] SERVLET_DETECTOR_CLASSES = {
            "org.apache.catalina.core.StandardContext",
            "org.apache.catalina.core.StandardWrapper"
    };

    private static final String[] SPRING_MAPPING_CLASSES = {
            "org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping",
            "org.springframework.web.servlet.handler.AbstractHandlerMapping"
    };

    private static final String[] WEBSOCKET_CLASSES = {
            "org.apache.tomcat.websocket.server.WsServerContainer"
    };

    private static final String[] AGENT_CLASSES = {
            "sun.instrument.TransformerManager"
    };

    private static final String[] VALVE_CLASSES = {
            "org.apache.catalina.core.StandardEngine",
            "org.apache.catalina.core.StandardHost",
            "org.apache.catalina.core.StandardContext"
    };

    // ========== 增强: 危险类名列表 - 覆盖多种 bypass 手段 ==========

    private static final String[] DANGEROUS_CLASS_NAMES = {
            // 命令执行
            "java.lang.Runtime",
            "java.lang.ProcessBuilder",
            "java.lang.UNIXProcess",
            "java.lang.ProcessImpl",
            // 反射链
            "java.lang.reflect.Method",
            "java.lang.reflect.Constructor",
            "java.lang.reflect.Field",
            "java.lang.reflect.Proxy",
            "java.lang.reflect.InvocationHandler",
            // TemplatesImpl 字节码注入
            "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
            "com.sun.org.apache.xalan.internal.xsltc.runtime.AbstractTranslet",
            "org.apache.xalan.xsltc.trax.TemplatesImpl",
            "org.apache.xalan.xsltc.runtime.AbstractTranslet",
            // ScriptEngine 脚本引擎
            "javax.script.ScriptEngine",
            "javax.script.ScriptEngineManager",
            "javax.script.ScriptEngineFactory",
            "jdk.nashorn.api.scripting.NashornScriptEngine",
            "org.mozilla.javascript.Context",
            "groovy.lang.GroovyShell",
            "groovy.lang.GroovyClassLoader",
            // JNDI 注入
            "javax.naming.directory.InitialDirContext",
            "javax.naming.InitialContext",
            "com.sun.jndi.rmi.object.trustURLCodebase",
            // 加密相关 (用于编码 bypass)
            "javax.crypto.Cipher",
            "javax.crypto.spec.SecretKeySpec",
            "javax.crypto.spec.IvParameterSpec",
            // 反序列化
            "java.io.ObjectInputStream",
            "com.sun.rowset.CachedRowSetImpl",
            // freemarker OGNL
            "freemarker.template.utility.Execute",
            "ognl.OgnlRuntime",
            "ognl.OgnlContext",
            // Spring 表达式
            "org.springframework.expression.spel.standard.SpelExpressionParser",
            "org.springframework.expression.Expression",
    };

    // ========== 增强: 危险字符串模式 - 覆盖更多 bypass 手段 ==========

    private static final Pattern DANGEROUS_STRING_PATTERN = Pattern.compile(
            "(" +
            // 直接危险类名
            "java\\.lang\\.Runtime|java\\.lang\\.ProcessBuilder|" +
            "javax\\.script\\.ScriptEngine|javax\\.naming|" +
            "com\\.sun\\.org\\.apache\\.xalan|" +
            // 危险方法名
            "getRuntime|ProcessBuilder|defineClass|loadClass|" +
            "ClassLoader\\.define|sun\\.misc\\.Unsafe|" +
            "newInstance|newInstance0|" +
            "getMethod|getDeclaredMethod|getDeclaredField|" +
            "setAccessible|invoke\\(|forName\\(" +
            // JNDI/LDAP URL
            "ldap://|rmi://|dns://|corba://|" +
            "jndi:|InitialDirContext|InitialContext|" +
            // TemplatesImpl 字段
            "_bytecodes|_tfactory|_name|_outputProperties|" +
            "getTransletInstance|newTransformer|" +
            // 动态代理
            "InvocationHandler|newProxyInstance|Proxy\\.new|" +
            // ScriptEngine
            "eval\\(|ScriptEngine|nashorn|rhino|groovy|" +
            // 加密/编码 bypass
            "Cipher|SecretKeySpec|encrypt|decrypt|AES|DES|RSA|" +
            "doFinal|XOR|xor_encode|xor_decode|" +
            // 反序列化
            "ObjectInputStream|readObject|readUnserialize|" +
            "ysoserial|CommonsCollections|CC[1-7]|" +
            // 表达式注入
            "SpEL|SpelExpression|OGNL|ognl\\.getValue|" +
            "el-resolver|ExpressionFactory|" +
            // 命令执行字符串
            "cmd\\.exe|/bin/bash|/bin/sh|powershell|whoami|id;|ls -la|" +
            // Base64 编码的危险关键词
            "Y21kLmV4ZWN1dGU=|Y2FsYy5leGVj|" +  // cmd.execute / calc.exec
            "amF2YS5sYW5nLlJ1bnRpbWU=|amF2YS5sYW5nLlByb2Nlc3NCdWlsZGVy|" +  // java.lang.Runtime / java.lang.ProcessBuilder
            "L2Jpbi9zaA==|L2Jpbi9iYXNo|" +  // /bin/sh / /bin/bash
            "Y21kLmV4ZQ==" +  // cmd.exe
            ")",
            Pattern.CASE_INSENSITIVE);

    // ========== 增强: 可疑字段名 - 用于检测编码后的 payload ==========

    private static final Pattern SUSPICIOUS_FIELD_NAME_PATTERN = Pattern.compile(
            "(payload|shellcode|bytecode|_bytecodes|evil|shell|inject|" +
            "cipher|encrypted|encoded|xor|key|secret|" +
            "command|cmd|exec|eval|script)",
            Pattern.CASE_INSENSITIVE);

    // 白名单数据
    private Set<String> safeClasses = new HashSet<String>();
    private Set<String> safePackages = new HashSet<String>();
    private Set<String> safeClassloaders = new HashSet<String>();
    private Set<String> dangerousClassPatterns = new HashSet<String>();
    private Set<String> dangerousMethodPatterns = new HashSet<String>();
    private boolean whitelistLoaded = false;

    public String getName() {
        return "MemShellDetector";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        List<String[]> findings = new ArrayList<String[]>();

        try {
            loadWhitelist();

            detectFilterType(heapHolder, findings);
            detectServletType(heapHolder, findings);
            detectListenerType(heapHolder, findings);
            detectControllerType(heapHolder, findings);
            detectInterceptorType(heapHolder, findings);
            detectWebSocketType(heapHolder, findings);
            detectAgentType(heapHolder, findings);
            detectValveType(heapHolder, findings);

            // 增强: 检测动态代理型内存马
            detectProxyType(heapHolder, findings);

            // 增强: 检测 TemplatesImpl 字节码注入
            detectTemplatesImpl(heapHolder, findings);

            if (!findings.isEmpty()) {
                for (String[] finding : findings) {
                    String riskLevel = finding.length > 4 ? finding[4] : "MEDIUM";
                    result.append(riskLevel.equals("HIGH") ? "[!] " : "[?] ");
                    result.append(finding[0]).append("\r\n");
                    result.append("  Type: ").append(finding[1]).append("\r\n");
                    result.append("  RiskLevel: ").append(riskLevel).append("\r\n");
                    result.append("  Reason: ").append(finding[2]).append("\r\n");
                    if (finding.length > 3 && finding[3] != null && !finding[3].isEmpty()) {
                        result.append("  Fields:\r\n").append(finding[3]).append("\r\n");
                    }
                    result.append("\r\n");
                }
            }
        } catch (Exception ex) {
            System.out.println("[-] MemShellDetector error: " + ex.getMessage());
        }
        return result.toString();
    }

    // ========== 白名单加载 ==========

    @SuppressWarnings("unchecked")
    private void loadWhitelist() {
        if (whitelistLoaded) return;
        whitelistLoaded = true;

        try {
            InputStream is = getClass().getResourceAsStream("/memshell-whitelist.yml");
            if (is == null) {
                loadDefaultWhitelist();
                return;
            }
            Yaml yaml = new Yaml();
            Map<String, Object> config = yaml.load(is);
            is.close();

            if (config == null) {
                loadDefaultWhitelist();
                return;
            }

            Object sc = config.get("safe_classes");
            if (sc instanceof List) safeClasses.addAll((List<String>) sc);
            Object sp = config.get("safe_packages");
            if (sp instanceof List) safePackages.addAll((List<String>) sp);
            Object scl = config.get("safe_classloaders");
            if (scl instanceof List) safeClassloaders.addAll((List<String>) scl);
            Object dcp = config.get("dangerous_class_patterns");
            if (dcp instanceof List) dangerousClassPatterns.addAll((List<String>) dcp);
            Object dmp = config.get("dangerous_method_patterns");
            if (dmp instanceof List) dangerousMethodPatterns.addAll((List<String>) dmp);

        } catch (Exception e) {
            System.out.println("[-] Failed to load memshell whitelist: " + e.getMessage());
            loadDefaultWhitelist();
        }
    }

    private void loadDefaultWhitelist() {
        safeClassloaders.addAll(Arrays.asList(SYSTEM_CLASSLOADERS));
    }

    // ========== Filter type detection ==========
    private void detectFilterType(IHeapHolder heapHolder, List<String[]> findings) {
        for (String className : FILTER_DETECTOR_CLASSES) {
            Object clazz = heapHolder.findClass(className);
            if (clazz == null) continue;

            for (Object instance : heapHolder.getInstances(clazz)) {
                try {
                    String filterClass = heapHolder.getFieldStringValue(instance, "filterClass");
                    if (filterClass == null || filterClass.isEmpty()) continue;

                    String filterName = heapHolder.getFieldStringValue(instance, "name");
                    String fields = dumpFields(heapHolder, instance);
                    String extra = "FilterName=" + filterName;

                    // 增强: 获取 filter 实例对象，用于后续分析
                    Object filterInstance = heapHolder.getFieldValue(instance, "filter");

                    analyzeComponentWithInstance(heapHolder, clazz, filterClass, "Filter", extra, fields, filterInstance, findings);
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    // ========== Servlet type detection ==========
    private void detectServletType(IHeapHolder heapHolder, List<String[]> findings) {
        Object wrapperClass = heapHolder.findClass("org.apache.catalina.core.StandardWrapper");
        if (wrapperClass == null) return;

        for (Object instance : heapHolder.getInstances(wrapperClass)) {
            try {
                String servletClass = heapHolder.getFieldStringValue(instance, "servletClass");
                if (servletClass == null || servletClass.isEmpty()) continue;

                String name = heapHolder.getFieldStringValue(instance, "name");
                String fields = dumpFields(heapHolder, instance);

                analyzeComponent(heapHolder, wrapperClass, servletClass, "Servlet", "ServletName=" + name, fields, findings);
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== Listener type detection ==========
    private void detectListenerType(IHeapHolder heapHolder, List<String[]> findings) {
        Object ctxClass = heapHolder.findClass("org.apache.catalina.core.StandardContext");
        if (ctxClass == null) return;

        for (Object instance : heapHolder.getInstances(ctxClass)) {
            try {
                Object listeners = heapHolder.getFieldValue(instance, "applicationEventListenersList");
                if (listeners == null) continue;

                if (listeners instanceof Object[]) {
                    for (Object listener : (Object[]) listeners) {
                        if (listener == null) continue;
                        String listenerClass = heapHolder.getClassName(listener);
                        String fields = dumpFields(heapHolder, listener);

                        analyzeComponent(heapHolder, ctxClass, listenerClass, "Listener", "", fields, findings);
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== Controller type detection (Spring MVC) ==========
    private void detectControllerType(IHeapHolder heapHolder, List<String[]> findings) {
        Object mappingClass = heapHolder.findClass("org.springframework.web.servlet.mvc.method.annotation.RequestMappingHandlerMapping");
        if (mappingClass == null) return;

        for (Object instance : heapHolder.getInstances(mappingClass)) {
            try {
                Object handlerMethods = heapHolder.getFieldValue(instance, "handlerMethods");
                if (handlerMethods == null || !heapHolder.isMap(handlerMethods)) continue;

                HashMap<String, String> methods = heapHolder.arrayDump(heapHolder.getMap(handlerMethods));
                if (methods == null) continue;

                for (Map.Entry<String, String> entry : methods.entrySet()) {
                    String handler = entry.getValue();
                    if (handler == null) continue;

                    String handlerClass = handler.contains("#") ? handler.substring(0, handler.indexOf("#")) : handler;

                    analyzeComponent(heapHolder, mappingClass, handlerClass, "Controller", "", "", findings);
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== Interceptor type detection (Spring MVC) ==========
    private void detectInterceptorType(IHeapHolder heapHolder, List<String[]> findings) {
        Object mappingClass = heapHolder.findClass("org.springframework.web.servlet.handler.AbstractHandlerMapping");
        if (mappingClass == null) return;

        for (Object instance : heapHolder.getInstances(mappingClass)) {
            try {
                Object interceptors = heapHolder.getFieldValue(instance, "adaptedInterceptors");
                if (interceptors == null) continue;

                if (interceptors instanceof List) {
                    for (Object interceptor : (List) interceptors) {
                        if (interceptor == null) continue;
                        String interceptorClass = heapHolder.getClassName(interceptor);
                        String fields = dumpFields(heapHolder, interceptor);

                        analyzeComponent(heapHolder, mappingClass, interceptorClass, "Interceptor", "", fields, findings);
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== WebSocket type detection ==========
    private void detectWebSocketType(IHeapHolder heapHolder, List<String[]> findings) {
        Object wsClass = heapHolder.findClass("org.apache.tomcat.websocket.server.WsServerContainer");
        if (wsClass == null) return;

        for (Object instance : heapHolder.getInstances(wsClass)) {
            try {
                Object configPaths = heapHolder.getFieldValue(instance, "configPaths");
                if (configPaths == null || !heapHolder.isMap(configPaths)) continue;

                HashMap<String, String> paths = heapHolder.arrayDump(heapHolder.getMap(configPaths));
                if (paths == null) continue;

                for (Map.Entry<String, String> entry : paths.entrySet()) {
                    String endpointClass = entry.getValue();
                    if (endpointClass == null) continue;

                    analyzeComponent(heapHolder, wsClass, endpointClass, "WebSocket", "Path=" + entry.getKey(), "", findings);
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== Agent type detection ==========
    private void detectAgentType(IHeapHolder heapHolder, List<String[]> findings) {
        Object tmClass = heapHolder.findClass("sun.instrument.TransformerManager");
        if (tmClass == null) return;

        for (Object instance : heapHolder.getInstances(tmClass)) {
            try {
                Object chain = heapHolder.getFieldValue(instance, "mTransformerChain");
                if (chain == null) continue;

                if (chain instanceof List) {
                    for (Object transformer : (List) chain) {
                        if (transformer == null) continue;
                        String transformerClass = heapHolder.getClassName(transformer);
                        String fields = dumpFields(heapHolder, transformer);

                        analyzeComponent(heapHolder, tmClass, transformerClass, "Agent(Transformer)", "", fields, findings);
                    }
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== Valve type detection ==========
    private void detectValveType(IHeapHolder heapHolder, List<String[]> findings) {
        for (String className : VALVE_CLASSES) {
            Object clazz = heapHolder.findClass(className);
            if (clazz == null) continue;

            for (Object instance : heapHolder.getInstances(clazz)) {
                try {
                    Object pipeline = heapHolder.getFieldValue(instance, "pipeline");
                    if (pipeline == null) continue;

                    Object valves = heapHolder.getFieldValue(pipeline, "valves");
                    if (valves == null) continue;

                    if (valves instanceof Object[]) {
                        for (Object valve : (Object[]) valves) {
                            if (valve == null) continue;
                            String valveClass = heapHolder.getClassName(valve);
                            String fields = dumpFields(heapHolder, valve);

                            analyzeComponent(heapHolder, clazz, valveClass, "Valve", "", fields, findings);
                        }
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    // ========== 增强: 动态代理型内存马检测 ==========

    private void detectProxyType(IHeapHolder heapHolder, List<String[]> findings) {
        Object proxyClass = heapHolder.findClass("java.lang.reflect.Proxy");
        if (proxyClass == null) return;

        for (Object instance : heapHolder.getInstances(proxyClass)) {
            try {
                Object handler = heapHolder.getFieldValue(instance, "h");
                if (handler == null) continue;

                String handlerClass = heapHolder.getClassName(handler);
                if (handlerClass == null) continue;

                // 跳过 JDK 自带的 InvocationHandler
                if (handlerClass.startsWith("java.lang.reflect.") ||
                    handlerClass.startsWith("sun.reflect.") ||
                    handlerClass.startsWith("com.sun.proxy.")) continue;

                String fields = dumpFields(heapHolder, handler);

                // 检查 InvocationHandler 是否可疑
                String reason = checkSuspicious(handlerClass);
                String clReason = checkClassLoader(heapHolder, handlerClass);
                String integrityReason = checkIntegrity(handlerClass);

                List<String> reasons = new ArrayList<String>();
                String riskLevel = "MEDIUM";

                if (reason != null) { reasons.add(reason); riskLevel = "HIGH"; }
                if (clReason != null) { reasons.add(clReason); riskLevel = "HIGH"; }
                if (integrityReason != null) reasons.add(integrityReason);

                // 检查 handler 的字段内容
                String refReason = checkFieldReferences(heapHolder, null, handlerClass);
                if (refReason != null) { reasons.add(refReason); riskLevel = "HIGH"; }

                if (!reasons.isEmpty()) {
                    findings.add(new String[]{
                            "InvocationHandler: " + handlerClass,
                            "DynamicProxy",
                            String.join("; ", reasons),
                            fields,
                            riskLevel
                    });
                }
            } catch (Exception e) {
                // ignore
            }
        }
    }

    // ========== 增强: TemplatesImpl 字节码注入检测 ==========

    private void detectTemplatesImpl(IHeapHolder heapHolder, List<String[]> findings) {
        String[] templatesClasses = {
                "com.sun.org.apache.xalan.internal.xsltc.trax.TemplatesImpl",
                "org.apache.xalan.xsltc.trax.TemplatesImpl"
        };

        for (String className : templatesClasses) {
            Object clazz = heapHolder.findClass(className);
            if (clazz == null) continue;

            for (Object instance : heapHolder.getInstances(clazz)) {
                try {
                    // 检查 _bytecodes 字段是否存在且非空
                    Object bytecodes = heapHolder.getFieldValue(instance, "_bytecodes");
                    if (bytecodes == null) continue;

                    String name = heapHolder.getFieldStringValue(instance, "_name");
                    String fields = dumpFields(heapHolder, instance);

                    List<String> reasons = new ArrayList<String>();
                    reasons.add("TemplatesImpl with _bytecodes - bytecode injection");
                    if (name != null && !name.isEmpty()) {
                        reasons.add("_name=" + name);
                    }

                    findings.add(new String[]{
                            "Class: " + className,
                            "TemplatesImpl Injection",
                            String.join("; ", reasons),
                            fields,
                            "HIGH"
                    });
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    // ========== 统一分析逻辑 ==========

    private void analyzeComponentWithInstance(IHeapHolder heapHolder, Object contextClass,
                                               String componentClass, String type,
                                               String extra, String fields,
                                               Object filterInstance,
                                               List<String[]> findings) {
        if (componentClass == null || componentClass.isEmpty()) return;

        List<String> reasons = new ArrayList<String>();
        String riskLevel = "LOW";

        // 1. 类名特征检查
        String classReason = checkSuspicious(componentClass);
        if (classReason != null) {
            reasons.add(classReason);
            riskLevel = "HIGH";
        }

        // 2. ClassLoader 检查
        String clReason = checkClassLoader(heapHolder, componentClass);
        if (clReason != null) {
            reasons.add(clReason);
            riskLevel = "HIGH";
        }

        // 3. 完整性校验（白名单）
        String integrityReason = checkIntegrity(componentClass);
        if (integrityReason != null) {
            reasons.add(integrityReason);
            if (riskLevel.equals("LOW")) riskLevel = "MEDIUM";
        }

        // 4. 字段引用分析（对可疑组件执行）
        if (riskLevel.equals("HIGH") || riskLevel.equals("MEDIUM")) {
            String refReason = checkFieldReferences(heapHolder, contextClass, componentClass);
            if (refReason != null) {
                reasons.add(refReason);
                riskLevel = "HIGH";
            }
        }

        // 5. 增强: 当注册的类名在堆中不存在时，直接分析 filter 实例对象
        if (filterInstance != null && heapHolder.findClass(componentClass) == null) {
            String instanceReason = analyzeInstanceFields(heapHolder, filterInstance);
            if (instanceReason != null) {
                reasons.add(instanceReason);
                riskLevel = "HIGH";
            }
        }

        if (!reasons.isEmpty()) {
            String reason = String.join("; ", reasons);
            String extraInfo = extra != null && !extra.isEmpty() ? ", " + extra : "";
            findings.add(new String[]{
                    "Class: " + componentClass,
                    type,
                    reason + extraInfo,
                    fields,
                    riskLevel
            });
        }
    }

    private void analyzeComponent(IHeapHolder heapHolder, Object contextClass,
                                   String componentClass, String type,
                                   String extra, String fields,
                                   List<String[]> findings) {
        if (componentClass == null || componentClass.isEmpty()) return;

        List<String> reasons = new ArrayList<String>();
        String riskLevel = "LOW";

        // 1. 类名特征检查
        String classReason = checkSuspicious(componentClass);
        if (classReason != null) {
            reasons.add(classReason);
            riskLevel = "HIGH";
        }

        // 2. ClassLoader 检查
        String clReason = checkClassLoader(heapHolder, componentClass);
        if (clReason != null) {
            reasons.add(clReason);
            riskLevel = "HIGH";
        }

        // 3. 完整性校验（白名单）
        String integrityReason = checkIntegrity(componentClass);
        if (integrityReason != null) {
            reasons.add(integrityReason);
            if (riskLevel.equals("LOW")) riskLevel = "MEDIUM";
        }

        // 4. 字段引用分析（对可疑组件执行）
        if (riskLevel.equals("HIGH") || riskLevel.equals("MEDIUM")) {
            String refReason = checkFieldReferences(heapHolder, contextClass, componentClass);
            if (refReason != null) {
                reasons.add(refReason);
                riskLevel = "HIGH";
            }
        }

        if (!reasons.isEmpty()) {
            String reason = String.join("; ", reasons);
            String extraInfo = extra != null && !extra.isEmpty() ? ", " + extra : "";
            findings.add(new String[]{
                    "Class: " + componentClass,
                    type,
                    reason + extraInfo,
                    fields,
                    riskLevel
            });
        }
    }

    // ========== ClassLoader 检查 ==========

    private String checkClassLoader(IHeapHolder heapHolder, String className) {
        try {
            Object clazz = heapHolder.findClass(className);
            if (clazz == null) return null;

            String clName = heapHolder.getClassLoaderName(clazz);
            if (clName == null || clName.equals("bootstrap")) return null;

            if (safeClassloaders.contains(clName)) return null;

            for (String pkg : safePackages) {
                if (className.startsWith(pkg)) return null;
            }

            return "non-system ClassLoader: " + clName;
        } catch (Exception e) {
            return null;
        }
    }

    // ========== 完整性校验 ==========

    private String checkIntegrity(String className) {
        if (className == null || className.isEmpty()) return null;

        if (safeClasses.contains(className)) return null;

        for (String pkg : safePackages) {
            if (className.startsWith(pkg + ".") || className.startsWith(pkg + "$")) return null;
        }

        String lower = className.toLowerCase();
        if (lower.startsWith("java.") || lower.startsWith("javax.") ||
            lower.startsWith("sun.") || lower.startsWith("com.sun.") ||
            lower.startsWith("jdk.")) return null;

        return "unknown component - not in whitelist";
    }

    // ========== 增强: 字段引用分析 ==========

    private String checkFieldReferences(IHeapHolder heapHolder, Object contextClass, String componentClass) {
        try {
            Object clazz = heapHolder.findClass(componentClass);
            if (clazz == null) return null;

            List<?> instances = heapHolder.getInstances(clazz);
            if (instances == null || instances.isEmpty()) return null;

            Object instance = instances.get(0);

            // 检查实例引用的对象（直接引用危险类）
            List<Object> refs = heapHolder.getReferences(instance);
            if (refs != null) {
                for (Object ref : refs) {
                    String refClassName = heapHolder.getClassName(ref);
                    if (refClassName != null && isDangerousClass(refClassName)) {
                        return "references dangerous class: " + refClassName;
                    }

                    // 增强: 检查引用对象是否是 InvocationHandler（动态代理）
                    if (refClassName != null && refClassName.contains("InvocationHandler")) {
                        return "references InvocationHandler: " + refClassName;
                    }

                    // 增强: 检查引用对象是否包含加密相关类
                    if (refClassName != null && isEncryptionClass(refClassName)) {
                        return "references encryption class: " + refClassName;
                    }
                }
            }

            // 检查字符串字段中的危险模式
            List<?> fields = heapHolder.getFields(clazz);
            if (fields != null) {
                for (Object field : fields) {
                    String fieldName = heapHolder.getFieldName(field);
                    if (fieldName == null) continue;

                    String value = heapHolder.getFieldStringValue(instance, fieldName);
                    if (value != null && containsDangerousPattern(value)) {
                        return "field '" + fieldName + "' contains dangerous pattern";
                    }

                    // 增强: 检查可疑字段名 + 非空值（可能是编码后的 payload）
                    if (SUSPICIOUS_FIELD_NAME_PATTERN.matcher(fieldName).find()) {
                        if (value != null && !value.isEmpty() && value.length() > 10) {
                            return "suspicious field '" + fieldName + "' has non-trivial value";
                        }
                    }
                }
            }

        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    private boolean isDangerousClass(String className) {
        if (className == null) return false;
        for (String dangerous : DANGEROUS_CLASS_NAMES) {
            if (className.equals(dangerous)) return true;
        }
        return false;
    }

    // 增强: 加密相关类检测
    private boolean isEncryptionClass(String className) {
        if (className == null) return false;
        return className.contains("Cipher") ||
               className.contains("SecretKey") ||
               className.contains("Encrypt") ||
               className.contains("Crypto");
    }

    private boolean containsDangerousPattern(String value) {
        if (value == null || value.length() > 10000) return false;
        return DANGEROUS_STRING_PATTERN.matcher(value).find();
    }

    // ========== 增强: 分析实例对象的字段（当注册类名不存在时）==========

    private String analyzeInstanceFields(IHeapHolder heapHolder, Object instance) {
        try {
            String instanceClassName = heapHolder.getInstanceClassName(instance);
            if (instanceClassName == null) return null;

            // 跳过 JDK 核心类
            if (instanceClassName.startsWith("java.") || instanceClassName.startsWith("javax.") ||
                instanceClassName.startsWith("sun.") || instanceClassName.startsWith("jdk.")) {
                return null;
            }

            // 获取实例的所有字段（包括父类）
            List<Object> allFields = new ArrayList<Object>();
            String className = instanceClassName;
            while (className != null && !className.equals("java.lang.Object")) {
                Object currentClass = heapHolder.findClass(className);
                if (currentClass == null) break;
                for (Object f : heapHolder.getFields(currentClass)) {
                    allFields.add(f);
                }
                Object superClass = heapHolder.getSuperClass(currentClass);
                if (superClass == null) break;
                className = heapHolder.getClassName(superClass);
            }

            // 检查每个字段
            for (Object field : allFields) {
                String fieldName = heapHolder.getFieldName(field);
                if (fieldName == null) continue;

                // 检查字段值
                String value = heapHolder.getFieldStringValue(instance, fieldName);
                if (value != null && containsDangerousPattern(value)) {
                    return "instance field '" + fieldName + "' contains dangerous pattern";
                }

                // 检查可疑字段名 + 非空值
                if (SUSPICIOUS_FIELD_NAME_PATTERN.matcher(fieldName).find()) {
                    if (value != null && !value.isEmpty() && value.length() > 10) {
                        return "instance has suspicious field '" + fieldName + "'";
                    }
                }

                // 检查字段引用的对象是否是危险类
                Object fieldValue = heapHolder.getFieldValue(instance, fieldName);
                if (fieldValue != null) {
                    String refClassName = heapHolder.getClassName(fieldValue);
                    if (refClassName != null && isDangerousClass(refClassName)) {
                        return "instance field '" + fieldName + "' references dangerous class: " + refClassName;
                    }
                    if (refClassName != null && isEncryptionClass(refClassName)) {
                        return "instance field '" + fieldName + "' references encryption class: " + refClassName;
                    }
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return null;
    }

    // ========== 类名特征检查 ==========

    private String checkSuspicious(String className) {
        if (className == null || className.isEmpty()) return null;

        List<String> reasons = new ArrayList<String>();

        if (SUSPICIOUS_CLASS_PATTERN.matcher(className).find()) {
            reasons.add("contains suspicious keyword");
        }

        if (!className.contains(".")) {
            reasons.add("no package name");
        }

        String simpleName = className.contains(".") ? className.substring(className.lastIndexOf(".") + 1) : className;
        if (RANDOM_NAME_PATTERN.matcher(simpleName).matches()) {
            reasons.add("random-looking class name");
        }

        if (className.matches(".*\\$[0-9]{2,}$")) {
            reasons.add("anonymous inner class with high index");
        }

        String lower = className.toLowerCase();
        if (lower.contains("templatesimpl") || lower.contains("translet")) {
            reasons.add("TemplatesImpl/Translet related");
        }

        return reasons.isEmpty() ? null : String.join(", ", reasons);
    }

    // ========== Helper methods ==========

    private boolean isKnownSafeClass(String className) {
        if (className == null) return true;
        String lower = className.toLowerCase();

        if (lower.startsWith("java.") || lower.startsWith("javax.") || lower.startsWith("sun.")) return true;
        if (lower.startsWith("com.sun.") || lower.startsWith("jdk.")) return true;
        if (lower.startsWith("org.springframework.") && !lower.contains("proxy")) return true;
        if (lower.startsWith("org.apache.") && !lower.contains("jsp")) return true;
        if (lower.startsWith("com.alibaba.") && !lower.contains("shell")) return true;
        if (lower.startsWith("org.hibernate.")) return true;
        if (lower.startsWith("com.fasterxml.")) return true;
        if (lower.startsWith("org.slf4j.") || lower.startsWith("ch.qos.")) return true;
        if (lower.startsWith("io.netty.")) return true;
        if (lower.startsWith("org.eclipse.")) return true;
        if (lower.startsWith("org.aspectj.")) return true;
        if (lower.contains("configuration") || lower.contains("autoconfigure")) return true;
        if (lower.contains("properties") || lower.contains("config")) return true;
        if (lower.contains("controller") && !lower.contains("evil")) return true;
        if (lower.contains("service") && lower.contains("impl")) return true;
        if (lower.contains("repository") || lower.contains("dao")) return true;

        return false;
    }

    private String dumpFields(IHeapHolder heapHolder, Object instance) {
        StringBuilder sb = new StringBuilder();
        try {
            Object clazz = instance;
            String className = heapHolder.getClassName(clazz);
            List<Object> fields = new ArrayList<Object>();
            while (className != null && !className.equals("java.lang.Object")) {
                Object currentClass = heapHolder.findClass(className);
                if (currentClass == null) break;
                for (Object f : heapHolder.getFields(currentClass)) {
                    fields.add(f);
                }
                Object superClass = heapHolder.getSuperClass(currentClass);
                if (superClass == null) break;
                className = heapHolder.getClassName(superClass);
            }

            for (Object field : fields) {
                String fieldName = heapHolder.getFieldName(field);
                String value = heapHolder.getFieldStringValue(instance, fieldName);
                if (value != null && !value.isEmpty()) {
                    sb.append("    ").append(fieldName).append(" = ");
                    if (value.length() > 200) {
                        sb.append(value.substring(0, 200)).append("...");
                    } else {
                        sb.append(value);
                    }
                    sb.append("\r\n");
                }
            }
        } catch (Exception e) {
            // ignore
        }
        return sb.toString();
    }
}
