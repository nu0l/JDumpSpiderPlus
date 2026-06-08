package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.Main;

import java.io.File;
import java.io.FileOutputStream;
import java.util.*;
import java.util.regex.Pattern;

public class MemShellDetector01 implements ISpider {

    private static final Pattern SUSPICIOUS_CLASS_PATTERN = Pattern.compile(
            "(shell|evil|inject|memshell|backdoor|behinder|godzilla|ant|冰蝎|哥斯拉|蚁剑)",
            Pattern.CASE_INSENSITIVE);

    private static final Pattern RANDOM_NAME_PATTERN = Pattern.compile(
            "^[a-zA-Z]{1,3}[0-9a-f]{8,}$|^[A-Z][a-z]+[A-Z][a-z]+[0-9]{4,}$|^[a-z]{1,2}[0-9]{10,}$");

    private static final String[] SYSTEM_CLASSLOADERS = {
            "sun.misc.Launcher$AppClassLoader",
            "sun.misc.Launcher$ExtClassLoader",
            "java.lang.ClassLoader",
            "org.apache.catalina.loader.WebappClassLoader",
            "org.apache.catalina.loader.WebappClassLoaderBase"
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

    public String getName() {
        return "MemShellDetector";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        List<String[]> findings = new ArrayList<String[]>();

        try {
            // 1. Filter type
            detectFilterType(heapHolder, findings);

            // 2. Servlet type
            detectServletType(heapHolder, findings);

            // 3. Listener type
            detectListenerType(heapHolder, findings);

            // 4. Controller type (Spring)
            detectControllerType(heapHolder, findings);

            // 5. Interceptor type (Spring)
            detectInterceptorType(heapHolder, findings);

            // 6. WebSocket type
            detectWebSocketType(heapHolder, findings);

            // 7. Agent type
            detectAgentType(heapHolder, findings);

            // 8. Valve type
            detectValveType(heapHolder, findings);

            // format output
            if (!findings.isEmpty()) {
                for (String[] finding : findings) {
                    result.append("[!] ").append(finding[0]).append("\r\n");
                    result.append("  Type: ").append(finding[1]).append("\r\n");
                    result.append("  Reason: ").append(finding[2]).append("\r\n");
                    if (finding.length > 3 && finding[3] != null && !finding[3].isEmpty()) {
                        result.append("  Fields:\r\n").append(finding[3]).append("\r\n");
                    }
                    result.append("\r\n");
                }
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
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

                    // skip known safe filters
                    if (isKnownSafeClass(filterClass)) continue;

                    String reason = checkSuspicious(filterClass);
                    if (reason != null) {
                        String filterName = heapHolder.getFieldStringValue(instance, "name");
                        String fields = dumpFields(heapHolder, instance);
                        String extra = "FilterName=" + filterName;
                        findings.add(new String[]{"Class: " + filterClass, "Filter", reason + ", " + extra, fields});
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }

        // also check filterDefs in StandardContext
        Object ctxClass = heapHolder.findClass("org.apache.catalina.core.StandardContext");
        if (ctxClass != null) {
            for (Object instance : heapHolder.getInstances(ctxClass)) {
                try {
                    Object filterConfigs = heapHolder.getFieldValue(instance, "filterConfigs");
                    if (filterConfigs != null && heapHolder.isMap(filterConfigs)) {
                        HashMap<String, String> configs = heapHolder.arrayDump(heapHolder.getMap(filterConfigs));
                        if (configs != null) {
                            for (Map.Entry<String, String> entry : configs.entrySet()) {
                                // filterConfigs key is filter name, value is ApplicationFilterConfig
                                // we already checked above
                            }
                        }
                    }
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

                if (isKnownSafeClass(servletClass)) continue;

                String reason = checkSuspicious(servletClass);
                if (reason != null) {
                    String name = heapHolder.getFieldStringValue(instance, "name");
                    String fields = dumpFields(heapHolder, instance);
                    findings.add(new String[]{"Class: " + servletClass, "Servlet", reason + ", ServletName=" + name, fields});
                }
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

                // listeners is an Object[] array
                if (listeners instanceof Object[]) {
                    for (Object listener : (Object[]) listeners) {
                        if (listener == null) continue;
                        String listenerClass = heapHolder.getClassName(listener);
                        if (isKnownSafeClass(listenerClass)) continue;

                        String reason = checkSuspicious(listenerClass);
                        if (reason != null) {
                            String fields = dumpFields(heapHolder, listener);
                            findings.add(new String[]{"Class: " + listenerClass, "Listener", reason, fields});
                        }
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

                    // handler is typically "ClassName#methodName"
                    String handlerClass = handler.contains("#") ? handler.substring(0, handler.indexOf("#")) : handler;
                    if (isKnownSafeClass(handlerClass)) continue;

                    String reason = checkSuspicious(handlerClass);
                    if (reason != null) {
                        findings.add(new String[]{"Handler: " + handler, "Controller", reason, ""});
                    }
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

                // interceptors is a List
                if (interceptors instanceof List) {
                    for (Object interceptor : (List) interceptors) {
                        if (interceptor == null) continue;
                        String interceptorClass = heapHolder.getClassName(interceptor);
                        if (isKnownSafeClass(interceptorClass)) continue;

                        String reason = checkSuspicious(interceptorClass);
                        if (reason != null) {
                            String fields = dumpFields(heapHolder, interceptor);
                            findings.add(new String[]{"Class: " + interceptorClass, "Interceptor", reason, fields});
                        }
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

                    if (isKnownSafeClass(endpointClass)) continue;

                    String reason = checkSuspicious(endpointClass);
                    if (reason != null) {
                        findings.add(new String[]{"Class: " + endpointClass, "WebSocket", reason + ", Path=" + entry.getKey(), ""});
                    }
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
                        if (isKnownSafeClass(transformerClass)) continue;

                        String reason = checkSuspicious(transformerClass);
                        if (reason != null) {
                            String fields = dumpFields(heapHolder, transformer);
                            findings.add(new String[]{"Class: " + transformerClass, "Agent(Transformer)", reason, fields});
                        }
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
                            if (isKnownSafeClass(valveClass)) continue;

                            String reason = checkSuspicious(valveClass);
                            if (reason != null) {
                                String fields = dumpFields(heapHolder, valve);
                                findings.add(new String[]{"Class: " + valveClass, "Valve", reason, fields});
                            }
                        }
                    }
                } catch (Exception e) {
                    // ignore
                }
            }
        }
    }

    // ========== Helper methods ==========

    private String checkSuspicious(String className) {
        if (className == null || className.isEmpty()) return null;

        List<String> reasons = new ArrayList<String>();

        // check for suspicious keywords
        if (SUSPICIOUS_CLASS_PATTERN.matcher(className).find()) {
            reasons.add("contains suspicious keyword");
        }

        // check for no package name
        if (!className.contains(".")) {
            reasons.add("no package name");
        }

        // check for random-looking names
        String simpleName = className.contains(".") ? className.substring(className.lastIndexOf(".") + 1) : className;
        if (RANDOM_NAME_PATTERN.matcher(simpleName).matches()) {
            reasons.add("random-looking class name");
        }

        // check for $ anonymous inner class with high number
        if (className.matches(".*\\$[0-9]{2,}$")) {
            reasons.add("anonymous inner class with high index");
        }

        // check for common memshell patterns
        String lower = className.toLowerCase();
        if (lower.contains("templatesimpl") || lower.contains("translet")) {
            reasons.add("TemplatesImpl/Translet related");
        }

        return reasons.isEmpty() ? null : String.join(", ", reasons);
    }

    private boolean isKnownSafeClass(String className) {
        if (className == null) return true;
        String lower = className.toLowerCase();

        // skip JDK classes
        if (lower.startsWith("java.") || lower.startsWith("javax.") || lower.startsWith("sun.")) return true;
        if (lower.startsWith("com.sun.") || lower.startsWith("jdk.")) return true;

        // skip common framework classes
        if (lower.startsWith("org.springframework.") && !lower.contains("proxy")) return true;
        if (lower.startsWith("org.apache.") && !lower.contains("jsp")) return true;
        if (lower.startsWith("com.alibaba.") && !lower.contains("shell")) return true;
        if (lower.startsWith("org.hibernate.")) return true;
        if (lower.startsWith("com.fasterxml.")) return true;
        if (lower.startsWith("org.slf4j.") || lower.startsWith("ch.qos.")) return true;
        if (lower.startsWith("io.netty.")) return true;
        if (lower.startsWith("org.eclipse.")) return true;
        if (lower.startsWith("org.aspectj.")) return true;

        // skip common safe patterns
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
            // get class name
            String className = heapHolder.getClassName(clazz);
            // iterate fields
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
