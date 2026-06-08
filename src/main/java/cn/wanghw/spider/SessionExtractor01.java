package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.*;

public class SessionExtractor01 implements ISpider {

    private static final String[][] SESSION_CLASSES = {
            {"org.apache.catalina.session.StandardSession", "id", "creationTime", "lastAccessedTime", "maxInactiveInterval"},
            {"org.springframework.session.MapSession", "id", "creationTime", "lastAccessedTime", "maxInactiveInterval"},
            {"org.apache.shiro.session.mgt.SimpleSession", "id", "startTimestamp", "lastAccessTime", "timeout"},
            {"org.apache.catalina.session.StandardManager", "sessionId", "sessionTimeout"},
    };

    private static final String[] SECURITY_CONTEXT_CLASSES = {
            "org.springframework.security.core.context.SecurityContextImpl",
            "org.apache.shiro.subject.support.DefaultSubjectContext",
    };

    public String getName() {
        return "SessionExtractor";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        try {
            // 1. extract from known session classes
            for (String[] classInfo : SESSION_CLASSES) {
                Object clazz = heapHolder.findClass(classInfo[0]);
                if (clazz == null) continue;

                for (Object instance : heapHolder.getInstances(clazz)) {
                    HashMap<String, String> values = new HashMap<String, String>();
                    for (int i = 1; i < classInfo.length; i++) {
                        try {
                            String val = heapHolder.getFieldStringValue(instance, classInfo[i]);
                            if (val != null && !val.isEmpty()) {
                                values.put(classInfo[i], val);
                            }
                        } catch (Exception e) {
                            // field not found
                        }
                    }

                    // try to get session attributes map
                    try {
                        Object attrs = heapHolder.getFieldValue(instance, "attributes");
                        if (attrs != null && heapHolder.isMap(attrs)) {
                            HashMap<String, String> attrMap = heapHolder.arrayDump(heapHolder.getMap(attrs));
                            if (attrMap != null && !attrMap.isEmpty()) {
                                for (Map.Entry<String, String> entry : attrMap.entrySet()) {
                                    values.put("attr." + entry.getKey(), entry.getValue());
                                }
                            }
                        }
                    } catch (Exception e) {
                        // ignore
                    }

                    if (!values.isEmpty()) {
                        result.append("[").append(classInfo[0]).append("]\r\n");
                        result.append(HashMapUtils.dumpString(values, false));
                        result.append("\r\n");
                    }
                }
            }

            // 2. extract security context
            for (String className : SECURITY_CONTEXT_CLASSES) {
                Object clazz = heapHolder.findClass(className);
                if (clazz == null) continue;

                for (Object instance : heapHolder.getInstances(clazz)) {
                    HashMap<String, String> values = new HashMap<String, String>();
                    values.put("class", className);

                    try {
                        String auth = heapHolder.getFieldStringValue(instance, "authentication");
                        if (auth != null) values.put("authentication", auth);
                    } catch (Exception e) {}

                    try {
                        String principal = heapHolder.getFieldStringValue(instance, "principal");
                        if (principal != null) values.put("principal", principal);
                    } catch (Exception e) {}

                    if (values.size() > 1) {
                        result.append("[").append(className).append("]\r\n");
                        result.append(HashMapUtils.dumpString(values, false));
                        result.append("\r\n");
                    }
                }
            }

            // 3. scan map entries for session-related keys
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

            LinkedHashMap<String, String> sessionEntries = new LinkedHashMap<String, String>();
            for (Object clazz : mapEntryClasses) {
                for (Object instance : heapHolder.getInstances(clazz)) {
                    String key = heapHolder.getFieldStringValue(instance, "key");
                    if (key != null && isSessionRelated(key)) {
                        String val = heapHolder.getFieldStringValue(instance, "value");
                        if (val != null && !val.isEmpty() && val.length() < 500) {
                            sessionEntries.put(key, val);
                        }
                    }
                }
                // also check subclasses
                Object[] subClasses = heapHolder.getSubClasses(clazz);
                if (subClasses != null) {
                    for (Object subClazz : subClasses) {
                        for (Object instance : heapHolder.getInstances(subClazz)) {
                            String key = heapHolder.getFieldStringValue(instance, "key");
                            if (key != null && isSessionRelated(key)) {
                                String val = heapHolder.getFieldStringValue(instance, "value");
                                if (val != null && !val.isEmpty() && val.length() < 500) {
                                    sessionEntries.put(key, val);
                                }
                            }
                        }
                    }
                }
            }

            if (!sessionEntries.isEmpty()) {
                result.append("[Session Entries]\r\n");
                result.append(HashMapUtils.dumpString(sessionEntries, false));
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }

    private boolean isSessionRelated(String key) {
        String lower = key.toLowerCase();
        return lower.contains("session") || lower.equals("jsessionid")
                || lower.contains("sessionid") || lower.contains("session_id")
                || lower.equals("sid") || lower.equals("token");
    }
}
