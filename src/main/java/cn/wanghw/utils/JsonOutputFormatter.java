package cn.wanghw.utils;

import java.util.*;

public class JsonOutputFormatter {

    public static String format(Map<String, List<String>> results) {
        StringBuilder json = new StringBuilder();
        json.append("{\n");
        json.append("  \"tool\": \"JDumpSpiderPlus\",\n");
        json.append("  \"version\": \"").append(cn.wanghw.Main.VERSION).append("\",\n");
        json.append("  \"timestamp\": \"").append(new java.text.SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss'Z'")
                .format(new java.util.Date())).append("\",\n");
        json.append("  \"results\": {\n");

        List<String> keys = new ArrayList<String>(results.keySet());
        for (int i = 0; i < keys.size(); i++) {
            String key = keys.get(i);
            List<String> values = results.get(key);
            json.append("    \"").append(escapeJson(key)).append("\": ");
            if (values.isEmpty()) {
                json.append("[]");
            } else {
                json.append("[\n");
                for (int j = 0; j < values.size(); j++) {
                    json.append("      \"").append(escapeJson(values.get(j))).append("\"");
                    if (j < values.size() - 1) json.append(",");
                    json.append("\n");
                }
                json.append("    ]");
            }
            if (i < keys.size() - 1) json.append(",");
            json.append("\n");
        }

        json.append("  }\n");
        json.append("}");
        return json.toString();
    }

    public static String formatSpiderResult(String spiderName, String result) {
        Map<String, List<String>> results = new LinkedHashMap<String, List<String>>();
        if (result != null && !result.isEmpty()) {
            results.put(spiderName, Arrays.asList(result.split("\n")));
        }
        return format(results);
    }

    private static String escapeJson(String s) {
        if (s == null) return "";
        return s.replace("\\", "\\\\")
                .replace("\"", "\\\"")
                .replace("\n", "\\n")
                .replace("\r", "\\r")
                .replace("\t", "\\t");
    }
}
