package cn.wanghw.utils;

import java.io.*;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * Excel报告生成器
 * 生成CSV格式的Excel报告（可直接用Excel打开）
 */
public class ExcelReportGenerator {

    /**
     * 生成CSV格式的Excel报告
     */
    public static String generate(String heapFile, Map<String, List<String>> results) {
        StringBuilder csv = new StringBuilder();

        // BOM头（让Excel正确识别UTF-8编码）
        csv.append("﻿");

        // 报告头部信息
        csv.append("=== JDumpSpiderPlus Scan Report ===\n");
        csv.append("Heap File,").append(escapeCsv(heapFile)).append("\n");
        csv.append("Scan Time,").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append("\n");
        csv.append("Version,").append(cn.wanghw.Main.VERSION).append("\n");
        csv.append("\n");

        // 统计摘要
        csv.append("=== Summary ===\n");
        csv.append("Category,Count,Severity\n");
        int totalItems = 0;
        for (Map.Entry<String, List<String>> entry : results.entrySet()) {
            String category = entry.getKey();
            List<String> values = entry.getValue();
            String severity = getSeverity(category);
            csv.append("\"").append(escapeCsv(category)).append("\",");
            csv.append(values.size()).append(",");
            csv.append("\"").append(severity).append("\"\n");
            totalItems += values.size();
        }
        csv.append("\"Total\",").append(totalItems).append(",\"-\"\n");
        csv.append("\n");

        // 详细数据（去重）
        csv.append("=== Details ===\n");
        csv.append("Category,Item,Severity\n");

        Set<String> globalSeen = new LinkedHashSet<String>();

        for (Map.Entry<String, List<String>> entry : results.entrySet()) {
            String category = entry.getKey();
            List<String> values = entry.getValue();
            String severity = getSeverity(category);

            // 去重
            Set<String> seen = new LinkedHashSet<String>();
            for (String value : values) {
                String trimmed = value.trim();
                if (!trimmed.isEmpty() && !trimmed.equals("not found!") && !seen.contains(trimmed)) {
                    seen.add(trimmed);
                    globalSeen.add(category + "|" + trimmed);

                    csv.append("\"").append(escapeCsv(category)).append("\",");
                    csv.append("\"").append(escapeCsv(trimmed)).append("\",");
                    csv.append("\"").append(severity).append("\"\n");
                }
            }
        }

        return csv.toString();
    }

    /**
     * 保存到文件
     */
    public static void saveToFile(String content, String filePath) {
        try {
            File file = new File(filePath);
            File parentDir = file.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
            FileWriter writer = new FileWriter(file);
            writer.write(content);
            writer.close();
        } catch (Exception e) {
            System.out.println("[-] Failed to save Excel report: " + e.getMessage());
        }
    }

    /**
     * 根据类别获取严重程度
     */
    private static String getSeverity(String category) {
        String lower = category.toLowerCase();
        // HIGH: 密码、密钥、凭证、Token
        if (lower.contains("password") || lower.contains("secret") || lower.contains("key") ||
            lower.contains("credential") || lower.contains("token") || lower.contains("private") ||
            lower.contains("accesskey") || lower.contains("secretkey") || lower.contains("shiro")) {
            return "HIGH";
        }
        // MEDIUM: 邮箱、手机号、身份证、地址、姓名、数据库配置
        if (lower.contains("email") || lower.contains("phone") || lower.contains("id card") ||
            lower.contains("idcard") || lower.contains("address") || lower.contains("name") ||
            lower.contains("user") || lower.contains("datasource") || lower.contains("jdbc") ||
            lower.contains("redis") || lower.contains("mongo") || lower.contains("kafka") ||
            lower.contains("rabbit") || lower.contains("elasticsearch") || lower.contains("nacos")) {
            return "MEDIUM";
        }
        // LOW: URL、链接、路径、域名、IP
        if (lower.contains("url") || lower.contains("link") || lower.contains("path") ||
            lower.contains("domain") || lower.contains("ip") || lower.contains("mac")) {
            return "LOW";
        }
        return "INFO";
    }

    /**
     * 转义CSV特殊字符
     */
    private static String escapeCsv(String text) {
        if (text == null) return "";
        // CSV中如果包含双引号，需要转义为两个双引号
        return text.replace("\"", "\"\"");
    }
}
