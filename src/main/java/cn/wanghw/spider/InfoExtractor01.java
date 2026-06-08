package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;

import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InfoExtractor01 implements ISpider {

    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[\\w\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);

    private static final Pattern IP_PATTERN = Pattern.compile(
            "((?:(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?)\\.){3}(?:25[0-5]|2[0-4]\\d|[01]?\\d\\d?))");

    private static final Pattern UNIX_PATH_PATTERN = Pattern.compile(
            "(/(?:[a-zA-Z0-9._-]+/){1,}[a-zA-Z0-9._-]+)");

    private static final Pattern WIN_PATH_PATTERN = Pattern.compile(
            "([a-zA-Z]:\\\\[^\\s\"'<>]+)");

    public String getName() {
        return "InfoExtractor";
    }

    public String sniff(IHeapHolder heapHolder) {
        StringBuilder result = new StringBuilder();
        try {
            Object clazz = heapHolder.findClass("java.lang.String");
            if (clazz == null) return null;

            LinkedHashSet<String> urls = new LinkedHashSet<String>();
            LinkedHashSet<String> ips = new LinkedHashSet<String>();
            LinkedHashSet<String> paths = new LinkedHashSet<String>();

            int count = 0;
            for (Object instance : heapHolder.getInstances(clazz)) {
                String text = heapHolder.toString(instance);
                if (text == null || text.isEmpty()) continue;

                // URL
                Matcher m = URL_PATTERN.matcher(text);
                while (m.find()) {
                    String url = m.group();
                    if (url.length() > 10 && url.length() < 2048) {
                        urls.add(url);
                    }
                }

                // IP (filter out version numbers and common false positives)
                m = IP_PATTERN.matcher(text);
                while (m.find()) {
                    String ip = m.group(1);
                    if (!isFalsePositiveIP(ip)) {
                        ips.add(ip);
                    }
                }

                // Unix path
                m = UNIX_PATH_PATTERN.matcher(text);
                while (m.find()) {
                    String path = m.group();
                    if (path.length() > 3 && !path.startsWith("/dev/") && !path.startsWith("/proc/")
                            && !path.startsWith("/lang/") && !path.startsWith("/util/")
                            && !path.startsWith("/io/") && !path.startsWith("/nio/")
                            && !path.startsWith("/jdk/") && !path.startsWith("/sun/")
                            && !path.startsWith("/management/") && !path.startsWith("/internal/")
                            && !path.startsWith("/time/") && !path.startsWith("/xml.")
                            && !path.startsWith("/www.") && !path.startsWith("/org/")
                            && !path.startsWith("/com/") && !path.startsWith("/javax/")
                            && !path.contains("/JavaVirtualMachines/")
                            && !path.contains("/Contents/Home/")) {
                        paths.add(path);
                    }
                }

                // Windows path
                m = WIN_PATH_PATTERN.matcher(text);
                while (m.find()) {
                    paths.add(m.group());
                }

                count++;
                if (count >= 500000) break;
            }

            if (!urls.isEmpty()) {
                result.append("[URL] (").append(urls.size()).append(")\r\n");
                for (String url : urls) {
                    result.append("  ").append(url).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!ips.isEmpty()) {
                result.append("[IP Address] (").append(ips.size()).append(")\r\n");
                for (String ip : ips) {
                    result.append("  ").append(ip).append("\r\n");
                }
                result.append("\r\n");
            }

            if (!paths.isEmpty()) {
                result.append("[File Path] (").append(paths.size()).append(")\r\n");
                for (String path : paths) {
                    result.append("  ").append(path).append("\r\n");
                }
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }

    private boolean isFalsePositiveIP(String ip) {
        // filter common false positives: version strings, dates, etc.
        String[] parts = ip.split("\\.");
        for (String part : parts) {
            int val = Integer.parseInt(part);
            if (val > 255) return true;
        }
        // filter 0.0.0.0 and 255.255.255.255
        if ("0.0.0.0".equals(ip) || "255.255.255.255".equals(ip)) return true;
        // filter common version-like patterns (e.g., 1.0.0.0, 2.0.0.1)
        if (ip.matches("^[1-9]\\.0\\.0\\.[0-9]$")) return true;
        return false;
    }
}
