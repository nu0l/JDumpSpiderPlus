package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;

import java.util.LinkedHashSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InfoExtractor01 implements ISpider {

    // URL pattern - more strict
    private static final Pattern URL_PATTERN = Pattern.compile(
            "https?://[a-zA-Z0-9\\-._~:/?#\\[\\]@!$&'()*+,;=%]+", Pattern.CASE_INSENSITIVE);

    // IP pattern - strict, no leading zeros
    private static final Pattern IP_PATTERN = Pattern.compile(
            "(?<![\\d.])((?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|[1-9])(?:\\.(?:25[0-5]|2[0-4]\\d|1\\d{2}|[1-9]\\d|[0-9])){3})(?![\\d.])");

    // Unix path pattern - require at least 2 segments
    private static final Pattern UNIX_PATH_PATTERN = Pattern.compile(
            "(/(?:[a-zA-Z0-9._-]+/){1,}[a-zA-Z0-9._-]+)");

    // Windows path pattern
    private static final Pattern WIN_PATH_PATTERN = Pattern.compile(
            "([a-zA-Z]:\\\\[^\\s\"'<>]+)");

    // Known false positive URL domains
    private static final String[] URL_BLACKLIST_DOMAINS = {
            "w3.org", "xml.org", "apache.org/xml", "java.sun.com/xml",
            "oracle.com/xml", "javax.xml", "logback.qos.ch", "slf4j.org",
            "digicert.com", "ocsp.", "crl.", "cacerts.",
            "schemas.openxmlformats.org", "schemas.xmlsoap.org",
            "schemas.microsoft.com", "bugreport.sun.com", "bugreport.java.com",
            "null.oracle.com", "www.omg.org", "openuri.org",
            "mybatis.org/dtd", "www.d-trust.net", "crl.dhimyotis.com",
            "crl.certigna.fr", "crl.usertrust.com", "crl.chambersign.org",
            "crl.comodo.net", "crl.comodoca.com", "crl.xrampsecurity.com",
            "crl.securetrust.com", "ocsp.quovadisoffshore.com",
            "invalid.uri", "www.liquibase.org/xml",
            // Additional filters
            "java.oracle.com", "java.sun.com/jaxp", "java.sun.com/dom",
            "xml.apache.org", "www.apache.org/internal",
            "www.bea.com", "commons.apache.org/proper",
            "en.wikipedia.org", "docs.liquibase.com",
            "www.eclipse.org/aspectj", "hub.liquibase.com",
            "null.oracle.com"
    };

    // Known OID prefixes (X.509 certificate object identifiers)
    private static final String[] OID_PREFIXES = {
            "1.3.6.", "2.5.29.", "2.5.4.", "2.5.8.",
            "1.2.840.", "1.3.14.", "1.3.36.", "1.3.101.",
            "1.3.132.", "3.2.8.", "4.1.42.", "5.5.7.",
            "49.1.", "49.2.", "045.", "040.", "009.",
            "00.100.", "40.1.", "0.9.", "2.16.",
            "1.0.", "1.1.", "1.2.", "1.3.", "1.4.", "1.5.",
            "2.1.", "2.2.", "2.3.", "2.4.", "2.5.", "2.6.",
            "2.7.", "2.8.", "2.9.", "2.10.", "2.11.",
            "2.23.", "2.25.", "2.54.",
            "3.4.", "7.1.", "7.2.", "7.3.", "7.4.", "7.5.",
            "8.1.", "8.2.", "8.3.", "8.4.",
            "9.1.", "9.2.", "9.3.", "9.4.",
            "11.10.", "11.11.", "11.12.",
            "148.0.", "148.1.", "148.2."
    };

    // Known false positive path prefixes
    private static final String[] PATH_BLACKLIST_PREFIXES = {
            "/lang/", "/util/", "/io/", "/nio/", "/jdk/", "/sun/",
            "/management/", "/internal/", "/time/", "/xml.", "/www.",
            "/org/", "/com/", "/javax/", "/swing/", "/services/",
            "/springframework/", "/baomidou/", "/mybatis/", "/apache/",
            "/slf4j/", "/logback/", "/undertow/", "/chanjar/",
            "/binarywang/", "/flowable/", "/iocoder/",
            "/BOOT-INF/", "/WEB-INF/", "/META-INF/",
            "/tmp/", "/dev/", "/proc/", "/sys/",
            "/data/appdata/java/", "/usr/java/", "/usr/lib",
            "/etc/ssl/", "/etc/pki/",
            // Java class paths
            "/security/", "/collections/", "/beans/", "/scene/",
            "/embed/", "/oracle/", "/GCM/", "/RSA/", "/AES/",
            "/DES/", "/SHA/", "/MD5/", "/HMAC/",
            "/qos/", "/yaml/", "/el/", "/jboss/", "/joda/",
            "/fasterxml/", "/validation/", "/annotation/",
            "/reflect/", "/schema/", "/parser/", "/w3c/",
            "/appender/", "/logger/", "/if/", "/root/level",
            "/root/appender-ref", "/validator/", "/swagger/",
            // API endpoint patterns
            "/v3/", "/api/", "/admin-api/", "/infra/", "/system/",
            "/demo0", "/oauth2/", "/actuator/",
            // Timezone paths
            "/Africa/", "/America/", "/Antarctica/", "/Arctic/",
            "/Asia/", "/Atlantic/", "/Australia/", "/Europe/",
            "/Indian/", "/Pacific/", "/Etc/", "/Brazil/",
            "/Canada/", "/Chile/", "/Mexico/", "/US/",
            "/Argentina/", "/North_Dakota/", "/South_Dakota/",
            "/Kentucky/", "/Indiana/", "/Montana/",
            // Date format patterns
            "/M/", "/H/", "/s/", "/S/", "/E/", "/G/",
            "/a/", "/k/", "/K/", "/z/", "/Z/",
            "/MMM/",
            // Crypto algorithm names
            "/NoPadding/", "/PKCS1Padding/", "/ECB/", "/CBC/",
            "/GCM/", "/CTR/", "/OFB/", "/CFB/",
            // URL-like paths (containing dots in first segment)
            "/java.sun.com/", "/javax.xml.", "/apache.org/",
            "/bugreport.sun.com/", "/null.oracle.com/",
            "/api.holdai.top/", "/yutou.mynatapp.cc/",
            "/lsjz.tzzhzjxt.com/", "/dashboard.yudao.",
            "/doc.iocoder.cn/", "/www.iocoder.cn/",
            "/test.yudao.iocoder.cn/", "/s3.cn-south-1.",
            "/msdn.microsoft.com/", "/www.microsoft.com/",
            "/purl.org/", "/ns.adobe.com/", "/www.adobe.com/",
            "/www.isotc211.org/", "/xspf.org/", "/www.gribuser.ru/",
            "/iptc.org/", "/earth.google.com/",
            "/docs.liquibase.com/", "/hub.liquibase.com/",
            "/www.liquibase.com/", "/www.liquibase.org/",
            "/www.omg.org/", "/schemas.openxmlformats.org/",
            "/schemas.xmlsoap.org/", "/schemas.microsoft.com/",
            "/commons.apache.org/", "/xml.apache.org/"
    };

    // Known false positive path suffixes
    private static final String[] PATH_BLACKLIST_SUFFIXES = {
            ".class", ".jar", ".so", ".dll", ".dylib",
            ".dtd", ".xsd", ".xsl", ".xml",
            ".properties", ".yml", ".yaml",
            ".html", ".htm", ".css", ".js",
            ".png", ".jpg", ".gif", ".ico",
            ".crt", ".cer", ".pem", ".key", ".crl"
    };

    // Known Java package prefixes (for filtering class paths)
    private static final String[] JAVA_PACKAGE_PREFIXES = {
            "logback", "snakeyaml", "jboss", "joda", "fasterxml",
            "slf4j", "log4j", "commons", "jackson", "gson",
            "guava", "netty", "jetty", "undertow", "tomcat",
            "hibernate", "mybatis", "spring", "aspectj",
            "validation", "el", "xml", "json", "yaml",
            "annotation", "reflect", "schema", "parser"
    };

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
                if (text == null || text.isEmpty() || text.length() > 10000) continue;

                // URL - only match interesting URLs
                Matcher m = URL_PATTERN.matcher(text);
                while (m.find()) {
                    String url = m.group();
                    if (url.length() > 15 && url.length() < 2048 && isValidUrl(url)) {
                        urls.add(url);
                    }
                }

                // IP - strict validation
                m = IP_PATTERN.matcher(text);
                while (m.find()) {
                    String ip = m.group(1);
                    if (isValidIP(ip)) {
                        ips.add(ip);
                    }
                }

                // Unix path - filter class paths and system paths
                m = UNIX_PATH_PATTERN.matcher(text);
                while (m.find()) {
                    String path = m.group();
                    if (path.length() > 4 && path.length() < 500 && isValidPath(path)) {
                        paths.add(path);
                    }
                }

                // Windows path
                m = WIN_PATH_PATTERN.matcher(text);
                while (m.find()) {
                    String path = m.group();
                    if (path.length() > 4 && path.length() < 500 && isValidWindowsPath(path)) {
                        paths.add(path);
                    }
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

    private boolean isValidUrl(String url) {
        String lower = url.toLowerCase();

        // filter blacklisted domains
        for (String domain : URL_BLACKLIST_DOMAINS) {
            if (lower.contains(domain)) return false;
        }

        // filter URLs that are just schema references
        if (lower.contains("#") && !lower.contains("?")) {
            // fragment-only URLs are usually documentation anchors
            String afterHash = lower.substring(lower.indexOf('#'));
            if (afterHash.length() < 30) return false;
        }

        // filter URLs ending with file extensions that are not interesting
        if (lower.matches(".*\\.(dtd|xsd|xsl|xml|wsdl|crl|crt|cer|pem)$")) return false;

        // keep URLs with ports (likely API endpoints)
        if (url.matches(".*:\\d{2,5}(/|$).*")) return true;

        // keep URLs with paths that look like API endpoints
        if (lower.contains("/api/") || lower.contains("/admin") || lower.contains("/actuator") ||
            lower.contains("/oauth") || lower.contains("/token") || lower.contains("/login") ||
            lower.contains("/auth") || lower.contains("/user") || lower.contains("/notify") ||
            lower.contains("/callback") || lower.contains("/webhook") || lower.contains("/sms") ||
            lower.contains("/pay") || lower.contains("/order")) return true;

        // keep URLs that look like service endpoints
        if (lower.contains("://api.") || lower.contains("://open.") || lower.contains("://sms.") ||
            lower.contains("://oauth.") || lower.contains("://auth.")) return true;

        // filter generic documentation/info URLs
        if (lower.contains("/doc") || lower.contains("/wiki") || lower.contains("/help") ||
            lower.contains("/manual") || lower.contains("/codes.html") || lower.contains("/download")) return false;

        return true;
    }

    private boolean isValidIP(String ip) {
        // filter 0.0.0.0 and 255.255.255.255
        if ("0.0.0.0".equals(ip) || "255.255.255.255".equals(ip)) return false;

        String[] parts = ip.split("\\.");
        int[] nums = new int[4];
        for (int i = 0; i < 4; i++) {
            nums[i] = Integer.parseInt(parts[i]);
        }

        // filter IPs with leading zeros (OIDs like 045.x.x.x)
        for (String part : parts) {
            if (part.length() > 1 && part.startsWith("0")) return false;
        }

        // filter OID patterns
        for (String prefix : OID_PREFIXES) {
            if (ip.startsWith(prefix)) return false;
        }

        // filter IPs where first octet is 0
        if (nums[0] == 0) return false;

        // filter link-local
        if (nums[0] == 169 && nums[1] == 254) return false;

        // filter multicast
        if (nums[0] >= 224 && nums[0] <= 239) return false;

        // filter reserved
        if (nums[0] == 192 && nums[1] == 0 && nums[2] == 2) return false;
        if (nums[0] == 198 && nums[1] == 51 && nums[2] == 100) return false;
        if (nums[0] == 203 && nums[1] == 0 && nums[2] == 113) return false;
        if (nums[0] >= 240) return false;

        // filter common version-like patterns (1.0.0.0, 2.0.0.1, etc.)
        if (nums[0] <= 9 && nums[1] == 0 && nums[2] == 0) return false;
        if (nums[0] <= 9 && nums[2] == 0 && nums[3] <= 9) return false;

        // filter patterns that look like version numbers
        // All octets < 10 is suspicious
        if (nums[0] < 10 && nums[1] < 10 && nums[2] < 10 && nums[3] < 10) {
            // Only keep 127.0.0.1 and similar
            if (nums[0] != 127) return false;
        }

        // filter single-digit first octet with small values (likely OID)
        if (nums[0] <= 5 && nums[1] <= 10 && nums[2] <= 10) return false;

        return true;
    }

    private boolean isValidPath(String path) {
        // filter blacklisted prefixes
        for (String prefix : PATH_BLACKLIST_PREFIXES) {
            if (path.startsWith(prefix)) return false;
        }

        // filter blacklisted suffixes
        String lower = path.toLowerCase();
        for (String suffix : PATH_BLACKLIST_SUFFIXES) {
            if (lower.endsWith(suffix)) return false;
        }

        // filter paths that look like Java class paths
        String[] segments = path.split("/");
        if (segments.length > 1) {
            String firstSegment = segments[1].toLowerCase();
            for (String pkg : JAVA_PACKAGE_PREFIXES) {
                if (firstSegment.equals(pkg) || firstSegment.startsWith(pkg + ".")) return false;
            }
        }

        // filter paths with too many segments (likely class paths)
        if (segments.length > 6) return false;

        // filter paths that are just class names (contain dots but no slashes in the name part)
        if (segments.length > 0) {
            String lastSegment = segments[segments.length - 1];
            // filter class-like names (e.g., javax.swing.JButton)
            if (lastSegment.contains(".") && !lastSegment.contains("-")) {
                String ext = lastSegment.substring(lastSegment.lastIndexOf('.'));
                if (ext.length() <= 4) return false;
            }
            // filter CamelCase class names
            if (lastSegment.matches("[A-Z][a-zA-Z]+[A-Z][a-zA-Z]+.*")) return false;
        }

        // filter paths that look like URL paths (first segment contains dots)
        if (segments.length > 1 && segments[1].contains(".")) {
            return false;
        }

        // Only keep paths that start with known real directories
        // This is the most reliable way to filter out class paths and API endpoints
        String[] realDirPrefixes = {
                "/tmp/", "/var/", "/home/", "/opt/", "/etc/", "/usr/local/",
                "/data/", "/root/", "/mnt/", "/srv/", "/log/",
                "/proc/", "/sys/", "/dev/"
        };

        for (String prefix : realDirPrefixes) {
            if (path.startsWith(prefix)) return true;
        }

        // Keep common system paths
        String[] systemPaths = {
                "/bin/bash", "/bin/sh", "/bin/dash", "/bin/zsh",
                "/usr/bin/nohup", "/usr/bin/java", "/usr/bin/env",
                "/usr/bin/python", "/usr/bin/perl", "/usr/bin/ruby",
                "/usr/local/sbin", "/usr/local/bin",
                "/usr/sbin", "/usr/bin", "/sbin", "/bin",
                "/root/bin", "/lib/security/java.policy"
        };

        for (String sysPath : systemPaths) {
            if (path.equals(sysPath)) return true;
        }

        // Keep paths with interesting file extensions
        String[] interestingExtensions = {
                ".log", ".txt", ".conf", ".cfg", ".ini", ".env",
                ".sh", ".py", ".php", ".jsp", ".sql", ".db",
                ".key", ".pem", ".crt", ".cer", ".p12", ".jks",
                ".properties", ".yml", ".yaml", ".xml", ".json"
        };

        for (String ext : interestingExtensions) {
            if (lower.endsWith(ext)) return true;
        }

        // Filter everything else (class paths, API endpoints, etc.)
        return false;
    }

    private boolean isValidWindowsPath(String path) {
        // filter paths with suspicious characters
        if (path.contains("$")) return false;

        // keep common Windows paths
        if (path.contains("\\Users\\") || path.contains("\\Windows\\") ||
            path.contains("\\Program Files") || path.contains("\\temp\\") ||
            path.contains("\\config\\") || path.contains("\\logs\\")) return true;

        return path.length() > 6;
    }
}
