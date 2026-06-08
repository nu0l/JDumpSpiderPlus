package cn.wanghw.utils;

import java.io.*;
import java.net.*;
import java.util.HashMap;
import java.util.Map;

public class HttpDownloader {

    private String proxyHost;
    private int proxyPort = -1;
    private Map<String, String> headers = new HashMap<String, String>();
    private int connectTimeout = 30000;
    private int readTimeout = 60000;

    public HttpDownloader() {
    }

    public HttpDownloader setProxy(String proxy) {
        if (proxy != null && !proxy.isEmpty()) {
            if (proxy.startsWith("http://")) {
                proxy = proxy.substring(7);
            }
            if (proxy.startsWith("socks://")) {
                proxy = proxy.substring(8);
            }
            String[] parts = proxy.split(":");
            if (parts.length == 2) {
                this.proxyHost = parts[0];
                this.proxyPort = Integer.parseInt(parts[1]);
            }
        }
        return this;
    }

    public HttpDownloader addHeader(String key, String value) {
        headers.put(key, value);
        return this;
    }

    public HttpDownloader setTimeout(int connectTimeout, int readTimeout) {
        this.connectTimeout = connectTimeout;
        this.readTimeout = readTimeout;
        return this;
    }

    public File download(String url) throws IOException {
        URL downloadUrl = new URL(url);
        HttpURLConnection conn = openConnection(downloadUrl);

        // Set headers
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            conn.setRequestProperty(entry.getKey(), entry.getValue());
        }
        conn.setRequestProperty("User-Agent", "JDumpSpiderPlus/2.1");
        conn.setConnectTimeout(connectTimeout);
        conn.setReadTimeout(readTimeout);

        int responseCode = conn.getResponseCode();
        if (responseCode != 200) {
            throw new IOException("HTTP request failed with status code: " + responseCode);
        }

        // Get filename from URL or Content-Disposition
        String filename = getFilename(conn, url);
        File tempFile = new File(System.getProperty("java.io.tmpdir"), filename);

        // Download file
        try (InputStream in = conn.getInputStream();
             FileOutputStream fos = new FileOutputStream(tempFile)) {
            byte[] buffer = new byte[8192];
            int bytesRead;
            long totalBytes = 0;
            while ((bytesRead = in.read(buffer)) != -1) {
                fos.write(buffer, 0, bytesRead);
                totalBytes += bytesRead;
                if (totalBytes % (1024 * 1024) == 0) {
                    System.out.print("\r[*] Downloaded: " + (totalBytes / 1024 / 1024) + " MB");
                }
            }
            System.out.println("\r[+] Downloaded: " + (totalBytes / 1024 / 1024) + " MB");
        }

        return tempFile;
    }

    private HttpURLConnection openConnection(URL url) throws IOException {
        if (proxyHost != null && proxyPort > 0) {
            Proxy proxy = new Proxy(Proxy.Type.HTTP, new InetSocketAddress(proxyHost, proxyPort));
            return (HttpURLConnection) url.openConnection(proxy);
        }
        return (HttpURLConnection) url.openConnection();
    }

    private String getFilename(HttpURLConnection conn, String urlStr) {
        // Try Content-Disposition header
        String disposition = conn.getHeaderField("Content-Disposition");
        if (disposition != null && disposition.contains("filename=")) {
            int start = disposition.indexOf("filename=") + 9;
            int end = disposition.indexOf(";", start);
            if (end == -1) end = disposition.length();
            String filename = disposition.substring(start, end).trim();
            if (filename.startsWith("\"") && filename.endsWith("\"")) {
                filename = filename.substring(1, filename.length() - 1);
            }
            return filename;
        }

        // Extract from URL
        try {
            URL url = new URL(urlStr);
            String path = url.getPath();
            if (path.contains("/")) {
                path = path.substring(path.lastIndexOf("/") + 1);
            }
            if (!path.isEmpty() && path.contains(".")) {
                return path;
            }
        } catch (Exception e) {
            // Ignore
        }
        return "heapdump_" + System.currentTimeMillis() + ".hprof";
    }
}
