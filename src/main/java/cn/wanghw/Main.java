package cn.wanghw;

import cn.wanghw.spider.*;
import cn.wanghw.utils.ConfigLoader;
import cn.wanghw.utils.ExcelReportGenerator;
import cn.wanghw.utils.HttpDownloader;
import cn.wanghw.utils.JsonOutputFormatter;
import org.graalvm.visualvm.lib.jfluid.heap.GraalvmHeapHolder;
import org.netbeans.lib.profiler.heap.NetbeansHeapHolder;

import java.io.*;
import java.nio.file.Path;
import java.util.*;

public class Main {

    public static final String VERSION = "2.4.0";
    private File heapfile;
    private final List<String> flag = new LinkedList<String>();
    static PrintStream out = null;
    private static String rulesPath = null;
    private static String heapFilePath = null;
    private static String outputFormat = "text"; // text or json
    private static ConfigLoader config = null;
    private static List<String> regexPatterns = new ArrayList<String>();
    private static String decryptKey = null;
    private static String decryptDictPath = null;

    public static String getRulesPath() {
        return rulesPath;
    }

    public static String getHeapFilePath() {
        return heapFilePath;
    }

    public static ConfigLoader getConfig() {
        return config;
    }

    public static List<String> getRegexPatterns() {
        return regexPatterns;
    }

    public static String getDecryptKey() {
        return decryptKey;
    }

    public static String getDecryptDictPath() {
        return decryptDictPath;
    }

    public static String run(String[] args) throws Exception {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        if (out == null) {
            out = new PrintStream(bout);
        }

        // 加载配置文件
        config = new ConfigLoader();
        config.load();

        if (args.length < 1) {
            printUsage();
            return "";
        }

        // Parse arguments
        List<String> argList = new ArrayList<String>(Arrays.asList(args));
        Main _main = new Main();

        // Check for help
        if (argList.contains("-h") || argList.contains("--help")) {
            printUsage();
            return "";
        }

        // Check for URL download mode
        if (argList.contains("-u")) {
            int urlIndex = argList.indexOf("-u");
            if (urlIndex + 1 >= argList.size()) {
                System.out.println("[-] Missing URL after -u");
                return "";
            }
            String url = argList.get(urlIndex + 1);
            argList.remove(urlIndex + 1);
            argList.remove(urlIndex);

            // Setup downloader
            HttpDownloader downloader = new HttpDownloader();
            if (argList.contains("--proxy")) {
                int proxyIndex = argList.indexOf("--proxy");
                if (proxyIndex + 1 < argList.size()) {
                    downloader.setProxy(argList.get(proxyIndex + 1));
                    argList.remove(proxyIndex + 1);
                    argList.remove(proxyIndex);
                }
            }
            if (argList.contains("--header")) {
                int headerIndex = argList.indexOf("--header");
                while (headerIndex != -1 && headerIndex + 1 < argList.size()) {
                    String headerValue = argList.get(headerIndex + 1);
                    int colonIndex = headerValue.indexOf(":");
                    if (colonIndex > 0) {
                        downloader.addHeader(headerValue.substring(0, colonIndex).trim(),
                                headerValue.substring(colonIndex + 1).trim());
                    }
                    argList.remove(headerIndex + 1);
                    argList.remove(headerIndex);
                    headerIndex = argList.indexOf("--header");
                }
            }

            // Download heapdump
            System.out.println("[*] Downloading heapdump from: " + url);
            try {
                _main.heapfile = downloader.download(url);
                System.out.println("[+] Downloaded to: " + _main.heapfile.getAbsolutePath());
            } catch (Exception e) {
                System.out.println("[-] Download failed: " + e.getMessage());
                return "";
            }
        } else {
            // Local file mode
            if (argList.isEmpty()) {
                printUsage();
                return "";
            }
            _main.heapfile = new File(argList.get(0));
            argList.remove(0);
            if (!_main.heapfile.exists() || !_main.heapfile.isFile()) {
                System.out.println("[-] File not found: " + _main.heapfile.getAbsolutePath());
                return "";
            }
        }

        // Parse remaining flags
        _main.flag.addAll(argList);

        // Check for output format
        if (_main.flag.contains("--format")) {
            int formatIndex = _main.flag.indexOf("--format");
            if (formatIndex + 1 < _main.flag.size()) {
                outputFormat = _main.flag.get(formatIndex + 1).toLowerCase();
                _main.flag.remove(formatIndex + 1);
                _main.flag.remove(formatIndex);
            }
        }

        // Check for decrypt key
        if (_main.flag.contains("--decrypt-key")) {
            int keyIndex = _main.flag.indexOf("--decrypt-key");
            if (keyIndex + 1 < _main.flag.size()) {
                decryptKey = _main.flag.get(keyIndex + 1);
                _main.flag.remove(keyIndex + 1);
                _main.flag.remove(keyIndex);
            }
        }

        // Check for decrypt dictionary
        if (_main.flag.contains("--decrypt-dict")) {
            int dictIndex = _main.flag.indexOf("--decrypt-dict");
            if (dictIndex + 1 < _main.flag.size()) {
                decryptDictPath = _main.flag.get(dictIndex + 1);
                _main.flag.remove(dictIndex + 1);
                _main.flag.remove(dictIndex);
            }
        }

        // Check for regex patterns (-reg)
        while (_main.flag.contains("-reg")) {
            int regIndex = _main.flag.indexOf("-reg");
            if (regIndex + 1 < _main.flag.size()) {
                regexPatterns.add(_main.flag.get(regIndex + 1));
                _main.flag.remove(regIndex + 1);
                _main.flag.remove(regIndex);
            } else {
                System.out.println("[-] Missing regex pattern after -reg");
                _main.flag.remove(regIndex);
                break;
            }
        }

        _main.call(out);
        return bout.toString();
    }

    private static void printUsage() {
        System.out.println("JDumpSpiderPlus v" + VERSION + " - HeapDump Sensitive Information Extractor");
        System.out.println();
        System.out.println("Usage:");
        System.out.println("  java -jar JDumpSpiderPlus.jar <heapfile> [options]");
        System.out.println("  java -jar JDumpSpiderPlus.jar -u <url> [options]");
        System.out.println();
        System.out.println("Options:");
        System.out.println("  -u <url>              Download heapdump from URL");
        System.out.println("  --proxy <proxy>       Set proxy (http://host:port)");
        System.out.println("  --header <header>     Add HTTP header (can be used multiple times)");
        System.out.println("  --rules <path>        Load custom HaE rules YAML file");
        System.out.println("  --format <format>     Output format: text (default), json, excel");
        System.out.println("  -out <path>           Output results to file");
        System.out.println("  -reg <pattern>        Regex search pattern (can be used multiple times)");
        System.out.println("  --decrypt-key <key>   Decryption key for encrypted configs");
        System.out.println("  --decrypt-dict <path> Decryption dictionary file (one password per line)");
        System.out.println("  export-strings        Export all strings from heap dump");
        System.out.println("  -h, --help            Show this help message");
        System.out.println();
        System.out.println("Examples:");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof");
        System.out.println("  java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump");
        System.out.println("  java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump --proxy http://127.0.0.1:8080");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof --format json");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof --format excel");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof -reg \"jdbc:[a-z:]+://[^\\s]+\"");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof -reg \"password\" -reg \"secret.*=.*\"");
        System.out.println("  java -jar JDumpSpiderPlus.jar heapdump.hprof --decrypt-key mySecretKey");
    }

    public static String runAsync(final String[] args) throws Exception {
        if (args.length < 2)
            return "In async call, you must give a result file path";
        Thread thread = new Thread(new Runnable() {
            public void run() {
                try {
                    String result = Main.run(args);
                    try (FileOutputStream fos = new FileOutputStream(args[1])) {
                        fos.write(result.getBytes());
                    }
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            }
        });
        thread.setDaemon(true);
        thread.start();
        return "start export thread:" + thread.getName();
    }

    public static void main(String[] args) throws Exception {
        out = System.out;
        run(args);
    }

    private ISpider[] allSpiders = new ISpider[]{
            new DataSource01(),
            new DataSource02(),
            new DataSource03(),
            new DataSource04(),
            new DataSource05(),
            new Redis01(),
            new Redis02(),
            new Redis03(),
            new MongoDB01(),
            new Kafka01(),
            new RabbitMQ01(),
            new Elasticsearch01(),
            new Nacos01(),
            new ShiroKey01(),
            new PropertySource01(),
            new PropertySource02(),
            new PropertySource03(),
            new PropertySource04(),
            new PropertySource05(),
            new EnvProperty01(),
            new OSS01(),
            new UserPassSearcher01(),
            new CookieThief(),
            new AuthThief(),
            new InfoExtractor01(),
            new MemShellDetector01(),
            new JwtKeyExtractor01(),
            new SessionExtractor01(),
            new EncryptedConfigDetector01(),
            new RegexSearchSpider(),
            new HeapdumpRegexSpiderParallel()
    };

    public int call(PrintStream out) throws Exception {
        heapFilePath = heapfile.getAbsolutePath();
        int ver = getFileVersion();
        float classVersion = Float.parseFloat(System.getProperty("java.class.version"));
        IHeapHolder heapHolder;

        if (ver == 1 || classVersion < 52) {
            heapHolder = new NetbeansHeapHolder(heapfile);
        } else {
            heapHolder = new GraalvmHeapHolder(heapfile);
        }
        if (flag.contains("export-strings")) {
            spiderCall(new ExportAllString(), heapHolder, out);
            return 0;
        }
        if (flag.contains("-out")) {
            String outFilePath = getArgValue("-out");
            System.out.println("[+] Output to: " + outFilePath);
            out = new PrintStream(new FileOutputStream(outFilePath), true);
        }
        if (flag.contains("--rules")) {
            rulesPath = getArgValue("--rules");
            System.out.println("[+] HaE rules file: " + rulesPath);
        }

        // Collect results for JSON output
        Map<String, List<String>> allResults = new LinkedHashMap<String, List<String>>();

        // Capture tool results for file output
        ByteArrayOutputStream toolCapture = new ByteArrayOutputStream();
        PrintStream toolFileOut = new PrintStream(toolCapture, true);

        // Print header
        String header = "===========================================\n" +
                "JDumpSpiderPlus v" + VERSION + " Scan Results\n" +
                "Heap File: " + heapFilePath + "\n" +
                "===========================================\n";
        if (!"json".equals(outputFormat)) {
            out.println(header);
        }
        toolFileOut.println(header);

        // Run built-in spiders (except regex spider)
        for (ISpider spider : allSpiders) {
            if (spider instanceof HeapdumpRegexSpiderParallel) {
                continue; // Handle separately
            }
            String result = spider.sniff(heapHolder);
            String spiderName = spider.getName();

            // Collect for JSON
            if (result != null && !result.isEmpty()) {
                List<String> lines = new ArrayList<String>(Arrays.asList(result.split("\n")));
                allResults.put(spiderName, lines);
            }

            // Print for text format
            if (!"json".equals(outputFormat)) {
                String section = "===========================================\n" +
                        spiderName + "\n" +
                        "-------------\n";
                String content;
                if (result != null && !result.isEmpty()) {
                    content = section + result + "\n";
                } else {
                    content = section + "not found!\n\n";
                }
                out.print(content);
                toolFileOut.print(content);
            }
        }

        // Save tool results to file
        saveToolResults(toolCapture.toString());
        toolFileOut.close();

        // Run regex spider (results saved separately by the spider itself)
        for (ISpider spider : allSpiders) {
            if (spider instanceof HeapdumpRegexSpiderParallel) {
                String result = spider.sniff(heapHolder);
                if (result != null && !result.isEmpty()) {
                    allResults.put("HaE Rules Scan", Arrays.asList(result.split("\n")));
                }
                if (!"json".equals(outputFormat)) {
                    out.println("\n===========================================");
                    out.println("HaE Rules Scan");
                    out.println("===========================================\n");
                    out.println(result);
                }
            }
        }

        // Output format
        if ("json".equals(outputFormat)) {
            out.println(JsonOutputFormatter.format(allResults));
        } else if ("excel".equals(outputFormat)) {
            String csv = ExcelReportGenerator.generate(heapFilePath, allResults);
            File resultsDir = getResultsDir();
            File csvFile = new File(resultsDir, "report.csv");
            ExcelReportGenerator.saveToFile(csv, csvFile.getAbsolutePath());
            System.out.println("[+] Excel report saved to: " + csvFile.getAbsolutePath());
            out.println("===========================================");
        } else {
            out.println("===========================================");
        }
        return 0;
    }

    private String getArgValue(String flagStr) throws Exception {
        try {
            return flag.get(flag.indexOf(flagStr) + 1);
        } catch (IndexOutOfBoundsException e) {
            throw new Exception("[-] Get '" + flagStr + "' value failed!");
        }
    }

    private void spiderCall(ISpider spider, IHeapHolder heapHolder, PrintStream out) {
        out.println("===========================================");
        out.println(spider.getName());
        out.println("-------------");
        String result = spider.sniff(heapHolder);
        if (!(result == null) && !result.equals("")) {
            out.println(result);
        } else {
            out.println("not found!\r\n");
        }
    }

    private void spiderCallDual(ISpider spider, IHeapHolder heapHolder, PrintStream consoleOut, PrintStream fileOut) {
        String section = "===========================================\n" +
                spider.getName() + "\n" +
                "-------------\n";
        String result = spider.sniff(heapHolder);
        String content;
        if (!(result == null) && !result.equals("")) {
            content = section + result + "\n";
        } else {
            content = section + "not found!\n\n";
        }
        consoleOut.print(content);
        fileOut.print(content);
    }

    private void saveToolResults(String content) {
        try {
            File resultsDir = getResultsDir();
            File outFile = new File(resultsDir, "tool_scan.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(outFile), true);
            pw.print(content);
            pw.close();
            System.out.println("[+] Tool results saved to: " + outFile.getAbsolutePath());
        } catch (Exception e) {
            System.out.println("[-] Failed to save tool results: " + e.getMessage());
        }
    }

    private File getResultsDir() {
        File resultsDir = new File(heapfile.getParent(), "results");
        if (!resultsDir.exists()) {
            resultsDir.mkdirs();
        }
        return resultsDir;
    }

    public static File getResultsDir(String heapFilePath) {
        File heapFile = new File(heapFilePath);
        File resultsDir = new File(heapFile.getParent(), "results");
        if (!resultsDir.exists()) {
            resultsDir.mkdirs();
        }
        return resultsDir;
    }

    public int getFileVersion() {
        try (FileInputStream io = new FileInputStream(heapfile)) {
            io.skip(17);
            byte subVersion = (byte) io.read();
            return Integer.parseInt(Character.valueOf((char) subVersion).toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
