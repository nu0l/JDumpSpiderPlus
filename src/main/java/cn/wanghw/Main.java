package cn.wanghw;

import cn.wanghw.spider.*;
import org.graalvm.visualvm.lib.jfluid.heap.GraalvmHeapHolder;
import org.netbeans.lib.profiler.heap.NetbeansHeapHolder;

import java.io.*;
import java.nio.file.Path;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;

public class Main {

    public static final String VERSION = "2.0";
    private File heapfile;
    private final List<String> flag = new LinkedList<String>();
    static PrintStream out = null;
    private static String rulesPath = null;
    private static String heapFilePath = null;

    public static String getRulesPath() {
        return rulesPath;
    }

    public static String getHeapFilePath() {
        return heapFilePath;
    }

    public static String run(String[] args) throws Exception {
        ByteArrayOutputStream bout = new ByteArrayOutputStream();
        if (out == null) {
            out = new PrintStream(bout);
        }
        if (args.length < 1) {
            System.out.println("JDumpSpiderPlus v" + VERSION + " - HeapDump Sensitive Information Extractor");
            System.out.println("Usage: java -jar JDumpSpiderPlus.jar <heapfile> [options]");
            System.out.println("Options:");
            System.out.println("  --rules <path>    Load custom HaE rules YAML file");
            System.out.println("  -out <path>       Output results to file");
            System.out.println("  export-strings    Export all strings from heap dump");
            System.out.println("  -h, --help        Show this help message");
            return "";
        } else {
            Main _main = new Main();
            _main.heapfile = new File(args[0]);
            if (_main.heapfile.exists() && _main.heapfile.isFile()) {
                if (args.length > 1) {
                    _main.flag.addAll(Arrays.asList(args).subList(1, args.length));
                }
                _main.call(out);
            } else {
                System.out.println("file not exist!");
            }
        }
        return bout.toString();
    }

    public static String runAsync(final String[] args) throws Exception {
        if (args.length < 2)
            return "In async call, you must give a result file path";
        Thread thread = new Thread(new Runnable() {
            public void run() {
                try {
                    String result = Main.run(args);
                    FileOutputStream fos = new FileOutputStream(args[1]);
                    fos.write(result.getBytes());
                    fos.close();
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
            new ShiroKey01(),
            new PropertySource01(),
            new PropertySource02(),
            new PropertySource03(),
            new PropertySource04(),
////            new JwtKey01(),
            new PropertySource05(),
            new EnvProperty01(),
            new OSS01(),
            new UserPassSearcher01(),
            new CookieThief(),
            new AuthThief(),
            new HeapdumpRegexSpider()
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

        // Capture tool results for file output
        ByteArrayOutputStream toolCapture = new ByteArrayOutputStream();
        PrintStream toolFileOut = new PrintStream(toolCapture, true);

        // Print header
        String header = "===========================================\n" +
                "JDumpSpiderPlus v" + VERSION + " Scan Results\n" +
                "Heap File: " + heapFilePath + "\n" +
                "===========================================\n";
        out.println(header);
        toolFileOut.println(header);

        // Run built-in spiders (except regex spider)
        for (ISpider spider : allSpiders) {
            if (spider instanceof HeapdumpRegexSpider) {
                continue; // Handle separately
            }
            spiderCallDual(spider, heapHolder, out, toolFileOut);
        }

        // Save tool results to file
        saveToolResults(toolCapture.toString());
        toolFileOut.close();

        // Run regex spider (results saved separately by the spider itself)
        for (ISpider spider : allSpiders) {
            if (spider instanceof HeapdumpRegexSpider) {
                out.println("\n===========================================");
                out.println("HaE Rules Scan");
                out.println("===========================================\n");
                spiderCall(spider, heapHolder, out);
            }
        }
        out.println("===========================================");
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
        try {
            FileInputStream io = new FileInputStream(heapfile);
            io.skip(17);
            byte subVersion = (byte) io.read();
            return Integer.parseInt(Character.valueOf((char) subVersion).toString());
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
