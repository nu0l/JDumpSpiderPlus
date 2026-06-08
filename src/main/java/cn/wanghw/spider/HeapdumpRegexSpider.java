package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.Main;
import cn.wanghw.har.HaERulesLoader;
import cn.wanghw.har.RuleDefinition;

import java.io.File;
import java.io.FileOutputStream;
import java.io.PrintWriter;
import java.text.MessageFormat;
import java.text.SimpleDateFormat;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class HeapdumpRegexSpider implements ISpider {

    private static final int MAX_STRINGS = 2000000;
    private static final int MAX_MATCH_PER_RULE = 5000;
    private static final String DEFAULT_RULES_RESOURCE = "/rules/Rules.yml";

    public String getName() {
        return "HeapdumpRegex (HaE Rules)";
    }

    public String sniff(IHeapHolder heapHolder) {
        try {
            List<RuleDefinition> rules = loadRules();
            if (rules.isEmpty()) {
                return "No rules loaded";
            }

            List<RuleDefinition> activeRules = filterActiveRules(rules);
            if (activeRules.isEmpty()) {
                return "No active rules found";
            }

            System.out.println("[*] Loaded " + activeRules.size() + " active rules");
            List<String> allStrings = extractAllStrings(heapHolder);
            System.out.println("[*] Extracted " + allStrings.size() + " strings from heap");

            if (allStrings.isEmpty()) {
                return "No strings found in heap dump";
            }

            String result = applyRules(activeRules, allStrings);
            if (result != null && !result.isEmpty()) {
                saveToFile(result);
            }
            return result;
        } catch (Exception e) {
            return "Error: " + e.getMessage();
        }
    }

    private List<RuleDefinition> loadRules() {
        // 1. Try loading from --rules flag (user-specified path)
        String rulesPath = Main.getRulesPath();
        if (rulesPath != null && !rulesPath.isEmpty()) {
            try {
                System.out.println("[*] Loading rules from: " + rulesPath);
                return HaERulesLoader.loadAllRules(rulesPath);
            } catch (Exception e) {
                System.out.println("[-] Failed to load rules from " + rulesPath + ": " + e.getMessage());
            }
        }

        // 2. Try loading from classpath (bundled rules)
        try {
            System.out.println("[*] Loading bundled rules");
            return HaERulesLoader.loadAllRulesFromResource(DEFAULT_RULES_RESOURCE);
        } catch (Exception e) {
            System.out.println("[-] Failed to load bundled rules: " + e.getMessage());
        }

        return new ArrayList<RuleDefinition>();
    }

    private List<RuleDefinition> filterActiveRules(List<RuleDefinition> rules) {
        List<RuleDefinition> active = new ArrayList<RuleDefinition>();
        for (RuleDefinition rule : rules) {
            if (rule.isLoaded() && rule.getFRegex() != null && !rule.getFRegex().isEmpty()) {
                active.add(rule);
            }
        }
        return active;
    }

    private List<String> extractAllStrings(IHeapHolder heapHolder) {
        List<String> strings = new ArrayList<String>();
        try {
            Object clazz = heapHolder.findClass("java.lang.String");
            if (clazz == null) {
                return strings;
            }
            int count = 0;
            for (Object instance : heapHolder.getInstances(clazz)) {
                String value = heapHolder.toString(instance);
                if (value != null && !value.isEmpty()) {
                    strings.add(value);
                }
                count++;
                if (count >= MAX_STRINGS) {
                    System.out.println("[!] Reached string limit (" + MAX_STRINGS + "), stopping extraction");
                    break;
                }
            }
        } catch (Exception e) {
            System.out.println("[-] Error extracting strings: " + e.getMessage());
        }
        return strings;
    }

    private String applyRules(List<RuleDefinition> rules, List<String> allStrings) {
        StringBuilder result = new StringBuilder();
        boolean hasAnyMatch = false;
        int totalMatches = 0;

        for (RuleDefinition rule : rules) {
            Set<String> matches = matchRule(rule, allStrings);
            if (!matches.isEmpty()) {
                hasAnyMatch = true;
                totalMatches += matches.size();
                result.append("[+] ").append(rule.getName());
                result.append(" (").append(matches.size()).append(" matches)\r\n");
                for (String match : matches) {
                    result.append("    ").append(match).append("\r\n");
                }
                result.append("\r\n");
            }
        }

        if (!hasAnyMatch) {
            return "";
        }

        // Add summary header
        StringBuilder header = new StringBuilder();
        header.append("===========================================\r\n");
        header.append("HaE Rules Scan Results\r\n");
        header.append("Total: ").append(totalMatches).append(" matches found\r\n");
        header.append("===========================================\r\n\r\n");

        return header.toString() + result.toString();
    }

    private Set<String> matchRule(RuleDefinition rule, List<String> allStrings) {
        Set<String> matches = new LinkedHashSet<String>();
        try {
            String fRegex = rule.getFRegex();
            if (fRegex == null || fRegex.isEmpty()) {
                return matches;
            }

            if (rule.isDfaEngine()) {
                matchDfa(rule, allStrings, matches);
            } else {
                matchNfa(rule, allStrings, matches);
            }
        } catch (Exception e) {
            // Skip rules that fail to match
        }
        return matches;
    }

    private void matchNfa(RuleDefinition rule, List<String> allStrings, Set<String> matches) {
        int flags = rule.isSensitive() ? 0 : Pattern.CASE_INSENSITIVE;
        Pattern pattern;
        try {
            pattern = Pattern.compile(rule.getFRegex(), flags);
        } catch (Exception e) {
            return;
        }

        Pattern sPattern = null;
        if (rule.getSRegex() != null && !rule.getSRegex().isEmpty()) {
            try {
                sPattern = Pattern.compile(rule.getSRegex(), flags);
            } catch (Exception e) {
                // s_regex is optional
            }
        }

        String format = rule.getFormat();
        boolean isSimpleFormat = "{0}".equals(format) || format == null || format.isEmpty();

        for (String str : allStrings) {
            if (matches.size() >= MAX_MATCH_PER_RULE) break;
            Matcher matcher = pattern.matcher(str);
            while (matcher.find()) {
                String extracted;
                if (isSimpleFormat) {
                    extracted = matcher.group(1);
                } else {
                    int groupCount = matcher.groupCount();
                    Object[] groups = new Object[groupCount + 1];
                    for (int i = 0; i <= groupCount; i++) {
                        groups[i] = matcher.group(i) != null ? matcher.group(i) : "";
                    }
                    try {
                        extracted = MessageFormat.format(format, groups);
                    } catch (Exception e) {
                        extracted = matcher.group(1);
                    }
                }
                if (extracted != null && !extracted.isEmpty()) {
                    if (sPattern != null) {
                        Matcher sMatcher = sPattern.matcher(extracted);
                        if (!sMatcher.find()) {
                            continue;
                        }
                    }
                    matches.add(extracted);
                }
            }
        }
    }

    private void matchDfa(RuleDefinition rule, List<String> allStrings, Set<String> matches) {
        String pattern = rule.getFRegex();
        if (pattern == null || pattern.isEmpty()) {
            return;
        }

        boolean caseSensitive = rule.isSensitive();
        String matchPattern = caseSensitive ? pattern : pattern.toLowerCase();

        for (String str : allStrings) {
            if (matches.size() >= MAX_MATCH_PER_RULE) break;
            String checkStr = caseSensitive ? str : str.toLowerCase();
            if (checkStr.contains(matchPattern)) {
                matches.add(str);
            }
        }
    }

    private void saveToFile(String content) {
        try {
            File resultsDir = Main.getResultsDir(Main.getHeapFilePath());
            File outFile = new File(resultsDir, "regex_scan.txt");
            PrintWriter pw = new PrintWriter(new FileOutputStream(outFile), true);
            pw.print(content);
            pw.close();
            System.out.println("[+] HaE rules results saved to: " + outFile.getAbsolutePath());
        } catch (Exception e) {
            System.out.println("[-] Failed to save results to file: " + e.getMessage());
        }
    }
}
