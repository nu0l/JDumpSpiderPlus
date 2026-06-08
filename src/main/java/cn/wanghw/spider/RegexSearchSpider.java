package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.Main;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class RegexSearchSpider implements ISpider {

    private static final int MAX_MATCHES_PER_PATTERN = 1000;

    public String getName() {
        return "RegexSearch";
    }

    public String sniff(IHeapHolder heapHolder) {
        List<String> patterns = Main.getRegexPatterns();
        if (patterns == null || patterns.isEmpty()) {
            return null;
        }

        StringBuilder result = new StringBuilder();
        try {
            Object clazz = heapHolder.findClass("java.lang.String");
            if (clazz == null) return null;

            // compile all patterns
            List<Pattern> compiledPatterns = new ArrayList<Pattern>();
            for (String pattern : patterns) {
                try {
                    compiledPatterns.add(Pattern.compile(pattern, Pattern.CASE_INSENSITIVE));
                } catch (Exception e) {
                    result.append("[!] Invalid regex: ").append(pattern).append(" - ").append(e.getMessage()).append("\r\n");
                }
            }

            if (compiledPatterns.isEmpty()) return null;

            // collect matches per pattern
            List<LinkedHashSet<String>> matchesPerPattern = new ArrayList<LinkedHashSet<String>>();
            for (int i = 0; i < compiledPatterns.size(); i++) {
                matchesPerPattern.add(new LinkedHashSet<String>());
            }

            // scan all strings
            int count = 0;
            for (Object instance : heapHolder.getInstances(clazz)) {
                String text = heapHolder.toString(instance);
                if (text == null || text.isEmpty()) continue;

                for (int i = 0; i < compiledPatterns.size(); i++) {
                    if (matchesPerPattern.get(i).size() >= MAX_MATCHES_PER_PATTERN) continue;

                    Matcher matcher = compiledPatterns.get(i).matcher(text);
                    while (matcher.find()) {
                        String match = matcher.group();
                        if (match.length() > 0) {
                            matchesPerPattern.get(i).add(match);
                            if (matchesPerPattern.get(i).size() >= MAX_MATCHES_PER_PATTERN) break;
                        }
                    }
                }

                count++;
                if (count >= 1000000) break;
            }

            // output results
            for (int i = 0; i < patterns.size(); i++) {
                LinkedHashSet<String> matches = matchesPerPattern.get(i);
                result.append("[Pattern: ").append(patterns.get(i)).append("] (").append(matches.size()).append(" matches)\r\n");
                for (String match : matches) {
                    if (match.length() > 300) {
                        result.append("  ").append(match.substring(0, 300)).append("...\r\n");
                    } else {
                        result.append("  ").append(match).append("\r\n");
                    }
                }
                result.append("\r\n");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
