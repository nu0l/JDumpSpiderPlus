package cn.wanghw.har;

import org.yaml.snakeyaml.Yaml;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

public class HaERulesLoader {

    public static List<Group> loadFromFile(String filePath) throws Exception {
        File file = new File(filePath);
        if (!file.exists() || !file.isFile()) {
            throw new Exception("Rules file not found: " + filePath);
        }
        FileInputStream fis = new FileInputStream(file);
        try {
            return loadFromStream(fis);
        } finally {
            fis.close();
        }
    }

    public static List<Group> loadFromResource(String resourcePath) throws Exception {
        InputStream is = HaERulesLoader.class.getResourceAsStream(resourcePath);
        if (is == null) {
            throw new Exception("Rules resource not found: " + resourcePath);
        }
        try {
            return loadFromStream(is);
        } finally {
            is.close();
        }
    }

    @SuppressWarnings("unchecked")
    public static List<Group> loadFromStream(InputStream inputStream) {
        Yaml yaml = new Yaml();
        Object data = yaml.load(inputStream);
        List<Group> groups = new ArrayList<Group>();

        if (!(data instanceof Map)) {
            return groups;
        }

        Map<String, Object> root = (Map<String, Object>) data;
        Object rulesObj = root.get("rules");
        if (!(rulesObj instanceof List)) {
            return groups;
        }

        List<Map<String, Object>> ruleGroups = (List<Map<String, Object>>) rulesObj;
        for (Map<String, Object> groupMap : ruleGroups) {
            String groupName = getString(groupMap, "group", "");
            Group group = new Group(groupName);

            Object ruleObj = groupMap.get("rule");
            if (ruleObj instanceof List) {
                List<Map<String, Object>> ruleList = (List<Map<String, Object>>) ruleObj;
                for (Map<String, Object> ruleMap : ruleList) {
                    RuleDefinition rule = parseRule(ruleMap);
                    if (rule != null) {
                        group.addRule(rule);
                    }
                }
            }
            groups.add(group);
        }
        return groups;
    }

    public static List<RuleDefinition> loadAllRules(String filePath) throws Exception {
        List<Group> groups = loadFromFile(filePath);
        List<RuleDefinition> allRules = new ArrayList<RuleDefinition>();
        for (Group group : groups) {
            allRules.addAll(group.getRules());
        }
        return allRules;
    }

    public static List<RuleDefinition> loadAllRulesFromResource(String resourcePath) throws Exception {
        List<Group> groups = loadFromResource(resourcePath);
        List<RuleDefinition> allRules = new ArrayList<RuleDefinition>();
        for (Group group : groups) {
            allRules.addAll(group.getRules());
        }
        return allRules;
    }

    private static RuleDefinition parseRule(Map<String, Object> ruleMap) {
        RuleDefinition rule = new RuleDefinition();
        rule.setName(getString(ruleMap, "name", ""));
        rule.setLoaded(getBoolean(ruleMap, "loaded", true));
        rule.setFRegex(getString(ruleMap, "f_regex", ""));
        rule.setSRegex(getString(ruleMap, "s_regex", ""));
        rule.setFormat(getString(ruleMap, "format", "{0}"));
        rule.setColor(getString(ruleMap, "color", ""));
        rule.setScope(getString(ruleMap, "scope", ""));
        rule.setEngine(getString(ruleMap, "engine", "nfa"));
        rule.setSensitive(getBoolean(ruleMap, "sensitive", false));
        return rule;
    }

    private static String getString(Map<String, Object> map, String key, String defaultValue) {
        Object val = map.get(key);
        if (val == null) {
            return defaultValue;
        }
        String s = val.toString().trim();
        return s.isEmpty() ? defaultValue : s;
    }

    private static boolean getBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        Object val = map.get(key);
        if (val == null) {
            return defaultValue;
        }
        if (val instanceof Boolean) {
            return (Boolean) val;
        }
        return Boolean.parseBoolean(val.toString());
    }
}
