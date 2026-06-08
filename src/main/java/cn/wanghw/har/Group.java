package cn.wanghw.har;

import java.util.ArrayList;
import java.util.List;

public class Group {
    private String name;
    private List<RuleDefinition> rules;

    public Group() {
        this.rules = new ArrayList<RuleDefinition>();
    }

    public Group(String name) {
        this.name = name;
        this.rules = new ArrayList<RuleDefinition>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<RuleDefinition> getRules() {
        return rules;
    }

    public void setRules(List<RuleDefinition> rules) {
        this.rules = rules;
    }

    public void addRule(RuleDefinition rule) {
        this.rules.add(rule);
    }
}
