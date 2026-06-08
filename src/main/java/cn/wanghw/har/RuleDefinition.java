package cn.wanghw.har;

public class RuleDefinition {
    private String name;
    private boolean loaded;
    private String fRegex;
    private String sRegex;
    private String format;
    private String color;
    private String scope;
    private String engine;
    private boolean sensitive;

    public RuleDefinition() {
    }

    public RuleDefinition(String name, boolean loaded, String fRegex, String sRegex,
                          String format, String color, String scope, String engine, boolean sensitive) {
        this.name = name;
        this.loaded = loaded;
        this.fRegex = fRegex;
        this.sRegex = sRegex;
        this.format = format;
        this.color = color;
        this.scope = scope;
        this.engine = engine;
        this.sensitive = sensitive;
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public boolean isLoaded() {
        return loaded;
    }

    public void setLoaded(boolean loaded) {
        this.loaded = loaded;
    }

    public String getFRegex() {
        return fRegex;
    }

    public void setFRegex(String fRegex) {
        this.fRegex = fRegex;
    }

    public String getSRegex() {
        return sRegex;
    }

    public void setSRegex(String sRegex) {
        this.sRegex = sRegex;
    }

    public String getFormat() {
        return format;
    }

    public void setFormat(String format) {
        this.format = format;
    }

    public String getColor() {
        return color;
    }

    public void setColor(String color) {
        this.color = color;
    }

    public String getScope() {
        return scope;
    }

    public void setScope(String scope) {
        this.scope = scope;
    }

    public String getEngine() {
        return engine;
    }

    public void setEngine(String engine) {
        this.engine = engine;
    }

    public boolean isSensitive() {
        return sensitive;
    }

    public void setSensitive(boolean sensitive) {
        this.sensitive = sensitive;
    }

    public boolean isDfaEngine() {
        return "dfa".equalsIgnoreCase(engine);
    }

    public boolean isNfaEngine() {
        return !"dfa".equalsIgnoreCase(engine);
    }
}
