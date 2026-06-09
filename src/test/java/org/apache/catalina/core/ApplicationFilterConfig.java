package org.apache.catalina.core;

/**
 * Mock Tomcat ApplicationFilterConfig for testing
 */
public class ApplicationFilterConfig {
    public String name;
    public String filterClass;
    public Object filter;

    public ApplicationFilterConfig(String name, String filterClass, Object filter) {
        this.name = name;
        this.filterClass = filterClass;
        this.filter = filter;
    }
}
