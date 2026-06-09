package org.apache.catalina.core;

/**
 * Mock Tomcat StandardWrapper for testing
 */
public class StandardWrapper {
    public String name;
    public String servletClass;
    public Object instance;

    public StandardWrapper(String name, String servletClass, Object instance) {
        this.name = name;
        this.servletClass = servletClass;
        this.instance = instance;
    }
}
