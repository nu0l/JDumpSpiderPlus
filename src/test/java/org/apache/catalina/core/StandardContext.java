package org.apache.catalina.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Mock Tomcat StandardContext for testing
 */
public class StandardContext {
    public Map<String, ApplicationFilterConfig> filterConfigs = new HashMap<>();
    public List<Object> applicationEventListenersList = new ArrayList<>();

    public void addFilterConfig(ApplicationFilterConfig config) {
        filterConfigs.put(config.name, config);
    }

    public void addListener(Object listener) {
        applicationEventListenersList.add(listener);
    }
}
