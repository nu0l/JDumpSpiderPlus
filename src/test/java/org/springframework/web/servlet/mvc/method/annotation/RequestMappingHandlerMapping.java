package org.springframework.web.servlet.mvc.method.annotation;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Mock Spring RequestMappingHandlerMapping for testing
 */
public class RequestMappingHandlerMapping {
    public Map<String, String> handlerMethods = new LinkedHashMap<>();

    public void registerHandler(String pattern, String handler) {
        handlerMethods.put(pattern, handler);
    }
}
