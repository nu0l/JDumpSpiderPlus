package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * RabbitMQ配置提取器
 * 提取RabbitMQ连接信息（主机、端口、用户名、密码等）
 */
public class RabbitMQ01 implements ISpider {

    public String getName() {
        return "RabbitProperties";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Spring Boot RabbitMQ配置
            Object clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.amqp.RabbitProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("host", "host");
                    put("port", "port");
                    put("username", "username");
                    put("password", "password");
                    put("virtualHost", "virtualHost");
                    put("addresses", "addresses");
                    put("name", "name");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // RabbitMQ SSL配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.amqp.RabbitProperties$SSL");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("enabled", "enabled");
                    put("keyStore", "keyStore");
                    put("keyStorePassword", "keyStorePassword");
                    put("trustStore", "trustStore");
                    put("trustStorePassword", "trustStorePassword");
                    put("algorithm", "algorithm");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // RabbitMQ Cache配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.amqp.RabbitProperties$Cache");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("channel", "channel");
                    put("connection", "connection");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
