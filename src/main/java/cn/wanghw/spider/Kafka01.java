package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * Kafka配置提取器
 * 提取Kafka连接信息（broker、SASL认证等）
 */
public class Kafka01 implements ISpider {

    public String getName() {
        return "KafkaProperties";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Spring Boot Kafka配置
            Object clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.kafka.KafkaProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("bootstrapServers", "bootstrapServers");
                    put("acks", "acks");
                    put("retries", "retries");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Kafka Producer配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.kafka.KafkaProperties$Producer");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("acks", "acks");
                    put("retries", "retries");
                    put("batchSize", "batchSize");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Kafka Consumer配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.kafka.KafkaProperties$Consumer");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("groupId", "groupId");
                    put("autoOffsetReset", "autoOffsetReset");
                    put("enableAutoCommit", "enableAutoCommit");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Kafka SSL配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.kafka.KafkaProperties$SSL");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("keyStoreLocation", "keyStoreLocation");
                    put("keyStorePassword", "keyStorePassword");
                    put("trustStoreLocation", "trustStoreLocation");
                    put("trustStorePassword", "trustStorePassword");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Kafka SASL配置
            clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.kafka.KafkaProperties$SASL");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("jaas", "jaas");
                    put("mechanism", "mechanism");
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
