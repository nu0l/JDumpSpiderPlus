package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * MongoDB配置提取器
 * 提取MongoDB连接信息（增强版）
 */
public class MongoDB01 implements ISpider {

    public String getName() {
        return "MongoDBProperties";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Spring Boot MongoDB配置
            Object clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.mongo.MongoProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("host", "host");
                    put("port", "port");
                    put("database", "database");
                    put("username", "username");
                    put("password", "password");
                    put("authenticationDatabase", "authenticationDatabase");
                    put("uri", "uri");
                    put("uuidRepresentation", "uuidRepresentation");
                    put("fieldNamingStrategy", "fieldNamingStrategy");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // MongoDB MongoClientSettings
            clazz = heapHolder.findClass("com.mongodb.MongoClientSettings");
            if (clazz != null) {
                result.append("[MongoClientSettings instance found]\n");
            }

            // MongoDB MongoTemplate
            clazz = heapHolder.findClass("org.springframework.data.mongodb.core.MongoTemplate");
            if (clazz != null) {
                result.append("[MongoTemplate instance found]\n");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
