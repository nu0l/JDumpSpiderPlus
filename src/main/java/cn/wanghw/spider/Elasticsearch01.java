package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * Elasticsearch配置提取器
 * 提取Elasticsearch连接信息（主机、端口、认证等）
 */
public class Elasticsearch01 implements ISpider {

    public String getName() {
        return "ElasticsearchProperties";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Spring Boot Elasticsearch配置
            Object clazz = heapHolder.findClass("org.springframework.boot.autoconfigure.elasticsearch.ElasticsearchProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("uris", "uris");
                    put("username", "username");
                    put("password", "password");
                    put("socketTimeout", "socketTimeout");
                    put("connectionTimeout", "connectionTimeout");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Elasticsearch RestClient配置
            clazz = heapHolder.findClass("org.elasticsearch.client.RestClientBuilder");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("defaultHeaders", "defaultHeaders");
                    put("pathPrefix", "pathPrefix");
                    put("strictDeprecationMode", "strictDeprecationMode");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Elasticsearch RestHighLevelClient配置
            clazz = heapHolder.findClass("org.elasticsearch.client.RestHighLevelClient");
            if (clazz != null) {
                result.append("[RestHighLevelClient instance found]\n");
            }

            // Spring Data Elasticsearch配置
            clazz = heapHolder.findClass("org.springframework.data.elasticsearch.client.ClientConfiguration");
            if (clazz != null) {
                result.append("[ClientConfiguration instance found]\n");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
