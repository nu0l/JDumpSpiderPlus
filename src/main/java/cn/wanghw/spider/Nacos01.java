package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * Nacos配置提取器
 * 提取Nacos配置中心和服务发现信息
 */
public class Nacos01 implements ISpider {

    public String getName() {
        return "NacosProperties";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Nacos配置中心
            Object clazz = heapHolder.findClass("com.alibaba.cloud.nacos.NacosConfigProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("serverAddr", "serverAddr");
                    put("namespace", "namespace");
                    put("group", "group");
                    put("username", "username");
                    put("password", "password");
                    put("accessKey", "accessKey");
                    put("secretKey", "secretKey");
                    put("contextPath", "contextPath");
                    put("clusterName", "clusterName");
                    put("encode", "encode");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Nacos服务发现
            clazz = heapHolder.findClass("com.alibaba.cloud.nacos.NacosDiscoveryProperties");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("serverAddr", "serverAddr");
                    put("namespace", "namespace");
                    put("service", "service");
                    put("weight", "weight");
                    put("clusterName", "clusterName");
                    put("group", "group");
                    put("namingLoadCacheAtStart", "namingLoadCacheAtStart");
                    put("metadata", "metadata");
                    put("username", "username");
                    put("password", "password");
                    put("accessKey", "accessKey");
                    put("secretKey", "secretKey");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Nacos旧版本配置
            clazz = heapHolder.findClass("com.alibaba.nacos.client.config.NacosConfigService");
            if (clazz != null) {
                result.append("[NacosConfigService instance found]\n");
            }

            clazz = heapHolder.findClass("com.alibaba.nacos.client.naming.NacosNamingService");
            if (clazz != null) {
                result.append("[NacosNamingService instance found]\n");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
