package cn.wanghw.spider;

import cn.wanghw.IHeapHolder;
import cn.wanghw.ISpider;
import cn.wanghw.utils.HashMapUtils;

import java.util.HashMap;

/**
 * Redis集群/Sentinel配置提取器
 * 提取Redis集群和哨兵模式配置
 */
public class Redis03 implements ISpider {

    public String getName() {
        return "RedisCluster/Sentinel";
    }

    public String sniff(IHeapHolder heapHolder) {
        final StringBuilder result = new StringBuilder();
        try {
            // Redis集群配置
            Object clazz = heapHolder.findClass("org.springframework.data.redis.connection.RedisClusterConfiguration");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("clusterNodes", "clusterNodes");
                    put("maxRedirects", "maxRedirects");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Redis哨兵配置
            clazz = heapHolder.findClass("org.springframework.data.redis.connection.RedisSentinelConfiguration");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("master", "master");
                    put("sentinels", "sentinels");
                    put("sentinelPassword", "sentinelPassword");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Jedis连接池配置
            clazz = heapHolder.findClass("redis.clients.jedis.JedisPoolConfig");
            if (clazz != null) {
                HashMap<String, String> fieldList = new HashMap<String, String>() {{
                    put("maxTotal", "maxTotal");
                    put("maxIdle", "maxIdle");
                    put("minIdle", "minIdle");
                    put("maxWaitMillis", "maxWaitMillis");
                }};
                for (Object instance : heapHolder.getInstances(clazz)) {
                    result.append(HashMapUtils.dumpString(heapHolder.getFieldsByNameList(instance, fieldList), false));
                }
            }

            // Lettuce配置
            clazz = heapHolder.findClass("io.lettuce.core.ClientOptions");
            if (clazz != null) {
                result.append("[Lettuce ClientOptions instance found]\n");
            }

            // Redisson配置
            clazz = heapHolder.findClass("org.redisson.config.Config");
            if (clazz != null) {
                result.append("[Redisson Config instance found]\n");
            }
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return result.toString();
    }
}
