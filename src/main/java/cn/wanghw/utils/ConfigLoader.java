package cn.wanghw.utils;

import org.yaml.snakeyaml.Yaml;

import java.io.*;
import java.util.*;

/**
 * 配置文件加载器
 * 支持YAML格式的配置文件
 */
public class ConfigLoader {

    private static final String DEFAULT_CONFIG_RESOURCE = "/config.yml";
    private static final String USER_CONFIG_DIR = System.getProperty("user.home") + File.separator + ".jdumpspider";
    private static final String USER_CONFIG_FILE = USER_CONFIG_DIR + File.separator + "config.yml";

    private Map<String, Object> config;

    public ConfigLoader() {
        this.config = new LinkedHashMap<String, Object>();
    }

    /**
     * 加载配置文件
     * 优先级：命令行参数 > 用户目录配置 > 内置配置
     */
    public void load() {
        // 1. 加载内置配置
        loadFromResource(DEFAULT_CONFIG_RESOURCE);

        // 2. 加载用户目录配置
        loadFromFile(USER_CONFIG_FILE);

        // 3. 加载当前目录配置
        loadFromFile("config.yml");
    }

    /**
     * 从资源文件加载配置
     */
    private void loadFromResource(String resourcePath) {
        try {
            InputStream is = ConfigLoader.class.getResourceAsStream(resourcePath);
            if (is != null) {
                Yaml yaml = new Yaml();
                Map<String, Object> loaded = yaml.load(is);
                if (loaded != null) {
                    mergeConfig(loaded);
                }
                is.close();
            }
        } catch (Exception e) {
            // 忽略资源加载失败
        }
    }

    /**
     * 从文件加载配置
     */
    private void loadFromFile(String filePath) {
        try {
            File file = new File(filePath);
            if (file.exists() && file.isFile()) {
                FileInputStream fis = new FileInputStream(file);
                Yaml yaml = new Yaml();
                Map<String, Object> loaded = yaml.load(fis);
                if (loaded != null) {
                    mergeConfig(loaded);
                }
                fis.close();
            }
        } catch (Exception e) {
            // 忽略文件加载失败
        }
    }

    /**
     * 合并配置
     */
    private void mergeConfig(Map<String, Object> newConfig) {
        for (Map.Entry<String, Object> entry : newConfig.entrySet()) {
            config.put(entry.getKey(), entry.getValue());
        }
    }

    /**
     * 获取配置值
     */
    public Object get(String key) {
        return config.get(key);
    }

    /**
     * 获取字符串配置
     */
    public String getString(String key, String defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        return value.toString();
    }

    /**
     * 获取整数配置
     */
    public int getInt(String key, int defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        try {
            return Integer.parseInt(value.toString());
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    /**
     * 获取布尔配置
     */
    public boolean getBoolean(String key, boolean defaultValue) {
        Object value = config.get(key);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean) {
            return (Boolean) value;
        }
        return Boolean.parseBoolean(value.toString());
    }

    /**
     * 获取列表配置
     */
    public List<String> getList(String key) {
        Object value = config.get(key);
        if (value instanceof List) {
            List<String> result = new ArrayList<String>();
            for (Object item : (List<?>) value) {
                result.add(item.toString());
            }
            return result;
        }
        return new ArrayList<String>();
    }

    /**
     * 获取所有配置
     */
    public Map<String, Object> getAll() {
        return config;
    }

    /**
     * 保存配置到文件
     */
    public void save(String filePath) {
        try {
            File file = new File(filePath);
            File parentDir = file.getParentFile();
            if (parentDir != null && !parentDir.exists()) {
                parentDir.mkdirs();
            }
            FileWriter writer = new FileWriter(file);
            Yaml yaml = new Yaml();
            yaml.dump(config, writer);
            writer.close();
        } catch (Exception e) {
            System.out.println("[-] Failed to save config: " + e.getMessage());
        }
    }
}
