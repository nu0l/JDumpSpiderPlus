# JDumpSpiderPlus

[![Java](https://img.shields.io/badge/Java-8+-blue.svg)](https://www.java.com/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.4.2-orange.svg)]()

HeapDump 敏感信息提取工具，用于从 Java 堆转储文件中自动提取数据库凭证、密钥、密码、内存马等敏感信息。基于 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 二次开发。

## 功能特性

### 核心功能
- 自动提取 30+ 种敏感信息类型
- 支持从 URL 远程下载 heapdump (`-u` 参数)
- 支持 HTTP 代理和自定义请求头
- 集成 HaE 规则引擎进行正则匹配
- 多线程并行扫描，高效处理大文件
- 支持 text/json/excel 三种输出格式
- 自动保存扫描结果到文件

### v2.4.0 新增功能
- **内存马检测** - 检测 8 种类型内存马 (Filter/Servlet/Listener/Controller/Interceptor/WebSocket/Agent/Valve)
- **加密配置识别与解密** - 自动识别 jasypt ENC、druid RSA、Spring Cloud {cipher}、Vault 等加密格式，内置弱密码字典自动尝试解密
- **JWT 密钥提取** - 提取 JWT token 和签名密钥
- **Session 信息提取** - 提取 Tomcat/Spring/Shiro Session 数据
- **URL/IP/文件路径提取** - 从堆中提取所有 URL、内网 IP、文件路径
- **自定义正则搜索** - `-reg` 参数支持追加式正则匹配

## 支持的敏感信息类型

| 类别 | 检测模块 |
|------|----------|
| 数据库 | Spring DataSource、WebLogic DataSource、阿里 Druid、HikariCP、MongoDB |
| 缓存/消息队列 | Redis (单机/集群/哨兵)、Jedis、Kafka、RabbitMQ |
| 搜索/注册中心 | Elasticsearch、Nacos、Consul |
| 对象存储 | OSS (阿里云/腾讯云/AWS) |
| 认证/密钥 | Shiro Key、Cookie、Auth Token、JWT |
| 配置信息 | Spring PropertySource、Java Properties、环境变量 |
| 敏感数据 | 用户密码、HaE 规则匹配 (手机号/身份证/银行卡/邮箱等) |
| 信息提取 | URL、IP 地址、文件路径 |
| 安全检测 | 内存马检测 (8种类型) |
| 加密配置 | jasypt ENC、druid RSA、Spring Cloud {cipher}、Vault |
| 会话信息 | Tomcat/Spring/Shiro Session |

## 获取 HeapDump

```bash
# 方式1: jmap (JDK 自带)
jmap -dump:live,format=b,file=/tmp/dumpHeap.hprof <PID>

# 方式2: jcmd (JDK 自带)
jcmd <PID> GC.heap_dump /tmp/dumpHeap.hprof

# 方式3: Spring Boot Actuator
curl -o heapdump http://target:8080/actuator/heapdump

# 方式4: 代码中生成
HotSpotDiagnosticMXBean.dumpHeap("heapdump.hprof", true);
```

## 命令行参数

```
java -jar JDumpSpiderPlus.jar <heapfile> [options]
java -jar JDumpSpiderPlus.jar -u <url> [options]
```

### 参数说明

| 参数 | 说明 | 示例 |
|------|------|------|
| `<heapfile>` | 本地 heapdump 文件路径 | `heapdump.hprof` |
| `-u <url>` | 从 URL 下载 heapdump | `-u http://target.com/actuator/heapdump` |
| `--proxy <proxy>` | 设置 HTTP 代理 | `--proxy http://127.0.0.1:8080` |
| `--header <header>` | 添加 HTTP 请求头 (可多次使用) | `--header "Authorization: Bearer xxx"` |
| `--rules <path>` | 加载自定义 HaE 规则 YAML 文件 | `--rules /path/to/rules.yml` |
| `--format <format>` | 输出格式: text (默认), json, excel | `--format json` |
| `-out <path>` | 输出结果到文件 | `-out result.txt` |
| `-reg <pattern>` | 自定义正则搜索 (可多次使用) | `-reg "password" -reg "secret.*="` |
| `--decrypt-key <key>` | 指定加密配置解密密钥 | `--decrypt-key mySecretKey` |
| `--decrypt-dict <path>` | 密码字典文件 (每行一个密码) | `--decrypt-dict passwords.txt` |
| `export-strings` | 导出堆中所有字符串 | `export-strings` |
| `-h, --help` | 显示帮助信息 | |

## 使用示例

### 基础用法

```bash
# 扫描本地文件
java -jar JDumpSpiderPlus.jar heapdump.hprof

# 从 URL 下载并扫描 (Spring Boot Actuator)
java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump

# 使用代理下载
java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump --proxy http://127.0.0.1:8080

# 添加认证头
java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump --header "Cookie: JSESSIONID=abc123"
```

### 正则搜索

```bash
# 单个正则
java -jar JDumpSpiderPlus.jar heapdump.hprof -reg "jdbc:[a-z:]+://[^\\s]+"

# 多个正则追加
java -jar JDumpSpiderPlus.jar heapdump.hprof -reg "password" -reg "secret.*=.*"

# 搜索云服务密钥
java -jar JDumpSpiderPlus.jar -u http://target/heapdump -reg "AKIA[0-9A-Z]{16}"
```

### 加密配置解密

```bash
# 自动尝试弱密码字典解密 (无需指定密码)
java -jar JDumpSpiderPlus.jar heapdump.hprof

# 指定解密密钥 (jasypt)
java -jar JDumpSpiderPlus.jar heapdump.hprof --decrypt-key mySecretKey

# 使用密码字典文件 (每行一个密码)
java -jar JDumpSpiderPlus.jar heapdump.hprof --decrypt-dict /path/to/passwords.txt
```

**支持的加密格式：**
- jasypt `ENC(...)` 格式
- Spring Cloud `{cipher}` 前缀
- druid RSA 加密
- Base64 编码值
- Hex 编码值

**解密优先级：**
1. `--decrypt-key` 指定的密钥
2. `--decrypt-dict` 字典文件中的密码
3. 内置弱密码字典自动尝试

### 输出格式

```bash
# JSON 格式输出
java -jar JDumpSpiderPlus.jar heapdump.hprof --format json

# Excel 报告 (CSV 格式，可直接用 Excel 打开)
java -jar JDumpSpiderPlus.jar heapdump.hprof --format excel

# 输出到文件
java -jar JDumpSpiderPlus.jar heapdump.hprof -out result.txt
```

### 自定义规则

```bash
# 使用自定义 HaE 规则
java -jar JDumpSpiderPlus.jar heapdump.hprof --rules /path/to/custom-rules.yml

# 导出所有字符串 (用于手动分析)
java -jar JDumpSpiderPlus.jar heapdump.hprof export-strings
```

## 输出说明

扫描结果自动保存到 heapdump 文件所在目录的 `results/` 文件夹：

```
results/
├── tool_scan.txt      # 内置模块扫描结果
├── regex_scan.txt     # HaE 规则匹配结果
├── report.csv         # Excel 格式报告 (--format excel 时)
└── memshell/          # 内存马字节码导出目录
```

## 配置文件

配置文件加载优先级：命令行参数 > 用户目录 > 当前目录 > 内置配置

- 用户目录: `~/.jdumpspider/config.yml`
- 当前目录: `./config.yml`

## 编译构建

```bash
cd JDumpSpider
mvn clean package -DskipTests
```

编译产物位于 `target/JDumpSpiderPlus-<version>-full.jar`

## 内存马检测

支持检测以下 8 种类型的内存马：

| 类型 | 检测方式 |
|------|----------|
| Filter | 检查 ApplicationFilterConfig 中的 Filter 类 |
| Servlet | 检查 StandardWrapper 中的 Servlet 类 |
| Listener | 检查 StandardContext 中的 Listener 类 |
| Controller | 检查 RequestMappingHandlerMapping 中的 Handler |
| Interceptor | 检查 AbstractHandlerMapping 中的 Interceptor |
| WebSocket | 检查 WsServerContainer 中的 Endpoint |
| Agent | 检查 TransformerManager 中的 Transformer |
| Valve | 检查 Pipeline 中的 Valve |

**可疑特征：**
- 类名无包名
- 类名包含随机字符
- 类名包含 shell/evil/inject 等关键词
- ClassLoader 非系统类加载器
- ProtectionDomain 为 null

## 版本历史

### v2.4.2 (2026-06-09)
- 优化 InfoExtractor 减少误报: URL -77%, IP -98%, File Path -99%
- 优化 HaE 规则减少误报: Cloud Key, Authorization Header, Windows Path, Sensitive Field
- 修复 GCP Service Account 规则匹配 SpEL 表达式误报
- 优化 EncryptedConfigDetector 减少误报

### v2.4.0 (2026-06-08)
- 新增内存马检测 (8种类型: Filter/Servlet/Listener/Controller/Interceptor/WebSocket/Agent/Valve)
- 新增加密配置识别与自动解密 (jasypt/druid/Spring Cloud/Vault)
- 新增 JWT 密钥提取
- 新增 Session 信息提取
- 新增 URL/IP/文件路径提取
- 新增 `-reg` 自定义正则搜索参数
- 新增 `--decrypt-key` 解密密钥参数
- 新增 `--decrypt-dict` 密码字典文件参数
- 修复 Map Entry 扫描模式匹配
- 优化文件路径过滤减少误报

### v2.3 (2024-03-22)
- 新增姓名、邮箱、手机号、地址、身份证字段匹配规则
- 新增 URL 下载功能 (`-u` 参数)
- 新增代理支持 (`--proxy` 参数)
- 新增 JSON 输出格式

### v2.1 (2023-04-06)
- 优化正则规则以适应 HeapDump 扫描场景
- 修复资源泄漏和死代码清理

### v2.0 (2023-02-02)
- 从 JDumpSpider 升级为 JDumpSpiderPlus
- 集成 HaE 规则引擎
- 新增 MongoDB/Kafka/RabbitMQ/Elasticsearch/Nacos 提取器

### v1.1 (原版 JDumpSpider)
- 初始版本
- 支持 Spring DataSource/Redis/ShiroKey 等提取

## 致谢

- [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) - 原版工具
- [HaE](https://github.com/gh0stkey/HaE) - 规则引擎

## License

MIT License
