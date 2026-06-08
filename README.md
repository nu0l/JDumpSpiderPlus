# JDumpSpiderPlus v2.3

HeapDump敏感信息提取工具（增强版）

基于 [JDumpSpider](https://github.com/whwlsfb/JDumpSpider) 扩展，集成了 [HaE](https://github.com/gh0stkey/HaE) 的正则规则引擎，支持从Java堆转储文件中提取更多类型的敏感信息。

## 功能特性

### 内置提取器（原JDumpSpider功能）

| 类型 | 提取器 | 说明 |
|------|--------|------|
| 数据源 | SpringDataSourceProperties | Spring Boot数据源配置 |
| 数据源 | WeblogicDataSourceConnectionPoolConfig | WebLogic数据源 |
| 数据源 | MongoClient | MongoDB连接信息 |
| 数据源 | AliDruidDataSourceWrapper | 阿里Druid数据源 |
| 数据源 | HikariDataSource | HikariCP数据源 |
| Redis | RedisStandaloneConfiguration | Redis单机配置 |
| Redis | JedisClient | Jedis客户端配置 |
| Redis | RedisCluster/Sentinel | Redis集群/哨兵配置 |
| MongoDB | MongoDBProperties | MongoDB配置（增强版） |
| Kafka | KafkaProperties | Kafka配置（SASL/SSL） |
| RabbitMQ | RabbitProperties | RabbitMQ配置 |
| Elasticsearch | ElasticsearchProperties | Elasticsearch配置 |
| Nacos | NacosProperties | Nacos配置中心/服务发现 |
| ShiroKey | CookieRememberMeManager | Shiro RememberMe密钥 |
| 配置文件 | OriginTrackedMapPropertySource | Spring Boot配置 |
| 配置文件 | MutablePropertySources | Spring环境属性 |
| 配置文件 | MapPropertySources | Map属性源 |
| 配置文件 | ConsulPropertySource | Consul配置 |
| 配置文件 | JavaProperties | Java Properties |
| 配置文件 | ProcessEnvironment | 环境变量 |
| OSS | OSS | 云存储凭证（模糊搜索） |
| 用户信息 | UserPassSearcher | 用户名/密码（模糊搜索） |
| Cookie | CookieThief | Cookie字符串 |
| 认证 | AuthThief | Authorization头 |

### HaE规则引擎（新增功能）

集成HaE的28条内置规则 + 20+条HeapDump增强规则，支持以下敏感信息匹配：

| 规则组 | 规则名 | 匹配内容 |
|--------|--------|----------|
| **Basic Information** | Email | 邮箱地址 |
| | Chinese IDCard | 身份证号码（18位，严格格式验证） |
| | Chinese Mobile Number | 手机号码（11位） |
| | Internal IP Address | 内网IP地址 |
| | MAC Address | MAC地址 |
| **Sensitive Information** | Cloud Key | 云服务密钥（阿里云LTAI等） |
| | Password Field | 密码字段（JSON/JS格式） |
| | Username Field | 用户名字段 |
| | JDBC Connection | JDBC连接串 |
| | Authorization Header | Basic/Bearer认证头 |
| | Sensitive Field | 敏感字段（key/secret/token等） |
| | Name Field | 姓名字段 |
| | Phone Field | 手机号字段 |
| | Email Field | 邮箱字段 |
| | Address Field | 地址字段 |
| | ID Card Field | 身份证字段 |
| **Cloud Service Credentials** | Alibaba Cloud AccessKey | 阿里云AccessKey |
| | Alibaba Cloud SecretKey | 阿里云SecretKey |
| | Tencent Cloud SecretId | 腾讯云SecretId |
| | Tencent Cloud SecretKey | 腾讯云SecretKey |
| | Huawei Cloud AK | 华为云AK |
| | Huawei Cloud SK | 华为云SK |
| | AWS Access Key | AWS访问密钥 |
| | Azure Storage Key | Azure存储密钥 |
| | GCP Service Account | GCP服务账号 |
| | Cloud Storage Bucket | 云存储桶 |
| | Mobile Number Field | 手机号字段 |
| | Userinfo In Link | URL中的用户凭证 |
| **Fingerprint** | Shiro | Apache Shiro特征 |
| | JSON Web Token | JWT令牌 |
| | Swagger UI | Swagger接口文档 |
| | Druid | Druid监控控制台 |
| **Other** | Linkfinder | URL和路径提取 |
| | All URL | HTTP/HTTPS链接 |
| | Source Map | Source Map文件 |
| **HeapDump Enhanced** | RSA Private Key | RSA私钥 |
| | AWS Access Key | AWS访问密钥 |
| | GitHub Token | GitHub令牌 |
| | Slack Token | Slack令牌 |
| | Connection String | 连接串（mongodb/redis/kafka） |
| | Internal Domain | 内网域名（.local/.internal等） |

## 使用方法

### 基本用法

```bash
# 使用内置规则（自动启用HaE规则引擎）
java -jar JDumpSpiderPlus.jar heapdump

# 指定自定义规则文件
java -jar JDumpSpiderPlus.jar heapdump --rules /path/to/Rules.yml

# 输出到指定文件
java -jar JDumpSpiderPlus.jar heapdump -out result.txt

# 导出所有字符串
java -jar JDumpSpiderPlus.jar heapdump export-strings
```

### 命令行参数

```
JDumpSpiderPlus v2.3 - HeapDump Sensitive Information Extractor

Usage:
  java -jar JDumpSpiderPlus.jar <heapfile> [options]
  java -jar JDumpSpiderPlus.jar -u <url> [options]

Options:
  -u <url>          Download heapdump from URL
  --proxy <proxy>   Set proxy (http://host:port)
  --header <header> Add HTTP header (can be used multiple times)
  --rules <path>    Load custom HaE rules YAML file
  --format <format> Output format: text (default), json
  -out <path>       Output results to file
  export-strings    Export all strings from heap dump
  -h, --help        Show this help message

Examples:
  java -jar JDumpSpiderPlus.jar heapdump.hprof
  java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump
  java -jar JDumpSpiderPlus.jar -u http://target.com/actuator/heapdump --proxy http://127.0.0.1:8080
  java -jar JDumpSpiderPlus.jar heapdump.hprof --format json
```

### 输出说明

扫描结果自动保存到heapdump文件同目录的`results/`文件夹：

```
results/
├── tool_scan.txt      # 工具自身扫描结果（数据库、Redis、Shiro等）
└── regex_scan.txt     # HaE规则扫描结果（邮箱、IP、URL等）
```

## 编译

需要Maven、JDK 1.8+。

```bash
# 首先安装netbeans-lib-profiler依赖
cd lib/
mvn install:install-file -Dfile=netbeans-lib-profiler.jar -DgroupId=netbeans -DartifactId=netbeans-lib-profiler -Dversion=1.0 -Dpackaging=jar

# 编译打包
cd ..
mvn package
```

编译完成后，目标文件在`target/JDumpSpiderPlus-2.3-SNAPSHOT-full.jar`。

## 自定义规则

支持HaE的YAML规则格式：

```yaml
rules:
  - group: Custom Rules
    rule:
      - name: 身份证号码
        loaded: true
        f_regex: '[^0-9]((\d{8}(0\d|10|11|12)([0-2]\d|30|31)\d{3}$)|(\d{6}(18|19|20)\d{2}(0[1-9]|10|11|12)([0-2]\d|30|31)\d{3}(\d|X|x)))[^0-9]'
        s_regex: ''
        format: '{0}'
        color: orange
        scope: response body
        engine: nfa
        sensitive: true
```

### 规则字段说明

| 字段 | 说明 | 示例 |
|------|------|------|
| name | 规则名称 | 身份证号码 |
| loaded | 是否启用 | true/false |
| f_regex | 主正则表达式 | `(\d{18})` |
| s_regex | 辅助正则（过滤用） | 可为空 |
| format | 输出格式 | `{0}` 表示第一个捕获组 |
| color | 颜色标记 | red/orange/yellow/green/cyan/blue/gray |
| scope | 匹配范围 | response body/any/request等 |
| engine | 正则引擎 | nfa（支持捕获组）/ dfa（快速匹配） |
| sensitive | 大小写敏感 | true/false |

## 配置文件

支持YAML格式的配置文件，配置文件位置：

- 内置配置：`src/main/resources/config.yml`
- 用户配置：`~/.jdumpspider/config.yml`
- 当前目录：`./config.yml`

配置优先级：命令行参数 > 用户目录配置 > 当前目录配置 > 内置配置

### 配置示例

```yaml
# 扫描设置
scan:
  max-strings: 2000000        # 最大字符串数量
  max-match-per-rule: 5000    # 每个规则最大匹配数
  threads: 0                  # 并行线程数 (0=CPU核心数)
  timeout: 300                # 超时时间（秒）

# 输出设置
output:
  format: text                # 输出格式: text, json
  save-to-file: true          # 是否保存到文件
  output-dir: results         # 输出目录

# 代理设置
proxy:
  url: http://127.0.0.1:8080  # 代理地址

# 规则设置
rules:
  use-builtin: true           # 是否使用内置规则
  custom-rules: null          # 自定义规则文件路径
  hae-rules: true             # 是否启用HaE规则
```

## 技术架构

```
JDumpSpiderPlus/
├── cn.wanghw/
│   ├── Main.java                    # 主入口
│   ├── ISpider.java                 # Spider接口
│   ├── IHeapHolder.java             # Heap抽象接口
│   ├── spider/                      # 内置提取器
│   │   ├── DataSource01-05          # 数据源提取器
│   │   ├── Redis01-03               # Redis提取器（含集群/哨兵）
│   │   ├── MongoDB01                # MongoDB提取器
│   │   ├── Kafka01                  # Kafka提取器
│   │   ├── RabbitMQ01               # RabbitMQ提取器
│   │   ├── Elasticsearch01          # Elasticsearch提取器
│   │   ├── Nacos01                  # Nacos提取器
│   │   ├── ShiroKey01               # ShiroKey提取器
│   │   ├── PropertySource01-05      # 配置文件提取器
│   │   ├── UserPassSearcher01       # 用户信息提取器
│   │   ├── CookieThief              # Cookie提取器
│   │   ├── AuthThief                # 认证信息提取器
│   │   └── HeapdumpRegexSpiderParallel  # HaE规则引擎（并行版）
│   ├── har/                         # HaE规则相关
│   │   ├── RuleDefinition           # 规则定义模型
│   │   ├── Group                    # 规则分组模型
│   │   └── HaERulesLoader           # YAML规则加载器
│   └── utils/                       # 工具类
│       ├── ConfigLoader             # 配置文件加载器
│       ├── HttpDownloader           # HTTP下载器
│       ├── JsonOutputFormatter      # JSON格式化器
│       └── LuhnValidator            # Luhn算法验证器
└── org.graalvm/                     # Heap解析库
```

## 与原版JDumpSpider的区别

| 特性 | JDumpSpider | JDumpSpiderPlus |
|------|-------------|-----------------|
| 数据源提取 | ✓ | ✓ |
| Redis配置提取 | ✓ | ✓（含集群/哨兵） |
| ShiroKey提取 | ✓ | ✓ |
| 配置文件提取 | ✓ | ✓ |
| 中间件提取 | ✗ | ✓（Kafka/RabbitMQ/ES/Nacos） |
| 正则规则引擎 | ✗ | ✓（HaE集成） |
| 邮箱/手机号/身份证匹配 | ✗ | ✓ |
| URL/路径提取 | ✗ | ✓ |
| 云服务密钥检测 | ✗ | ✓（阿里/腾讯/华为/AWS/Azure/GCP） |
| 自定义规则 | ✗ | ✓（YAML格式） |
| URL下载 | ✗ | ✓（-u参数） |
| 代理支持 | ✗ | ✓（--proxy参数） |
| JSON输出 | ✗ | ✓（--format json） |
| 并行处理 | ✗ | ✓（多线程扫描） |
| 配置文件 | ✗ | ✓（config.yml） |
| 结果自动保存 | ✗ | ✓（results/目录） |

## 致谢

本项目基于以下优秀开源项目，特此感谢：

- **[JDumpSpider](https://github.com/whwlsfb/JDumpSpider)** - 原版HeapDump敏感信息提取工具，由 [whwlsfb](https://github.com/whwlsfb) 开发
- **[HaE](https://github.com/gh0stkey/HaE)** - 正则规则引擎，用于高亮和提取HTTP消息中的敏感信息，由 [gh0stkey](https://github.com/gh0stkey) 开发

感谢原作者们的杰出工作！

## License

[Apache License 2.0](LICENSE)
