# 降误报判定工具：正向关键字 + 负向排除联合判定（见 agents.md §5）


def match_positive(text, positives, negatives=None):
    """正向命中：text 含任一 positives 且不含任何 negatives

    Args:
        text: 响应文本
        positives: 正向关键字列表（命中任一即为正向特征存在）
        negatives: 负向排除关键字列表（命中任一即判为噪声/WAF/错误页）
    """
    if text is None:
        return False
    if not any(p in text for p in positives):
        return False
    if negatives and any(n in text for n in negatives):
        return False
    return True


def match_all(text, keywords):
    """联合命中：text 必须同时包含所有 keywords（如 root + :/）"""
    if text is None:
        return False
    return all(k in text for k in keywords)


def match_php_eval_response(text):
    """检测响应是否是 PHP 函数求值结果（phpinfo / phpversion 真实漏洞响应）

    用于 ThinkPHP RCE 类插件在真实漏洞环境上的判定补充：
    签名靶场返回 marker 字符串，真实漏洞返回 phpinfo HTML 或 phpversion 字符串。
    本函数判定 phpinfo HTML 表格 / phpversion 输出特征。

    Args:
        text: 响应文本

    Returns:
        True 表示响应含 PHP 函数求值结果（真实漏洞响应）
    """
    if not text:
        return False
    # phpinfo() HTML 输出特征：含 PHP Version + phpinfo() 或 <!DOCTYPE
    if 'PHP Version' in text and ('phpinfo()' in text or '<!DOCTYPE' in text):
        return True
    # phpinfo() 调用痕迹（部分环境仅输出 phpinfo() 错误或部分内容）
    if 'phpinfo()' in text and 'PHP' in text:
        return True
    # phpversion() 输出：短字符串 7.x.x / 8.x.x 格式
    # 真实 phpversion 输出通常 < 50 字节，形如 '7.2.34' 或 '8.1.0'
    if len(text) < 50 and any(p in text for p in ['7.', '8.']) and '.' in text:
        # 排除常见误报：'7.' 单独出现可能是页码、时间等
        # phpversion 输出是纯版本号，不含 HTML/JSON 标记
        if '<' not in text and '{' not in text:
            return True
    return False


def match_sql_error(text):
    """检测响应是否含 SQL 报错注入特征（extractvalue / updatexml 真实回显）

    用于 SQL 注入类插件在真实漏洞环境上的判定补充。
    真实漏洞响应含 'XPATH syntax error' '~<dbname>~' 'SQLSTATE' 等特征。
    """
    if not text:
        return False
    sql_error_features = [
        'XPATH syntax error',           # MySQL extractvalue 报错
        'SQLSTATE',                     # PDO/MySQL 错误
        'You have an error in your SQL syntax',  # MySQL 语法错误
        'Operand should contain',       # MySQL 类型错误
        'Truncated incorrect',          # MySQL 截断错误
        'Data too long for column',     # MySQL 数据过长
    ]
    return any(f in text for f in sql_error_features)


def match_file_read_leak(text):
    """检测响应是否含敏感文件内容特征（/etc/passwd 等）

    用于文件读取类插件在真实漏洞环境上的判定补充。
    """
    if not text:
        return False
    file_features = [
        'root:x:0:0:',                  # /etc/passwd
        'root:*:0:0:',                  # /etc/passwd (BSD)
        'daemon:x:1:1:',                # /etc/passwd
        'nobody:x:65534:',              # /etc/passwd
        'www-data:x:33:',               # /etc/passwd Debian/Ubuntu
        'apache:x:48:',                 # /etc/passwd CentOS
        '[boot loader]',                # Windows boot.ini
    ]
    return any(f in text for f in file_features)


def match_spring_actuator_env(text):
    """检测响应是否是 Spring Boot Actuator env 真实响应

    用于 actuator_env_rce / actuator_unauth 等插件在真实漏洞环境上的判定补充。
    真实 /actuator/env 响应含 propertySources / activeProfiles / applicationConfig 等特征。
    """
    if not text:
        return False
    env_features = [
        'propertySources',          # /actuator/env 标准字段
        'applicationConfig',         # 配置源标识
        'activeProfiles',            # 激活的 profile
        'spring.datasource',         # 数据源配置（含敏感信息）
    ]
    return any(f in text for f in env_features)


def match_heapdump_binary(text):
    """检测响应是否是 Spring Boot heapdump 二进制内容

    用于 heapdump_leak 插件在真实漏洞环境上的判定补充。
    真实 heapdump 是 hprof 二进制，含 JAVA PROFILE 头 / 敏感字符串特征。
    """
    if not text:
        return False
    heap_features = [
        'JAVA PROFILE',              # hprof 文件头
        'hprof',                     # hprof 标识
        'password=',                 # 堆中字符串敏感信息
        'aws_secret_access_key',     # AWS 凭证
        'BEGIN RSA PRIVATE KEY',     # RSA 私钥
        'BEGIN PRIVATE KEY',         # PKCS#8 私钥
        'Authorization: Bearer',    # JWT/Token
        'jdbc:mysql://',             # 数据库连接串
        'jdbc:postgresql://',        # PostgreSQL 连接串
    ]
    return any(f in text for f in heap_features)


def match_h2_console(text):
    """检测响应是否是 H2 Console 真实页面

    用于 h2_console_rce 插件在真实漏洞环境上的判定补充。
    真实 H2 Console 返回 HTML 含 <title>H2 Console</title> 或 H2 登录表单。
    """
    if not text:
        return False
    h2_features = [
        '<title>H2 Console</title>',     # H2 Console 页面标题
        'H2 Console',                    # H2 Console 文本
        'Generic H2',                     # H2 驱动选项
        'org.h2.Driver',                  # H2 JDBC 驱动类
        'h2-console',                     # H2 Console 路径
    ]
    return any(f in text for f in h2_features)


def match_jolokia_response(text):
    """检测响应是否是 Jolokia JMX-HTTP 桥真实响应

    用于 jolokia_rce / jolokia_mlet_rce 插件在真实漏洞环境上的判定补充。
    真实 Jolokia 响应含 JMX MBean 域 / reloadByURL / request.type 等特征。
    """
    if not text:
        return False
    jolokia_features = [
        'reloadByURL',                # logback JNDI 链关键 MBean 操作
        'JMXConfigurator',            # logback JMX MBean 类名
        'javax.management',            # JMX 标识
        'mbean',                       # Jolokia 请求字段
        '"type":"EXEC"',              # Jolokia EXEC 请求
        "'type': 'EXEC'",
    ]
    return any(f in text for f in jolokia_features)


def match_spring4shell_response(text):
    """检测响应是否是 Spring4Shell 利用成功响应

    用于 spring4shell 插件在真实漏洞环境上的判定补充。
    Spring4Shell 实际利用不直接返回特征（写 Tomcat 日志），但当 class.module.classLoader
    探针 POST 返回 200 且响应无错误标识时，说明参数绑定可访问 ClassLoader。

    真实成功响应特征：
    - JSON 含 "status":200 或 "status": 200（Spring Boot 标准成功响应）
    - JSON 含 "timestamp"（Spring Boot 标准响应格式）
    - 空响应体（部分 Tomcat 直接返回 200 空体）

    排除的失败响应特征：
    - "Bad Request" / "error" / "Whitelabel Error Page" / "status":400
    """
    if not text:
        # 空响应体 + 200 状态码（由插件保证）= 成功利用
        return True
    # 排除失败响应特征
    fail_indicators = [
        'Bad Request', '"error"', "'error'",
        'Whitelabel Error Page', '"status":400', '"status": 400',
        '"status":404', '"status": 404',
        '"status":500', '"status": 500',
    ]
    if any(ind in text for ind in fail_indicators):
        return False
    # 真实成功响应特征：JSON 含 "status":200 / "timestamp"
    success_indicators = ['"status":200', '"status": 200', '"timestamp"', 'message']
    return any(ind in text for ind in success_indicators)


def match_trace_leak(text):
    """检测响应是否是 Spring Boot Actuator /trace 真实响应

    用于 trace_leak 插件在真实漏洞环境上的判定补充。
    真实 /actuator/trace 响应含 traces 数组 + request/response 字段。
    """
    if not text:
        return False
    trace_features = [
        '"traces"',                  # traces 数组字段
        "'traces'",
        'httptrace',                 # /actuator/httptrace 端点
        'timeTaken',                 # 请求耗时字段
        'request": {"method"',       # 请求结构
        "request': {'method'",
    ]
    return any(f in text for f in trace_features)


def match_cloud_function_spel(text):
    """检测响应是否是 Spring Cloud Function SpEL 求值结果

    用于 cloud_function_rce 插件在真实漏洞环境上的判定补充。
    真实 SpEL 求值 T(java.lang.String).valueOf(7*7) 返回 '49'（短字符串数字）。
    """
    if not text:
        return False
    text_stripped = text.strip()
    # SpEL 求值结果 7*7=49 / 6*7=42 / 8*8=64 等短数字字符串
    if len(text_stripped) < 20 and text_stripped.isdigit():
        return True
    # SpEL 命令执行结果回显（短输出）
    if 'uid=' in text and 'gid=' in text:
        return True  # id 命令输出
    if 'root' in text and ':' in text and len(text) < 100:
        return True  # /etc/passwd 读取结果
    return False


def match_gateway_route_created(text):
    """检测响应是否是 Spring Cloud Gateway 路由创建成功响应

    用于 gateway_rce 插件在真实漏洞环境上的判定补充。
    真实路由创建返回 201 Created + 路由信息（filters / uri / order）。
    """
    if not text:
        return False
    gateway_features = [
        'AddResponseHeader',         # 路由 Filter 名
        'filters',                   # 路由字段
        'route',                      # 路由标识
        'predicate',                  # 路由谓词
    ]
    # 至少命中 2 个特征才算 Gateway 路由响应
    return sum(1 for f in gateway_features if f in text) >= 2

