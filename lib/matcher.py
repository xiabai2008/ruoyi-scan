# 降误报判定工具：正向关键字 + 负向排除联合判定（见 agents.md §5）
import re

# 框架自带的「资源不存在」错误页标记。
# 若依 v4.8.3（Spring Boot 4）对**任意**路径都返回 HTTP 200 + JSON：
#   {"msg":"No static resource rocketmq for request '/rocketmq/'.","code":500}
# 正文里回显了请求路径 → 组件探测类插件若拿路径名当关键字（/rocketmq/、/minio/…），
# 会 100% 误判成「组件存在且未授权」（实测 2026-10-29：R5 上 RocketMQ Dashboard
# 未授权误报，靶场根本没装 RocketMQ）。
_MISSING_RESOURCE_MARKERS = (
    "no static resource",
    "no handler found",
    "resource not found",
)

# 登录墙的「认证失败」JSON 同样不是「组件存在」的证据：
# 若依前后端分离版未认证访问任意受保护路径返回 HTTP 200 +
#   {"msg":"请求访问：/rocketmq/，认证失败，无法访问系统资源","code":401}
# 正文回显请求路径 → 拿路径名当关键字的组件探测插件 100% 误判。
# 实测 2026-10-29 R7（只反代 /prod-api/）：/prod-api/rocketmq/ 返回 401 回显，
# 「RocketMQ Dashboard 未授权」被误报（靶场根本没装 RocketMQ）。
_AUTH_FAILURE_RE = re.compile(r'"(?:code|status)"\s*:\s*(?:401|403)\b|认证失败|无法访问系统资源')

# 例外：当「正向关键字」本身就是鉴权拦截文案时（未授权类插件用它判定「已鉴权」），
# 不能把 401 响应一律排除，否则这些插件会把「被拦截」误判成「未命中」。
_AUTH_BLOCK_KEYWORDS = frozenset(
    {"认证失败", "无法访问系统资源", "请先登录", "未登录", "登录", "unauthorized", "未授权"}
)


def is_auth_failure_page(text) -> bool:
    """判断正文是否是登录墙返回的「认证失败」统一响应（不是资源/组件存在证据）"""
    if not text:
        return False
    return bool(_AUTH_FAILURE_RE.search(text))


# 「当前会话已认证」的响应特征。用于未授权类插件的**反向证据**：
# 如果拿到的 200 是「某个已登录用户」的响应，就不能据此判「未授权访问」。
#
# 特征选择原则：只认**业务身份回显**，不认泛用词。
# 宁可漏判（退回 UNKNOWN）也不能误伤——若把普通公开页误判成「已认证」，
# 真正的未授权漏洞就会被降级成 UNKNOWN（假阴性）。
_AUTHENTICATED_HINTS = (
    # 若依/Jeecg 常见的登录用户回显字段（JSON）
    re.compile(r'"(?:userName|loginName|nickName)"\s*:\s*"[^"]{1,40}"'),
    re.compile(r'"userId"\s*:\s*\d+'),
    # 权限/角色列表：只有已认证用户才会有这些东西
    re.compile(r'"(?:permissions|roles)"\s*:\s*\[\s*[{\["]'),
    # 会话 token 回显（部分网关把 token 放在响应体里）
    re.compile(r'"(?:access_token|accessToken|token)"\s*:\s*"[A-Za-z0-9._\-]{16,}"'),
)


def looks_authenticated(body, headers=None):
    """响应是否透露出「当前会话已认证」的迹象（未授权类插件的反向证据）。

    为什么需要它（v1.6 A2）：未授权类插件的被测命题是「不登录就能访问」。
    即使引擎已用干净会话探测（`anonymous_probe`），仍有一种情况无法排除——
    目标把「未授权可访问」和「登录后可访问」返回得一模一样。
    此时响应里的身份回显就是唯一能区分两者的信号。

    Returns:
        (hit: bool, reason: str)
    """
    text = body or ""
    if not isinstance(text, str):
        try:
            text = text.decode("utf-8", errors="ignore")
        except Exception:
            return False, "响应体无法解码"

    # Set-Cookie 里下发**认证态**凭证 = 当前会话是登录的。
    #
    # ⚠ 这里刻意不含 JSESSIONID（2026-11-02 修正）：
    #   任何 Java 应用（Tomcat/Shiro）对**匿名**请求也会下发 JSESSIONID，
    #   它与「是否已登录」没有因果关系。把它当认证信号会让
    #   「未授权访问」在这类站点上被判成 SAFE——一个假阴性就抵掉一次真实告警，
    #   方向与三态纪律完全相反（该报没报）。
    #   只认应用层自己签发的 token 名：Sa-Token 的 satoken、Jeecg 的 X-Access-Token、
    #   以及若依 Plus 的 Admin-Token / Authorization。
    if headers:
        try:
            cookies = str(headers.get("Set-Cookie", "") or "")
            if re.search(r"(?:satoken|X-Access-Token|Admin-Token|Authorization)\s*=", cookies, re.I):
                return True, "响应下发了应用层会话凭证（Set-Cookie）"
        except Exception:
            pass

    for pat in _AUTHENTICATED_HINTS:
        m = pat.search(text)
        if m:
            snippet = m.group(0)[:60]
            return True, f"响应含已登录用户特征：{snippet}"
    return False, "未发现已认证痕迹"


def is_missing_resource_page(text) -> bool:
    """判断响应正文是否是「资源不存在」错误页

    Args:
        text: 响应文本

    Returns:
        True 表示这是框架回显的「找不到该资源」页面，不含任何有效组件特征
    """
    if not text:
        return False
    low = text.lower()
    return any(m in low for m in _MISSING_RESOURCE_MARKERS)


# HTML catch-all 路由的特征：把**请求路径本身**写进页面。
#
# 第三类「路径回显」陷阱（2026-11-01 盲测 v2 实测）：
# 靶场用 `/**` 路由兜底时，任意路径都返回 200 HTML，页面标题/正文里带着请求路径：
#   GET /rocketmq/       → <html><body><h2>页面: rocketmq/</h2></body></html>
#   GET /swagger-ui.html → <html><body><h2>页面: swagger-ui.html</h2></body></html>
#
# 组件探测类插件拿路径名当关键字（"rocketmq"、"swagger"），于是 100% 误判。
# 前两道排除（missing resource / auth failure）只覆盖 JSON 回显，管不了 HTML。
_CATCH_ALL_MAX_LEN = 600


def is_path_echo_page(text, request_path: str = "") -> bool:
    """判断响应是否是「把请求路径回显在页面里」的 catch-all 兜底页。

    与 is_missing_resource_page / is_auth_failure_page 同类，是第三道排除。
    区别：靠**「页面里出现了请求路径」**判定，不依赖固定文案。

    Args:
        text: 响应正文
        request_path: 实际请求的路径（如 "/rocketmq/"）。为空时无法可靠判定，返回 False。

    Returns:
        True 表示这是 catch-all 回显页，正文里的路径名不能当组件存在证据。
    """
    if not text or not request_path:
        return False
    # 只处理短页面：真实组件页面（Swagger UI / Druid / RocketMQ 控制台）
    # 都在几十 KB 量级，不会短到这个程度。设上限避免误杀正常页面。
    if len(text) > _CATCH_ALL_MAX_LEN:
        return False

    low = text.lower()
    if "<html" not in low and "<body" not in low and "<h2" not in low:
        return False

    full = request_path.split("?")[0].strip("/")
    if not full:
        return False

    # ⚠ 判据核心：「页面内容几乎只有路径」。
    #
    # 不能用「路径作为词出现」—— 踩过两次坑：
    #   1. 裸子串：`rocketmqCluster` 里的 `rocketmq` 会命中
    #   2. 词边界：真实 RocketMQ 控制台的 `<title>RocketMQ Dashboard</title>`
    #      里 `rocketmq` 前后是 `>` 和空格，**是合法词边界**，但那是品牌词，
    #      不是路径回显 → 真实控制台被误杀成 SAFE
    #
    # 回显页的真正形态是「整页除了这句路径几乎没有别的东西」。
    # 所以判据改为：把路径从页面里**剥掉**，剩下的「有效内容」极少。
    # 真实组件页面剥掉品牌词后仍有大量结构/脚本/文案，不会被误判。
    needle = full.lower()
    seg = full.rsplit("/", 1)[-1].lower()
    # 路径本身必须先出现在正文里，才谈得上「路径回显」。
    # 真实但很短的组件页可能只含品牌词（如签名靶场的 75 字节 Swagger 页
    # "<h1>swagger 接口文档</h1>"，并不包含 "/swagger-ui.html"），
    # 若把这类页面也判成回显，会把真实端点误杀成 SAFE（2026-11-02 CI 实测）。
    if needle not in low and seg not in low:
        return False
    stripped = low.replace(needle, "").replace(seg, "")

    # 剥掉路径后剩下的「有效字符」（去掉 HTML 标签和空白）
    residual = re.sub(r"<[^>]*>", "", stripped)
    residual = re.sub(r"[\s:：\-—()（）\[\]{}'\"+/.,;]", "", residual)

    # 剩下的非路径内容少于 20 个字符 → 整页基本就是路径回显
    if len(residual) <= 20:
        return True

    # 页面很短（<=150）时再看「残留内容占正文有效内容的比例」：
    # 真实组件页即使很短，剥掉路径后它本该有的文案仍在（如 Druid 监控页
    # "<title>Druid Stat Index</title>...Druid Monitor View"），残留占比很高；
    # 而回显页的正文几乎只有路径，残留占比很低。
    # 不能用「残留 < 正文长度一半」这种按整页长度的算法 —— 短真实页会被误杀
    # （2026-11-02 实测：Druid Stat Index 88 字节页被误判成路径回显，导致
    #  regression_ruoyi 的 Druid 监控用例从 CONFIRMED 退化为 SAFE）。
    content = re.sub(r"<[^>]*>", "", low)
    content = re.sub(r"[\s:：\-—()（）\[\]{}'\"+/.,;]", "", content)
    return len(text) <= 150 and bool(content) and len(residual) * 2 <= len(content)


def match_positive(text, positives, negatives=None, request_path=""):
    """正向命中：text 含任一 positives 且不含任何 negatives

    三类「路径回显」噪声一律判负 —— 它们只是把请求路径写在正文里，
    对组件探测类插件是纯噪声：

    1. 资源不存在错误页（JSON）
    2. 登录墙认证失败页（JSON）
    3. catch-all 路由把路径当页面内容回显（HTML），**需要传 request_path 才能识别**

    Args:
        text: 响应文本
        positives: 正向关键字列表（命中任一即为正向特征存在）
        negatives: 负向排除关键字列表（命中任一即判为噪声/WAF/错误页）
        request_path: 实际请求的路径（如 "/rocketmq/"）。传了才能排除 HTML catch-all；
            不传时保持旧行为（不少老插件没有现成的 path 变量）。
    """
    if text is None:
        return False
    if is_missing_resource_page(text):
        return False
    if is_auth_failure_page(text) and not any(p in _AUTH_BLOCK_KEYWORDS for p in positives):
        return False
    if request_path and is_path_echo_page(text, request_path):
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


def parse_json_body(resp):
    """从响应中尽最大努力解析出 JSON 对象（dict），失败或非对象返回 None

    优先用 resp.json()；部分 response 实现（测试桩/老版本客户端）未提供可用的 .json()，
    此时回退解析 resp.text。统一封装避免各插件重复 try/except 导致行为漂移。
    """
    if resp is None:
        return None
    try:
        body = resp.json()
    except Exception:
        body = None
    # 空 dict 视为未解析出有效对象：部分测试桩 .json() 恒返回 {}（即使正文有 JSON），
    # 若直接采信会丢失真实响应体，故继续走正文回退。
    if isinstance(body, dict) and body:
        return body
    # 回退：直接解析正文（.json() 抛错/返回非对象/返回空对象时）
    import json

    try:
        body = json.loads(getattr(resp, "text", "") or "")
    except Exception:
        return None
    return body if isinstance(body, dict) else None


def match_php_eval_response(text):
    """检测响应是否是 PHP 函数求值结果（phpinfo / phpversion 真实漏洞响应）

    通用判定函数：签名靶场返回 marker 字符串，真实漏洞返回 phpinfo HTML 或 phpversion 字符串。
    本函数判定 phpinfo HTML 表格 / phpversion 输出特征。

    Args:
        text: 响应文本

    Returns:
        True 表示响应含 PHP 函数求值结果（真实漏洞响应）
    """
    if not text:
        return False
    # phpinfo() HTML 输出特征：含 PHP Version + phpinfo() 或 <!DOCTYPE
    if "PHP Version" in text and ("phpinfo()" in text or "<!DOCTYPE" in text):
        return True
    # phpinfo() 调用痕迹（部分环境仅输出 phpinfo() 错误或部分内容）
    if "phpinfo()" in text and "PHP" in text:
        return True
    # phpversion() 输出：纯版本号短字符串（如 '7.2.34' / '8.1.0'）
    # 用整串版本号正则而非子串 "7."/"8."：避免 file7.txt、'Page 7.' 之类误命中
    if len(text) < 50 and re.match(r"^\d+\.\d+(\.\d+)*$", text.strip()):
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
        "XPATH syntax error",  # MySQL extractvalue 报错
        "SQLSTATE",  # PDO/MySQL 错误
        "You have an error in your SQL syntax",  # MySQL 语法错误
        "Operand should contain",  # MySQL 类型错误
        "Truncated incorrect",  # MySQL 截断错误
        "Data too long for column",  # MySQL 数据过长
    ]
    return any(f in text for f in sql_error_features)


def match_file_read_leak(text):
    """检测响应是否含敏感文件内容特征（/etc/passwd、win.ini 等）

    用于文件读取类插件在真实漏洞环境上的判定补充。
    """
    if not text:
        return False
    file_features = [
        "root:x:0:0:",  # /etc/passwd
        "root:*:0:0:",  # /etc/passwd (BSD)
        "daemon:x:1:1:",  # /etc/passwd
        "nobody:x:65534:",  # /etc/passwd
        "www-data:x:33:",  # /etc/passwd Debian/Ubuntu
        "apache:x:48:",  # /etc/passwd CentOS
        "[boot loader]",  # Windows boot.ini（**不是** win.ini，见 is_windows_ini）
    ]
    return any(f in text for f in file_features)


# win.ini 的真实结构（Windows 10/11 实测，2026-11-02，C:\Windows\win.ini 共 92 字节）：
#     ; for 16-bit app support
#     [fonts]
#     [extensions]
#     [mci extensions]
#     [files]
#     [Mail]
#     MAPI=1
#
# 为什么必须要求**多个段头共现**，不能只认单个 `[fonts]`：
#   - 单个段名太泛：`[files]`、`[Mail]` 在任意 INI 配置、甚至 HTML/JS 里都可能出现；
#   - 而 win.ini 的真实特征恰恰是「这几个段同时存在且几乎为空」——这是 Windows
#     为兼容 16 位程序保留的骨架，不是用户配置的产物。
#   - 也不能用 `[boot loader]`：那是 boot.ini（XP 引导配置）的段，与 win.ini 是
#     不同文件，混用会在 Win10/11 上漏报（boot.ini 早已不存在）。
_WIN_INI_MARKER = "for 16-bit app support"
_WIN_INI_SECTIONS = ("[fonts]", "[extensions]", "[mci extensions]", "[files]", "[Mail]")


def is_windows_ini(text):
    """判定响应是否为真实 win.ini 内容（Windows 任意文件读取的正向证据）

    两条路径任一成立即判真（保守优先，避免误报）：
      1. 含 `for 16-bit app support` 注释行（win.ini 独有，最可靠）；
      2. 含 ≥3 个 win.ini 特征段头（用户可能删了注释行，但段头是骨架）。

    Returns:
        (hit: bool, evidence: str)
    """
    if not text:
        return False, "空响应"
    lowered = text.lower()
    if _WIN_INI_MARKER in lowered:
        return True, "读取到 Windows win.ini（含 for 16-bit app support 特征行）"
    hit_sections = [s for s in _WIN_INI_SECTIONS if s.lower() in lowered]
    if len(hit_sections) >= 3:
        return True, "读取到 Windows win.ini（命中 %d 个特征段：%s）" % (len(hit_sections), ", ".join(hit_sections))
    if hit_sections:
        return False, "仅命中 %d 个 INI 段头（%s），不足以确认是 win.ini" % (
            len(hit_sections),
            ", ".join(hit_sections),
        )
    return False, "响应不含 win.ini 特征"


def is_passwd_file(text):
    """判定响应是否为真实 /etc/passwd 文件内容（严格正向证据，可复用于文件读取类插件）

    真实 /etc/passwd 文件特征：
    - 每行格式：username:x:uid:gid:gecos:home:shell
    - 含 root 账户行：root:x:0:0:root:/root:/bin/bash（或 /bin/sh）
    - 含 daemon/bin/sys 等系统账户行
    - uid/gid 为数字

    提取自 plugins/ruoyi/file_read_path.py 的私有 _is_passwd_file，统一为可复用公共函数，
    供 file_read / file_read_path 等插件共享，避免各自维护一份易漂移的判定逻辑。

    Returns:
        (hit: bool, evidence: str)
    """
    if not text:
        return False, "空响应"

    import re

    # 要求 ≥2 个 passwd 格式行：单行 root:x:0:0: 可能是恰好命中的噪声片段，
    # 真实 /etc/passwd 必含 root + 多个系统账户
    passwd_pattern = re.compile(r"^([a-zA-Z_][a-zA-Z0-9_-]*):x:(\d+):(\d+):", re.MULTILINE)
    matches = passwd_pattern.findall(text)
    if not matches:
        return False, "响应不含 passwd 格式行"
    if len(matches) < 2:
        return False, f"仅匹配到 {len(matches)} 个 passwd 行（需 ≥2）"

    # 强特征：含 root 账户（uid=0）
    has_root = any(name == "root" and uid == "0" for name, uid, gid in matches)
    # 次强特征：含常见系统账户（daemon/bin/sys/nobody/mail 等）
    system_accounts = {"root", "daemon", "bin", "sys", "nobody", "mail", "ftp", "www-data"}
    has_system = any(name in system_accounts for name, uid, gid in matches)

    if has_root or has_system:
        # 提取前 3 个账户名作为证据
        names = [m[0] for m in matches[:3]]
        return True, f"读取到 /etc/passwd：{names}"
    return False, "passwd 行无 root/系统账户"


def match_spring_actuator_env(text):
    """检测响应是否是 Spring Boot Actuator env 真实响应

    用于 actuator_env_rce / actuator_unauth 等插件在真实漏洞环境上的判定补充。
    真实 /actuator/env 响应含 propertySources / activeProfiles / applicationConfig 等特征。
    """
    if not text:
        return False
    env_features = [
        "propertySources",  # /actuator/env 标准字段
        "applicationConfig",  # 配置源标识
        "activeProfiles",  # 激活的 profile
        "spring.datasource",  # 数据源配置（含敏感信息）
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
        "JAVA PROFILE",  # hprof 文件头
        "hprof",  # hprof 标识
        "password=",  # 堆中字符串敏感信息
        "aws_secret_access_key",  # AWS 凭证
        "BEGIN RSA PRIVATE KEY",  # RSA 私钥
        "BEGIN PRIVATE KEY",  # PKCS#8 私钥
        "Authorization: Bearer",  # JWT/Token
        "jdbc:mysql://",  # 数据库连接串
        "jdbc:postgresql://",  # PostgreSQL 连接串
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
        "<title>H2 Console</title>",  # H2 Console 页面标题
        "H2 Console",  # H2 Console 文本
        "Generic H2",  # H2 驱动选项
        "org.h2.Driver",  # H2 JDBC 驱动类
        "h2-console",  # H2 Console 路径
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
        "reloadByURL",  # logback JNDI 链关键 MBean 操作
        "JMXConfigurator",  # logback JMX MBean 类名
        "javax.management",  # JMX 标识
        "mbean",  # Jolokia 请求字段
        '"type":"EXEC"',  # Jolokia EXEC 请求
        "'type': 'EXEC'",
    ]
    return any(f in text for f in jolokia_features)


def match_spring4shell_response(text):
    """检测响应是否是 Spring4Shell 利用成功响应

    用于 spring4shell 插件在真实漏洞环境上的判定补充。
    Spring4Shell 实际利用不直接返回特征（写 Tomcat 日志），但当 class.module.classLoader
    探针 POST 返回 200 且响应无错误标识时，说明参数绑定可访问 ClassLoader。

    真实成功响应特征（正向证据，缺一不可）：
    - JSON 含 "status":200 或 "status": 200（Spring Boot 标准成功响应）
    - JSON 含 "timestamp"（Spring Boot 标准响应格式）

    排除的失败响应特征：
    - "Bad Request" / "error" / "Whitelabel Error Page" / "status":400
    - 空响应体：200 + 空体在各类服务/网关中极常见，不足以作为成功证据（防误报）
    """
    if not text:
        # 空响应体不构成成功证据（调用方 200 + 空体极常见，不能据此判 CONFIRMED）
        return False
    # 排除失败响应特征
    fail_indicators = [
        "Bad Request",
        '"error"',
        "'error'",
        "Whitelabel Error Page",
        '"status":400',
        '"status": 400',
        '"status":404',
        '"status": 404',
        '"status":500',
        '"status": 500',
    ]
    if any(ind in text for ind in fail_indicators):
        return False
    # 真实成功响应特征：JSON 含 "status":200 / "timestamp"
    # （"message" 过于通用，404/参数校验错误 JSON 也常带，已移除以防误报）
    success_indicators = ['"status":200', '"status": 200', '"timestamp"']
    return any(ind in text for ind in success_indicators)


def match_trace_leak(text):
    """检测响应是否是 Spring Boot Actuator /trace 真实响应

    用于 trace_leak 插件在真实漏洞环境上的判定补充。
    真实 /actuator/trace 响应含 traces 数组 + request/response 字段。
    """
    if not text:
        return False
    trace_features = [
        '"traces"',  # traces 数组字段
        "'traces'",
        "httptrace",  # /actuator/httptrace 端点
        "timeTaken",  # 请求耗时字段
        'request": {"method"',  # 请求结构
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
    if "uid=" in text and "gid=" in text:
        return True  # id 命令输出
    # /etc/passwd 读取结果：必须命中 root 账户行特征（root:...:0:0:），
    # 否则 "root: permission denied" 之类的普通报错会被误判
    if len(text) < 100 and re.search(r"root:.*:0:0:", text):
        return True
    return False


def match_gateway_route_created(text):
    """检测响应是否是 Spring Cloud Gateway 路由创建成功响应

    用于 gateway_rce 插件在真实漏洞环境上的判定补充。
    真实路由创建返回 201 Created + 路由信息（filters / uri / order）。
    """
    if not text:
        return False
    gateway_features = [
        "AddResponseHeader",  # 路由 Filter 名
        "filters",  # 路由字段
        "route",  # 路由标识
        "predicate",  # 路由谓词
    ]
    # 至少命中 2 个特征才算 Gateway 路由响应
    return sum(1 for f in gateway_features if f in text) >= 2
