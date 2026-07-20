# D31：业务逻辑漏洞检测
#
# 检测业务逻辑类漏洞，这类漏洞无法通过传统特征匹配发现，需要基于认证状态、
# 权限边界、数据所有权等业务语义进行判断。
#
# 检测类型：
#   1. IDOR（不安全直接对象引用）：水平/垂直越权访问
#   2. 权限提升：普通用户访问管理接口
#   4. 批量操作滥用：绕过单次限制
#   5. 价格/数量篡改：订单参数修改
#   6. 并发竞争：重复提交、余额双花
#
# 依赖：
#   - D26 认证扫描（lib/auth_scan.py）：提供认证状态
#   - D9 Web API（core/session.py）：发起请求
#
# 使用方式：
#   python main.py -u http://target/ --logic-scan --auth-login admin:password
#   python main.py -u http://target/ --logic-scan --auth-file cookies.txt
import re
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.parse import urljoin, urlparse

# ============================================================
# 数据模型
# ============================================================


@dataclass
class LogicVuln:
    """业务逻辑漏洞"""

    vuln_type: str  # idor/privilege_escalation/parameter_tampering/race_condition
    name: str  # 漏洞名称
    severity: str  # high/medium/low
    url: str  # 漏洞 URL
    method: str = "GET"  # HTTP 方法
    evidence: str = ""  # 证据
    fix: str = ""  # 修复建议
    fix_detail: str = ""  # 修复详情
    reproduce: str = ""  # 复现命令
    description: str = ""  # 漏洞描述
    compliance: str = "等保2.0:8.1.4;OWASP:A01:2021"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_type": self.vuln_type,
            "name": self.name,
            "severity": self.severity,
            "url": self.url,
            "method": self.method,
            "evidence": self.evidence,
            "fix": self.fix,
            "fix_detail": self.fix_detail,
            "reproduce": self.reproduce,
            "description": self.description,
            "compliance": self.compliance,
        }


@dataclass
class EndpointInfo:
    """端点信息（从爬虫或手动收集）"""

    url: str
    method: str = "GET"
    params: List[str] = field(default_factory=list)
    requires_auth: bool = True
    id_param: Optional[str] = None  # 可能的对象引用参数名（id/uid/userId/orderId）
    response_size: int = 0
    response_code: int = 200


# ============================================================
# IDOR 检测器
# ============================================================

# 常见对象引用参数名
ID_PARAM_PATTERNS = [
    "id",
    "uid",
    "userid",
    "orderid",
    "docid",
    "fileid",
    "recordid",
    "itemid",
    "accountid",
    "deptid",
    "roleid",
    "menuid",
    "configid",
    "postid",
    "noticeid",
]


class IDORDetector:
    """IDOR（不安全直接对象引用）检测器

    检测策略：
    1. 识别含 ID 参数的端点
    2. 访问其他用户的资源 ID（递增/递减 1）
    3. 对比响应内容（状态码/大小/关键字段）
    4. 如果能访问他人数据，判定为 IDOR
    """

    def __init__(self, session=None, auth_info: Optional[Dict] = None):
        """
        Args:
            session: SessionManager 实例（已认证）
            auth_info: 认证信息（用户身份/角色等）
        """
        self.session = session
        self.auth_info = auth_info or {}
        self.results: List[LogicVuln] = []

    def detect_id_params(self, url: str, params: List[str]) -> List[str]:
        """识别 URL 中可能的 ID 参数

        Args:
            url: 目标 URL
            params: 已知参数列表

        Returns:
            匹配 ID 模式的参数名列表
        """
        id_params = []
        for p in params:
            if p.lower() in ID_PARAM_PATTERNS or re.search(r"(id|Id|ID)$", p):
                id_params.append(p)
        return id_params

    def test_idor(self, endpoint: EndpointInfo, test_ids: List[str] = None) -> Optional[LogicVuln]:
        """测试单个端点的 IDOR

        Args:
            endpoint: 端点信息
            test_ids: 要测试的 ID 列表（默认 [1, 2, 100]）

        Returns:
            发现的 LogicVuln，未发现返回 None
        """
        if not self.session:
            return None

        if test_ids is None:
            test_ids = ["1", "2", "100"]

        # 识别 ID 参数
        id_params = self.detect_id_params(endpoint.url, endpoint.params)
        if not id_params and not endpoint.id_param:
            return None

        target_param = endpoint.id_param or id_params[0]

        # 访问基准响应（当前用户自己的资源）
        try:
            baseline_resp = self.session.get(endpoint.url)
            baseline_text = baseline_resp.text or ""
            baseline_size = len(baseline_text)
        except Exception:
            return None

        # 测试其他 ID
        for test_id in test_ids:
            test_url = self._replace_param(endpoint.url, target_param, test_id)
            try:
                resp = self.session.get(test_url)
                resp_text = resp.text or ""
                resp_size = len(resp_text)
                resp_code = resp.status_code
            except Exception:
                continue

            # 判定逻辑：
            # 1. 状态码 200 + 有响应内容
            # 2. 响应大小与基准相近（不是 403/404 错误页）
            # 3. 不是明确的"无权限"错误提示
            if resp_code == 200 and resp_size > 100:
                # 检查是否含权限拒绝关键字
                denied_keywords = [
                    "无权限",
                    "权限不足",
                    "forbidden",
                    "unauthorized",
                    "禁止访问",
                    "没有权限",
                    "access denied",
                ]
                text_lower = resp_text.lower()
                if any(kw in text_lower for kw in denied_keywords):
                    continue

                # 响应大小相近（0.5x ~ 2x），可能是成功访问
                if baseline_size > 0:
                    ratio = resp_size / baseline_size
                    if 0.3 < ratio < 3.0:
                        return LogicVuln(
                            vuln_type="idor",
                            name=f"IDOR 越权访问 - {target_param}={test_id}",
                            severity="high",
                            url=test_url,
                            method="GET",
                            evidence=f"访问他人资源 {target_param}={test_id} 返回 200，"
                            f"响应大小 {resp_size}B（基准 {baseline_size}B）",
                            fix="实施严格的权限校验：服务端校验当前用户是否有权访问该资源",
                            fix_detail=(
                                "【代码修复】在 Controller 层校验资源所有权\n"
                                "【权限框架】使用 @PreAuthorize 注解或 AOP 拦截\n"
                                "【配置加固】启用 Spring Security 方法级权限\n"
                                "【WAF 规则】对敏感端点添加用户-资源归属校验\n"
                                "【合规】OWASP A01:2021 / 等保 2.0 8.1.4"
                            ),
                            reproduce=(
                                f"# 1. 使用普通用户认证\n"
                                f'curl -b "JSESSIONID=xxx" "{endpoint.url}"\n\n'
                                f"# 2. 篡改 ID 访问他人资源\n"
                                f'curl -b "JSESSIONID=xxx" "{test_url}"\n\n'
                                f"# 预期：返回 200 + 他人数据（应返回 403）"
                            ),
                            description="通过修改 URL 中的 ID 参数可访问其他用户的资源",
                        )

        return None

    def _replace_param(self, url: str, param: str, new_value: str) -> str:
        """替换 URL 中的参数值"""
        if "?" not in url:
            return f"{url}?{param}={new_value}"

        base, query = url.split("?", 1)
        params = query.split("&")
        new_params = []
        replaced = False
        for p in params:
            if "=" in p:
                k, v = p.split("=", 1)
                if k == param:
                    new_params.append(f"{param}={new_value}")
                    replaced = True
                else:
                    new_params.append(p)
            else:
                new_params.append(p)

        if not replaced:
            new_params.append(f"{param}={new_value}")

        return f"{base}?{'&'.join(new_params)}"


# ============================================================
# 权限提升检测器
# ============================================================

# 管理端点常见路径模式
ADMIN_PATH_PATTERNS = [
    r"/admin/",
    r"/manage/",
    r"/system/",
    r"/sys/",
    r"/backend/",
    r"/console/",
    r"/dashboard/",
    r"/api/admin/",
    r"/api/system/",
    r"/api/manage/",
]


class PrivilegeEscalationDetector:
    """权限提升检测器

    检测普通用户是否能访问管理接口。
    """

    def __init__(self, session=None, auth_info: Optional[Dict] = None):
        self.session = session
        self.auth_info = auth_info or {}
        self.results: List[LogicVuln] = []

    def detect_admin_endpoints(self, base_url: str, paths: List[str] = None) -> List[str]:
        """发现可能的管理端点

        Args:
            base_url: 目标基础 URL
            paths: 自定义路径列表（默认扫描常见管理路径）

        Returns:
            存在的管理端点 URL 列表
        """
        if paths is None:
            paths = [
                "/admin/index",
                "/admin/list",
                "/admin/user",
                "/system/user/list",
                "/system/role/list",
                "/system/menu/list",
                "/system/config/list",
                "/system/dept/list",
                "/manage/dashboard",
                "/console/api/users",
            ]

        found = []
        for path in paths:
            url = urljoin(base_url, path)
            if not self.session:
                # 无 session 时仅做路径匹配判断
                for pattern in ADMIN_PATH_PATTERNS:
                    if re.search(pattern, url, re.IGNORECASE):
                        found.append(url)
                        break
                continue

            try:
                resp = self.session.get(url)
                # 200 且非登录页
                if resp.status_code == 200:
                    text = resp.text or ""
                    login_keywords = ["登录", "login", "请先登录", "unauthorized"]
                    if not any(kw in text.lower() for kw in login_keywords):
                        found.append(url)
            except Exception:
                continue

        return found

    def test_privilege_escalation(self, url: str) -> Optional[LogicVuln]:
        """测试单个端点的权限提升

        Args:
            url: 管理端点 URL

        Returns:
            发现的 LogicVuln，未发现返回 None
        """
        if not self.session:
            return None

        try:
            resp = self.session.get(url)
            resp_code = resp.status_code
            resp_text = resp.text or ""
            resp_size = len(resp_text)
        except Exception:
            return None

        # 普通用户能 200 访问管理接口
        if resp_code == 200 and resp_size > 100:
            denied_keywords = ["无权限", "权限不足", "forbidden", "unauthorized", "禁止访问", "没有权限"]
            if any(kw in resp_text.lower() for kw in denied_keywords):
                return None

            return LogicVuln(
                vuln_type="privilege_escalation",
                name=f"权限提升 - 普通用户可访问管理接口 {url}",
                severity="high",
                url=url,
                method="GET",
                evidence=f"普通用户访问管理端点返回 200，响应大小 {resp_size}B",
                fix="实施基于角色的访问控制（RBAC），校验用户角色权限",
                fix_detail=(
                    "【代码修复】使用 Spring Security @PreAuthorize 注解\n"
                    "【权限框架】配置 RoleHierarchy 区分普通用户/管理员\n"
                    "【配置加固】Spring Security 配置 intercept-url 角色映射\n"
                    "【WAF 规则】对 /admin/** /system/** 路径强制角色校验\n"
                    "【合规】OWASP A01:2021 / 等保 2.0 8.1.4"
                ),
                reproduce=(
                    f"# 1. 普通用户登录获取 Cookie\n"
                    f'curl -c cookies.txt -d "username=user&password=pass" "{url}/login"\n\n'
                    f"# 2. 访问管理端点\n"
                    f'curl -b cookies.txt "{url}"\n\n'
                    f"# 预期：返回 403（实际返回 200 + 管理数据）"
                ),
                description="普通用户通过认证后可访问应仅限管理员访问的接口",
            )

        return None


# ============================================================
# 参数篡改检测器
# ============================================================


class ParameterTamperingDetector:
    """参数篡改检测器

    检测价格/数量等关键参数是否可被客户端篡改。
    """

    # 价格/数量相关参数
    PRICE_PARAMS = ["price", "amount", "totalPrice", "total", "fee", "cost", "payment"]
    QUANTITY_PARAMS = ["quantity", "count", "num", "qty"]

    def __init__(self, session=None, auth_info: Optional[Dict] = None):
        self.session = session
        self.auth_info = auth_info or {}
        self.results: List[LogicVuln] = []

    def detect_tamperable_params(self, endpoint: EndpointInfo) -> List[str]:
        """识别可能可篡改的参数"""
        tamperable = []
        for p in endpoint.params:
            p_lower = p.lower()
            if any(kw in p_lower for kw in self.PRICE_PARAMS + self.QUANTITY_PARAMS):
                tamperable.append(p)
        return tamperable

    def test_parameter_tampering(
        self, endpoint: EndpointInfo, param: str, original_value: str = "100", tampered_value: str = "0.01"
    ) -> Optional[LogicVuln]:
        """测试参数篡改

        Args:
            endpoint: 端点信息
            param: 参数名
            original_value: 原始值
            tampered_value: 篡改后的值

        Returns:
            发现的 LogicVuln
        """
        if not self.session:
            return None

        # 发送篡改后的值
        test_url = self._build_tampered_url(endpoint.url, param, tampered_value)
        try:
            resp = self.session.get(test_url)
            resp_code = resp.status_code
            resp_text = resp.text or ""
        except Exception:
            return None

        # 如果服务端接受篡改值（200 + 成功响应），判定为参数篡改
        if resp_code == 200:
            success_keywords = ["成功", "success", "ok", "completed", "已完成", "订单"]
            if any(kw in resp_text.lower() for kw in success_keywords):
                return LogicVuln(
                    vuln_type="parameter_tampering",
                    name=f"参数篡改 - {param} 可被客户端修改",
                    severity="high",
                    url=test_url,
                    method="GET",
                    evidence=f"篡改 {param}={tampered_value}（原值 {original_value}）服务端返回 200 成功",
                    fix="服务端应从会话/数据库获取价格，不信任客户端传入的价格参数",
                    fix_detail=(
                        "【代码修复】从服务端 Session/DB 读取价格，忽略客户端传值\n"
                        "【代码修复】下单前服务端重新计算总价\n"
                        "【配置加固】对金额参数启用服务端签名校验\n"
                        "【WAF 规则】拦截异常金额（负数/极大值/0.01）\n"
                        "【合规】OWASP A04:2021 / 等保 2.0 8.1.3"
                    ),
                    reproduce=(
                        f"# 1. 正常下单请求\n"
                        f'curl -b cookies.txt "{endpoint.url}"\n\n'
                        f"# 2. 篡改参数\n"
                        f'curl -b cookies.txt "{test_url}"\n\n'
                        f"# 预期：服务端拒绝篡改的 {param}（实际接受）"
                    ),
                    description="客户端可篡改关键业务参数（价格/数量），服务端未校验",
                    compliance="等保2.0:8.1.3;OWASP:A04:2021",
                )

        return None

    def _build_tampered_url(self, url: str, param: str, value: str) -> str:
        """构建篡改后的 URL"""
        if "?" not in url:
            return f"{url}?{param}={value}"
        base, query = url.split("?", 1)
        params = query.split("&")
        new_params = []
        replaced = False
        for p in params:
            if "=" in p:
                k, v = p.split("=", 1)
                if k == param:
                    new_params.append(f"{param}={value}")
                    replaced = True
                else:
                    new_params.append(p)
            else:
                new_params.append(p)
        if not replaced:
            new_params.append(f"{param}={value}")
        return f"{base}?{'&'.join(new_params)}"


# ============================================================
# 竞争条件检测器
# ============================================================


class RaceConditionDetector:
    """竞争条件检测器

    通过并发发送多个相同请求检测竞争条件（如重复领取优惠券、双花）。
    """

    def __init__(self, session=None, auth_info: Optional[Dict] = None, concurrency: int = 10):
        self.session = session
        self.auth_info = auth_info or {}
        self.concurrency = concurrency
        self.results: List[LogicVuln] = []

    def test_race_condition(self, endpoint: EndpointInfo, expected_success_count: int = 1) -> Optional[LogicVuln]:
        """测试竞争条件

        Args:
            endpoint: 端点信息
            expected_success_count: 预期成功次数（通常为 1）

        Returns:
            发现的 LogicVuln
        """
        import threading

        if not self.session:
            return None

        results = []
        lock = threading.Lock()

        def send_request():
            try:
                resp = self.session.get(endpoint.url)
                with lock:
                    results.append(
                        {
                            "code": resp.status_code,
                            "size": len(resp.text or ""),
                        }
                    )
            except Exception as e:
                with lock:
                    results.append({"error": str(e)})

        # 并发发送
        threads = []
        for _ in range(self.concurrency):
            t = threading.Thread(target=send_request)
            threads.append(t)

        # 同时启动
        for t in threads:
            t.start()

        for t in threads:
            t.join(timeout=10)

        # 分析结果
        success_count = sum(1 for r in results if r.get("code") == 200)

        if success_count > expected_success_count:
            return LogicVuln(
                vuln_type="race_condition",
                name=f"竞争条件 - {endpoint.url} 可被并发利用",
                severity="high",
                url=endpoint.url,
                method="GET",
                evidence=f"并发 {self.concurrency} 次请求，{success_count} 次成功"
                f"（应仅 {expected_success_count} 次成功）",
                fix="使用数据库事务 + 行锁/乐观锁，确保操作的原子性",
                fix_detail=(
                    "【代码修复】@Transactional + SELECT FOR UPDATE 行锁\n"
                    "【代码修复】Redis 分布式锁（Redlock）\n"
                    "【代码修复】数据库唯一约束防止重复\n"
                    "【配置加固】限流中间件（单用户 QPS 限制）\n"
                    "【合规】OWASP A04:2021 / 等保 2.0 8.1.3"
                ),
                reproduce=(
                    f"# 使用 Apache Bench 并发测试\n"
                    f"ab -n {self.concurrency} -c {self.concurrency} "
                    f'-H "Cookie: JSESSIONID=xxx" "{endpoint.url}"\n\n'
                    f"# 预期：仅 1 次成功（实际 {success_count} 次成功）"
                ),
                description="并发请求可绕过单次操作限制，导致重复操作/双花",
                compliance="等保2.0:8.1.3;OWASP:A04:2021",
            )

        return None


# ============================================================
# 业务逻辑扫描入口
# ============================================================


class LogicScanner:
    """业务逻辑漏洞扫描器（聚合所有检测器）"""

    def __init__(self, session=None, auth_info: Optional[Dict] = None):
        self.session = session
        self.auth_info = auth_info or {}
        self.idor_detector = IDORDetector(session, auth_info)
        self.priv_detector = PrivilegeEscalationDetector(session, auth_info)
        self.tamper_detector = ParameterTamperingDetector(session, auth_info)
        self.race_detector = RaceConditionDetector(session, auth_info)

    def scan(self, base_url: str, endpoints: List[EndpointInfo] = None) -> List[LogicVuln]:
        """执行业务逻辑扫描

        Args:
            base_url: 目标基础 URL
            endpoints: 端点列表（无则自动发现）

        Returns:
            发现的漏洞列表
        """
        results = []

        # IDOR 检测
        if endpoints:
            for ep in endpoints:
                vuln = self.idor_detector.test_idor(ep)
                if vuln:
                    results.append(vuln)

        # 权限提升检测
        admin_endpoints = self.priv_detector.detect_admin_endpoints(base_url)
        for url in admin_endpoints:
            vuln = self.priv_detector.test_privilege_escalation(url)
            if vuln:
                results.append(vuln)

        # 参数篡改检测
        if endpoints:
            for ep in endpoints:
                tamperable = self.tamper_detector.detect_tamperable_params(ep)
                for param in tamperable:
                    vuln = self.tamper_detector.test_parameter_tampering(ep, param)
                    if vuln:
                        results.append(vuln)

        return results


def parse_endpoints_from_urls(urls: List[str]) -> List[EndpointInfo]:
    """从 URL 列表解析端点信息

    Args:
        urls: URL 列表

    Returns:
        EndpointInfo 列表
    """
    from urllib.parse import parse_qs

    endpoints = []
    for url in urls:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        id_param = None
        for p in params:
            if p.lower() in ID_PARAM_PATTERNS:
                id_param = p
                break

        endpoints.append(
            EndpointInfo(
                url=url,
                params=params,
                id_param=id_param,
            )
        )
    return endpoints


def run_logic_scan_mode(args, session, base_url: str) -> List[LogicVuln]:
    """业务逻辑扫描模式入口

    Args:
        args: CLI 参数
        session: SessionManager 实例
        base_url: 目标基础 URL

    Returns:
        发现的漏洞列表
    """
    auth_info = getattr(args, "_auth_info", None) or {}
    scanner = LogicScanner(session=session, auth_info=auth_info)

    # 从参数或爬虫结果获取端点
    endpoints = []
    if hasattr(args, "_crawl_endpoints") and args._crawl_endpoints:
        endpoints = parse_endpoints_from_urls(args._crawl_endpoints)

    return scanner.scan(base_url, endpoints)
