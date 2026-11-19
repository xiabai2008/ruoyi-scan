"""RuoYi-Cloud Nacos 控制台默认口令检测（nacos/nacos）。

R8 实测（2026-11-19）
====================
RuoYi-Cloud v3.6.8 + Nacos 3.0.2：
  - 8848 是 HTTP API：POST /nacos/v1/auth/users/login 返回 accessToken
  - 8080 是控制台：POST /v3/auth/user/login 返回 accessToken + globalAdmin=true
  - Nacos 3.x 的 /nacos/ 路径在 8080 上已不存在，不能用固定 /nacos 前缀

为什么要探同主机端口
====================
扫描目标是 R8 入口 19108（Nginx 只反代 /prod-api/），Nacos 8080 不经过网关。
仅扫站点入口永远看不到 Nacos（既有盲测已记录该拓扑缺口）。本插件只在确认
目标为 Cloud（gateway 路由表）后才探测同主机 8080/8848，且只发登录请求，
不改密码、不创建用户。

判定纪律
========
  CONFIRMED  任一候选端点返回 200 JSON 且含非空 accessToken（默认口令有效）
  SAFE       Nacos 控制台存在，但默认口令被拒绝
  UNKNOWN    Cloud 目标但未在 8080/8848 发现 Nacos 控制台（拓扑未知，不能判不存在）
"""

from typing import Any, Dict, List
from urllib.parse import urlparse

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult, UnknownReason
from lib.cloud_routes import discover_cloud_profile
from plugins.base import PluginBase


class CloudNacosDefaultPasswordPlugin(PluginBase):
    """Nacos 控制台默认口令 nacos/nacos。"""

    name = "Nacos 控制台默认口令（RuoYi-Cloud）"
    cve = "N/A"
    severity = "high"
    category = "brute"
    # 本插件内部使用匿名会话做登录尝试；共享会话的 cookie 不应参与默认口令判定
    anonymous_probe = True
    vuln_type = "auth"
    description = (
        "RuoYi-Cloud 的 Nacos 控制台保留默认口令 nacos/nacos，攻击者登录后可读取/修改全部配置，"
        "常含数据库、Redis、JWT 密钥"
    )
    fix = "立即修改 Nacos 默认口令并启用强密码；Nacos 控制台仅内网可达；开启 Nacos 鉴权"
    fix_detail = (
        "【改密码】Nacos 控制台 → 权限控制 → 用户管理 → 修改 nacos 用户密码（≥12 位）\n"
        "【开鉴权】application.properties：nacos.core.auth.enabled=true\n"
        "  并替换默认 token.secret.key 与 identity key/value\n"
        "【网络隔离】8080/8848 仅允许内网访问，禁止暴露公网\n"
        "【审计】检查 Nacos 用户表/操作日志是否有异常登录\n"
        "【合规】等保 2.0 8.1.4 身份鉴别；OWASP A07:2021 身份认证失效"
    )
    reproduce = (
        "# Nacos 3.x 控制台（8080）：\n"
        'curl -i -X POST "http://nacos-host:8080/v3/auth/user/login" \\\n'
        '  -d "username=nacos&password=nacos"\n'
        '# 预期响应：200 + {"accessToken":"...","globalAdmin":true,...}\n'
        "\n"
        "# Nacos 2.x / 3.x API（8848，/nacos 前缀）：\n"
        'curl -i -X POST "http://nacos-host:8848/nacos/v1/auth/users/login" \\\n'
        '  -d "username=nacos&password=nacos"\n'
        "\n"
        "# 拿到 token 后读取配置（仅授权测试）：\n"
        'curl -H "accessToken: <token>" \\\n'
        '  "http://nacos-host:8848/nacos/v1/cs/configs?dataId=ruoyi-gateway-dev.yml&group=DEFAULT_GROUP"'
    )
    affected_versions = ""
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A07:2021"

    USERNAME = "nacos"
    PASSWORD = "nacos"

    @staticmethod
    def _host_literal(parsed: Any) -> str:
        host = parsed.hostname or ""
        if ":" in host and not host.startswith("["):
            host = "[%s]" % host
        return host

    def _candidate_bases(self, target: str) -> List[str]:
        """候选控制台根 URL：优先当前目标，再按 Nacos 常见端口推导。"""
        parsed = urlparse(target)
        scheme = parsed.scheme or "http"
        host = self._host_literal(parsed)
        if not host:
            return []
        bases: List[str] = []
        path = parsed.path.rstrip("/")
        target_port = parsed.port
        if target_port in (8080, 8848) or "/nacos" in path:
            base_path = "/nacos" if path.endswith("/nacos") else ""
            port_part = f":{target_port}" if target_port else ""
            bases.append(f"{scheme}://{host}{port_part}{base_path}")
        bases.extend(
            [
                f"http://{host}:8080",
                f"http://{host}:8848/nacos",
            ]
        )
        unique: List[str] = []
        for base in bases:
            if base not in unique:
                unique.append(base)
        return unique

    @staticmethod
    def _login_urls(base: str) -> List[str]:
        """按 Nacos 版本形态生成登录端点。"""
        parsed = urlparse(base)
        path = parsed.path.rstrip("/")
        if path.endswith("/nacos"):
            return [
                base + "/v3/auth/user/login",
                base + "/v1/auth/users/login",
                base + "/v1/auth/login",
            ]
        if parsed.port == 8848:
            return [
                base + "/nacos/v3/auth/user/login",
                base + "/nacos/v1/auth/users/login",
                base + "/nacos/v1/auth/login",
            ]
        # Nacos 3.x 控制台根（8080）
        return [base + "/v3/auth/user/login", base + "/v1/auth/users/login"]

    @staticmethod
    def _token_from_response(resp: Any) -> Dict[str, Any]:
        if getattr(resp, "status_code", 0) != 200:
            return {}
        try:
            body = resp.json()
        except Exception:
            return {}
        if not isinstance(body, dict):
            return {}
        token = body.get("accessToken")
        if not isinstance(token, str) or len(token) < 20:
            return {}
        return body

    @staticmethod
    def _looks_nacos(resp: Any) -> bool:
        """默认口令失败时，判断候选端点是否确实是 Nacos（避免把普通 401 当 SAFE）。"""
        status = getattr(resp, "status_code", 0)
        if status not in (200, 401, 403, 500):
            return False
        text = (getattr(resp, "text", "") or "")[:500]
        low = text.lower()
        return any(
            marker in low
            for marker in ("nacos", "user not found", "password is right", "auth_system_type", "access token")
        )

    def verify(self, target, session) -> ScanResult:
        profile = getattr(session, "cloud_profile", None)
        if not profile:
            profile = discover_cloud_profile(session, target)
        parsed = urlparse(target)
        target_is_console = parsed.port in (8080, 8848) or "/nacos" in parsed.path
        if not profile and not target_is_console:
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=target,
                evidence="非 Cloud/Nacos 目标，跳过 Nacos 控制台默认口令探测",
            )

        bases = self._candidate_bases(target)
        if not bases:
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                unknown_reason=UnknownReason.INSUFFICIENT_EVIDENCE.value,
                evidence="无法从目标 URL 推导 Nacos 控制台地址",
            )

        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        saw_nacos = False
        attempts = 0
        try:
            for base in bases:
                for login_url in self._login_urls(base):
                    attempts += 1
                    try:
                        resp = probe.post(
                            login_url,
                            data={"username": self.USERNAME, "password": self.PASSWORD},
                            timeout=min(float(getattr(probe, "timeout", 10) or 10), 5.0),
                        )
                    except Exception:
                        continue
                    body = self._token_from_response(resp)
                    if body:
                        global_admin = bool(body.get("globalAdmin"))
                        return ScanResult(
                            kind="brute",
                            name=self.name,
                            severity=self.severity,
                            status=STATUS_CONFIRMED,
                            url=login_url,
                            evidence=(
                                "Nacos 控制台默认口令 nacos/nacos 登录成功（%s，globalAdmin=%s，token 已脱敏）"
                                % (base, global_admin)
                            ),
                            extra={
                                "console": base,
                                "endpoint": login_url,
                                "global_admin": global_admin,
                                "username": self.USERNAME,
                            },
                            fix=self.fix,
                        )
                    if self._looks_nacos(resp):
                        saw_nacos = True
        finally:
            if probe is not session:
                probe.close()

        if saw_nacos:
            return ScanResult(
                kind="brute",
                name=self.name,
                severity=self.severity,
                status=STATUS_SAFE,
                url=target,
                evidence="Nacos 控制台存在，但默认口令 nacos/nacos 未通过（已修改或已禁用）",
            )
        return ScanResult(
            kind="brute",
            name=self.name,
            severity=self.severity,
            status=STATUS_UNKNOWN,
            url=target,
            unknown_reason=UnknownReason.INSUFFICIENT_EVIDENCE.value,
            evidence=(
                "Cloud 目标，但未在 %s 发现 Nacos 控制台（尝试 %d 个端点）；"
                "端口未暴露不等于默认口令不存在" % (", ".join(bases), attempts)
            ),
        )
