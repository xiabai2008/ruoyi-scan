"""RuoYi-Cloud Gateway 路由表泄露检测。

R8 实测（2026-10-29 / 2026-11-19 复测）
=====================================
入口 19108 只反代 /prod-api/，但 actuator 就在 gateway 自身：
  GET /prod-api/actuator/gateway/routes  → 200 application/json，11 条路由
  同域 /prod-api/actuator/env、/gateway/globalfilters 也可匿名读取

判定纪律
========
必须同时满足：
  1. HTTP 200；
  2. 响应是 JSON 数组；
  3. 至少一条对象含 route_id / uri / predicate，并能解析出路径前缀。
只有「路由表结构」才算泄漏；SPA 通配 200、HTML、空数组、401/403 都不算。
"""

from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.cloud_routes import GATEWAY_ROUTES_PATH, build_cloud_profile
from plugins.base import PluginBase


class CloudGatewayRoutesPlugin(PluginBase):
    """Gateway actuator 路由表可匿名读取。"""

    name = "Gateway 路由表泄露（RuoYi-Cloud）"
    cve = "N/A"
    severity = "medium"
    category = "vuln"
    # 路由表是未授权可达性判定，必须用干净会话；共享会话可能被登录污染
    anonymous_probe = True
    path_scope = "api"
    vuln_type = "info_leak"
    description = (
        "RuoYi-Cloud 的 gateway actuator 未鉴权暴露 /actuator/gateway/routes，"
        "泄露全部网关路由、后端服务名与 Nacos 实例信息"
    )
    fix = "关闭 gateway actuator 暴露，或为 /actuator/** 强制鉴权；限制 actuator 仅内网/管理端口访问"
    fix_detail = (
        "【配置加固】application.yml 关闭 gateway 端点：\n"
        "  management.endpoint.gateway.enabled: false\n"
        "  management.endpoints.web.exposure.exclude: gateway,env,heapdump\n"
        "【权限加固】Spring Security 为 /actuator/** 配置 ADMIN 角色\n"
        "【网络隔离】actuator 管理端口仅监听 127.0.0.1，或仅允许运维网段\n"
        "【WAF】拦截 /actuator/gateway/routes 的外网访问\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 经 Nginx 的 /prod-api/ 前缀访问 gateway actuator：\n"
        'curl -i "http://target/prod-api/actuator/gateway/routes"\n'
        "\n"
        "# 预期响应：HTTP 200 + JSON 数组，元素含 route_id / uri / predicate：\n"
        '# [{"route_id":"ruoyi-auth","uri":"lb://ruoyi-auth",'
        '"predicate":"... Paths: [/auth/**] ..."}]\n'
        "\n"
        "# 同时可读其他 actuator 端点（存在性确认，不修改）：\n"
        'curl -s "http://target/prod-api/actuator/env" | head -c 300\n'
        'curl -s "http://target/prod-api/actuator/gateway/globalfilters" | head -c 300'
    )
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"

    def verify(self, target, session) -> ScanResult:
        url = join_url(target, GATEWAY_ROUTES_PATH)
        anon = getattr(session, "anonymous", None)
        probe = anon() if callable(anon) else session
        try:
            try:
                resp = probe.get(url)
            except Exception as e:
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_UNKNOWN,
                    url=url,
                    evidence=f"网关路由表探测网络异常：{e}",
                )
            code = getattr(resp, "status_code", 0)
            if code in (401, 403):
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=url,
                    evidence=f"gateway actuator 存在但要求鉴权（HTTP {code}）",
                )
            if code != 200:
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=url,
                    evidence=f"未发现 gateway 路由表（HTTP {code}）",
                )
            try:
                payload = resp.json()
            except Exception:
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=url,
                    evidence="HTTP 200 但响应不是 JSON（SPA/HTML/网关兜底页）",
                )
            profile = build_cloud_profile(payload)
            if not profile or not profile.get("routes"):
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_SAFE,
                    url=url,
                    evidence="响应为 JSON 但未含可解析的网关路由（route_id/uri/predicate）",
                )
            # 缓存给后续 Cloud 插件（Nacos 默认口令、job/gen 别名）使用
            try:
                setattr(session, "cloud_profile", profile)
            except Exception:
                pass
            prefixes = profile.get("prefixes", [])
            services = profile.get("services", [])
            route_sample = profile.get("routes", [])[:12]
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=url,
                evidence=(
                    "gateway 路由表可匿名读取：%d 条路由，前缀 %s，后端服务 %s"
                    % (profile.get("route_count", 0), ",".join(prefixes[:12]), ",".join(services[:12]))
                ),
                extra={
                    "route_count": profile.get("route_count", 0),
                    "prefixes": prefixes,
                    "services": services,
                    "routes": route_sample,
                },
                fix=self.fix,
            )
        finally:
            if probe is not session:
                probe.close()
