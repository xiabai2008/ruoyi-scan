# 盲 SSRF（带外确认）— 把 OAST HTTP 回调 URL 注入常见 URL 参数。
#
# 为什么是独立插件而不是塞进 surface_sweep：
#   surface_sweep 只做资产盘点，不应产生 CONFIRMED；本插件只有收到回调才判
#   CONFIRMED，没有回调一律 UNKNOWN（不能证明"不存在"，也不冒充 SAFE）。
#
# 请求量：每个目标最多 8 条候选请求；只有 --oast 显式开启才会加载。
import urllib.parse

from common.models import SEVERITY_HIGH, STATUS_CONFIRMED, STATUS_UNKNOWN, ScanResult, UnknownReason
from core.http import join_url
from plugins.base import PluginBase


class BlindSsrfPlugin(PluginBase):
    """盲 SSRF：OAST 回调是唯一 CONFIRMED 依据。"""

    name = "盲 SSRF（带外确认）"
    cve = "N/A"
    severity = SEVERITY_HIGH
    category = "vuln"
    requires_oast = True
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A10:2021"
    description = "应用会把用户可控 URL 发起服务端请求；通过 OAST 带外回调确认"
    fix = "对用户可控 URL 做协议/域名白名单校验，禁止访问内网与回环地址"
    fix_detail = (
        "【代码修复】只允许 http/https，解析后按白名单校验 host；拒绝 127.0.0.0/8、\n"
        "  10/8、172.16/12、192.168/16、169.254/16 与云元数据地址\n"
        "【网络】出站流量走代理/网关，默认拒绝内网访问\n"
        "【合规】OWASP A10:2021 SSRF；等保 2.0 8.1.3 边界防护"
    )

    reproduce = (
        "# 1) 生成回调 URL：python main.py -p http://target/ --oast --oast-host <本机可达IP>\n"
        "# 2) 观察 OAST 事件里的 http_port，将回调地址注入候选参数：\n"
        '#    curl -i "http://target/?url=http://<oast-host>:<http_port>/?id=<id>"\n'
        "# 预期响应：目标返回 200/302，同时 OAST 记录到来自目标的 HTTP 回调；\n"
        "# 无回调不能判不存在（目标可能不允许出网或参数未生效）"
    )

    # (路径, 参数名)：只覆盖常见的 URL 型参数，避免无边界扫描
    _CANDIDATES = (
        ("/", "url"),
        ("/", "uri"),
        ("/", "target"),
        ("/", "redirect"),
        ("/login", "redirect"),
        ("/common/download/resource", "resource"),
        ("/system/user/profile/updateAvatar", "avatar"),
        ("/system/user/profile/updatePwd", "url"),
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
                evidence="未启用 OAST，无法确认盲 SSRF",
            )

        interactions = []
        probes = []
        try:
            for path, param in self._CANDIDATES:
                interaction = client.new_http_interaction()
                sep = "&" if "?" in path else "?"
                url = join_url(target, path) + f"{sep}{param}=" + urllib.parse.quote(interaction.url, safe="")
                probes.append(url)
                interactions.append((interaction, url, param))
                try:
                    session.get(url, timeout=min(float(getattr(session, "timeout", 10) or 10), 5.0))
                except Exception:
                    continue

            hit = client.wait_any([item[0] for item in interactions])
            if hit is not None:
                matched = next(item for item in interactions if item[0].interaction_id == hit.interaction_id)
                callbacks = hit.callbacks()
                first = callbacks[0] if callbacks else {}
                return ScanResult(
                    kind="vuln",
                    name=self.name,
                    severity=self.severity,
                    status=STATUS_CONFIRMED,
                    url=matched[1],
                    evidence=(
                        "OAST 回调命中：参数 %s 触发服务端请求（来源 %s，方法 %s）"
                        % (matched[2], first.get("from", "?"), first.get("method", "?"))
                    ),
                    extra={
                        "parameter": matched[2],
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
                evidence="SSRF payload 已注入 %d 个候选参数，但 OAST 未收到 HTTP 回调" % len(probes),
                extra={"probes": probes},
            )
        finally:
            for interaction, _url, _param in interactions:
                try:
                    interaction.close()
                except Exception:
                    pass
