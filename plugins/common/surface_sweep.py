# 爬取攻击面盘点：消费 session.surface，输出端点清单 + 未认证可达状态
#
# 定位（D14 回流）：把 --crawl / --js-extract 的发现物真正交给插件层消费。
# 本插件**只做资产盘点**，不判漏洞——未授权越权结论属于 lib/auth_surface.py 的
# 高权/低权对照能力，此处输出 CONFIRMED 会造成"发现入口"被读成"确认漏洞"。
from typing import Any, Dict, List

from common.models import STATUS_UNKNOWN, ScanResult, UnknownReason
from lib.auth_surface import _extract_data_rows, _looks_denied
from lib.reachability import login_wall_reason
from lib.soft404 import Soft404Baseline
from plugins.base import PluginBase


def _classify_auth(resp: Any, rows: int) -> str:
    """判定单次响应体现的认证状态

    复用既有判定，不另写关键词：登录墙走 lib.reachability.login_wall_reason，
    明确拒绝走 lib.auth_surface._looks_denied（HTTP 401/403 + RuoYi 业务码/文案）。

    Returns:
        "login_wall" — 被登录墙拦截（302→/login 或 200 登录页）
        "denied"     — 401/403 或业务语义明确拒绝
        "anon_ok"    — 2xx 且解析出业务数据行（未认证可读）
        "ok"         — 其余可达响应（无拒绝证据，也未取到业务数据）
    """
    if login_wall_reason(resp):
        return "login_wall"
    code = int(getattr(resp, "status_code", 0) or 0)
    text = str(getattr(resp, "text", "") or "")
    if _looks_denied(code, text):
        return "denied"
    if 200 <= code < 300 and rows > 0:
        return "anon_ok"
    return "ok"


class SurfaceSweepPlugin(PluginBase):
    """遍历爬虫/JS 提取得到的入口，记录未认证可达状态（信息级盘点）"""

    name = "爬取攻击面盘点"
    cve = "N/A"
    severity = "low"
    category = "recon"  # 与 directory_scan 同级：信息收集，不是漏洞判定
    path_scope = "root"  # 爬到的多是页面/静态路径，不能跟随 API 前缀
    anonymous_probe = True  # 被测命题是「未登录能否访问」
    consumes_surface = True
    vuln_type = "info_leak"
    supports_waf_bypass = False
    description = (
        "消费 --crawl / --js-extract 产出的攻击面清单，逐个入口用匿名会话探测，"
        "输出端点清单与未认证可达状态（是否被登录墙拦截/明确拒绝/可读业务数据）"
    )
    fix = "对爬取到的业务接口统一实施服务端鉴权，删除前端遗留的调试/测试入口"
    fix_detail = (
        "【权限加固】对照本清单逐条确认入口归属，对非公开路径添加服务端鉴权\n"
        "【Spring Security 配置】在 SecurityConfig.configure() 中把业务接口显式纳入认证范围：\n"
        '  .antMatchers("/system/**", "/monitor/**", "/tool/**").authenticated()\n'
        "【前端清理】删除打包产物中遗留的调试/测试接口引用，避免入口被轻易枚举\n"
        "【接口收敛】配合 actuator/swagger 下线，仅暴露业务必需的公开接口\n"
        "【WAF 规则】对未认证访问管理类接口返回 401/403，禁止返回业务数据\n"
        "【合规】等保 2.0 8.1.4 要求：访问控制覆盖全部资源"
    )
    reproduce = (
        "# 1. 爬取并提取 JS 端点（生成攻击面清单）：\n"
        "ruoyi-scan -u http://target/ --crawl --js-extract\n"
        "\n"
        "# 2. 按清单逐个未认证访问（不带任何 Cookie）：\n"
        'curl -i "http://target/system/user/list"\n'
        'curl -i "http://target/monitor/online/list"\n'
        "\n"
        "# 预期响应：401/403 或跳转登录页 = 受保护；\n"
        "#   200 且返回业务数据（rows/records 非空）= 未认证可读，需人工复核权限模型"
    )
    # D2：recon 类与版本无关，全版本适用
    affected_versions = ""
    # D12：仅表达「入口暴露」的最低影响，不代表已确认越权
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A01:2021"

    def verify(self, target: str, session: Any) -> ScanResult:
        """盘点 session.surface 中的入口

        判定纪律：
          - 无清单 / 清单为空 → UNKNOWN(insufficient_evidence)，且**不发出任何请求**
          - 有清单 → 逐条匿名 GET，只记录资产与认证状态，恒返回 UNKNOWN（非 CONFIRMED）
        """
        inv = getattr(session, "surface", None)
        if inv is None or not getattr(inv, "endpoints", None):
            return ScanResult(
                kind="info",
                name=self.name,
                status=STATUS_UNKNOWN,
                url=target,
                unknown_reason=UnknownReason.INSUFFICIENT_EVIDENCE.value,
                evidence="未启用 --crawl/--js-extract 或未发现入口，无攻击面清单可盘点",
            )

        # 匿名会话：清单里的入口是否「未登录可达」必须在不带凭据的状态下测。
        # 基线也必须走同一匿名会话——否则共享会话若已登录，基线与探测的响应形态
        # 不一致，looks_like_real_file 会拿错基线把兜底页/真实入口判反。
        anon = getattr(session, "anonymous", None)
        probe_session = anon() if callable(anon) else session
        # 软 404 基线：登录墙/兜底页对任意路径都返回同一响应，不能算作独立入口
        base = Soft404Baseline.probe(target, probe_session)

        hits: List[Dict[str, Any]] = []
        skipped = 0
        try:
            for ep in inv.endpoints:
                try:
                    resp = probe_session.get(ep.url)
                except Exception:
                    skipped += 1
                    continue
                if not base.looks_like_real_file(resp, ep.url):
                    # 兜底页/登录墙产物不构成独立入口，不计入清单
                    continue
                rows = _extract_data_rows(str(getattr(resp, "text", "") or ""))
                hits.append(
                    {
                        "url": ep.url,
                        "source": ep.source,
                        "status": getattr(resp, "status_code", 0),
                        "auth": _classify_auth(resp, len(rows)),
                        "json_rows": len(rows),
                    }
                )
        finally:
            # 只关闭自己创建的匿名会话，绝不关闭调用方传入的共享会话
            if probe_session is not session:
                close = getattr(probe_session, "close", None)
                if callable(close):
                    try:
                        close()
                    except Exception:
                        pass

        evidence = f"盘点 {len(hits)}/{len(inv.endpoints)} 个入口"
        if inv.truncated:
            evidence += "（清单已截断）"
        return ScanResult(
            kind="recon",
            name=self.name,
            severity=self.severity,
            status=STATUS_UNKNOWN,
            url=target,
            evidence=evidence,
            extra={"hits": hits, "truncated": inv.truncated, "skipped": skipped},
        )
