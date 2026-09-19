# 目录扫描：读 ruoyi.txt 字典，逐条 GET 并打印 响应码/标题/长度/最终 URL
import re
from typing import Dict

from common.models import STATUS_UNKNOWN, ScanResult
from config import settings
from core.http import join_url
from lib.colors import GREEN, RED, RESET, YELLOW
from lib.reporter import emit
from plugins.base import PluginBase

# 请求异常消息里的 URL 匹配：requests 把请求地址内嵌在异常文本中（形如
# "... Max retries exceeded with url: /acm"），去重键必须先剥离它，否则每条路径
# 都是「新原因」，去重形同虚设。
_URL_IN_MSG_RE = re.compile(r"(with url:)\s*[^\s)]+|(url=)\S+|https?://[^\s）)]+")


class DirectoryScanPlugin(PluginBase):
    name = "目录扫描"
    cve = "N/A"
    severity = "low"
    category = "recon"
    description = "基于 ruoyi.txt 字典的端点探测，输出状态码/标题/长度/URL（沿用原 path_scan 格式）"
    fix = "关闭未授权端点，敏感路径强制鉴权，下线调试与监控面板"
    fix_detail = (
        "【权限加固】对所有非公开路径（/druid、/actuator、/swagger、/monitor 等）添加鉴权拦截器\n"
        "【Spring Security 配置】在 SecurityConfig.configure() 中：\n"
        '  .antMatchers("/druid/**", "/actuator/**", "/swagger-ui/**").authenticated()\n'
        "【下线调试】生产环境关闭：\n"
        "  management.endpoints.web.exposure.include: health,info\n"
        "  swagger.enabled: false\n"
        "  spring.datasource.druid.stat-view-servlet.enabled: false\n"
        "【WAF 规则】拦截常见敏感路径：/druid, /actuator, /swagger, /v2/api-docs, /env, /heapdump\n"
        "【合规】等保 2.0 8.1.4 要求：访问控制覆盖全部资源"
    )
    reproduce = (
        "# 探测 Druid 监控：\n"
        'curl -i "http://target/druid/"\n'
        "\n"
        "# 探测 Swagger 文档：\n"
        'curl -i "http://target/swagger-ui.html"\n'
        'curl -i "http://target/v2/api-docs"\n'
        "\n"
        "# 探测 Actuator 端点：\n"
        'curl -i "http://target/actuator"\n'
        'curl -i "http://target/actuator/env"\n'
        'curl -i "http://target/actuator/heapdump" -o heapdump.bin\n'
        "\n"
        "# 预期响应：HTTP 200 即表示端点未授权可访问"
    )
    # D2：目录扫描全版本适用（取决于目标配置）
    affected_versions = ""  # recon 类目录探测与版本无关，全版本适用
    # D12：CVSS v3.1 + 合规映射
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    # D7: 目录扫描不参与 WAF 绕过（非漏洞利用类）
    vuln_type = ""
    supports_waf_bypass = False

    def verify(self, target, session):
        """逐条读取 ruoyi.txt 字典并 GET 探测，输出 状态码/标题/长度/URL

        输出格式与命中收集均严格保留原 path_scan 行为（兼容旧报告解析）
        @param target: 目标主机，用于拼接探测路径
        @param session: 复用的 HTTP 会话对象
        @return: ScanResult——recon 类统一 UNKNOWN 语义，命中清单放 extra.hits 供报告收集
        """
        # 原 path_scan 输出格式严格保留：
        #   [*]\033[33m响应:[{code}\033[33m] -> 标题:[{title}\033[33m] -> 长度:[\033[32m{len}\033[33m] -> {respnse.request.url}\033[0m
        # 状态码 '20' in code 为绿，否则红；标题为空显示红色 NULL，否则绿色
        hits = []
        try:
            with open(settings.RUOYI_DICT, encoding="utf-8") as f:
                path_list = f.read().splitlines()
        except Exception as e:
            emit(f"{RED}[/]目录字典读取失败：{e}{RESET}")
            return ScanResult(
                kind="dir", name=self.name, status=STATUS_UNKNOWN, url=settings.RUOYI_DICT, evidence=str(e)
            )

        fail_reasons: Dict[str, int] = {}
        for path in path_list:
            url = join_url(target, path)
            try:
                respnse = session.get(url)
            except Exception as e:
                # 网络异常：保留 UNKNOWN 语义（不阻断后续条目）。
                # 同一原因只提示一次：逐路径打印会在目标不可用时刷出数百行（实测自签名
                # HTTPS 目标输出 99 行且不含原因），既淹没工具输出、又掩盖真正的失败原因。
                reason = f"{type(e).__name__}: {e}"
                # 去重键须剥离 URL：requests 的异常消息内嵌请求地址（"... with url: /acm"），
                # 直接把消息当键会让每条路径都成为「新原因」，去重形同虚设。
                key = _URL_IN_MSG_RE.sub(r"\1<x>", reason)
                if key not in fail_reasons:
                    emit(f"{RED}[/]请求异常：{reason}{RESET}")
                fail_reasons[key] = fail_reasons.get(key, 0) + 1
                continue
            text = respnse.text
            # 标题正则严格保留：<title>(\w+)</title>
            title = re.findall("<title>(\\w+)</title>", text)
            if len(title) < 1:
                title = f"{RED}NULL{RESET}"
            else:
                title = f"{GREEN}{title[0]}{RESET}"
            code = str(respnse.status_code)
            # 状态码判定严格保留：'20' in code（200/201/204 均为绿）
            if "20" in code:
                code = f"{GREEN}{code}{RESET}"
            else:
                code = f"{RED}{code}{RESET}"
            # 行格式严格保留（[*] 前缀 + 黄色字段标签）
            emit(
                f"[*]{YELLOW}响应:[{code}{YELLOW}] -> 标题:[{title}{YELLOW}] -> 长度:[{GREEN}{len(text)}{YELLOW}] -> {respnse.request.url}{RESET}"
            )
            # 收集 2xx / 3xx / 解析出真实标题的条目供报告
            # 修正：原条件用 `"20" in str(status_code)` 做子串匹配，会把 420 / 520 / 1200
            # 等非 2xx 状态码一并判为可用，现改为真正的状态码区间判断。
            # 遗留风险：软 404 页面通常带 <title>，仍会因「有真实标题」被收录，
            # 需要配合响应长度基线判别，勿仅凭 hits 数量判断目录泄露面。
            code_num = int(respnse.status_code) if str(respnse.status_code).isdigit() else 0
            has_real_title = bool(title) and "NULL" not in title
            if 200 <= code_num < 400 or has_real_title:
                hits.append(
                    {
                        "url": respnse.request.url,
                        "code": str(respnse.status_code),
                        "length": len(text),
                    }
                )
        evidence = f"扫描 {len(path_list)} 条，命中 {len(hits)} 条"
        if fail_reasons:
            # 失败原因进 evidence：目标不可用时命中性判断失去意义，报告需能自证这一点
            detail = "；".join(f"{r} × {n}" for r, n in fail_reasons.items())
            evidence += f"；请求失败 {sum(fail_reasons.values())} 条（{detail}）"
        return ScanResult(
            kind="dir",
            name=self.name,
            status=STATUS_UNKNOWN,
            url=target,
            evidence=evidence,
            extra={"hits": hits, "fail_reasons": fail_reasons},
        )
