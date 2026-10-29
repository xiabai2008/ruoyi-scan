# 目录扫描：读 ruoyi.txt 字典，逐条 GET 并打印 响应码/标题/长度/最终 URL
import logging
import re
from typing import Dict

from common.logger import get_logger
from common.models import STATUS_UNKNOWN, ScanResult
from config import settings
from core.http import join_url
from lib.colors import GREEN, RED, RESET, YELLOW
from lib.reporter import emit
from lib.soft404 import Soft404Baseline
from plugins.base import PluginBase

logger = get_logger(__name__)

# 请求异常消息里的 URL 匹配：requests 把请求地址内嵌在异常文本中（形如
# "... Max retries exceeded with url: /acm"），去重键必须先剥离它，否则每条路径
# 都是「新原因」，去重形同虚设。
_URL_IN_MSG_RE = re.compile(r"(with url:)\s*[^\s)]+|(url=)\S+|https?://[^\s）)]+")


def _debug_detail_enabled() -> bool:
    """--debug（DEBUG 级日志）时才输出目录扫描的全量明细"""
    return logger.isEnabledFor(logging.DEBUG)


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
        #   [*]\033[33m响应:[{code}\033[33m] -> 标题:[{title}\033[33m] -> 长度:[\033[32m{len}\033[33m] -> {response.request.url}\033[0m
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
        skipped = 0  # 非 2xx 且无标题的条数（明细不打印，仅计数）
        # 软 404 基线：先用随机不存在路径取一份「兜底页」指纹，后续响应与它逐字节一致时
        # 判为同一个兜底页而非独立路径。否则「命中 N 条」这个数字会被登录墙放大——
        # 若依对任意受保护路径一律 302 到 /login，跟随重定向后都是 200 + 登录页正文，
        # 与真正不存在的路径完全无法区分（2026-10-29 真实靶场实测：/actuator/env 与
        # 随机不存在路径的响应体 md5 完全相同）。
        baseline = Soft404Baseline.probe(target, session)
        soft_removed = 0  # 与兜底页一致的条数（已剔除，不计入命中）
        for path in path_list:
            url = join_url(target, path)
            try:
                response = session.get(url)
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
            text = response.text
            # 标题提取：正则由 <title>(\w+)</title> 放宽为 [^<>]+ —— 原式只匹配纯单词标题，
            # 含空格/标点的真实标题（如 "My App - Home"）会显示 NULL 并失去标题命中资格。
            # 行格式（标题:[...]）保持不变，仅捕获内容更准确。
            title_match = re.findall(r"<title>([^<>]+)</title>", text)
            title_text = title_match[0].strip() if title_match else ""
            has_real_title = bool(title_text)
            title = f"{GREEN}{title_text}{RESET}" if has_real_title else f"{RED}NULL{RESET}"
            code = str(response.status_code)
            # 状态码判定严格保留：'20' in code（200/201/204 均为绿）
            if "20" in code:
                code = f"{GREEN}{code}{RESET}"
            else:
                code = f"{RED}{code}{RESET}"
            # 状态码数值化：明细过滤与命中收集共用（原实现只在命中收集处定义）
            code_num = int(response.status_code) if str(response.status_code).isdigit() else 0
            # 行格式严格保留（[*] 前缀 + 黄色字段标签）
            # 逐条明细只在「像是有东西」时打印：2xx/3xx 或解析出真实标题。
            # 之前 404 也逐条打印，实测对签名靶场一次 -u 就刷出 700+ 行（其中 690 条
            # 是 404），既淹没真正的命中，也让日志文件失去检索价值。
            # --debug 下保留全量明细（排查软 404 / 兜底路由时需要）。
            interesting = 200 <= code_num < 400 or has_real_title
            if interesting or _debug_detail_enabled():
                emit(
                    f"[*]{YELLOW}响应:[{code}{YELLOW}] -> 标题:[{title}{YELLOW}] -> 长度:[{GREEN}{len(text)}{YELLOW}] -> {response.request.url}{RESET}"
                )
            else:
                skipped += 1
            # 收集 2xx / 3xx / 解析出真实标题的条目供报告
            # 修正：原条件用 `"20" in str(status_code)` 做子串匹配，会把 420 / 520 / 1200
            # 等非 2xx 状态码一并判为可用，现改为真正的状态码区间判断。
            if interesting:
                # 与兜底页逐字节一致的响应不是独立路径：有登录墙时几乎全体命中此项，
                # 剔除后「命中 N 条」才反映真实的目录暴露面。
                # 仅在「基线可用且站点确为兜底路由」时比对内容；基线不可用则保持原判定
                # （不因基线探测失败而漏报），非 2xx 响应（如 403 Forbidden）仍算路径存在。
                if baseline.is_catch_all and 200 <= code_num < 300:
                    if not baseline.looks_like_real_file(response):
                        soft_removed += 1
                        continue
                hits.append(
                    {
                        "url": response.request.url,
                        "code": str(response.status_code),
                        "length": len(text),
                    }
                )
        if skipped:
            emit(
                f"{YELLOW}[*]目录扫描：{len(path_list)} 条路径，{len(hits)} 条命中（{skipped} 条非 2xx 明细已省略，--debug 查看）{RESET}"
            )
        evidence = f"扫描 {len(path_list)} 条，命中 {len(hits)} 条"
        if soft_removed:
            evidence += f"；剔除兜底页 {soft_removed} 条（与基线响应逐字节一致，非独立路径）"
        if baseline.reachable:
            evidence += f"；{baseline.describe()}"
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
            extra={
                "hits": hits,
                "fail_reasons": fail_reasons,
                "soft_removed": soft_removed,
                "baseline": baseline.describe() if baseline.reachable else "",
            },
        )
