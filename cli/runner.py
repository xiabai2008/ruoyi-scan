# Ruoyi-Scan CLI 控制层 — 核心扫描与批处理
"""CLI 控制层：扫描主流程（run_mode）与批处理；命令实现见 cli/*_runner.py。

层：控制层（cli）｜上游：dispatcher｜下游：orchestrator/report
先读：docs/CONCEPTS.md#12-报告管线
"""

from __future__ import annotations

import copy
import datetime
import os
import re
import sys
import threading
import time
from argparse import Namespace
from typing import Any, List, Optional

from cli.preflight import EXIT_PARTIAL, EXIT_UNREACHABLE, preflight_target
from cli.reporting import run_cli_report
from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, ScanResult
from config import settings
from core.http import normalize_target
from core.orchestrator import ScanRequest
from core.report import BatchReport, ReportBuilder
from core.session import SessionManager
from lib.attribution import ATTR_KEY, SCOPE_HOST, scope_of
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW
from lib.output import is_findings_muted, set_findings_muted
from lib.star_cta import print_star_cta

logger = get_logger(__name__)

# ── 模式配置（对齐原脚本）──
# 模式→类别映射：u=综合（侦察+漏洞+爆破）/ m=目录 / p=漏洞 / l=爆破
MODE_CATEGORIES = {
    "u": ["recon", "vuln", "brute"],
    "m": ["recon"],
    "p": ["vuln"],
    "l": ["brute"],
}
MODE_LABELS = {
    "u": ("综合扫描", RED),
    "m": ("目录扫描", GREEN),
    "p": ("漏洞扫描", GREEN),
    "l": ("登录爆破", GREEN),
}


def _PayloadView(payload: dict) -> Any:  # noqa: N802 — 轻量只读视图，命名贴近数据形状
    """把事件 payload（dict）包装成 scope_of() 可读的对象。

    事件流里传的是 `ScanResult.to_dict()`，不是 ScanResult 本体。归属标记的读取
    逻辑只依赖 `extra`，所以给个最小视图即可，避免为打印再重建一次结果对象。
    """

    class _View:
        def __init__(self, data: dict) -> None:
            self.extra = data.get("extra") or {}

    return _View(payload)


def _attribution_tag(res: Any) -> str:
    """宿主级确认项的终端标记（空串 = 站点级，不打扰输出）

    为什么终端也要标：CLI 的「存在 Redis 未授权访问」和报告里的「宿主级」如果
    只在一处出现，读者看到的结论就会随查看渠道变化。归属标注在 engine 里完成
    （见 core/engine.py 与 F13 同一条纪律），这里只负责呈现。
    """
    if scope_of(res) != SCOPE_HOST:
        return ""
    info = getattr(res, "extra", None) or {}
    attr = info.get(ATTR_KEY) if isinstance(info, dict) else None
    reason = attr.get("reason", "") if isinstance(attr, dict) else ""
    return f"{YELLOW}（宿主级：{reason}）{RESET}"


def _print_scan_result(res: ScanResult) -> None:
    """实时输出扫描结果（作为 ScanEngine.run 的 on_result 回调）

    配色语义遵循 agents.md §3.1：
    - CONFIRMED → 绿色 [*]（命中/成功）
    - SAFE → 红色 [/]（未命中）
    - UNKNOWN → 黄色 [?]（无法判定）
    """
    if res.status == STATUS_CONFIRMED:
        print(f"{GREEN}[*]存在{res.name}{RESET}{_attribution_tag(res)}")
    elif res.status == STATUS_SAFE:
        print(f"{RED}[/]不存在{res.name}{RESET}")
    else:
        print(f"{YELLOW}[?]无法判定{res.name}: {res.evidence}{RESET}")


def _parse_report_formats(fmt_str: Optional[str]) -> Optional[List[str]]:
    """解析 --report-format 参数"""
    if not fmt_str:
        return None
    fmt_str = fmt_str.strip().lower()
    # "all" 直接透传字符串（render_all 内部识别），与其余路径返回的列表形态不同
    if fmt_str == "all":
        return "all"
    valid = {"html", "json", "csv", "pdf", "docx", "xlsx", "sarif"}
    parts = [f.strip() for f in fmt_str.split(",") if f.strip()]
    invalid = [p for p in parts if p not in valid]
    if invalid:
        print(f"{YELLOW}[!]未知报告格式: {invalid}（支持: {sorted(valid)}）{RESET}")
    parts = [p for p in parts if p in valid]
    return parts or None


def _safe_report_stem(target: str) -> str:
    """把目标 URL 变成文件名安全前缀（保留 host:port，去掉协议/路径/非法字符）"""
    stem = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", target)
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return stem[:80] or "target"


def _render_batch_target_reports(batch: "BatchReport", out_dir: str, fmt_raw: Optional[str]) -> List[str]:
    """批量模式：为每个目标单独输出一份报告。

    此前批量只输出 batch_report.html/csv，但 docs/usage.md 明确承诺
    「每个目标生成独立的报告文件（<target>_<timestamp>.<ext>）」——文档与实现不一致，
    安服交付时也无法逐目标归档。这里按同一 --report-format 逐目标渲染。
    """
    formats = _parse_report_formats(fmt_raw)
    stamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    used = set()
    paths: List[str] = []
    for builder in batch.builders:
        base = f"{_safe_report_stem(builder.target)}_{stamp}"
        stem = base
        idx = 2
        while stem in used:  # 目标列表里可能出现重复目标，避免互相覆盖
            stem = f"{base}_{idx}"
            idx += 1
        used.add(stem)
        paths.extend(builder.render_all(out_dir, formats=formats, stem=stem))
    return paths


# ── 主扫描流程 ──


def _build_scan_request(mode: str, target: str, args: Namespace) -> ScanRequest:
    """从 CLI args 构造 ScanRequest（供 ScanOrchestrator 统一执行）"""

    # D26：解析认证配置
    auth_config = None
    # --auth-login 的登录链路可能明确判定「目标启用了二次验证」，需要带回状态；
    # 仅凭 auth_config 是否为空只能区分 ok/failed，无法区分 MFA。
    auth_status_hint = ""
    if getattr(args, "auth", None) or getattr(args, "auth_file", None) or getattr(args, "auth_login", None):
        from lib.auth_inject import auto_login, load_auth_file, parse_auth_arg, parse_login_arg

        # 认证三来源（--auth 参数 / --auth-file 文件 / --auth-login 自动登录）合并进同一结构
        auth_config = {"cookies": {}, "headers": {}, "type": None}
        if args.auth:
            parsed = parse_auth_arg(args.auth)
            auth_config["cookies"].update(parsed["cookies"])
            auth_config["headers"].update(parsed["headers"])
            if parsed["type"]:
                auth_config["type"] = parsed["type"]
        if args.auth_file:
            try:
                file_config = load_auth_file(args.auth_file)
                auth_config["cookies"].update(file_config["cookies"])
                auth_config["headers"].update(file_config["headers"])
                if file_config["type"]:
                    auth_config["type"] = file_config["type"]
                print(f"{YELLOW}[*]已加载认证文件: {args.auth_file}{RESET}")
            except FileNotFoundError as e:
                print(f"{RED}[!]{e}{RESET}")
        if args.auth_login:
            try:
                username, password = parse_login_arg(args.auth_login)
                login_config = auto_login(target, username, password, verbose=True)
                hint = login_config.get("auth_status") if isinstance(login_config, dict) else None
                if hint:
                    auth_status_hint = str(hint)
                if login_config["cookies"] or login_config["headers"]:
                    auth_config["cookies"].update(login_config["cookies"])
                    auth_config["headers"].update(login_config["headers"])
                    if login_config["type"]:
                        auth_config["type"] = login_config["type"]
            except ValueError as e:
                print(f"{RED}[!]{e}{RESET}")
        # 三来源均未产生可用凭据时整体回退为 None（无认证扫描）
        if not auth_config["cookies"] and not auth_config["headers"]:
            auth_config = None

    # 认证状态：报告元信息、终端提示与「需会话插件」统一降级都依赖它。
    # not_attempted = 用户没要求认证；failed = 要求了但没拿到任何凭据；ok = 拿到凭据。
    auth_requested = bool(
        getattr(args, "auth", None) or getattr(args, "auth_file", None) or getattr(args, "auth_login", None)
    )
    if not auth_requested:
        auth_status = "not_attempted"
    elif auth_config:
        auth_status = "ok"
    elif auth_status_hint == "mfa_required":
        auth_status = "mfa_required"
    else:
        auth_status = "failed"

    return ScanRequest(
        target=target,
        mode=mode,
        cms=getattr(args, "cms", "") or "",
        threads=args.threads,
        rate=args.rate,
        rate_scope=getattr(args, "rate_scope", "request"),
        proxy=getattr(args, "proxy", "") or "",
        proxy_file=getattr(args, "proxy_file", "") or "",
        proxy_strategy=getattr(args, "proxy_rotate", "round-robin") or "round-robin",
        timeout=args.timeout,
        time_budget=getattr(args, "time_budget", 0.0) or 0.0,
        time_based=getattr(args, "time_based", False),
        debug=getattr(args, "debug", False),
        report_dir="",  # CLI 自行处理报告（含基线/差异/通知等后处理）
        report_format=getattr(args, "report_format", "all") or "all",
        no_dedup=getattr(args, "no_dedup", False),
        pass_level=getattr(args, "pass_level", "full"),
        portscan=getattr(args, "portscan", False),
        ports=getattr(args, "ports", "") or "",
        bypass_waf=getattr(args, "bypass_waf", "auto"),
        # 方案 A：对抗型传输层（--adversarial-transport 启用；默认关闭，向后兼容）
        adversarial_transport=getattr(args, "adversarial_transport", False),
        # F8：Spring4Shell 真实利用（默认关闭，非回环/内网目标由插件二次拒绝）
        exploit=getattr(args, "exploit", False),
        auth=auth_config,
        surface_account=getattr(args, "surface_account", None),
        # v1.5.6 WP1：显式 API 前缀（--base-path），优先级高于自动探测
        base_paths=getattr(args, "base_path", None),
        auth_status=auth_status,
        template=getattr(args, "template", "") or "",
        crawl=getattr(args, "crawl", False),
        crawl_depth=getattr(args, "crawl_depth", 2),
        crawl_max_pages=getattr(args, "crawl_max_pages", 50),
        subdomain=getattr(args, "subdomain", False),
        js_extract=getattr(args, "js_extract", False),
        plugin_paths=getattr(args, "plugin_path", None),
        # E2：组件版本检测（--components 启用；默认关闭，向后兼容）
        components=getattr(args, "components", False),
        # E4：nuclei YAML 模板
        nuclei_paths=getattr(args, "nuclei", None),
        nuclei_tags=[t.strip() for t in (args.nuclei_tags or "").split(",") if t.strip()],
        nuclei_severity=[s.strip() for s in (args.nuclei_severity or "").split(",") if s.strip()],
        nuclei_exclude_tags=[t.strip() for t in (args.nuclei_exclude_tags or "").split(",") if t.strip()],
    )


# 指纹检测结果的捕获已下沉到 run_mode 内的每次调用闭包（_on_event）：
# 此前是模块级全局 dict，--async 批量各目标并发时会互相覆盖，导致报告串用其他目标的指纹。
# 注意：检测到的指纹必须进报告——此前摘要只认人工 --cms，导致版权年份版本号
# 识别成功却进不了 report.json（2026-09-19 实测）。


def _cli_event_handler(event_type: str, payload):
    """CLI 事件回调：将 orchestrator 事件转为彩色终端输出

    此函数替代了原 run_mode 中散落的 print 语句，实现 CLI/API 统一编排。
    """
    if event_type == "portscan":
        ports = payload.get("ports", [])
        print(f"{YELLOW}[*]端口扫描完成：开放 {payload['open_count']}/{payload['total']}{RESET}")
        for p in ports:
            detail = f"{p['port']}/tcp {p.get('service', '')}"
            if p.get("banner"):
                detail += f" — {p['banner'][:80]}"
            print(f"{GREEN}  [*] {detail}{RESET}")

    elif event_type == "recon_start":
        rtype = payload.get("type", "")
        if rtype == "subdomain":
            print(f"{YELLOW}[*]子域名枚举：{payload.get('domain', '')}（crt.sh + 字典）...{RESET}")
        elif rtype == "crawl":
            print(
                f"{YELLOW}[*]主动爬虫：target={payload.get('target', '')} "
                f"depth={payload.get('max_depth', 2)} max_pages={payload.get('max_pages', 50)}...{RESET}"
            )
        elif rtype == "js_extract":
            print(f"{YELLOW}[*]JS 端点提取：{payload.get('js_count', 0)} 个 JS 文件...{RESET}")

    elif event_type == "recon":
        rtype = payload.get("type", "")
        if rtype == "subdomain":
            subs = payload.get("subdomains", [])
            print(f"{YELLOW}[*]子域名枚举完成：发现 {payload.get('count', 0)} 个（含主域）{RESET}")
            for s in subs[:20]:
                print(f"{GREEN}  [*] {s}{RESET}")
            if len(subs) > 20:
                print(f"{YELLOW}  ...（共 {len(subs)} 个，已省略 {len(subs) - 20} 个）{RESET}")
        elif rtype == "crawl":
            urls = payload.get("urls", [])
            print(f"{YELLOW}[*]爬虫完成：抓取 {payload.get('count', 0)} 个页面{RESET}")
            for u in urls[:10]:
                print(f"{GREEN}  [*] {u}{RESET}")
            if len(urls) > 10:
                print(f"{YELLOW}  ...（共 {len(urls)} 个页面，已省略 {len(urls) - 10} 个）{RESET}")
        elif rtype == "js_extract":
            endpoints = payload.get("endpoints", [])
            print(f"{YELLOW}[*]JS 端点提取完成：发现 {payload.get('count', 0)} 个端点{RESET}")
            for u in endpoints[:20]:
                print(f"{GREEN}  [*] {u}{RESET}")
            if len(endpoints) > 20:
                print(f"{YELLOW}  ...（共 {len(endpoints)} 个端点，已省略 {len(endpoints) - 20} 个）{RESET}")

    elif event_type == "recon_error":
        print(f"{RED}[!]信息收集异常（{payload.get('type', '')}）: {payload.get('error', '')}{RESET}")

    elif event_type == "auth":
        summary = payload.get("summary", "")
        if summary:
            print(f"{YELLOW}[*]认证扫描: {summary} 已注入{RESET}")

    elif event_type == "template":
        name = payload.get("name", "")
        before = payload.get("before", 0)
        after = payload.get("after", 0)
        print(f"{YELLOW}[*]模板过滤: {name} ({before} → {after} 个插件){RESET}")

    elif event_type == "fingerprint":
        cms = payload.get("cms", "")
        if cms:
            variant = payload.get("variant", "")
            variant_txt = f" variant={variant}" if variant else ""
            print(
                f"{YELLOW}[*]指纹识别：cms={cms}{variant_txt} 置信度={payload.get('confidence', 0):.2f} "
                f"命中={payload.get('matched', [])}{RESET}"
            )
        else:
            print(f"{YELLOW}[*]指纹识别：未识别到已知 CMS 特征{RESET}")

    elif event_type == "component":
        # E2：组件版本检测结果（绿=命中 CVE 风险 / 黄=UNKNOWN / 红=SAFE 或不适用）
        if "error" in payload:
            print(f"{RED}[!]组件检测异常: {payload['error']}{RESET}")
            return
        component = payload.get("component", "")
        status = payload.get("status", "")
        cve = payload.get("cve", "")
        version = payload.get("detected_version", "")
        evidence = payload.get("evidence", "")
        ver_txt = f" 版本={version}" if version else ""
        cve_txt = f" 命中={cve}" if cve else ""
        if status == STATUS_CONFIRMED:
            print(f"{GREEN}[*]组件风险: {component}{ver_txt}{cve_txt} — {evidence}{RESET}")
        elif status == STATUS_SAFE:
            print(f"{RED}[/]组件安全: {component}{ver_txt} — {evidence}{RESET}")
        else:
            print(f"{YELLOW}[?]组件未知: {component}{ver_txt} — {evidence}{RESET}")

    elif event_type == "waf":
        waf = payload.get("waf", "")
        if waf:
            print(f"{RED}[!]检测到 WAF: {payload.get('display', '')} — {payload.get('bypass_hint', '')}{RESET}")
        else:
            print(f"{YELLOW}[*]未检测到已知 WAF 特征{RESET}")

    elif event_type == "waf_bypass":
        mode = payload.get("mode", "auto")
        origin = payload.get("origin_ip", "")
        if origin:
            print(f"{YELLOW}[*]源站 IP 探测: {origin}{RESET}")
        print(f"{YELLOW}[*]WAF 绕过已启用（{mode} 模式）{RESET}")

    elif event_type == "plugin_fallback":
        # 这条事件有两个来源，文案必须如实区分，否则会误导排查：
        #   1. cms 未识别 → 回退 ruoyi + spring
        #   2. cms 弱证据命中 → 在原包基础上补加载（不丢原包）
        # 早先两种情况都打同一句「未匹配插件包」，实测排查时被误导过 ——
        # 明明 cms=spring 且加载了 14 个插件，日志却说「未匹配」。
        reason = payload.get("reason", "")
        plugin = payload.get("plugin", "auto")
        if "弱证据" in reason:
            print(f"{YELLOW}[*]指纹弱证据（{plugin}）：{reason}{RESET}")
        else:
            print(f"{YELLOW}[*]未匹配插件包，回退默认 ruoyi + spring 插件包（阶段一兼容）{RESET}")

    elif event_type == "plugins_loaded":
        # 插件按来源分批加载，每个来源各发一次事件（common / 外部目录 / 用户安装 /
        # entry_points / nuclei）。此前一律按 common_count 取值：外部来源事件缺该键，
        # 于是打出一行多余的「已加载 0 个通用插件」，与上一行自相矛盾。
        sources = (
            ("common_count", "通用漏洞检测：已加载 {n} 个通用插件"),
            ("external_count", "外部插件：已加载 {n} 个"),
            ("user_plugin_count", "用户安装插件：已加载 {n} 个"),
            ("entry_point_count", "entry_points 插件：已加载 {n} 个"),
            ("nuclei_count", "nuclei 模板：已加载 {n} 个"),
        )
        for key, fmt in sources:
            count = payload.get(key)
            if count:
                print(f"{YELLOW}[*]{fmt.format(n=count)}{RESET}")

    elif event_type == "blocked":
        # 全站拦截：必须在扫描一开始就让操作者看见，否则报告里的「不存在」会被误读
        print(
            f"{RED}[!]目标疑似被 WAF / 网关全站拦截：{payload.get('reason', '')}"
            f"（probe={payload.get('status', 0)} root={payload.get('root_status', 0)}）{RESET}"
        )
        print(f"{YELLOW}[*]本次 SAFE 结论将统一降级为 UNKNOWN（三态纪律），请更换出口或加 --proxy{RESET}")

    elif event_type == "auth_wall":
        print(f"{YELLOW}[*]目标存在登录墙：{payload.get('reason', '')}（未登录访问受保护接口会跳登录页）{RESET}")
        print(
            f"{YELLOW}[*]登录墙下「没测到」的 SAFE 会改为 UNKNOWN；"
            f'要拿到完整结论请用 --auth-login 或 --auth "cookie=JSESSIONID=..."{RESET}'
        )

    elif event_type == "basepath":
        # 前后端分离版只反代 /prod-api/ 时，根路径探测全落在 SPA 兜底页上
        print(
            f"{YELLOW}[*]检测到 API 前缀 {payload.get('base', '')}/："
            f"后续插件探测以 {payload.get('plugin_target', '')} 为基准"
            f"（前后端分离部署，根路径只有前端静态页）{RESET}"
        )

    elif event_type == "auth_wall_downgrade":
        print(f"{YELLOW}[*]已把 {payload.get('count', 0)} 条 SAFE 改为 UNKNOWN（登录墙，需登录后判定）{RESET}")

    elif event_type == "denied_downgrade":
        print(
            f"{YELLOW}[*]有 {payload.get('count', 0)} 条结论因接口返回 401/403/429 被改为 UNKNOWN"
            f"（未登录/无权限，不能算「不存在」）{RESET}"
        )

    elif event_type == "evidence_downgrade":
        print(f"{YELLOW}[*]有 {payload.get('count', 0)} 条 SAFE 因缺少判定证据被改为 UNKNOWN（三态纪律）{RESET}")

    elif event_type == "blocked_downgrade":
        print(f"{YELLOW}[*]已把 {payload.get('count', 0)} 条 SAFE 降级为 UNKNOWN（全站拦截，无有效响应）{RESET}")

    elif event_type == "category_start":
        print(SEPARATOR)

    # 单插件结果事件：配色与 _print_scan_result 保持一致（存在/不存在/无法判定）
    elif event_type == "result":
        name = payload.get("name", "")
        status = payload.get("status", "")
        evidence = payload.get("evidence", "")
        if status == STATUS_CONFIRMED:
            # payload 是 ScanResult.to_dict()，extra 里带 attribution → 复用同一标记函数
            print(f"{GREEN}[*]存在{name}{RESET}{_attribution_tag(_PayloadView(payload))}")
        elif status == STATUS_SAFE:
            print(f"{RED}[/]不存在{name}{RESET}")
        else:
            print(f"{YELLOW}[?]无法判定{name}: {evidence}{RESET}")

    elif event_type == "error":
        print(f"{RED}[!]扫描异常: {payload.get('error', '')}{RESET}")


def run_mode(
    mode: str, target: str, args: Namespace, show_cta: bool = True, exit_on_auth_failure: bool = True
) -> List[ScanResult]:
    """分发到各扫描模式：指纹→路由→插件 主流程

    重构后：核心扫描流程委托 ScanOrchestrator.run_sync()，
    CLI 仅负责参数构造、事件输出、报告后处理（基线/差异/通知/逻辑扫描/SIEM/CI）。

    Args:
        mode: 扫描模式 u/m/p/l
        target: 目标 URL
        args: CLI 参数命名空间
        show_cta: 是否在结尾输出仓库引导。批量扫描与被动代理会重复调用本函数，
            需传 False 避免刷屏，改由上层在汇总后统一输出一次。
        exit_on_auth_failure: 显式认证失败（含 MFA）时是否用 EXIT_PARTIAL 退出。
            单目标为 True（CI 才能感知覆盖不全）；批量由上层统一判定，传 False。
    """
    from core.orchestrator import ScanOrchestrator

    label, color = MODE_LABELS[mode]
    print(f"{YELLOW}[*]当前扫描模式:[{color}{label}{YELLOW}]{RESET}")

    # --async 只接在批量分支（_run_batch_async）；单目标下静默无效会让人误以为提速了
    if getattr(args, "async_mode", False):
        print(f"{YELLOW}[*]--async 仅对批量模式（-f）生效；本次单目标按同步并发执行{RESET}")

    # 口令字典分级：不在 CLI 修改 settings.PASSWORD_DICT 全局——--async 批量并发时
    # 各目标的 set/restore 会互相污染，改由 orchestrator 按 req.pass_level 统一处理
    if args.pass_level != "full" and args.pass_level in settings.PASSWORD_DICT_BY_LEVEL:
        print(f"{YELLOW}[*]口令字典级别: {args.pass_level}{RESET}")

    # 本次调用的指纹检测结果（供报告摘要）；每次扫描独立捕获。
    # 此前用模块级全局 dict，--async 批量下各目标并发运行会互相覆盖指纹
    detected_fingerprint: dict = {}

    def _on_event(event_type: str, payload):
        """本次扫描的事件处理器：捕获指纹后转发给终端输出"""
        if event_type == "fingerprint" and isinstance(payload, dict):
            detected_fingerprint.clear()
            detected_fingerprint.update(payload)
        _cli_event_handler(event_type, payload)

    # 构造扫描请求并委托 orchestrator 执行
    req = _build_scan_request(mode, target, args)
    t0 = time.time()
    orch = ScanOrchestrator()
    # 结论行去重：引擎按 ScanResult 统一打印「存在 / 不存在 / 无法判定」，
    # 插件在 verify() 里 emit 的同类结论行在此静音，避免一次扫描每条结论打两遍。
    # --debug 保留插件侧原文（排查误报特征时有用）。
    muted_before = is_findings_muted()
    set_findings_muted(not getattr(args, "debug", False))
    try:
        all_results = orch.run_sync(req, on_event=_on_event)
    finally:
        set_findings_muted(muted_before)
    duration = time.time() - t0

    # 认证失败必须在终端显式说清：否则报告看起来"完整"，读者会把未认证扫描
    # 产出的 UNKNOWN/SAFE 当成已登录结论。密码只显示用户名，不回显口令。
    # 用 getattr 兜底：部分调用方（单测、插件直调）用轻量对象代替 ScanRequest，
    # 没有 auth_status 字段时应视为"未尝试认证"，而不是抛 AttributeError。
    if getattr(req, "auth_status", "not_attempted") == "failed":
        auth_desc = ""
        if getattr(args, "auth_login", None):
            _user = str(args.auth_login).split(":", 1)[0]
            auth_desc = f"--auth-login {_user}:***"
        elif getattr(args, "auth_file", None):
            auth_desc = f"--auth-file {args.auth_file}"
        elif getattr(args, "auth", None):
            auth_desc = "--auth"
        print(
            f"{RED}[!] 主扫描未认证：{auth_desc} 登录失败，"
            f"主扫描中需要会话的插件结论不可信（--auth-surface 使用独立会话，另计）{RESET}"
        )
    elif getattr(req, "auth_status", "not_attempted") == "mfa_required":
        print(
            f"{RED}[!] 主扫描未认证：目标启用了二次验证（动态口令/OTP/MFA），"
            f"无法自动登录；请用 --auth cookie=... 复用已登录会话{RESET}"
        )

    # --auth-surface 尚未执行时也要有确定状态，供报告摘要使用；后续 G1 段会覆盖。
    surface_status = "not_attempted"
    target_normalized = normalize_target(target)

    # G1：认证后深度扫描（登录态接口资产盘点 + 越权矩阵）。
    # 必须在报告生成之前执行：否则 surface 的 CONFIRMED/状态写不进本次报告，
    # 出现「正文有 surface 结论、meta 却说 surface 未尝试」的自相矛盾。
    if getattr(args, "auth_surface", False):
        from lib.auth_surface import run_auth_surface_mode

        print(f"{YELLOW}[*]认证后深度扫描：登录态资产盘点 + 越权矩阵...{RESET}")
        surface_assets, surface_vulns, surface_status = run_auth_surface_mode(args, target_normalized)
        if surface_status == "login_failed":
            # 登录失败与“扫完无结果”语义已由 status 区分，避免误报“0 资产 0 漏洞”为扫描完成
            print(f"{RED}[!]认证后深度扫描未执行：高权登录失败（检查 --auth-login）{RESET}")
        else:
            print(
                f"{YELLOW}[*]认证后深度扫描完成：盘点资产 {len(surface_assets)} 个，"
                f"越权/未授权发现 {len(surface_vulns)} 个{RESET}"
            )
        if getattr(args, "surface_output", None) and surface_assets:
            print(f"{GREEN}[*]资产清单已输出：{args.surface_output}{RESET}")
        # 漏洞并入统一结果集（CONFIRMED 语义已在扫描器内保证，UNKNOWN 仅记录资产不产漏洞）
        for lv in surface_vulns:
            all_results.append(
                ScanResult(
                    kind="vuln",
                    name=lv.name,
                    severity=lv.severity,
                    status=STATUS_CONFIRMED,
                    url=lv.url,
                    evidence=lv.evidence,
                    fix=lv.fix,
                    fix_detail=lv.fix_detail,
                    reproduce=lv.reproduce,
                )
            )

    # 认证状态按链路分开记录：admin 是主扫描（--auth-login），surface 是
    # --auth-surface 的独立会话。两者成败可以不同，报告不能混成一句"未认证"。
    req.surface_auth_status = surface_status

    # ── 报告生成 + 后处理（CLI 专属，orchestrator 不涉及）──
    if args.report:
        run_cli_report(
            args,
            req,
            all_results,
            target_normalized,
            label,
            duration,
            detected_fingerprint,
            orch,
            surface_status,
            _parse_report_formats(args.report_format),
        )

    # D31：业务逻辑漏洞扫描
    if getattr(args, "logic_scan", False):
        from lib.logic_scan import LogicScanner, parse_endpoints_from_urls

        print(f"{YELLOW}[*]业务逻辑漏洞扫描...{RESET}")
        endpoints = []
        if getattr(args, "logic_endpoints", None):
            if os.path.isfile(args.logic_endpoints):
                with open(args.logic_endpoints, encoding="utf-8") as f:
                    urls = [line.strip() for line in f if line.strip()]
                endpoints = parse_endpoints_from_urls(urls)
        logic_session = SessionManager(proxy=args.proxy, debug=args.debug, timeout=args.timeout)
        try:
            scanner = LogicScanner(
                session=logic_session,
                concurrency=max(1, int(getattr(args, "logic_concurrency", 10) or 10)),
            )
            logic_vulns = scanner.scan(target_normalized, endpoints)
            # 逻辑链已验证的漏洞直接标记 CONFIRMED 并入结果集，统一参与报告与去重
            for lv in logic_vulns:
                all_results.append(
                    ScanResult(
                        kind="vuln",
                        name=lv.name,
                        severity=lv.severity,
                        status=STATUS_CONFIRMED,
                        url=lv.url,
                        evidence=lv.evidence,
                        fix=lv.fix,
                        fix_detail=lv.fix_detail,
                        reproduce=lv.reproduce,
                    )
                )
            print(f"{YELLOW}[*]业务逻辑扫描完成：发现 {len(logic_vulns)} 个漏洞{RESET}")
        finally:
            # 异常路径同样释放会话连接（scan 抛错时不能泄漏 socket/连接池）
            logic_session.close()

    # D33：SIEM 导出
    if getattr(args, "siem_export", None):
        from lib.siem_export import run_siem_export_mode

        run_siem_export_mode(
            args, all_results, target_normalized, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        )

    # D28：CI 模式退出码
    if getattr(args, "ci", False):
        from lib.ci_runner import run_ci_mode

        exit_code = run_ci_mode(args, all_results, target_normalized, duration, has_error=False)
        if exit_code != 0:
            sys.exit(exit_code)

    # 收尾引导：仅单目标扫描在此输出；批量/被动由上层汇总后统一输出一次
    # CI 模式需要干净的机器可读输出，故跳过
    if show_cta and not getattr(args, "ci", False):
        print_star_cta(explicit_off=getattr(args, "no_cta", False))

    # F6-3：显式要求认证但没拿到可用会话 → EXIT_PARTIAL（4），CI 才能感知
    # 「报告里的 UNKNOWN 是覆盖不全，而不是目标干净」。未传认证参数时保持 0。
    if exit_on_auth_failure and getattr(req, "auth_status", "not_attempted") in ("failed", "mfa_required"):
        sys.exit(EXIT_PARTIAL)

    return all_results


def _run_batch_async(targets: list, mode: str, args: Namespace, label: str, max_workers: int) -> Optional[BatchReport]:
    """异步批量扫描（P1: --async 参数接线）

    使用 AsyncScanEngine 并发扫描多个目标，每个目标内部仍走同步 orchestrator。
    适用于大规模资产盘点（100+ 目标）。
    """
    from lib.async_engine import scan_batch_targets

    # 每个目标的结果单独留存（按目标重建报告时与 scan_batch_targets 的返回值解耦，
    # 单目标失败也不影响其他目标的留存）
    results_by_target: dict = {}
    results_lock = threading.Lock()

    # 批量模式报告统一在最后渲染：给每个目标一份 args 副本并清空 report，
    # 避免 run_mode 为每个目标重复写 report.html（互相覆盖），也避免多线程共享 args 竞态
    scan_args = copy.copy(args)
    scan_args.report = ""
    # 同 run_mode_batch：批量内禁用单目标 CI 退出码，否则第一个超阈值目标就 sys.exit()，
    # 并发场景下会让整批只扫到一部分目标。整批结束后统一判定。
    if getattr(args, "ci", False):
        scan_args.ci = False

    def _scan_single(target: str):
        """单目标扫描函数（供 AsyncScanEngine 调用）"""
        try:
            results = run_mode(mode, target, scan_args, show_cta=False, exit_on_auth_failure=False)
        except Exception as e:
            print(f"{RED}[!]扫描异常 ({target})：{e}{RESET}")
            return []
        with results_lock:
            results_by_target[target] = results
        return results

    total = len(targets)

    def _progress(done, total_count, current):
        print(f"\r{YELLOW}[*]进度 [{done}/{total_count}] 当前：{current:<40}{RESET}", end="", flush=True)

    print(f"{YELLOW}[*]开始并发扫描 {total} 个目标（{max_workers} workers）...{RESET}")
    scan_batch_targets(
        scan_fn=_scan_single,
        targets=targets,
        max_workers=max_workers,
        progress_callback=_progress,
    )
    print()  # 换行结束进度条

    # 按 target 分组重建报告（结果已在 _scan_single 中按目标留存）
    batch = BatchReport()
    out_dir = args.report or settings.REPORT_DIR
    for target in targets:
        results = results_by_target.get(target, [])
        if results:
            builder = ReportBuilder(
                results=results,
                target=target,
                summary={
                    "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "duration": 0,
                    "request_count": len(results),
                    "mode": label,
                    "fingerprint": {"cms": "", "confidence": 0},
                },
                dedup=not args.no_dedup,
            )
            batch.add(builder)

    if batch.builders:
        bpaths = batch.render_all(out_dir)
        tpaths = _render_batch_target_reports(batch, out_dir, getattr(args, "report_format", "all"))
        print(SEPARATOR)
        print(f"{YELLOW}[*]批量汇总：{batch.total_targets} 个目标 共 {batch.total_confirmed()} 个确认漏洞{RESET}")
        for p in bpaths:
            print(f"{GREEN}[*]批量汇总报告：{p}{RESET}")
        if tpaths:
            print(f"{GREEN}[*]每目标报告：{batch.total_targets} 个目标，共 {len(tpaths)} 个文件（{out_dir}）{RESET}")
    else:
        print(f"{RED}[!]无扫描结果{RESET}")
    # 显式列出失败/无结果目标，杜绝“99 个目标静默显示 0 漏洞”的观感
    # （_scan_single 异常返回 []，与“扫完确实无漏洞”同为空——统一列入清单提示人工复核）
    failed_targets = [t for t in targets if not results_by_target.get(t)]
    if failed_targets:
        print(f"{YELLOW}[!]以下 {len(failed_targets)} 个目标无结果（扫描失败或未发现漏洞）：{RESET}")
        for ft in failed_targets:
            print(f"    {YELLOW}- {ft}{RESET}")
    # 批量收尾统一输出一次引导（每个目标各输出一次会刷屏）
    if not getattr(args, "ci", False):
        print_star_cta(explicit_off=getattr(args, "no_cta", False))

    # 退出码语义与同步批量路径保持一致（见 run_mode_batch）
    if not batch.builders:
        sys.exit(EXIT_UNREACHABLE)
    if getattr(args, "ci", False):
        from lib.ci_runner import get_ci_exit_code

        merged_results: List[ScanResult] = []
        for target in targets:
            merged_results.extend(results_by_target.get(target, []))
        ci_code = get_ci_exit_code(
            merged_results,
            getattr(args, "severity_threshold", "high"),
            has_error=bool(failed_targets),
        )
        if ci_code != 0:
            sys.exit(ci_code)
        if failed_targets:
            sys.exit(EXIT_PARTIAL)
    if failed_targets:
        sys.exit(EXIT_PARTIAL)

    return batch


def run_mode_batch(filepath: str, mode: str, args: Namespace) -> Optional[BatchReport]:
    """批量扫描：从文件读目标，逐目标扫描并生成单报告 + 批量汇总报告

    P1: --async 参数接线
    - 默认（同步）：逐目标顺序扫描
    - --async：使用 AsyncScanEngine 并发扫描多个目标，大幅提升批量扫描速度
    """
    if not os.path.isfile(filepath):
        print(f"{RED}[!]目标文件不存在：{filepath}{RESET}")
        return

    label, color = MODE_LABELS[mode]
    print(f"{YELLOW}[*]批量扫描模式：[{color}{label}{YELLOW}]{RESET}")
    print(f"{YELLOW}[*]目标文件：{filepath}{RESET}")

    with open(filepath, encoding="utf-8") as f:
        raw_lines = [line.strip() for line in f]
    # 跳过空行与 "#" 注释（usage 文档承诺 # 开头为注释），并对缺协议目标补 http://
    from core.http import ensure_scheme

    targets = []
    for line in raw_lines:
        if not line or line.startswith("#"):
            continue
        fixed, added = ensure_scheme(line)
        if added:
            print(f"{YELLOW}[*]目标未带协议，按 {fixed} 处理{RESET}")
        targets.append(fixed)
    if not targets:
        print(f"{RED}[!]目标文件为空{RESET}")
        return
    print(f"{YELLOW}[*]共 {len(targets)} 个目标待扫描{RESET}")

    # P1: --async 并发批量扫描
    use_async = getattr(args, "async_mode", False)
    async_workers = getattr(args, "async_workers", 10)
    if use_async:
        print(f"{YELLOW}[*]异步模式：{async_workers} 个并发 worker{RESET}")
        return _run_batch_async(targets, mode, args, label, async_workers)

    batch = BatchReport()
    out_dir = args.report or settings.REPORT_DIR
    skipped: List[str] = []
    failed: List[str] = []
    all_results: List[ScanResult] = []
    # 批量模式报告统一在最后渲染：单目标扫描不要写 report.html（会被下一个目标覆盖）
    scan_args = copy.copy(args)
    scan_args.report = ""
    # 批量 + --ci 必须禁用「单目标 CI 退出码」：run_mode 里的 CI 分支会 sys.exit()，
    # 命中第一个超阈值目标就整批中断，后续目标根本没扫——用户拿到的却是
    # 「只覆盖 1/N 目标」的报告，却以为整批都扫过了（2026-10-29 真实靶场实测）。
    # 改为整批跑完后由本函数统一汇总判定退出码。
    batch_ci = bool(getattr(args, "ci", False))
    if batch_ci:
        scan_args.ci = False

    for i, target in enumerate(targets, 1):
        print(f"\n{SEPARATOR}")
        print(f"{YELLOW}[*]进度 [{i}/{len(targets)}] 目标：{target}{RESET}")
        # 逐目标预检：不可用的目标跳过并继续，不中断整批——目标列表里混着下线主机是
        # 常态，因一个目标不可用而中止整批是错的行为
        if not preflight_target(target, scan_args):
            skipped.append(target)
            continue
        try:
            results = run_mode(mode, target, scan_args, show_cta=False, exit_on_auth_failure=False)
        except Exception as e:
            print(f"{RED}[!]扫描异常 ({target})：{e}{RESET}")
            failed.append(target)
            continue

        all_results.extend(results)
        builder = ReportBuilder(
            results=results,
            target=target,
            summary={
                "started_at": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "duration": 0,
                "request_count": len(results),
                "mode": label,
                "fingerprint": {"cms": "", "confidence": 0},
            },
            dedup=not args.no_dedup,
        )
        batch.add(builder)

    if batch.builders:
        bpaths = batch.render_all(out_dir)
        tpaths = _render_batch_target_reports(batch, out_dir, getattr(args, "report_format", "all"))
        print(SEPARATOR)
        print(f"{YELLOW}[*]批量汇总：{batch.total_targets} 个目标 共 {batch.total_confirmed()} 个确认漏洞{RESET}")
        if skipped:
            # 明确列出被跳过的目标：静默少扫几个目标会让使用者误判覆盖面
            print(
                f"{RED}[!]因目标不可用跳过 {len(skipped)} 个：{', '.join(skipped[:5])}"
                f"{' 等' if len(skipped) > 5 else ''}{RESET}"
            )
        if failed:
            print(
                f"{RED}[!]扫描异常失败 {len(failed)} 个：{', '.join(failed[:5])}"
                f"{' 等' if len(failed) > 5 else ''}{RESET}"
            )
        for p in bpaths:
            print(f"{GREEN}[*]批量汇总报告：{p}{RESET}")
        if tpaths:
            print(f"{GREEN}[*]每目标报告：{batch.total_targets} 个目标，共 {len(tpaths)} 个文件（{out_dir}）{RESET}")
        # 批量收尾统一输出一次引导（每个目标各输出一次会刷屏）
        if not getattr(args, "ci", False):
            print_star_cta(explicit_off=getattr(args, "no_cta", False))
    elif skipped:
        print(f"\n{RED}[!]全部 {len(skipped)} 个目标均不可用，未产生任何扫描结果{RESET}")

    # ── 退出码语义（批量）──────────────────────────────────────────────
    # 与单目标对齐：全部扫不到 → 3（EXIT_UNREACHABLE，与单目标预检失败同码）；
    # 部分扫不到 → 4（EXIT_PARTIAL，表示「扫到了但覆盖面不全」）；
    # 全部扫到 → 0。--ci 模式下还要叠加漏洞阈值判定（有超阈值漏洞 → 1）。
    if not batch.builders:
        # 一个目标都没扫成：整批不可用（含全部异常），与单目标预检失败同码
        sys.exit(EXIT_UNREACHABLE)

    if batch_ci:
        from lib.ci_runner import get_ci_exit_code

        # has_error：批量内个别目标抛异常说明覆盖面有缺口，按扫描异常处理
        ci_code = get_ci_exit_code(
            all_results,
            getattr(args, "severity_threshold", "high"),
            has_error=bool(failed),
        )
        if ci_code != 0:
            sys.exit(ci_code)
        # CI 判定通过但仍有目标没扫到：退出码需体现覆盖不全（4），否则流水线
        # 会把「只扫了 3/10 个目标」当成全量通过
        if skipped or failed:
            sys.exit(EXIT_PARTIAL)

    if skipped or failed:
        sys.exit(EXIT_PARTIAL)

    return batch


def final_prompt(no_pause: bool = False) -> None:
    """结尾交互（保留原 input 习惯；非 tty / CI / --no-pause 时自动跳过）

    Args:
        no_pause: CLI --no-pause 或 --ci 为真时跳过等待
    """
    if no_pause or not sys.stdin.isatty():
        return
    # Windows 的 NUL 设备（`cmd < nul`、MSYS `/dev/null`）isatty() 仍返回 True，
    # 仅看 stdin 会在重定向场景误判为交互终端；stdout 也不是终端时同样不该停。
    if not sys.stdout.isatty():
        return
    # CI 里有时仍分配了 tty（如 docker -t），此时靠环境变量兜底，避免卡住流水线
    if os.environ.get("CI") or os.environ.get("RUOYI_SCAN_NO_PAUSE"):
        return
    try:
        input("[*]工作完毕,感谢你的使用,回车退出.../")
    except EOFError:
        logger.debug("用户输入读取失败", exc_info=True)


__all__ = [
    "run_mode",
    "run_mode_batch",
    "final_prompt",
]
