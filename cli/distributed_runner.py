"""D36 分布式扫描接线层。

`lib/distributed.py` 早就实现了队列 / Master / Worker / 本机分发，但 CLI 一直没接：
`main.py` 把 `--distributed` 算进"可执行模式"，`cli/dispatcher.py` 却没有对应分支，
命令静默退出 0、什么都不做（2026-10-28 实测）。本模块负责补上这条链路。

职责边界：
    1. 解析目标列表（-f 文件 或 单个 -u/-m/-p/-l 目标），统一补协议；
    2. 解析扫描配置（threads/rate/proxy/timeout/...），下发给 Worker；
    3. 按 master / worker / standalone 分派到 lib/distributed 的入口。

判定一致性：Worker 与 standalone 的扫描函数都走 `ScanOrchestrator.run_sync`，
与 CLI / API 同一条编排链，三态语义、去重、插件路由不会出现第二套实现。
"""

from __future__ import annotations

import json
import os
from argparse import Namespace
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Any, Dict, List, Optional

from lib.colors import GREEN, RED, RESET, YELLOW
from lib.reporter import emit

# ScanTask.mode 是 full/vuln/dir/brute 这套旧词汇，ScanRequest.mode 是 u/m/p/l；
# 两边都必须显式映射——直接把 "full" 丢给 ScanRequest 会命中
# core/orchestrator.py::mode_categories 的默认分支（只跑 vuln），静默丢掉目录与爆破。
MODE_TO_TASK = {"u": "full", "p": "vuln", "m": "dir", "l": "brute"}
TASK_TO_MODE = {"full": "u", "vuln": "p", "dir": "m", "brute": "l"}
_MODE_KEYS = ("u", "m", "p", "l")

# 可下发给 Worker 的扫描参数（ScanRequest 字段的子集）
_SCAN_KEYS = (
    "threads",
    "rate",
    "timeout",
    "cms",
    "pass_level",
    "portscan",
    "ports",
    "bypass_waf",
    "no_dedup",
    "template",
)

STANDALONE_WORKERS = 4
EXIT_BAD_ARGS = 2


def _resolve_redis_url(args: Namespace) -> str:
    """Redis 地址三级回退：命令行 > 环境变量 REDIS_URL > 默认本机"""
    return getattr(args, "redis_url", None) or os.environ.get("REDIS_URL", "") or "redis://127.0.0.1:6379"


def _collect_targets(args: Namespace) -> List[str]:
    """收集目标：优先 -f 文件，否则取第一个真实扫描目标。

    裸开关（-p 不带 URL）的值是 "__flag__"，必须剔除，否则会把占位符当目标扫。
    """
    from core.http import ensure_scheme

    raw: List[str] = []
    if getattr(args, "file", None):
        path = args.file
        if not os.path.isfile(path):
            emit(f"[!]目标文件不存在: {path}")
            return []
        with open(path, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"):
                    raw.append(line)
    else:
        for key in _MODE_KEYS:
            val = getattr(args, key, None)
            if val and val != "__flag__":
                raw.append(val)
                break

    targets: List[str] = []
    for item in raw:
        url, added = ensure_scheme(item)
        if added:
            emit(f"[*]目标未带协议，按 {url} 处理")
        if url not in targets:
            targets.append(url)
    return targets


def _scan_config(args: Namespace) -> Dict[str, Any]:
    """从 CLI args 提取可下发的扫描配置（只取 ScanRequest 认识的字段）"""
    config: Dict[str, Any] = {}
    for key in _SCAN_KEYS:
        val = getattr(args, key, None)
        if val is not None:
            config[key] = val
    proxy = getattr(args, "proxy", "") or ""
    if proxy:
        config["proxy"] = proxy
    return config


def _scan_one(target: str, config: Dict[str, Any], task_mode: str = "full") -> List[Dict[str, Any]]:
    """扫一个目标并返回可序列化结果（Worker 与 standalone 共用）"""
    from core.orchestrator import ScanOrchestrator, ScanRequest

    mode = TASK_TO_MODE.get(task_mode, task_mode)
    if mode not in _MODE_KEYS:
        mode = "u"

    req = ScanRequest(
        target=target,
        mode=mode,
        cms=str(config.get("cms", "") or ""),
        threads=int(config.get("threads", 1) or 1),
        rate=int(config.get("rate", 0) or 0),
        proxy=str(config.get("proxy", "") or ""),
        timeout=int(config.get("timeout", 10) or 10),
        pass_level=str(config.get("pass_level", "full") or "full"),
        portscan=bool(config.get("portscan", False)),
        ports=str(config.get("ports", "") or ""),
        bypass_waf=str(config.get("bypass_waf", "auto") or "auto"),
        no_dedup=bool(config.get("no_dedup", False)),
        template=str(config.get("template", "") or ""),
    )
    results = ScanOrchestrator().run_sync(req)
    return [r.to_dict() for r in results]


def _merged_config(defaults: Dict[str, Any], overrides: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    """任务自带 config 覆盖 Worker 本地默认值（Master 下发的优先级更高）"""
    merged = dict(defaults)
    for key, val in (overrides or {}).items():
        if val is not None and (key in _SCAN_KEYS or key == "proxy"):
            merged[key] = val
    return merged


def _run_standalone(args: Namespace, targets: List[str], config: Dict[str, Any], task_mode: str = "full") -> int:
    """本机多线程分发（无 Redis）。

    刻意不复用 lib 的 StandaloneDistributor：它把单个目标的异常吞进 debug 日志，
    失败目标会从结果里凭空消失——违反"异常绝不静默"的纪律。
    """
    workers = max(1, min(len(targets), STANDALONE_WORKERS))
    emit(f"[*]独立模式：{len(targets)} 个目标，本机并发 {workers}")
    emit(YELLOW + "-" * 60 + RESET)

    all_vulns: List[Dict[str, Any]] = []
    failed: List[Dict[str, str]] = []
    done = 0

    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_scan_one, t, config, task_mode): t for t in targets}
        for fut in as_completed(futures):
            target = futures[fut]
            done += 1
            try:
                results = fut.result()
            except Exception as exc:  # 单目标失败不拖垮整批，但必须记名上报
                failed.append({"target": target, "error": f"{type(exc).__name__}: {exc}"})
                emit(RED + f"[!]扫描失败 {target}: {type(exc).__name__}: {exc}" + RESET)
                continue
            confirmed = [r for r in results if r.get("status") == "CONFIRMED"]
            all_vulns.extend(confirmed)
            emit(f"[{done}/{len(targets)}] {target} 确认 {len(confirmed)} 个 / 判定 {len(results)} 条")

    emit(YELLOW + "-" * 60 + RESET)
    emit(f"[*]总确认漏洞: {len(all_vulns)}")
    if failed:
        emit(RED + f"[!]失败目标: {len(failed)}" + RESET)
        for item in failed:
            emit(RED + f"    - {item['target']}: {item['error']}" + RESET)

    report = {
        "mode": "standalone",
        "targets": len(targets),
        "successful": len(targets) - len(failed),
        "failed": len(failed),
        "total_vulns": len(all_vulns),
        "all_vulns": all_vulns,
        "failed_targets": failed,
    }
    out_dir = "reports"
    os.makedirs(out_dir, exist_ok=True)
    report_path = os.path.join(out_dir, "distributed_report.json")
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    emit(GREEN + f"[+]聚合报告已保存: {report_path}" + RESET)
    return 1 if failed else 0


def run_distributed_mode(args: Namespace) -> int:
    """--distributed 总入口，返回进程退出码"""
    kind = getattr(args, "distributed", None)
    if kind not in ("master", "worker", "standalone"):
        emit(RED + f"[!]未知分布式模式: {kind}（可选 master/worker/standalone）" + RESET)
        return EXIT_BAD_ARGS

    args.redis_url = _resolve_redis_url(args)
    config = _scan_config(args)

    if kind == "worker":
        from lib.distributed import run_distributed_worker_mode

        emit(YELLOW + f"[*]Worker 节点连接 {args.redis_url}（凭据已隐藏）" + RESET)

        def scan_task(task: Any, rate_limiter: Any = None) -> List[Dict[str, Any]]:
            # Worker 的签名是 fn(task, rate_limiter)，少一个参数会直接抛 TypeError，
            # 任务被记为失败（2026-10-28 实跑抓到）。限速器是任务级共享令牌桶。
            if rate_limiter is not None:
                rate_limiter.acquire()
            results = _scan_one(task.target, _merged_config(config, task.config), task.mode)
            # 只回传 CONFIRMED：Master 的聚合把每条记为一个漏洞，把 SAFE/UNKNOWN 一起送过去
            # 会让「总漏洞」等于判定条数（实测 50 条判定被报成 50 个漏洞）。
            return [r for r in results if r.get("status") == "CONFIRMED"]

        return run_distributed_worker_mode(args, scan_task)

    targets = _collect_targets(args)
    if not targets:
        emit(RED + "[!]未提供扫描目标：用 -f targets.txt 或 -u/-m/-p/-l <url> 指定" + RESET)
        return EXIT_BAD_ARGS

    # 模式由调用方决定：-p → vuln，-m → dir，-l → brute，-u/未指定 → full
    # 注意：配合 -f 时模式开关的值是 "__flag__"（只作标记），不能用真值判断，
    # 否则批量分布式会全部退化成 full（2026-10-28 实测踩过：-p 批量跑出了爆破日志）。
    task_mode = "full"
    for key in _MODE_KEYS:
        if getattr(args, key, None) is not None:
            task_mode = MODE_TO_TASK[key]
            break

    if kind == "standalone":
        return _run_standalone(args, targets, config, task_mode)

    from lib.distributed import run_distributed_master_mode

    return run_distributed_master_mode(args, targets, config, mode=task_mode)
