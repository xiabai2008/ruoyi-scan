# F4：真实靶场验收脚本（lab/ Tier A 签名靶场）
#
# 用法：
#   python lab/run_acceptance.py --baseline data/acceptance_baseline.json --output acceptance.json
#     （默认扫描基线中配置的本地靶场 URL）
#   python lab/run_acceptance.py --target http://127.0.0.1:8080 --target http://127.0.0.1:8081 ...
#
# 行为：
#   1. 对每个目标执行 ScanOrchestrator 全量扫描（mode=u）
#   2. 与 data/acceptance_baseline.json 对拍：
#      - vuln 模式：expected_confirmed ⊆ 实际 CONFIRMED（漏报门禁）
#      - safe 模式：实际 CONFIRMED == 空（误报门禁）
#   3. 输出 JSON 对拍报告 + 退出码（0=全部通过 / 1=存在漏报或误报 / 2=执行错误）
import argparse
import json
import os
import sys
import time

# lab 脚本在子目录运行，需把项目根加入 sys.path 才能 import core / common 包
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED


def load_baseline(path: str) -> dict:
    """加载验收基线（schema 校验）"""
    with open(path, "r", encoding="utf-8") as f:
        baseline = json.load(f)
    if baseline.get("schema") != "ruoyi-scan-acceptance-baseline":
        raise ValueError("基线文件 schema 不匹配（应为 ruoyi-scan-acceptance-baseline）")
    targets = baseline.get("targets")
    if not targets:
        raise ValueError("基线缺少 targets")
    # 逐条校验 target schema：字段缺失在此给出明确报错，而不是扫描时抛 KeyError
    for i, t in enumerate(targets):
        if not isinstance(t, dict) or not t.get("url"):
            raise ValueError("基线 targets[%d] 缺少 url 字段" % i)
    return baseline


def scan_target(url: str, scan_mode: str = "u") -> list:
    """对目标执行全量扫描，返回 CONFIRMED 结果的 name 列表"""
    from core.orchestrator import ScanOrchestrator, ScanRequest

    req = ScanRequest(
        target=url,
        mode=scan_mode,
        threads=4,
        timeout=10,
        no_dedup=True,
    )
    orch = ScanOrchestrator()
    try:
        results = orch.run_sync(req, on_event=None)
    finally:
        # run_sync 抛异常（网络错误/插件崩溃/超时）时也必须回收线程池，避免线程泄漏
        orch.shutdown()
    # 只取 CONFIRMED（确认存在）结果：suspected 视为未坐实，不进入对拍门禁
    return [r.name for r in results if r.status == STATUS_CONFIRMED]


def check_target(target_cfg: dict, actual_confirmed: list) -> dict:
    """对拍单个目标

    Returns:
        {'name', 'passed', 'missing': [...], 'unexpected': [...], 'actual_confirmed': [...]}
    """
    expected = set(target_cfg.get("expected_confirmed", []))
    allowed = set(target_cfg.get("allowed_confirmed", []))
    actual = set(actual_confirmed)
    missing = sorted(expected - actual)  # 漏报（核心门禁）
    unexpected = sorted(actual - expected)  # 预期外命中
    # 预期外命中但属于无害豁免（allowed_confirmed）→ 不判失败
    unexpected = [n for n in unexpected if n not in allowed]
    if target_cfg.get("expected_safe_all"):
        # safe 模式：除豁免外零 CONFIRMED 门禁
        unexpected = sorted(actual - allowed)
        missing = []
    passed = not missing and not unexpected
    return {
        "name": target_cfg.get("name", target_cfg.get("url", "")),
        "url": target_cfg.get("url", ""),
        "mode": target_cfg.get("mode", ""),
        "passed": passed,
        "missing": missing,
        "unexpected": unexpected,
        "actual_confirmed": actual_confirmed,
    }


def write_report(report: dict, output_path: str) -> bool:
    """写出对拍报告；失败仅告警不抛出（避免掩盖原始错误与退出码），返回是否写成功"""
    if not output_path:
        return True
    try:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
        return True
    except OSError as e:
        print("[!] 对拍报告写入失败: %s" % e)
        return False


def run_acceptance(baseline_path: str, targets: list = None, output_path: str = "") -> int:
    """执行验收

    Args:
        baseline_path: 基线 JSON 路径
        targets: 覆盖的目标列表（None 用基线配置）
        output_path: 对拍报告输出路径（空则不写文件）

    Returns:
        退出码：0=通过 / 1=漏报或误报 / 2=执行错误
    """
    try:
        baseline = load_baseline(baseline_path)
        target_cfgs = list(baseline["targets"])
        if targets is not None:
            # 仅校验指定 URL（按 URL 匹配基线配置）
            target_cfgs = [t for t in target_cfgs if t["url"] in targets]
            if not target_cfgs:
                raise ValueError("指定目标不在基线中: %s" % targets)
    except (OSError, ValueError, KeyError) as e:
        # 基线缺失/损坏/schema 不符/指定目标不在基线 → 配置错误映射退出码 2（与门禁失败 1 区分）
        print("[!] 验收配置错误: %s" % e)
        return 2

    report = {
        "schema": "ruoyi-scan-acceptance",
        "version": baseline.get("version", "1.0.0"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": [],
        "passed": True,
    }
    had_error = False
    try:
        for cfg in target_cfgs:
            print("[*] 对拍目标: %s (%s)" % (cfg["url"], cfg.get("mode", "")))
            try:
                actual = scan_target(cfg["url"], cfg.get("scan_mode", "u"))
                result = check_target(cfg, actual)
            except Exception as e:
                # 单个目标异常不中断整体验收：记录错误项后继续扫描剩余目标，
                # 一次报告呈现全部结果（执行失败最终以退出码 2 反映）
                print("[!] 目标 %s 执行异常: %s" % (cfg.get("url", ""), e))
                had_error = True
                report["passed"] = False
                report["targets"].append(
                    {
                        "name": cfg.get("name", cfg.get("url", "")),
                        "url": cfg.get("url", ""),
                        "mode": cfg.get("mode", ""),
                        "passed": False,
                        "error": f"{type(e).__name__}: {e}",
                        "missing": [],
                        "unexpected": [],
                        "actual_confirmed": [],
                    }
                )
                continue
            # 单个目标判定失败不中断循环：继续扫描剩余目标，一次报告呈现全部漏报/误报
            report["targets"].append(result)
            if result["passed"]:
                print("    [OK] 通过（命中 %d 个确认项）" % len(actual))
            else:
                report["passed"] = False
                if result["missing"]:
                    print("    [X] 漏报: %s" % ", ".join(result["missing"]))
                if result["unexpected"]:
                    print("    [X] 误报: %s" % ", ".join(result["unexpected"]))
    except Exception as e:
        print("[!] 验收执行异常: %s" % e)
        # 报告写入失败不得冒出 handler：否则掩盖原始错误并丢失退出码 2
        write_report(report, output_path)
        # 执行异常映射为退出码 2：与判定失败（1）区分，便于 CI 区分环境故障与门禁失败
        return 2

    write_ok = write_report(report, output_path)
    print("[*] 验收结果: %s" % ("全部通过" if report["passed"] else "存在失败项"))
    if had_error or not write_ok:
        return 2
    return 0 if report["passed"] else 1


def main():
    """解析命令行参数并执行验收对拍，退出码原样透传（0=通过/1=门禁失败/2=执行错误）"""
    parser = argparse.ArgumentParser(description="lab 靶场验收对拍")
    parser.add_argument("--baseline", default=os.path.join("data", "acceptance_baseline.json"), help="基线 JSON 路径")
    parser.add_argument("--target", action="append", default=None, help="覆盖扫描目标 URL（可多次）")
    parser.add_argument("--output", default="", help="对拍报告输出路径")
    args = parser.parse_args()
    sys.exit(run_acceptance(args.baseline, targets=args.target, output_path=args.output))


if __name__ == "__main__":
    main()
