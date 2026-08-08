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

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED


def load_baseline(path: str) -> dict:
    """加载验收基线（schema 校验）"""
    with open(path, "r", encoding="utf-8") as f:
        baseline = json.load(f)
    if baseline.get("schema") != "ruoyi-scan-acceptance-baseline":
        raise ValueError("基线文件 schema 不匹配（应为 ruoyi-scan-acceptance-baseline）")
    if not baseline.get("targets"):
        raise ValueError("基线缺少 targets")
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
    results = orch.run_sync(req, on_event=None)
    orch.shutdown()
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


def run_acceptance(baseline_path: str, targets: list = None, output_path: str = "") -> int:
    """执行验收

    Args:
        baseline_path: 基线 JSON 路径
        targets: 覆盖的目标列表（None 用基线配置）
        output_path: 对拍报告输出路径（空则不写文件）

    Returns:
        退出码：0=通过 / 1=漏报或误报 / 2=执行错误
    """
    baseline = load_baseline(baseline_path)
    target_cfgs = list(baseline["targets"])
    if targets is not None:
        # 仅校验指定 URL（按 URL 匹配基线配置）
        target_cfgs = [t for t in target_cfgs if t["url"] in targets]
        if not target_cfgs:
            raise ValueError("指定目标不在基线中: %s" % targets)

    report = {
        "schema": "ruoyi-scan-acceptance",
        "version": baseline.get("version", "1.0.0"),
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "targets": [],
        "passed": True,
    }
    try:
        for cfg in target_cfgs:
            print("[*] 对拍目标: %s (%s)" % (cfg["url"], cfg.get("mode", "")))
            actual = scan_target(cfg["url"], cfg.get("scan_mode", "u"))
            result = check_target(cfg, actual)
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
        if output_path:
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(report, f, ensure_ascii=False, indent=2)
        return 2

    if output_path:
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(report, f, ensure_ascii=False, indent=2)
    print("[*] 验收结果: %s" % ("全部通过" if report["passed"] else "存在失败项"))
    return 0 if report["passed"] else 1


def main():
    parser = argparse.ArgumentParser(description="lab 靶场验收对拍")
    parser.add_argument("--baseline", default=os.path.join("data", "acceptance_baseline.json"), help="基线 JSON 路径")
    parser.add_argument("--target", action="append", default=None, help="覆盖扫描目标 URL（可多次）")
    parser.add_argument("--output", default="", help="对拍报告输出路径")
    args = parser.parse_args()
    sys.exit(run_acceptance(args.baseline, targets=args.target, output_path=args.output))


if __name__ == "__main__":
    main()
