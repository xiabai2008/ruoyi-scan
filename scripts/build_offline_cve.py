# G1：离线 CVE 库生成器（内网无外网场景兜底）
#
# 从 data/component_cve_map.json（组件版本→CVE 区间映射，随包分发）自动生成
# data/cve_offline.json（按 CVE 编号索引的离线漏洞库），供 lib/cve_sync.lookup_offline
# 在 NVD/GHSA/CNVD 均不可达（内网渗透测试常态）时兜底查询。
#
# 用法：
#   python scripts/build_offline_cve.py                # 生成/更新离线库
#   python scripts/build_offline_cve.py --merge        # 保留已有 CNVD 别名等手工字段
#
# 手工扩充：直接编辑 data/cve_offline.json 的 entries（--merge 时保留手工字段）。
# CNVD 别名（aliases）字段：可后续人工补充已知 CVE↔CNVD 对应关系；不自动编造。
import argparse
import json
import os
import sys
from typing import Optional

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
COMPONENT_MAP = os.path.join(PROJECT_ROOT, "data", "component_cve_map.json")
OFFLINE_OUT = os.path.join(PROJECT_ROOT, "data", "cve_offline.json")


def severity_from_cvss(cvss: float) -> str:
    """CVSS → NVD 严重度词汇"""
    if cvss >= 9.0:
        return "CRITICAL"
    if cvss >= 7.0:
        return "HIGH"
    if cvss >= 4.0:
        return "MEDIUM"
    return "LOW"


def parse_cvss(value) -> Optional[float]:
    """宽松解析 CVSS 数值：缺失/None/非数字返回 None（未知）

    不能把未知静默当成 0.0——severity_from_cvss(0.0) 会得出 LOW，
    把「严重度未知」误报成「低危」。
    """
    if value is None or isinstance(value, bool):
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def merge_cvss(a: Optional[float], b: Optional[float]) -> Optional[float]:
    """合并同一 CVE 多个版本段的 CVSS：取已知值的较大者；两者均未知返回 None"""
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def build_entries() -> list:
    """从组件 CVE 映射表生成离线条目（range='*' 兜底提示项不生成 CVE 条目）"""
    with open(COMPONENT_MAP, encoding="utf-8") as f:
        cve_map = json.load(f)

    entries = []
    unknown_cvss = []
    for component, items in cve_map.items():
        for item in items:
            cve_id = item.get("cve", "")
            if not cve_id or item.get("range") == "*":
                continue  # 兜底提示项无 CVE 编号，离线库按编号索引不收录
            cvss = parse_cvss(item.get("cvss"))
            if cvss is None:
                unknown_cvss.append(f"{component}/{cve_id}")
            entries.append(
                {
                    "id": cve_id,
                    "aliases": [],  # CNVD/CNNVD 别名（人工/后续同步补充，不自动编造）
                    "component": component,
                    "cvss": cvss,  # None = 源数据缺失，落盘前统一折算为 UNKNOWN
                    "fix": item.get("fix", ""),
                    "description": item.get("note", ""),
                }
            )

    # 同一 CVE 多版本段的条目合并（如 Tomcat Ghostcat 三个版本段 → 一条）
    merged = {}
    for e in entries:
        key = e["id"]
        if key in merged:
            merged[key]["description"] = merged[key]["description"] or e["description"]
            merged[key]["cvss"] = merge_cvss(merged[key]["cvss"], e["cvss"])
            if e["fix"]:
                # 按 " / " 分段比较，避免子串误吞（如 "2.0.64" 是 "1.2.83 / 2.0.64" 的子串）
                existing = [t for t in merged[key]["fix"].split(" / ") if t]
                if e["fix"] not in existing:
                    merged[key]["fix"] = " / ".join(existing + [e["fix"]])
        else:
            merged[key] = e
    for e in merged.values():
        if e["cvss"] is None:
            # 未知严重度显式标注 UNKNOWN；cvss 落盘为 0.0 仅为兼容下游 float() 解析
            e["cvss"] = 0.0
            e["severity"] = "UNKNOWN"
        else:
            e["severity"] = severity_from_cvss(e["cvss"])
    if unknown_cvss:
        preview = ", ".join(unknown_cvss[:5]) + (" ..." if len(unknown_cvss) > 5 else "")
        print(f"[!] {len(unknown_cvss)} 条源数据缺少/非法 cvss，severity 记为 UNKNOWN：{preview}")
    return sorted(merged.values(), key=lambda x: (-x["cvss"], x["id"]))


def main() -> int:
    parser = argparse.ArgumentParser(description="生成离线 CVE 库 data/cve_offline.json")
    parser.add_argument("--merge", action="store_true", help="保留已有条目的手工字段（如 CNVD 别名）")
    args = parser.parse_args()

    entries = build_entries()

    # --merge：保留旧库中同 id 条目的 aliases（手工补充字段不丢失）
    if args.merge and os.path.exists(OFFLINE_OUT):
        with open(OFFLINE_OUT, encoding="utf-8") as f:
            old = json.load(f)
        # 手工文件可能被改坏：缺 id 的条目用 get 跳过并告警，而不是 KeyError 中断整个构建
        old_by_id = {}
        for e in old.get("entries", []):
            oid = e.get("id")
            if not oid:
                print(f"[!] 旧库存在缺少 id 的条目，已忽略：{str(e)[:80]}")
                continue
            old_by_id[oid] = e
        matched = set()
        for e in entries:
            prev = old_by_id.get(e["id"])
            if not prev:
                continue
            matched.add(e["id"])
            if prev.get("aliases"):
                e["aliases"] = prev["aliases"]
        # 映射表已不含的旧条目（人工增补）显式保留——文件头承诺手工数据不因 --merge 丢失
        unmatched = [e for oid, e in old_by_id.items() if oid not in matched]
        if unmatched:
            print(f"[+] 保留 {len(unmatched)} 条映射表已不含的旧条目（人工数据）")
            entries.extend(unmatched)
        entries = sorted(entries, key=lambda x: (-(parse_cvss(x.get("cvss")) or 0.0), str(x.get("id", ""))))

    doc = {
        "schema": "ruoyi-scan-offline-cve",
        "updated": __import__("datetime").date.today().isoformat(),
        "source": "auto-generated from data/component_cve_map.json by scripts/build_offline_cve.py",
        "entries": entries,
    }
    with open(OFFLINE_OUT, "w", encoding="utf-8", newline="\n") as f:
        json.dump(doc, f, ensure_ascii=False, indent=2)
        f.write("\n")
    print(f"[+]离线 CVE 库已生成: {OFFLINE_OUT}（{len(entries)} 条）")
    return 0


if __name__ == "__main__":
    sys.path.insert(0, PROJECT_ROOT)
    sys.exit(main())
