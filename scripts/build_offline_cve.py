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


def build_entries() -> list:
    """从组件 CVE 映射表生成离线条目（range='*' 兜底提示项不生成 CVE 条目）"""
    with open(COMPONENT_MAP, encoding="utf-8") as f:
        cve_map = json.load(f)

    entries = []
    for component, items in cve_map.items():
        for item in items:
            cve_id = item.get("cve", "")
            if not cve_id or item.get("range") == "*":
                continue  # 兜底提示项无 CVE 编号，离线库按编号索引不收录
            entries.append(
                {
                    "id": cve_id,
                    "aliases": [],  # CNVD/CNNVD 别名（人工/后续同步补充，不自动编造）
                    "component": component,
                    "cvss": float(item.get("cvss", 0.0)),
                    "severity": severity_from_cvss(float(item.get("cvss", 0.0))),
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
            merged[key]["cvss"] = max(merged[key]["cvss"], e["cvss"])
            merged[key]["severity"] = severity_from_cvss(merged[key]["cvss"])
            if e["fix"] and e["fix"] not in merged[key]["fix"]:
                merged[key]["fix"] = f"{merged[key]['fix']} / {e['fix']}"
        else:
            merged[key] = e
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
        old_by_id = {e["id"]: e for e in old.get("entries", [])}
        for e in entries:
            prev = old_by_id.get(e["id"])
            if prev and prev.get("aliases"):
                e["aliases"] = prev["aliases"]

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
