# 导出插件清单（docs/promo/ruoyi-scan-plugins.txt）
#
# 用途：下载/试用前先看这个工具覆盖哪些漏洞，不必装 Python 跑 --plugin-list。
# 数据来源与运行时完全一致：core.loader.discover_plugin_packages() + 插件类元信息。
#
# 用法：
#   python scripts/export_plugin_list.py
#
# 约定：输出不含时间戳——同一版本重复生成应得到完全相同的文件，避免无意义 diff。

import importlib
import pkgutil
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO))

from config import settings  # noqa: E402
from core.loader import discover_plugin_packages  # noqa: E402
from plugins.base import PluginBase  # noqa: E402

OUT = REPO / "docs" / "promo" / "ruoyi-scan-plugins.txt"

CATEGORY_ORDER = ["ruoyi", "spring", "common", "jeecgboot"]
CATEGORY_LABEL = {
    "ruoyi": "若依专项",
    "spring": "Spring 生态",
    "common": "通用 Web",
    "jeecgboot": "JeecgBoot",
}
SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
WIDTH = 79


def collect() -> list:
    """按插件包顺序收集元信息（与运行期加载口径一致）"""
    plugins = []
    for pkg_name in discover_plugin_packages():
        pkg = importlib.import_module(pkg_name)
        for _, mod_name, is_pkg in pkgutil.iter_modules(pkg.__path__):
            if is_pkg or mod_name.startswith("_"):
                continue
            full = f"{pkg_name}.{mod_name}"
            try:
                module = importlib.import_module(full)
            except Exception as exc:  # 单个插件坏掉不应让清单生成失败
                print(f"[!] 跳过无法导入的插件模块 {full}: {exc}", file=sys.stderr)
                continue
            for attr in vars(module).values():
                if (
                    isinstance(attr, type)
                    and issubclass(attr, PluginBase)
                    and attr is not PluginBase
                    and attr.__module__ == full
                ):
                    try:
                        inst = attr()
                    except Exception as exc:
                        print(f"[!] 跳过无法实例化的插件 {full}.{attr.__name__}: {exc}", file=sys.stderr)
                        continue
                    plugins.append(
                        {
                            "name": getattr(inst, "name", "") or attr.__name__,
                            # 注意：插件实例的 category 是漏洞类别（vuln/recon/brute），
                            # 不是所属包；按包分组必须用 pkg_name（plugins.ruoyi → ruoyi）。
                            "package": pkg_name.split(".")[-1],
                            "category": getattr(inst, "category", "") or "",
                            "severity": getattr(inst, "severity", "") or "low",
                            "cve": (getattr(inst, "cve", "") or "").strip(),
                            "description": (getattr(inst, "description", "") or "").strip(),
                            "affected": (getattr(inst, "affected_versions", "") or "").strip(),
                            "variant": (getattr(inst, "variant", "") or "").strip(),
                            "fix": (getattr(inst, "fix", "") or "").strip(),
                        }
                    )
    return plugins


def main() -> int:
    plugins = collect()
    if not plugins:
        print("[!] 未收集到任何插件，检查插件包是否可导入", file=sys.stderr)
        return 1

    cats = {}
    for p in plugins:
        cats.setdefault(p["package"], []).append(p)

    ordered = []
    for cat in CATEGORY_ORDER:
        ordered.extend(sorted(cats.get(cat, []), key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)))
    for cat in sorted(cats):
        if cat not in CATEGORY_ORDER:
            ordered.extend(cats[cat])

    sev = {"high": 0, "medium": 0, "low": 0}
    for p in ordered:
        sev[p["severity"]] = sev.get(p["severity"], 0) + 1
    cves = sorted({p["cve"] for p in ordered if p["cve"] and p["cve"].upper() != "N/A"})

    bar_eq = "=" * WIDTH
    bar_dash = "-" * WIDTH
    out = []
    out.append(bar_eq)
    out.append(" Ruoyi-Scan 插件清单（POC 覆盖范围）")
    out.append(f" 版本：v{settings.VERSION}　共 {len(ordered)} 个插件")
    out.append(f" 高危 {sev['high']}　中危 {sev['medium']}　低危 {sev['low']}　含 CVE 编号 {len(cves)} 个")
    out.append(" 说明：本清单由 scripts/export_plugin_list.py 从插件源码导出，与运行时一致；")
    out.append("       装好后可用 ruoyi-scan --plugin-list 实时查看同一份数据。")
    out.append(bar_eq)
    out.append("")
    out.append(" 按类别：")
    for cat in CATEGORY_ORDER + sorted(c for c in cats if c not in CATEGORY_ORDER):
        if cat in cats:
            out.append(f"   {cat:<12}{CATEGORY_LABEL.get(cat, cat):<12}{len(cats[cat]):>3} 个")
    out.append("")

    idx = 0
    for cat in CATEGORY_ORDER + sorted(c for c in cats if c not in CATEGORY_ORDER):
        if cat not in cats:
            continue
        out.append(bar_eq)
        out.append(f" {CATEGORY_LABEL.get(cat, cat)}（{cat}）· {len(cats[cat])} 个")
        out.append(bar_eq)
        out.append("")
        for p in sorted(cats[cat], key=lambda x: SEVERITY_ORDER.get(x["severity"], 9)):
            idx += 1
            sev_cn = {"high": "高危", "medium": "中危", "low": "低危"}.get(p["severity"], p["severity"])
            cat_cn = {"vuln": "漏洞", "recon": "信息", "brute": "爆破"}.get(p["category"], p["category"] or "-")
            head = f" {idx:03d}  {sev_cn}  {cat_cn}"
            if p["cve"] and p["cve"].upper() != "N/A":
                head += f"  {p['cve']}"
            out.append(head)
            out.append(f"      名称：{p['name']}")
            if p["variant"]:
                out.append(f"      适用变体：{p['variant']}")
            if p["affected"]:
                out.append(f"      影响版本：{p['affected']}")
            if p["description"]:
                out.append(f"      说明：{p['description']}")
            if p["fix"]:
                out.append(f"      修复：{p['fix']}")
            out.append("")

    out.append(bar_eq)
    out.append(" 覆盖的 CVE 索引")
    out.append(bar_eq)
    out.append("")
    if cves:
        for cve in cves:
            names = [p["name"] for p in ordered if p["cve"] == cve]
            out.append(f"   {cve:<18}{' / '.join(names)}")
    else:
        out.append("   （无）")
    out.append("")
    out.append(bar_dash)
    out.append(f" 项目地址：{settings.GITHUB}")
    out.append(" 仅限授权测试；插件均只做存在性验证，不做破坏性利用。")
    out.append(bar_eq)

    OUT.write_text("\r\n".join(out) + "\r\n", encoding="utf-8-sig", newline="")
    print(f"[+] 已生成 {OUT.relative_to(REPO)}：{len(ordered)} 个插件，{len(cves)} 个 CVE")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
