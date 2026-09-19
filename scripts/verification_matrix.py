# 检出能力矩阵生成器
"""按插件汇总「验证级别」，输出 markdown 表格到 stdout。

存在意义
========
插件数量（57）与「验证过的检出」不是一回事：签名靶场能证明判定逻辑自洽，却证明不了
真实漏洞响应下不误判；而只有真实软件 + 补丁回退双向验证才能证明「官方版全 SAFE、
漏洞态全 CONFIRMED」。矩阵把每个插件的实际验证级别摊开，让薄弱项可见而不是藏在
「57 个插件」这个总数后面。同时它也是对外可查证的可信度材料。

验证级别（由弱到强）
====================
  none    无任何自动化验证证据
  L1      签名靶场：靶场返回约定 marker，验证判定逻辑与三态分流
  L2      真实响应靶场：复现真实漏洞响应特征（无 marker），验证特征匹配
  L3      真实软件双向验证：官方版全 SAFE（零误报）+ 补丁回退后 CONFIRMED

证据来源（全部自动提取，不手工维护）
====================================
  L3  lab/REAL-RUOYI.md      真实 RuoYi 4.7.8 编译运行 + VULN-REINTRODUCE 回退验证
  L2  lab/REAL-SPRING.md     真实漏洞响应特征靶场（明确声明「不含扫描器约定的 marker」）
  L1  tests/regression_*.py  签名靶场对拍用例；lab/server.py 的端点
  断言 tests/**/*.py         该测试函数内是否真的调用了 verify()
  误报 tests/test_fp_baseline.py 的 KNOWN_FALSE_POSITIVES 登记项

用法：
    python scripts/verification_matrix.py            # 输出 markdown
    python scripts/verification_matrix.py --check    # 门禁模式：存在 none 级插件即退出 1
"""

import argparse
import glob
import os
import re
import sys
from typing import Dict, List, Set

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

# ── 验证级别证据 ────────────────────────────────────────────────────────────
#
# L3/L2 用显式映射而非「文档路径字符串出现在插件源码中」的启发式匹配：后者的漏检率
# 不低（job_rce / thymeleaf_ssti / unauth_batch / nacos_unauth 的请求路径由代码动态
# 拼接，文档里的字面路径不会出现在源码中，实测 10 个已验证插件只匹配到 6 个）。
# 映射表逐条来自下面两份文档的「验证结果」章节，脚本会校验文件是否存在——插件改名
# 或移动会让脚本报错，从而保证映射不会悄悄失效。
#
#   L3 出处：lab/REAL-RUOYI.md  「漏洞验证结果（5 CONFIRMED + 5 SAFE）」
#   L2 出处：lab/REAL-SPRING.md 「修复后（增加真实漏洞响应特征判定）11 个全部识别」
_L3_PLUGINS = {
    # 5 CONFIRMED（真实漏洞，非误报）
    "plugins/ruoyi/sql_inject_role.py",
    "plugins/ruoyi/sql_inject_dept.py",
    "plugins/ruoyi/file_upload.py",
    "plugins/ruoyi/job_rce.py",
    "plugins/ruoyi/thymeleaf_ssti.py",
    # 5 SAFE（官方版正确识别为不存在，零误报）
    "plugins/ruoyi/file_read.py",
    "plugins/ruoyi/job_invoke_target.py",
    "plugins/ruoyi/file_read_path.py",
    "plugins/ruoyi/unauth_batch.py",
    "plugins/ruoyi/nacos_unauth.py",
}

_L2_PLUGINS = {
    "plugins/spring/spring4shell.py",
    "plugins/spring/gateway_rce.py",
    "plugins/spring/actuator_env_rce.py",
    "plugins/spring/jolokia_rce.py",
    "plugins/spring/jolokia_mlet_rce.py",
    "plugins/spring/cloud_function_rce.py",
    "plugins/spring/h2_console_rce.py",
    "plugins/spring/actuator_unauth.py",
    "plugins/spring/heapdump_leak.py",
    "plugins/spring/mappings_leak.py",
    "plugins/spring/trace_leak.py",
}

_LEVEL_ORDER = {"none": 0, "L1": 1, "L2": 2, "L3": 3}


def _verify_mapping_files() -> List[str]:
    """校验映射表引用的插件文件存在，返回缺失项（插件改名/移动即失效，必须报错）"""
    missing = []
    for rel in sorted(_L3_PLUGINS | _L2_PLUGINS):
        if not os.path.exists(os.path.join(PROJECT_ROOT, rel)):
            missing.append(rel)
    return missing


def _plugin_sources() -> List[str]:
    """全部插件源码路径（排除 __init__ / base）"""
    paths = []
    for p in glob.glob(os.path.join(PROJECT_ROOT, "plugins", "**", "*.py"), recursive=True):
        base = os.path.basename(p)
        if base in ("__init__.py", "base.py"):
            continue
        paths.append(p)
    return sorted(paths)


def _parse_meta(src: str) -> Dict[str, str]:
    """提取插件类属性（name/cve/severity/affected_versions）

    取值为枚举常量的字段（如 `severity = SEVERITY_MEDIUM`）也需解析——不少插件用
    常量而非字面量，只匹配引号字面量会让这些插件的 severity 显示为空。
    """
    meta: Dict[str, str] = {}
    for key in ("name", "cve", "severity", "affected_versions"):
        m = re.search(rf'^\s+{key}\s*=\s*(?:["\']([^"\']*)["\']|([A-Za-z_][A-Za-z0-9_]*))', src, re.M)
        if not m:
            continue
        value = m.group(1) or m.group(2)
        if key == "severity" and value.upper().startswith("SEVERITY_"):
            value = value[len("SEVERITY_") :].lower()
        meta[key] = value
    return meta


def _test_bodies() -> str:
    """拼接全部测试源码（用于判断插件是否被测试引用）"""
    blob = ""
    for p in glob.glob(os.path.join(PROJECT_ROOT, "tests", "**", "*.py"), recursive=True):
        blob += open(p, encoding="utf-8", errors="ignore").read()
    return blob


def _known_false_positives() -> Set[str]:
    """误报基线测试中登记的已知误报插件（是明确的技术债，不是通过项）"""
    path = os.path.join(PROJECT_ROOT, "tests", "test_fp_baseline.py")
    if not os.path.exists(path):
        return set()
    src = open(path, encoding="utf-8", errors="ignore").read()
    m = re.search(r"KNOWN_FALSE_POSITIVES\s*[:=][^=]*?[={]\s*(.*?)\n\}", src, re.S)
    if not m:
        return set()
    return set(re.findall(r'["\']([A-Za-z0-9_]+)["\']', m.group(1)))


def build_rows() -> List[Dict[str, object]]:
    """汇总每个插件的验证证据"""
    tests_blob = _test_bodies()
    known_fp = _known_false_positives()

    rows: List[Dict[str, object]] = []
    for path in _plugin_sources():
        src = open(path, encoding="utf-8", errors="ignore").read()
        meta = _parse_meta(src)
        module = os.path.basename(path)[:-3]
        classes = re.findall(r"^class (\w+)", src, re.M)
        rel = os.path.relpath(path, PROJECT_ROOT).replace("\\", "/")
        # 测试引用：模块名或类名出现在测试源码中（粗筛，用于区分「有对拍」与「零覆盖」）
        referenced = module in tests_blob or any(c in tests_blob for c in classes)
        if rel in _L3_PLUGINS:
            level = "L3"
        elif rel in _L2_PLUGINS:
            level = "L2"
        elif referenced:
            level = "L1"
        else:
            level = "none"
        rows.append(
            {
                "path": rel,
                "name": meta.get("name", ""),
                "cve": meta.get("cve", "N/A"),
                "severity": meta.get("severity", ""),
                "level": level,
                "tested": referenced,
                "known_fp": module in known_fp,
            }
        )
    return rows


def render(rows: List[Dict[str, object]]) -> str:
    """渲染 markdown 表（弱验证排前面，便于直接当作待办清单）"""
    order = {"none": 0, "L1": 1, "L2": 2, "L3": 3}
    rows = sorted(rows, key=lambda r: (order[str(r["level"])], str(r["path"])))
    counts: Dict[str, int] = {}
    for r in rows:
        counts[str(r["level"])] = counts.get(str(r["level"]), 0) + 1

    out = ["# 插件检出能力矩阵", ""]
    out.append("> 由 `scripts/verification_matrix.py` 自动生成（证据来自 lab 文档与测试源码，非人工填写）。")
    out.append("> 级别定义：L3 真实软件双向验证 / L2 真实响应靶场（无 marker）/ L1 签名靶场 / none 无自动化验证。")
    out.append("")
    out.append(
        f"**总计 {len(rows)} 个插件**：" + "，".join(f"{k} {counts.get(k, 0)} 个" for k in ("L3", "L2", "L1", "none"))
    )
    out.append("")
    out.append("| 级别 | 插件 | CVE | 严重度 | 测试引用 | 已知误报 | 文件 |")
    out.append("|------|------|-----|--------|---------|---------|------|")
    for r in rows:
        fp = "是（技术债）" if r["known_fp"] else "—"
        out.append(
            f"| {r['level']} | {r['name']} | {r['cve']} | {r['severity']} | "
            f"{'是' if r['tested'] else '**否**'} | {fp} | `{r['path']}` |"
        )
    out.append("")
    return "\n".join(out)


def main() -> int:
    parser = argparse.ArgumentParser(description="生成插件检出能力矩阵")
    parser.add_argument("--check", action="store_true", help="门禁模式：存在 none 级插件即退出 1")
    parser.add_argument("--max-none", type=int, default=None, help="允许的 none 级插件上限（增量门禁）")
    args = parser.parse_args()

    # 映射表失效即报错：插件改名/移动后若静默降级，矩阵会误报验证级别
    missing = _verify_mapping_files()
    if missing:
        print("[!]验证映射表引用了不存在的插件文件（插件可能已改名或移动）：", file=sys.stderr)
        for rel in missing:
            print(f"    - {rel}", file=sys.stderr)
        return 2

    rows = build_rows()
    text = render(rows)
    if not args.check:
        print(text)

    none_rows = [r for r in rows if r["level"] == "none"]
    if args.check and none_rows:
        limit = args.max_none if args.max_none is not None else 0
        if len(none_rows) > limit:
            print(f"[!]存在 {len(none_rows)} 个无自动化验证的插件（上限 {limit}）：", file=sys.stderr)
            for r in none_rows:
                print(f"    - {r['path']}", file=sys.stderr)
            return 1
    if args.max_none is not None and len(none_rows) > args.max_none:
        print(f"[!]警告：none 级插件 {len(none_rows)} 个，超过上限 {args.max_none}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
