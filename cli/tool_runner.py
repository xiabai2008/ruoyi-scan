"""CLI submodule — 工具模式"""
from __future__ import annotations

import datetime
import os
import sys
import time
from argparse import Namespace
from typing import Optional

from common.logger import get_logger
from common.models import STATUS_CONFIRMED, STATUS_SAFE, FingerprintResult, ScanResult
from config import settings
from core.session import SessionManager
from lib.colors import GREEN, RED, RESET, SEPARATOR, YELLOW

logger = get_logger(__name__)

def run_template_list_mode() -> None:
    """列出所有可用的扫描模板（D19）"""
    from lib.scan_templates import list_templates

    print(f"{SEPARATOR}")
    print(f"{YELLOW}[*]可用扫描模板{RESET}")
    print(f"{SEPARATOR}")
    for t in list_templates():
        print(f"{GREEN}  {t.name}{RESET}")
        print(f"    名称：{t.display_name}")
        print(f"    描述：{t.description}")
        print(f"    预估耗时：{t.estimated_time}")
        if t.severity_filter:
            print(f"    严重度过滤：{', '.join(sorted(t.severity_filter))}")
        if t.category_filter:
            print(f"    类别过滤：{', '.join(sorted(t.category_filter))}")
        if t.compliance_filter:
            print(f"    合规过滤：{', '.join(sorted(t.compliance_filter))}")
        if t.default_args:
            defaults_str = ", ".join(f"{k}={v}" for k, v in t.default_args.items())
            print(f"    默认参数：{defaults_str}")
        print()
    print(f"{YELLOW}用法：python main.py --template <name> -u <target>{RESET}")
    print(f"{SEPARATOR}")



def run_diff_only_mode(old_path: str, new_path: str) -> None:
    """仅对比两个 JSON 报告（D20）"""
    import json as _json

    from lib.diff_scan import diff_reports, load_report, render_diff_report

    print(f"{YELLOW}[*]差异对比模式{RESET}")
    print(f"    旧报告: {old_path}")
    print(f"    新报告: {new_path}")
    try:
        old_report = load_report(old_path)
        new_report = load_report(new_path)
    except FileNotFoundError as e:
        print(f"{RED}[!]{e}{RESET}")
        return
    except _json.JSONDecodeError as e:
        print(f"{RED}[!]JSON 解析失败: {e}{RESET}")
        return

    diff = diff_reports(old_report, new_report)
    print(f"{SEPARATOR}")
    print(f"{YELLOW}[*]差异结果{RESET}")
    print(f"    旧扫描: {diff.old_scan_time}（{diff.old_total} 个漏洞）")
    print(f"    新扫描: {diff.new_scan_time}（{diff.new_total} 个漏洞）")
    print(f"    {GREEN}🆕 新增: {diff.total_new} 个{RESET}")
    print(f"    {GREEN}✅ 已修复: {diff.total_fixed} 个{RESET}")
    print(f"    {YELLOW}⚠️ 状态变化: {diff.total_changed} 个{RESET}")
    print(f"    {YELLOW}⏳ 未变: {diff.total_persisted} 个{RESET}")

    out_dir = os.path.dirname(new_path) or "."
    paths = render_diff_report(diff, os.path.join(out_dir, "diff"))
    print(f"{SEPARATOR}")
    print(f"{GREEN}[+]差异报告已生成:{RESET}")
    for p in paths:
        print(f"    {p}")
    print(f"{SEPARATOR}")



def run_ci_init_mode(args: Namespace) -> None:
    """生成 CI 配置文件（D28）"""
    from lib.ci_runner import generate_ci_config

    platform = args.ci_init
    output_paths = {
        "github": ".github/workflows/security-scan.yml",
        "gitlab": ".gitlab-ci-security.yml",
        "jenkins": "Jenkinsfile.security",
    }
    output_path = output_paths.get(platform, f"ci-{platform}.yml")
    print(f"{YELLOW}[*]生成 CI 配置: {platform}{RESET}")
    try:
        generate_ci_config(platform, output_path)
        print(f"{GREEN}[+]CI 配置已生成: {output_path}{RESET}")
        if platform == "github":
            print(f"{YELLOW}[*]使用方法:{RESET}")
            print("    1. 将文件提交到仓库")
            print("    2. 在 GitHub Secrets 中设置 SCAN_TARGET")
            print("    3. 推送代码触发扫描")
            print("    4. 在 GitHub → Security → Code scanning 查看结果")
    except ValueError as e:
        print(f"{RED}[!]{e}{RESET}")



def run_wiki_mode(args: Namespace) -> None:
    """生成漏洞知识库（D29）"""
    from lib.vuln_wiki import generate_wiki

    output_path = args.wiki_output or "vuln_wiki.html"
    print(f"{YELLOW}[*]生成漏洞知识库{RESET}")
    paths = generate_wiki(output_path, formats=["html", "json"])
    print(f"{GREEN}[+]知识库已生成:{RESET}")
    for p in paths:
        print(f"    {p}")
    print(f"{YELLOW}[*]用浏览器打开 HTML 文件查看{RESET}")

