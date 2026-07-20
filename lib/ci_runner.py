# D28：CI/CD 集成
#
# 提供 CI 模式扫描，适配 GitHub Actions / GitLab CI / Jenkins 等流水线
#
# CI 模式特性：
#   1. 非零退出码：发现高危漏洞时退出码 1，CI 流水线自动失败
#   2. SARIF 输出：自动生成 SARIF 格式报告，可上传 GitHub Code Scanning
#   3. 简化日志：减少彩色输出和交互提示，适合日志收集
#   4. 超时控制：可配置扫描超时时间
#   5. 严重度阈值：仅当漏洞超过指定严重度时才失败
#
# 使用方式：
#   # CI 模式（命令行）
#   python main.py --ci -u http://target/ --report reports/ --severity-threshold high
#
#   # GitHub Actions（自动生成 workflow）
#   python main.py --ci-init github -o .github/workflows/security-scan.yml
#
#   # GitLab CI
#   python main.py --ci-init gitlab -o .gitlab-ci-security.yml
#
# 退出码：
#   0 = 无漏洞或漏洞低于阈值
#   1 = 发现超阈值漏洞
#   2 = 扫描异常
import os
from typing import List

# CI 模式退出码
EXIT_SUCCESS = 0  # 无漏洞或漏洞低于阈值
EXIT_VULN_FOUND = 1  # 发现超阈值漏洞
EXIT_ERROR = 2  # 扫描异常

# 严重度等级（数值越高越严重）
SEVERITY_LEVELS = {
    "low": 1,
    "medium": 2,
    "high": 3,
}


def should_fail_ci(results: List, severity_threshold: str = "high") -> bool:
    """判断是否应让 CI 失败

    Args:
        results: 扫描结果列表（ScanResult 或 AggregatedVuln）
        severity_threshold: 严重度阈值（low/medium/high）
    Returns:
        True 表示应失败（发现超阈值漏洞）
    """
    from common.models import STATUS_CONFIRMED

    threshold_level = SEVERITY_LEVELS.get(severity_threshold, 3)

    for r in results:
        if r.status != STATUS_CONFIRMED:
            continue
        sev_level = SEVERITY_LEVELS.get(r.severity, 0)
        if sev_level >= threshold_level:
            return True
    return False


def get_ci_exit_code(results: List, severity_threshold: str = "high", has_error: bool = False) -> int:
    """获取 CI 退出码

    Args:
        results: 扫描结果列表
        severity_threshold: 严重度阈值
        has_error: 是否发生异常
    Returns:
        退出码（0/1/2）
    """
    if has_error:
        return EXIT_ERROR
    if should_fail_ci(results, severity_threshold):
        return EXIT_VULN_FOUND
    return EXIT_SUCCESS


def format_ci_summary(results: List, target: str, duration: float = 0) -> str:
    """格式化 CI 摘要（适合日志输出，无颜色）

    Args:
        results: 扫描结果列表
        target: 目标 URL
        duration: 耗时
    Returns:
        摘要字符串（纯文本，无 ANSI 颜色码）
    """
    from common.models import STATUS_CONFIRMED

    dist = {"high": 0, "medium": 0, "low": 0, "total": 0}
    for r in results:
        if r.status != STATUS_CONFIRMED:
            continue
        dist["total"] += 1
        if r.severity in dist:
            dist[r.severity] += 1

    lines = [
        "=" * 60,
        "Ruoyi-Scan CI Summary",
        "=" * 60,
        f"Target: {target}",
        f"Duration: {duration:.2f}s",
        f"Confirmed vulns: {dist['total']}",
        f"  High:   {dist['high']}",
        f"  Medium: {dist['medium']}",
        f"  Low:    {dist['low']}",
        "=" * 60,
    ]
    return "\n".join(lines)


def format_ci_vulns(results: List, max_display: int = 50) -> str:
    """格式化漏洞列表（CI 日志输出）

    Args:
        results: 扫描结果列表
        max_display: 最多显示条数
    Returns:
        漏洞列表字符串
    """
    from common.models import STATUS_CONFIRMED

    confirmed = [r for r in results if r.status == STATUS_CONFIRMED]
    if not confirmed:
        return "No confirmed vulnerabilities."

    lines = [f"Confirmed vulnerabilities ({len(confirmed)}):"]
    for i, r in enumerate(confirmed[:max_display], 1):
        cve_str = f" [{r.cve}]" if getattr(r, "cve", "") else ""
        lines.append(f"  {i}. [{r.severity.upper()}] {r.name}{cve_str}")
        lines.append(f"     URL: {r.url}")

    if len(confirmed) > max_display:
        lines.append(f"  ... and {len(confirmed) - max_display} more")

    return "\n".join(lines)


# ============================================================
# CI 配置文件生成
# ============================================================

GITHUB_ACTIONS_TEMPLATE = """# Ruoyi-Scan Security Scan
# 自动生成 by Ruoyi-Scan --ci-init github
name: Security Scan

on:
  push:
    branches: [ main, master, develop ]
  pull_request:
    branches: [ main, master, develop ]
  schedule:
    # 每天凌晨 2 点定时扫描
    - cron: '0 18 * * *'  # UTC 18:00 = Beijing 02:00

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.9'

      - name: Install dependencies
        run: |
          python -m pip install --upgrade pip
          pip install requests pyyaml openpyxl python-docx reportlab

      - name: Run Ruoyi-Scan
        env:
          SCAN_TARGET: ${{{{ secrets.SCAN_TARGET }}}}
        run: |
          python main.py --ci -u "$SCAN_TARGET" \\
            --report reports/ \\
            --report-format sarif,json \\
            --severity-threshold high

      - name: Upload SARIF to GitHub Code Scanning
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: reports/report.sarif

      - name: Upload scan reports
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: reports/
"""


GITLAB_CI_TEMPLATE = """# Ruoyi-Scan Security Scan
# 自动生成 by Ruoyi-Scan --ci-init gitlab
security-scan:
  stage: test
  image: python:3.9-slim
  before_script:
    - pip install requests pyyaml openpyxl python-docx reportlab
  script:
    - python main.py --ci -u "$SCAN_TARGET" --report reports/ --report-format json --severity-threshold high
  artifacts:
    when: always
    paths:
      - reports/
    reports:
      junit: reports/report.json
  variables:
    SCAN_TARGET: "http://target.example.com/"
  only:
    - main
    - merge_requests
"""


JENKINSFILE_TEMPLATE = """// Ruoyi-Scan Security Scan
// 自动生成 by Ruoyi-Scan --ci-init jenkins
pipeline {
    agent any
    environment {
        SCAN_TARGET = 'http://target.example.com/'
    }
    stages {
        stage('Install') {
            steps {
                sh 'pip install requests pyyaml openpyxl python-docx reportlab'
            }
        }
        stage('Scan') {
            steps {
                sh "python main.py --ci -u ${SCAN_TARGET} --report reports/ --severity-threshold high"
            }
        }
    }
    post {
        always {
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
            publishHTML(target: [
                reportDir: 'reports',
                reportFiles: 'report.html',
                reportName: 'Security Report'
            ])
        }
    }
}
"""


def generate_ci_config(platform: str, output_path: str = None) -> str:
    """生成 CI 配置文件

    Args:
        platform: CI 平台（github/gitlab/jenkins）
        output_path: 输出文件路径（为空时仅返回内容）
    Returns:
        配置文件内容
    """
    templates = {
        "github": GITHUB_ACTIONS_TEMPLATE,
        "gitlab": GITLAB_CI_TEMPLATE,
        "jenkins": JENKINSFILE_TEMPLATE,
    }

    if platform not in templates:
        raise ValueError(f"不支持的 CI 平台: {platform}（支持: {list(templates.keys())}）")

    content = templates[platform]

    if output_path:
        os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)

    return content


def run_ci_mode(args, results: List, target: str, duration: float = 0, has_error: bool = False) -> int:
    """CI 模式运行入口

    Args:
        args: CLI 参数（含 severity_threshold）
        results: 扫描结果列表
        target: 目标 URL
        duration: 耗时
        has_error: 是否发生异常
    Returns:
        退出码（0/1/2）
    """
    severity_threshold = getattr(args, "severity_threshold", "high")

    # 输出 CI 摘要
    print(format_ci_summary(results, target, duration))
    print()
    print(format_ci_vulns(results))

    # 判断退出码
    exit_code = get_ci_exit_code(results, severity_threshold, has_error)

    if exit_code == EXIT_VULN_FOUND:
        print(f"\n[CI] FAILED: 发现 {severity_threshold}+ 级别漏洞")
    elif exit_code == EXIT_SUCCESS:
        print("\n[CI] PASSED: 无超阈值漏洞")
    elif exit_code == EXIT_ERROR:
        print("\n[CI] ERROR: 扫描异常")

    return exit_code
