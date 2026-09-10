---
hide:
  - navigation
  - toc
---

# Ruoyi-Scan

<div class="rs-hero" markdown>

**若依（RuoYi）专项漏洞扫描器** —— 插件化架构 · 三态判定 · 合规交付

一款合法授权的若依专项漏洞扫描工具：网络异常绝不判 SAFE、UNKNOWN 永不冒充 SAFE，
检测结果只信三态：**CONFIRMED / SAFE / UNKNOWN**。

</div>

<div class="rs-badges" markdown>

[![CI](https://github.com/xiabai2008/Ruoyi-Scan/actions/workflows/ci.yml/badge.svg){: loading=lazy }](https://github.com/xiabai2008/Ruoyi-Scan/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ruoyi-scan){: loading=lazy }](https://pypi.org/project/ruoyi-scan/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/ruoyi-scan){: loading=lazy }](https://pypi.org/project/ruoyi-scan/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg){: loading=lazy }](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/LICENSE)
[![codecov](https://codecov.io/gh/xiabai2008/Ruoyi-Scan/branch/main/graph/badge.svg){: loading=lazy }](https://codecov.io/gh/xiabai2008/Ruoyi-Scan)

</div>

<div class="rs-tri" markdown>
<span class="confirmed">CONFIRMED 确认存在</span>
<span class="safe">SAFE 确认不存在</span>
<span class="unknown">UNKNOWN 无法判定</span>
</div>

```bash
pip install ruoyi-scan
```

## 为什么是「专项」而不是「通用」

通用扫描器（nuclei / xray）追求广度，Ruoyi-Scan 选择深度：**只深耕若依系 + 国产
Java 管理框架**，把指纹、变体、版本矩阵、利用链做透，并以三态判定与合规交付建立
与「结果全红」扫描器的信任差异。

## 核心能力一览

<div class="rs-grid" markdown>

=== "检测"

    - **51 个 POC 插件**：若依 18 / Spring Boot 14 / 通用 11 / JeecgBoot 8
    - 若依 5 变体识别（Vue3 / App / Plus / Cloud / Cloud-Plus）
    - 20 组件 CVE 比对（fastjson / Shiro / Nacos / Log4j …，`--components`）
    - WAF 绕过 11 策略 + 三态保护矩阵
    - 漏洞利用链 DAG 编排（3 条内置链）
    - nuclei 模板兼容执行（http 协议子集）

=== "交付"

    - 7 种报告格式：HTML / JSON / CSV / PDF / Word / Excel / SARIF
    - 等保 2.0 / OWASP 合规映射报告级章节
    - 安服 docx 模板引擎（`--report-template`）
    - 整改复测工作流（`--remediation`）

=== "工程"

    - Web API：REST + WebSocket + 权限分级 + 定时扫描
    - AI 闭环：POC 生成即验证 / UNKNOWN 智能降噪 / Ollama 本地模型
    - 插件模板仓库：Ed25519 强制验签分发
    - 桌面端单 exe：免安装双击即用（内嵌引擎）

</div>

## 五分钟上手

```bash
# 安装
pip install ruoyi-scan

# 对目标执行综合扫描（指纹 → WAF → 路由 → POC → 报告）
ruoyi-scan -u http://target:8080

# 结果示例
[+] CONFIRMED  RuoYi 定时任务任意文件读取  severity=high
[-] SAFE       SnappyData 未授权访问      （已验证不存在）
[?] UNKNOWN    Druid 未授权               （网络异常，请人工复核）
```

[快速上手 :material-arrow-right:](QUICKSTART.md){ .md-button .md-button--primary }
[插件开发 :material-arrow-right:](PLUGIN_DEV.md){ .md-button }
[Web API :material-arrow-right:](API.md){ .md-button }

## 文档导航

| 分类 | 文档 |
|------|------|
| 使用 | [用户手册](USAGE.md) · [版本矩阵](version-matrix.md) · [安全报告说明](SECURITY_REPORT.md) |
| 桌面端 | [单 exe 发布](DESKTOP.md) |
| 开发 | [插件开发教程](PLUGIN_DEV.md) · [插件模板仓库](TEMPLATE_REPO.md) · [API 文档](API.md) · [DevSecOps 集成](DEVSECOPS.md) |
| 社区 | [社区总览](COMMUNITY.md)（贡献指南 / 变更日志 / 路线图） · [发布流程](RELEASE.md) |

## 合规声明

!!! warning "仅限授权测试"
    本工具仅用于**授权范围内的安全测试与漏洞验证**，只做漏洞存在性确认、不做破坏性利用。
    使用者需遵守《网络安全法》及所在地法律法规，未经授权对目标系统进行测试属违法行为。
