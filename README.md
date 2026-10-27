# Ruoyi-Scan · 若依专项漏洞扫描器

[![CI](https://github.com/xiabai2008/ruoyi-scan/actions/workflows/ci.yml/badge.svg)](https://github.com/xiabai2008/ruoyi-scan/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/ruoyi-scan)](https://pypi.org/project/ruoyi-scan/)
[![PyPI Downloads](https://img.shields.io/pypi/dm/ruoyi-scan)](https://pypi.org/project/ruoyi-scan/)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

> 合法授权的**若依（RuoYi）专项漏洞扫描器**。54 个 POC、5 变体识别、20 组件 CVE 比对，
> 结论只有三种：**CONFIRMED 确认存在 / SAFE 确认不存在 / UNKNOWN 无法判定**。
>
> `pip install -U ruoyi-scan`　或　[下载单文件桌面端](https://github.com/xiabai2008/ruoyi-scan/releases/latest/download/ruoyi-scan-desktop.exe)（双击即用，无需 Python）

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/report-overview.png" alt="扫描报告：风险分布 + 等保 2.0 / OWASP 合规映射" width="900" />
</p>

> 一次 `-p` 扫描产出的 HTML 报告（真实运行，v1.5.2，对签名靶场）：风险分布、等保 2.0 与 OWASP
> 条款命中、20 条确认漏洞——报告本身就是可交付物，7 种格式（HTML/JSON/CSV/PDF/Word/Excel/SARIF；
> PDF/Word/Excel 需 `pip install "ruoyi-scan[report]"`）。

---

## 它和通用扫描器的差别：敢说「不存在」

通用扫描器（nuclei / xray）告诉你「这里可能有东西」；Ruoyi-Scan 对每个插件给出**可交付的判定**：

| | 通用扫描器 | Ruoyi-Scan |
|---|---|---|
| 未命中 | 报告里不出现，你不知道测没测 | `SAFE` —— 测过了，排除 |
| 网络异常 / WAF 拦截 / 验证码阻断 | 报错或跳过 | `UNKNOWN` —— **绝不冒充 SAFE**，建议人工复核 |
| 判定依据 | 特征命中 | 结构化校验 + 回显证据（读到的文件内容、注入标记） |

这条纪律是可验证的：内置签名靶场有 `vuln`（带洞）与 `safe`（全修复）双模式，CI 与 nightly
验收分别断言「vuln 模式 20 个确认命中」与「safe 模式零误报」；每个插件的验证级别
（L1 靶场 / L2 真实响应 / L3 真实软件双向验证）公开在
[docs/verification-matrix.md](docs/verification-matrix.md)。

## 30 秒上手

```bash
pip install -U ruoyi-scan

# 漏洞检测（最快，只跑 vuln 类插件）
ruoyi-scan -p http://target:8080/

# 综合扫描（指纹 → 目录扫描 → POC → 弱口令爆破）
ruoyi-scan -u http://target:8080/

# 出报告：HTML / JSON / CSV / PDF / Word / Excel / SARIF
ruoyi-scan -u http://target:8080/ --report ./reports --report-format all
```

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/cli-demo.png" alt="命令行输出：绿色=确认存在 / 红色=确认不存在 / 黄色=无法判定" width="780" />
</p>

> 真实输出（v1.5.2，对仓库内置签名靶场执行 `-p`）：每行一条结论，三态配色，末尾给出
> 摘要、去重统计与报告路径。本地复现：源码仓库根目录 `LAB_MODE=vuln LAB_PORT=8080 python lab/server.py`，
> 再执行 `ruoyi-scan -p http://127.0.0.1:8080/`（pip 包不含 lab，需 clone 仓库）。

## 报告与交付

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/report-findings.png" alt="报告详细结果：11 列，含证据、修复建议、修复详情、复现命令、合规映射" width="900" />
</p>

每条结果都带：**证据**（状态码 + 命中关键字 / 回显内容）、**修复建议**、**修复详情**（nginx / Apache /
IIS 配置片段与代码改法）、**复现命令**、**合规映射**（等保条款 + OWASP 类别）、CVE / CVSS。

## 四种扫描模式

| 模式 | 命令 | 说明 |
|---|---|---|
| 漏洞检测 | `-p <url>` | 只跑 POC 判定，快，请求量小 |
| 综合扫描 | `-u <url>` | 指纹 → 目录扫描 → POC → 弱口令爆破 |
| 目录扫描 | `-m <url>` | 敏感路径 / 后台 / actuator 等探测 |
| 登录爆破 | `-l <url>` | Druid / 后台默认口令字典爆破（`--pass-level top100` 可收敛） |

批量：`ruoyi-scan -f targets.txt -p --report ./reports`　·　全部参数：[docs/usage.md](docs/usage.md)

## 能力概览

**检测**（54 个 POC 插件）

- 若依 20 个插件 + **5 变体识别**（Vue3 / App / Plus / Cloud-Plus / Magic），变体感知路由
- Spring Boot 14 个 POC（Actuator / Jolokia / Spring4Shell / Gateway …）、通用 12 个、JeecgBoot 8 个
- 20 个 Java 组件版本 → CVE 比对（`--components`），兼容执行 nuclei YAML 模板（`--nuclei`）
- WAF 绕过 11 策略 + 对抗型传输层（`--adversarial-transport`，可选依赖）

**交付**

- 7 种报告格式；等保 2.0 / OWASP 合规映射章节；**docx 模板引擎**（`--report-template`）
- 整改复测（`--remediation baseline.json`）、版本对照矩阵、SARIF 接 GitHub Code Scanning

**工程**

- Web API + WebSocket + 权限分级 + 定时扫描（`--serve`）；桌面端单 exe；Docker
- 靶场可复跑：签名靶场 / 行为级仿真（验证码 + CSRF + 差分判定）/ 对抗网络（WAF / 限流 / 软 404）/
  真实 Docker 栈（4.7.8 + MySQL + nginx + ModSecurity）
- 8 类真实用法脚本化审计（`scripts/scenario_audit.py`），结论与复现见 [lab/SCENARIO-AUDIT.md](lab/SCENARIO-AUDIT.md)
- 插件 SDK（`--plugin-init` / `--plugin-check`）、社区模板仓库（Ed25519 强制验签）
- AI 辅助：自然语言生成 POC 并经靶场自验证（`--ai`）、UNKNOWN 智能降噪（`--ai-triage`）

## 安装形态

| 形态 | 获取方式 | 说明 |
|---|---|---|
| pip | `pip install -U ruoyi-scan` | 推荐；可选依赖按需装（`ruoyi-scan[report,serve]`） |
| 单文件 exe | [Releases](https://github.com/xiabai2008/ruoyi-scan/releases/latest) · `ruoyi-scan-desktop.exe` | 约 49 MB，引擎与 54 个 POC 编译期嵌入，免安装 |
| 安装包 | `Ruoyi-Scan_*_x64-setup.exe` | NSIS 安装，含卸载清理 |
| Docker | `docker build -t ruoyi-scan .` / `docker compose up -d` | 多阶段构建、非 root；compose 自带两个签名靶场 |

## 桌面端

<p align="center">
  <img src="https://raw.githubusercontent.com/xiabai2008/ruoyi-scan/main/docs/images/desktop-app.png" alt="桌面端：任务列表、扫描配置、实时结果与报告" width="900" />
</p>

> Windows 单文件 exe（Tauri + WebView2）：引擎与 54 个 POC 内置，新建扫描 / 实时结果 / 报告归档在同一窗口完成。
> 引擎子进程挂 JobObject，强杀不留孤儿进程；细节见 [docs/desktop.md](docs/desktop.md)。

## 文档

| 文档 | 内容 |
|---|---|
| [快速上手](docs/quickstart.md) | 5 分钟从安装到出第一份报告 |
| [用户手册](docs/usage.md) | 扫描模式、**全部参数速查**、配置文件、分布式、CI/CD |
| [插件开发](docs/plugin_dev.md) | `PluginBase` 三态契约、`--plugin-init` 脚手架 |
| [检出能力矩阵](docs/verification-matrix.md) | 每个插件的验证级别（L1/L2/L3）与证据 |
| [桌面端](docs/desktop.md) · [API](docs/api.md) · [DevSecOps](docs/devsecops.md) | 单 exe / REST+WebSocket / CI 集成 |
| [在线文档站](https://xiabai2008.github.io/ruoyi-scan/) | 以上文档的在线阅读版 |

## 质量与供应链

[![Coverage](https://codecov.io/gh/xiabai2008/ruoyi-scan/branch/main/graph/badge.svg)](https://codecov.io/gh/xiabai2008/ruoyi-scan)
[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/xiabai2008/ruoyi-scan/badge)](https://securityscorecards.dev/viewer/?uri=github.com/xiabai2008/ruoyi-scan)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)

CI 覆盖 lint（ruff + mypy）/ 4 组单测矩阵（Ubuntu + Windows × py3.11/3.12）/ 签名靶场双模式验收 /
报告与 API 端到端；Release 产物附 SHA256 校验和与 **SLSA 构建来源证明**
（`gh attestation verify <file> -R xiabai2008/ruoyi-scan`）。

## 合规声明

本工具仅用于**授权范围内**的安全测试与漏洞验证，只做漏洞存在性确认、不做破坏性利用。
使用者需遵守《网络安全法》及所在地法律法规；未经授权对目标系统进行测试属违法行为。

## License

[MIT](LICENSE) © XIABAI
