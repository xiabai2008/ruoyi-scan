# Ruoyi-Scan Code Wiki

> 面向开发者与维护者的代码结构文档。目标读者：需要读懂、修改、扩展或评审本仓库的人。
> 文档基于仓库源码（`main` 分支，版本 `1.4.3`）静态分析生成，所有结论均可追溯到具体文件。

---

## 一、这是什么项目

Ruoyi-Scan 是一款**若依（RuoYi）专项漏洞扫描器**。核心差异点不在「扫得多」，而在「判得准」：

- **插件化**：一个漏洞 = 一个 `PluginBase` 子类，通过 `plugin_list` 显式登记；
- **三态判定**：每个插件必须给出 `CONFIRMED` / `SAFE` / `UNKNOWN`，网络异常一律 `UNKNOWN`，**绝不冒充 SAFE**；
- **双入口统一编排**：CLI（`-u/-m/-p/-l`）与 Web API（FastAPI）共用同一个 `ScanOrchestrator`；
- **多形态分发**：pip 包 / Docker 镜像 / 单文件桌面端 exe（Tauri 壳 + 内嵌 PyInstaller 引擎）。

### 项目速览

| 项目 | 值 |
|------|-----|
| 版本 | `1.4.3`（`pyproject.toml` / `config/settings.py` / `main.py` banner 三处同步） |
| Python | >= 3.8（mypy 分析目标 `3.10`，仅影响类型检查） |
| 核心依赖 | `requests`、`requests-mock`（零系统依赖） |
| 入口点 | `ruoyi-scan = "main:main"`（`pyproject.toml` `[project.scripts]`） |
| 许可 | MIT |

### 代码规模（按 `main` 分支实际文件统计）

| 目录 | 模块数 | 说明 |
|------|--------|------|
| `core/` | 24 | 核心引擎层（引擎、编排、指纹、路由、会话、报告） |
| `lib/` | 40 | 工具库层（信息收集、AI、WAF、合规、缓存等） |
| `api/` | 12 | FastAPI + WebSocket 服务层 |
| `cli/` | 8 | CLI 控制层（分发 + 各模式执行器） |
| `common/` | 3 | 共享基础层（模型、日志、控制台） |
| `config/` | 1 | 全局配置 |
| `plugins/` | 53 个已注册插件 | 4 个框架包 + 1 个链专用包（详见 [04](04-plugins-chains.md)） |
| `chains/` | 3 条利用链 | DAG 编排 |
| `desktop/` | Tauri 2 + React 18 | 桌面端（含 Rust 壳与 Python 引擎） |
| `tests/` | 66 个测试文件 | pytest + 回归脚本 |
| `lab/` | 多套靶场 | 签名靶场（vuln/safe 双模式） |

---

## 二、阅读路径建议

不同目的建议的阅读顺序：

| 你的目的 | 推荐路径 |
|----------|----------|
| **快速跑起来** | 本页 → [02 入口与 CLI](02-entrypoint-cli.md) 的「运行方式」 → 回 `README.md` |
| **理解整体设计** | [01 整体架构](01-architecture.md) → [03 核心引擎层](03-core.md) |
| **写一个新 POC** | [04 插件体系](04-plugins-chains.md)（PluginBase 契约 + 发现机制） |
| **改 Web API** | [06 API 与 Web 控制台](06-api-web.md) |
| **改桌面端** | [07 桌面端与部署](07-desktop-deploy.md) |
| **做架构评审 / 加新框架** | [01 架构](01-architecture.md) → [04 插件体系](04-plugins-chains.md) → [08 依赖关系](08-dependencies.md) |

---

## 三、章节导航

| 章节 | 内容 | 关键问题 |
|------|------|----------|
| [01 整体架构](01-architecture.md) | 分层结构、端到端数据流、扫描主流程 9 步、三态判定纪律、关键设计决策 | 项目怎么搭起来的？一次扫描发生什么？ |
| [02 入口与 CLI](02-entrypoint-cli.md) | `main.py`、`cli/` 分发层、参数全景、预检、环境变量、运行方式 | 命令行怎么进来的？各模式怎么执行？ |
| [03 核心引擎层](03-core.md) | `core/` 24 个模块逐模块说明（关键类/函数/依赖/设计要点） | 引擎、会话、指纹、路由、报告各自做什么？ |
| [04 插件体系与利用链](04-plugins-chains.md) | `PluginBase` 契约、5 条插件发现路径、53 个插件清单、3 条链、`data/` 字典 | 插件怎么写、怎么被发现、怎么被路由？ |
| [05 工具库层](05-lib.md) | `lib/` 40 个模块按功能分组说明 | WAF 绕过、OAST、nuclei 兼容、AI 闭环怎么做？ |
| [06 API 与 Web 控制台](06-api-web.md) | FastAPI 应用工厂、鉴权分级、全部 REST 端点、WebSocket 事件、定时扫描 | 服务端接口契约是什么？ |
| [07 桌面端与部署](07-desktop-deploy.md) | Tauri 桌面端、靶场、Docker、监控、CI/Release、测试 | 怎么打包、部署、验收？ |
| [08 依赖关系](08-dependencies.md) | 内部依赖分层规则、依赖矩阵、第三方依赖、打包分发 | 谁依赖谁？改一处会影响什么？ |

---

## 四、目录地图

```
Ruoyi-Scan/
├── main.py                    # CLI 入口：仅参数解析 + 模式分发（约 525 行）
├── config/settings.py         # 全局配置（模块导入时求值）
├── common/                    # 共享基础层：models / logger / console
├── cli/                       # CLI 控制层：dispatcher + runner + 各模式执行器
├── core/                      # 核心引擎层：编排、引擎、会话、指纹、路由、报告
├── lib/                       # 工具库层：40 个独立能力模块
├── plugins/                   # 插件系统
│   ├── base.py                #   PluginBase 抽象基类 + CVSS 计算
│   ├── ruoyi/                 #   20 个若依插件
│   ├── spring/                #   14 个 Spring Boot POC
│   ├── common/                #   11 个通用 Web 插件
│   ├── jeecgboot/             #   8 个 JeecgBoot 插件
│   └── chain/                 #   利用链专用步骤插件（不参与主路由）
├── chains/                    # 3 条漏洞利用链定义 + registry
├── api/                       # FastAPI 应用（app/auth/deps/metrics + routes/ws/models）
├── web/index.html             # 单文件 Web 控制台
├── data/                      # 字典 + CVE 映射 + 基线 + SQLite（cache/tasks）
├── desktop/                   # Tauri 桌面端（React 前端 + Rust 壳 + Python 引擎）
├── lab/                       # 签名靶场（vuln/safe 双模式）
├── monitoring/                # Prometheus + Grafana
├── tests/                     # pytest 用例 + 回归脚本
├── scripts/                   # 构建/验收/OpenAPI 导出脚本
├── docs/                      # 用户文档站（mkdocs-material）
└── .github/workflows/         # CI / Release / CodeQL / Scorecard 等 8 个 workflow
```

---

## 五、文档与实现的一致性说明

编写本文档时发现以下**文档与代码不一致**之处。文档层的偏差已在 2026-09-24 全部修正，仅剩 2 项属代码层问题待后续处理。

### 已修正

| 位置 | 原表述 | 修正为 |
|------|--------|--------|
| `README.md`、`README_EN.md`、`docs/index.md` | 「51 个 POC 插件」 | **53**（`plugin_list` 登记总数） |
| `pyproject.toml` description | 「57 检测插件」 | **53**（与 README 口径统一） |
| `README.md`、`README_EN.md` 目录结构 | `core/runner.py  # 扫描编排器` | 拆为 `cli/runner.py`（扫描模式执行器）与 `core/orchestrator.py`（CLI/API 共用编排器） |
| `README.md`、`README_EN.md` | `plugins/ruoyi/` 18 个插件 | **20 个（含 2 个 Plus 变体专属）** |
| `README.md`、`README_EN.md` | `lib/` 33 个模块 | **40** |
| `README.md`、`README_EN.md` | `tests/` 51 个测试文件 | **66** |
| `README.md`、`README_EN.md` | `main.py` ~440 行 | **~525 行** |
| `pyproject.toml` dev 组 | `ruff==0.16.7`、`mypy==2.3.1` | **`ruff==0.16.2`、`mypy==2.1.0`**（与 `ci.yml` 及 CHANGELOG 记载对齐） |

#### 插件数量的三个口径（重要）

原 README 的「51 / 18」并非随手写错，而是**按"通用目标实际执行数"统计**（53 登记数中减去 2 个 Plus 变体专属插件 = 51），与 [tests/test_fingerprint.py](../../tests/test_fingerprint.py) 的断言一致。修正后统一到"登记总数"口径，并保留 Plus 专属的说明：

| 口径 | 数量 | 来源 | 说明 |
|------|------|------|------|
| `plugins/` 下插件文件总数 | **57** | `scripts/verification_matrix.py` 按文件统计 | 含未登记的 `shiro_rememberme.py` 与 `plugins/chain/` 的 3 个链步骤文件 |
| `plugin_list` 登记总数 | **53** | 各包 `__init__.py` | 本 Wiki 与 README 统一采用此口径 |
| 通用目标实际执行数 | **51** | `Router().resolve()` | 减去 2 个 RuoYi-Plus 变体专属插件（`PlusAuthLoginProbePlugin`、`PlusJobUnauthPlugin`） |

### 仍待处理（代码层，非文档问题）

| 位置 | 情况 |
|------|------|
| `plugins/common/shiro_rememberme.py` | 文件存在但**未登记进 `plugin_list`**，当前不参与主扫描（`lib/component_detect.py` 复用了其探测思路） |
| `api/ws/events.py` 的 `ALL_EVENTS` | 看似"全部事件"清单（10 类），但 `ScanOrchestrator` 实际还会发 `recon`/`component`/`auth`/`template`/`plugins_loaded`/`waf_bypass` 等事件，并非穷举 |

> 本文档中所有模块数、插件数均以 `plugin_list` 与目录实际文件为准。