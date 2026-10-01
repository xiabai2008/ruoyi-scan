# 08 · 依赖关系

> 本篇回答：谁依赖谁？为什么这么分？装哪些包？怎么打包分发？

---

## 1. 依赖哲学三条

| 原则 | 体现 |
|------|------|
| **核心零系统依赖** | 运行时核心只有 `requests`——不需要编译器、字体、数据库驱动 |
| **可选能力集，缺失只降级** | 报告/服务/分布式/异步/YAML 都是 optional extra，未安装时功能降级而非崩溃 |
| **能用标准库就不引三方** | CVSS 算法内联、零依赖 YAML 解析器、Ed25519 缺库时 fail-closed 而非自动装库 |

第三条尤其明显：[requirements.txt](../../requirements.txt) 头部写"核心依赖（零系统依赖，必装）"，而它下面列的报告、Web API 分组都带"缺时自动降级"的注释。

---

## 2. 包内分层

### 2.1 分层图

```
                    ┌──────────────┐
                    │    main.py   │  入口（只依赖 common/config/lib.colors）
                    └──────┬───────┘
                           │
        ┌──────────────────┼──────────────────┐
        ▼                  ▼                  ▼
   ┌─────────┐        ┌─────────┐       ┌─────────┐
   │  cli/   │        │  api/   │       │desktop/ │  ← 三个"外壳"，互不依赖
   └────┬────┘        └────┬────┘       │(独立进程)│
        │                  │            └─────────┘
        └────────┬─────────┘
                 ▼
            ┌─────────┐
            │  core/  │  核心引擎（编排/引擎/会话/指纹/路由/报告/存储）
            └────┬────┘
                 │
        ┌────────┴────────┐
        ▼                 ▼
   ┌─────────┐      ┌──────────┐
   │ plugins/│      │ chains/  │  插件与利用链
   └────┬────┘      └────┬─────┘
        │                │
        └────────┬───────┘
                 ▼
            ┌─────────┐
            │  lib/   │  可选工具能力集（40 模块）
            └────┬────┘
                 │
                 ▼
            ┌──────────┐
            │ common/  │  基础层（models / logger / console）
            └──────────┘
```

### 2.2 分层规则

| 层 | 允许依赖 | 硬性约束 |
|----|---------|---------|
| `common/` | 标准库 | 不依赖任何项目内部包——它是所有人的地板 |
| `core/` | `common/` + `core/` 内 | 可选能力通过**函数内延迟导入** `lib/` |
| `lib/` | `common/` + `core.http` 等无环模块 | 不依赖 `cli/`、`api/` |
| `plugins/` | `common.models`、`core.http`、`lib.{colors,matcher,reporter}` | 不直接依赖 `core.orchestrator`（避免反向耦合） |
| `chains/` | `core.chain` + `plugins.chain.*` | 只负责声明 DAG，不实现探测逻辑 |
| `cli/` | `common/`、`core/`、`lib/` | 不做扫描逻辑，只做参数 → 请求的翻译 |
| `api/` | `common/`、`core/`、`lib.reporter` | 不做扫描逻辑 |
| `main.py` | `common/console`、`common/logger`、`config.settings`、`lib.colors` | 保持极轻——启动就要快 |

`config/`（仅 [settings.py](../../config/settings.py)）是被所有层读取的全局配置，不算依赖环。

### 2.3 真实依赖矩阵

下面是按源码 import 实测的矩阵（✓ = 有依赖）：

| ↓依赖 → | common | core | lib | plugins | chains | cli | api |
|---------|:------:|:----:|:---:|:-------:|:------:|:---:|:---:|
| **common** | ✓ | | | | | | |
| **core** | ✓ | ✓ | △ | | | | |
| **lib** | ✓ | △ | ✓ | △ | | | |
| **plugins** | ✓ | △ | ✓ | ✓ | | | |
| **chains** | | ✓ | | ✓ | ✓ | | |
| **cli** | ✓ | ✓ | ✓ | △ | △ | ✓ | |
| **api** | ✓ | ✓ | △ | △ | | | ✓ |

- `core → lib`：**只有 3 处**。`report.py` 的 `from lib.star_cta import REPO_URL`（模块级，唯一一处），`session.py` 的 `from lib.proxy_pool import ProxyPool`（`TYPE_CHECKING` 下，仅类型标注），其余全部是 `orchestrator` 里的函数内延迟导入。
- `lib → core`：`core.http.join_url`（多处）、`lib.plugin_sdk` 的 `core.loader`。
- `plugins → chains`、`cli → chains`：仅 `cli/chain_runner.py` 经注册表间接使用。
- `cli → api`：**不存在**——`cli/serve_runner.py` 通过 `import api.app` 的延迟导入启动服务（只捕获 `ImportError` 以给出 `pip install ".[serve]"` 提示）。

### 2.4 循环依赖怎么绕开的

`core` 与 `lib` 之间在语义上互相需要（引擎要用 WAF 绕过、WAF 绕过要用 HTTP 工具），项目用**三种延迟导入手法**拆分：

**① 函数内导入（最常用，占绝大多数）**

[core/orchestrator.py](../../core/orchestrator.py) 里 11 处：

```python
def _run_recon(self): ...
    from lib.subdomain import SubdomainEnumerator     # L754
    from lib.crawler import Crawler                   # L782
    from lib.js_extractor import JSExtractor          # L783

def _build_waf_bypass(self): ...
    from lib.origin_finder import OriginIPFinder      # L708
    from lib.waf_bypass import BypassStatsTracker, WafBypassCoordinator  # L709

def _run(self): ...
    from lib.auth_scan import apply_auth_to_session   # L347
    from lib.component_detect import ComponentDetector, to_detect_result  # L407
    from lib.plugin_repo import load_user_installed_plugins  # L480
    from lib.nuclei_loader import load_nuclei_templates      # L516
    from lib.scan_templates import filter_plugins, get_template  # L546
```

**② `TYPE_CHECKING` 导入（只用于类型标注）**

```python
# core/session.py L20
if TYPE_CHECKING:
    from lib.proxy_pool import ProxyPool
```

运行时不执行，mypy 仍能看到类型。

**③ CLI 分发层的延迟导入（兼具"可选依赖不阻断启动"作用）**

[cli/dispatcher.py](../../cli/dispatcher.py) 中每个工具模式都是函数内导入：

```python
if args.oast:        from lib.oast import run_oast_mode
if args.cve_sync:    from lib.cve_sync import run_cve_sync_mode
if args.web_ui:      from lib.web_ui import run_web_ui_mode
if args.cache_stats: from lib.cache import run_cache_stats_mode
if args.ai_validate: from lib.ai_validate import run_ai_validate_mode
if args.ai_generate: from lib.ai_generator import run_ai_generate_mode
```

**代价的诚实记录**：`core/report.py` 是唯一一处模块级 `core → lib` 导入（为了 `REPO_URL` 常量）。它之所以没造成环，是因为 `lib.star_cta` 是纯常量模块、不反向依赖 `core`。

---

## 3. 第三方依赖

### 3.1 运行时核心（必装）

| 包 | 版本 | 用途 |
|----|------|------|
| `requests` | `>=2.28` | 唯一的 HTTP 客户端（同步） |
| `requests-mock` | `>=1.11` | 测试 mock 用，同时列在核心与 dev 中 |

`requests-mock` 出现在核心依赖里略显特别——它在运行时只有一个用途：让 `--oast` 之类模式在离线时可被替换。真正需要 mock 的是测试。

### 3.2 可选依赖分组（`pip install ".[group]"`）

| 分组 | 包 | 触发能力 | 缺失行为 |
|------|----|---------|---------|
| `report` | `reportlab>=4.0`、`python-docx>=1.1`、`openpyxl>=3.1` | PDF / Word / Excel 报告 | 降级为 HTML/JSON/CSV |
| `serve` | `fastapi>=0.100`、`uvicorn[standard]>=0.23` | `--serve` Web API + WS + 控制台 | `serve_runner` 捕获 `ImportError` 给出安装提示 |
| `distributed` | `redis>=4.5` | `--distributed` Master-Worker 队列 | 不可用 |
| `async` | `aiohttp>=3.8` | `--async` 异步 HTTP 客户端 | 回退同步引擎 |
| `yaml` | `pyyaml>=6.0` | `--config` YAML 配置文件 | 见下（nuclei 模板有自研降级） |
| `lab` | `flask>=2.3` | 启动 `lab/` 靶场 | 靶场不可用（不影响扫描器） |
| `all` | 以上全部 | — | — |
| `dev` | 见 3.3 | 开发与 CI | — |

### 3.3 开发依赖

两处声明，需保持一致：

- [pyproject.toml](../../pyproject.toml) `[project.optional-dependencies].dev`
- [requirements-dev.txt](../../requirements-dev.txt)（CI 实际使用，`-r requirements.txt` 起头）

| 包 | 用途 |
|----|------|
| `pytest` / `pytest-timeout` / `pytest-cov` / `pytest-asyncio` | 测试框架 |
| `pytest-benchmark` | 性能基线（仅 pyproject 声明） |
| `httpx2` | `starlette.testclient` 的隐式依赖 |
| `ruff==0.16.2` / `mypy==2.1.0` | lint 与类型检查 |

**版本固定在 pyproject 里是刻意的**，注释：

> `ruff format` 输出随版本演进，不固定会造成 CI 与本地格式漂移

同一组版本号也出现在 [ci.yml](../../.github/workflows/ci.yml)（`pip install ruff==0.16.2 mypy==2.1.0`）与 [CHANGELOG.md](../../CHANGELOG.md) 的「CI lint 转绿」条目中，三处需保持一致——CI 注释已明确提醒"升级时需本地重跑 ruff format 并同步此处与 pyproject dev 依赖"。

### 3.4 `cryptography`：可选但 fail-closed

[lib/plugin_repo.py](../../lib/plugin_repo.py) 的 `cryptography` **不在任何 extra 分组里**，属"要用才装"：

- **签名（本地打包）**：无 `cryptography` → 签名为空串，仍可生成 manifest。
- **验签（远程安装）**：无 `cryptography` → **直接拒绝安装**，并提示 `pip install cryptography`。

源码注释把这条规则写得毫不含糊：

> 远程安装强制 Ed25519 验签（公钥来自本地可信存储 `~/.ruoyi-scan/signing.pub`）
> 无 cryptography 时远程安装直接拒绝（不降级为纯摘要校验）

这是**供应链安全的 fail-closed**：可选依赖的缺失不允许降低安全等级。

### 3.5 用标准库替代三方库的三处

| 功能 | 常规做法 | 本项目 | 收益 |
|------|---------|--------|------|
| CVSS v3.1 评分 | 引入 `cvss` 库 | [plugins/base.py](../../plugins/base.py) 内联 `_CVSS_WEIGHTS` / `_CVSS_PR_SC` 与六步算法 | 零依赖、可审计、可按需微调 |
| YAML 解析（nuclei 模板） | 强制 `pyyaml` | [lib/nuclei_loader.py](../../lib/nuclei_loader.py) 先试 `import yaml`，失败则用 `_parse_simple_yaml()` | 不装 pyyaml 也能跑 nuclei 模板 |
| Ed25519 验签 | 强制 `cryptography` | 缺库时拒绝而非降级（见 3.4） | 安全等级不因依赖缺失而下降 |

再加上整个项目**没有系统级依赖**（无编译工具、无字体包、无数据库驱动），PDF 报告改用 `reportlab` 内置的 STSong-Light CJK 字体——[Dockerfile](../../Dockerfile) 因此可以在 `python:3.11-slim` 上直接跑。

---

## 4. 打包与分发

### 4.1 setuptools 配置要点

```toml
[project.scripts]
ruoyi-scan = "main:main"          # 安装后 CLI 直接可用

[tool.setuptools]
py-modules = ["main"]             # 非 src-layout：main.py 在根目录

[tool.setuptools.packages.find]
include = ["common*","cli*","core*","lib*","api*","plugins*","config*","chains*","data*"]
exclude = ["tests*","lab*","web*","monitoring*",".github*",".reasonix*"]

[tool.setuptools.package-data]
data = ["*.txt", "*.json"]        # 字典与 CVE 数据必须随包分发
```

三点值得注意：

- **显式声明 `py-modules`**：项目不是 src-layout，`main.py` 裸在根目录，不走 `packages.find`。
- **`data*` 必须在 include 里，且 `package-data` 显式声明**：`data/` 下的 `password.txt`、`ruoyi.txt`、`component_cve_map.json`、`cve_offline.json` 是**运行时必需资产**，漏了会导致字典为空、离线 CVE 失效。
- **`exclude` 排掉 lab/web/desktop 相关**：靶场与前端不进 wheel。

### 4.2 插件入口点（第三方扩展契约）

```toml
[project.entry-points."ruoyi_scan.plugins"]
# 内置插件不在此注册（通过 discover_plugin_packages 自动扫描）
```

第三方插件在自己的 `pyproject.toml` 声明：

```toml
[project.entry-points."ruoyi_scan.plugins"]
my-plugin = "my_plugin_pkg:plugin_list"
```

安装后即被 [core/loader.py](../../core/loader.py) 自动发现——这是[插件发现五条路径](04-plugins-chains.md)中的第四条。

### 4.3 发布流水线

**Python 包**（[release.yml](../../.github/workflows/release.yml)）：

```
tag v* 推送
   │
   ├─ Gate on CI       等待该 tag 提交的 CI 全绿（不绿不发）
   │
   ├─ build wheel + sdist
   ├─ 打包 nuclei 模板包
   ├─ sha256sum → dist/checksums.txt        ← 供应链完整性校验
   ├─ actions/attest-build-provenance       ← SLSA 构建来源证明
   ├─ Smoke test built artifact             ← 装完真跑一次
   └─ Publish to PyPI（OIDC Trusted Publisher，无长期 token）
```

三个安全设计：

| 机制 | 作用 |
|------|------|
| `id-token: write` + OIDC Trusted Publisher | 免长期 PyPI token，无凭据泄漏面 |
| `attestations: write` + `attest-build-provenance` | SLSA 来源证明，消费者可 `gh attestation verify <file> -R xiabai2008/ruoyi-scan` |
| `sha256sum` 校验文件 | 下载者可校验产物完整性 |

注释中还留了 PyPI 侧配置指引的引用块（Workflow name / Environment name / PyPI 项目设置），减少发布者的试错。

**桌面端**（[desktop-release.yml](../../.github/workflows/desktop-release.yml)）：

```
1. PyInstaller 打引擎 exe → smoke test 引擎
2. cargo tauri build（engine/dist/ 已就位 → build.rs 嵌入）
3. 产出 NSIS 安装包 + portable 单 exe
4. 分别 smoke test 两种形态
5. 生成 checksums → 上传 Release
6. 失败时上传 engine build log（便于定位）
```

注意第 1 步与第 2 步的**顺序依赖**：`build.rs` 在编译期读取 `engine/dist/ruoyi-scan-engine.exe`，所以引擎必须先构建完成。这也是 [07 章](07-desktop-deploy.md)里"编译期嵌入"的落地代价。

### 4.4 发行形态一览

| 产物 | 来源 | 面向 |
|------|------|------|
| wheel / sdist | `release.yml` | Python 用户、被其它项目依赖 |
| PyPI `ruoyi-scan` | OIDC 发布 | `pip install ruoyi-scan` |
| nuclei 模板包 zip | `release.yml` | 配合 nuclei 使用 |
| Windows 单 exe | `desktop-release.yml` | 非技术用户 |
| NSIS 安装包 | `desktop-release.yml` | Windows 常规安装 |
| Docker 镜像 | [Dockerfile](../../Dockerfile) | 服务端部署 |

---

## 5. 版本与兼容性约束

| 项 | 值 | 说明 |
|----|----|------|
| `requires-python` | `>=3.8` | 运行时支持 3.8+ |
| `[tool.mypy] python_version` | `3.10` | **仅影响类型分析**，注释已说明"运行时仍支持 3.8+" |
| `[tool.ruff] target-version` | `py38` | lint 目标版本 |
| CI 测试矩阵 | 3.11 / 3.12 × ubuntu / windows | 实际验证面 |
| mypy 严格度 | `common.*` / `core.*` = `strict`；`lib.*` / `api.*` = `ignore_errors` | 分层收紧，不搞一刀切 |

`requires-python >=3.8` 与 `mypy python_version 3.10` 的不一致是**有意的**：前者是承诺，后者是分析基线。这类"看似矛盾但注释已解释"的设计在本项目里很常见，读代码时先看注释能省很多困惑。

---

## 6. 新增依赖时的决策清单

按本项目既有惯例，加一个依赖前应先回答：

1. **标准库能否胜任？** CVSS、YAML 解析都选了自研。
2. **能否做成 optional extra 并优雅降级？** 报告、服务、分布式、异步、YAML 全是这个模式。
3. **缺失时是降级还是 fail-closed？** 安全相关能力（如 Ed25519 验签）必须 fail-closed 且给出安装指引。
4. **是否引入系统级依赖？** Dockerfile 用 slim 基础镜像，答案应倾向"否"。
5. **是否需要固定版本？** 输出敏感的格式化工具（ruff）必须固定；业务库用 `>=`。
6. **是否要在 CI 加对应验收 job？** 现有每个能力（D7 WAF / D8 报告 / D9 API）都有独立 job 与靶场证据。

---

## 7. 小结

| 现象 | 意图 |
|------|------|
| `common/` 只依赖标准库 | 它是全项目地板，改动风险最低 |
| `core → lib` 只有 3 处、且多为延迟导入 | 打破 `core ↔ lib` 语义环，同时保持启动轻量 |
| `main.py` 只 import 4 个内部模块 | CLI 启动快，帮助信息零成本 |
| 可选依赖全部"缺失即降级" | `pip install ruoyi-scan` 就能用，能力按需加 |
| Ed25519 缺库拒绝而非降级 | 可选依赖不允许降低安全等级 |
| `data/` 走 package-data 分发 | 字典与 CVE 数据是运行时资产，不是测试夹具 |
| 发布走 OIDC + SLSA + SHA256 | 供应链有据可查，无长期凭据 |
| ruff 版本在 pyproject / ci.yml / CHANGELOG 三处固定 | 消除格式漂移，代价是一次有意识的版本同步动作 |

---

**上一篇**：[07 桌面端、靶场与部署](07-desktop-deploy.md) · **返回**：[Wiki 索引](README.md)