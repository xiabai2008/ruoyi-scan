# Ruoyi-Scan 用户指南

> 版本：1.1.0 ｜ 作者：XIABAI ｜ 适用对象：安全工程师 / 渗透测试人员 / DevSecOps 工程师
>
> 本指南详细说明 Ruoyi-Scan 的安装、各扫描模式、配置、模板、WAF 绕过、利用链、报告输出、Web API、认证扫描、分布式扫描、CI/CD 集成与缓存性能优化等内容。所有示例命令均可直接复制运行。

---

## 目录

- [安装方式](#安装方式)
  - [PyPI 安装](#pypi-安装)
  - [源码安装](#源码安装)
  - [Docker 安装](#docker-安装)
  - [依赖要求](#依赖要求)
- [扫描模式详解](#扫描模式详解)
  - [-p 漏洞检测模式](#-p-漏洞检测模式)
  - [-m 目录扫描模式](#-m-目录扫描模式)
  - [-u 综合扫描模式](#-u-综合扫描模式)
  - [-l 登录爆破模式](#-l-登录爆破模式)
  - [-f 批量扫描模式](#-f-批量扫描模式)
  - [--passive 被动代理模式](#--passive-被动代理模式)
- [配置文件](#配置文件)
- [扫描模板](#扫描模板)
- [WAF 绕过](#waf-绕过)
- [漏洞利用链](#漏洞利用链)
- [报告输出](#报告输出)
- [Web API 服务](#web-api-服务)
- [认证扫描](#认证扫描)
- [分布式扫描](#分布式扫描)
- [CI/CD 集成](#cicd-集成)
- [缓存与性能优化](#缓存与性能优化)

---

## 安装方式

Ruoyi-Scan 采用 PEP 621 元数据规范，提供三种主流安装方式。**核心依赖仅 `requests` 与 `requests-mock`，零系统级依赖**，其余能力通过可选依赖组按需启用。

### PyPI 安装

最简单的方式，直接从 Python 包索引安装：

```bash
# 1. 仅核心依赖（漏洞检测 + JSON/CSV/HTML 报告 + CLI）
pip install ruoyi-scan

# 2. 全功能安装（一次到位，包含所有可选依赖）
pip install "ruoyi-scan[all]"

# 3. 按需安装（推荐生产环境，减小依赖体积）
pip install "ruoyi-scan[report]"          # PDF / Word / Excel 报告增强
pip install "ruoyi-scan[serve]"           # FastAPI Web API + WebSocket + Web 控制台
pip install "ruoyi-scan[distributed]"     # Redis 分布式扫描（master/worker）
pip install "ruoyi-scan[async]"           # aiohttp 异步 HTTP 引擎
pip install "ruoyi-scan[yaml]"            # --config YAML 配置文件支持
pip install "ruoyi-scan[lab]"             # 内置 Flask 靶场环境

# 4. 组合安装
pip install "ruoyi-scan[report,serve,yaml]"

# 5. 安装后即可使用全局命令
ruoyi-scan -p http://target:8080/
ruoyi-scan --version
```

#### 各可选依赖组说明

| 依赖组 | 启用的功能 | 包含的 Python 包 | 推荐场景 |
|--------|-----------|-----------------|---------|
| （核心） | 漏洞检测、指纹识别、三态判定、HTML/JSON/CSV/SARIF 报告、CLI、插件 SDK | `requests`、`requests-mock` | 所有场景必装 |
| `report` | PDF / Word / Excel 报告 | `reportlab`、`python-docx`、`openpyxl` | 需要交付正式报告 |
| `serve` | Web API 服务、Web 控制台、WebSocket 实时推送 | `fastapi`、`uvicorn[standard]` | 团队共享、远程调用 |
| `distributed` | Redis Master-Worker 分布式扫描 | `redis` | 大规模批量扫描 |
| `async` | 异步 HTTP 引擎（高并发场景） | `aiohttp` | 千级目标批量扫描 |
| `yaml` | `--config` YAML 配置文件 | `pyyaml` | 复杂参数固化 |
| `lab` | 内置 Flask 靶场（用于测试） | `flask` | 本地验证、POC 开发 |
| `all` | 上述全部 | 全部 | 全功能体验 |
| `dev` | 测试与开发工具 | `pytest`、`ruff`、`mypy` 等 | 贡献代码、运行测试 |

### 源码安装

适合二次开发、调试或需要最新未发布特性的场景：

```bash
# 1. 克隆仓库
git clone https://github.com/xiabai2004/Ruoyi-Scan.git
cd Ruoyi-Scan

# 2. 可编辑模式安装（修改源码即时生效）
pip install -e .

# 3. 按需安装可选依赖（开发场景推荐 dev + all）
pip install -e ".[dev,all]"

# 4. 直接通过 main.py 运行
python main.py -p http://target:8080/

# 5. 运行测试验证安装
python -m pytest tests/ -q
python tests/regression_ruoyi.py
python tests/regression_spring.py
```

> 提示：可编辑模式（`-e`）下，`ruoyi-scan` 命令同样可用，且对源码的修改立即生效，适合插件开发与调试。

### Docker 安装

生产推荐的隔离部署方式，提供多阶段构建、非 root 用户运行的安全镜像。

**1. 构建镜像**

```bash
docker build -t ruoyi-scan .
```

**2. 单次扫描任务**

```bash
# 基本扫描
docker run --rm ruoyi-scan -p http://target:8080/

# 扫描并将报告挂载到宿主机
docker run --rm -v "$(pwd)/reports:/app/reports" ruoyi-scan \
  -p http://target:8080/ --report /app/reports --report-format all

# 使用环境变量传递 API Key
docker run --rm -e RUOYI_SCAN_API_KEY=your-secret ruoyi-scan \
  -p http://target:8080/ --api-key your-secret
```

**3. 启动 Web API 服务**

```bash
docker run --rm -p 8000:8000 ruoyi-scan \
  --serve --host 0.0.0.0 --port 8000

# 带鉴权
docker run --rm -p 8000:8000 \
  -e RUOYI_SCAN_API_KEY=your-secret \
  ruoyi-scan --serve --host 0.0.0.0 --port 8000 --api-key your-secret
```

**4. Docker Compose 一键部署（推荐）**

```bash
# 启动全部服务（扫描器 + API + 2 个签名靶场）
docker compose up -d

# 扫描内置靶场
docker compose run --rm scanner -p http://lab-ruoyi:8080/ --report /app/reports

# 启动监控栈（Prometheus + Grafana）
docker compose --profile monitor up -d
# Grafana:      http://localhost:3000  (admin/admin)
# Prometheus:   http://localhost:9090

# 清理
docker compose down
```

| 服务 | 端口 | 说明 |
|------|------|------|
| scanner | - | 扫描器 CLI（通过 `docker compose run` 调用） |
| api | 8000 | FastAPI Web API + WebSocket + Web 控制台 |
| lab-ruoyi | 8080 | 若依签名靶场（vuln 模式） |
| lab-spring | 8091 | Spring Boot 签名靶场（vuln 模式） |
| prometheus | 9090 | 指标采集（需 `--profile monitor`） |
| grafana | 3000 | 监控面板（需 `--profile monitor`） |

### 依赖要求

| 类别 | 要求 | 说明 |
|------|------|------|
| Python 版本 | **3.8+**（推荐 3.10 ~ 3.12） | 已在 3.8 / 3.9 / 3.10 / 3.11 / 3.12 测试通过 |
| 操作系统 | 跨平台 | Windows / Linux / macOS 均可 |
| 核心依赖 | `requests>=2.28`、`requests-mock>=1.11` | 零系统级依赖 |
| Docker | Docker 20.10+、Docker Compose v2+ | 仅 Docker 部署场景需要 |
| Redis | Redis 6.0+ | 仅 `--distributed` 模式需要 |

#### 可选依赖与功能对照表

| 功能 | 需要的依赖组 | 关键参数 |
|------|------------|---------|
| PDF / Word / Excel 报告 | `report` | `--report-format pdf/docx/xlsx` |
| Web API + Web 控制台 | `serve` | `--serve` |
| 分布式 Master-Worker | `distributed` | `--distributed master/worker` |
| 异步扫描引擎 | `async` | `--async` |
| YAML 配置文件 | `yaml` | `--config config.yaml` |
| 内置靶场 | `lab` | `python -m lab.run` |
| 全部能力 | `all` | 一键全开 |

---

## 扫描模式详解

Ruoyi-Scan 提供 6 种扫描模式，覆盖从单点验证到全量攻防演练的不同场景。

### -p 漏洞检测模式

**适用场景**：已知目标为若依/Spring Boot 系统，需快速验证已知漏洞（POC 检测）。这是最常用的模式，仅做存在性验证，不做实际破坏。

**核心特性**：
- 自动指纹识别（favicon hash + 特征路径 + 关键字）
- 多版本适配（RuoYi 4.2 / 4.7 / v5 版本感知 POC 过滤）
- 三态判定：CONFIRMED（确认存在）/ SAFE（确认不存在）/ UNKNOWN（无法判定）
- 38 个 POC：若依 16 个 + Spring 14 个 + 通用 8 个

**示例命令**：

```bash
# 1. 基础漏洞扫描
ruoyi-scan -p http://target:8080/

# 2. 跳过指纹识别，手动指定 CMS
ruoyi-scan -p http://target:8080/ --cms ruoyi
ruoyi-scan -p http://target:8080/ --cms spring

# 3. 指定插件类别（缩小检测范围）
ruoyi-scan -p http://target:8080/ --category ruoyi
ruoyi-scan -p http://target:8080/ --category spring
ruoyi-scan -p http://target:8080/ --category common

# 4. 配合并发与限速（生产环境推荐）
ruoyi-scan -p http://target:8080/ --threads 10 --rate 20 --timeout 10

# 5. 通过代理扫描（如 BurpSuite 调试）
ruoyi-scan -p http://target:8080/ --proxy http://127.0.0.1:8080

# 6. 启用 WAF 自动绕过
ruoyi-scan -p http://target:8080/ --bypass-waf auto

# 7. 生成全格式报告
ruoyi-scan -p http://target:8080/ --report ./reports --report-format all

# 8. 启用 OAST 带外检测（盲漏洞）
ruoyi-scan -p http://target:8080/ --oast

# 9. 启用业务逻辑检测（IDOR / 越权 / 参数篡改 / 竞争条件）
ruoyi-scan -p http://target:8080/ --logic-scan
```

**输出说明**：
- 实时输出至 stderr：每个 POC 的执行结果（CONFIRMED/SAFE/UNKNOWN）
- 退出码：0 = 未发现高危漏洞；非 0 = 发现漏洞或发生错误（CI 模式下根据阈值决定）
- 报告文件：根据 `--report` 与 `--report-format` 生成到指定目录

### -m 目录扫描模式

**适用场景**：探测目标的隐藏路径、备份文件、敏感目录（如 `/druid/`、`/actuator/`、`/.git/`），用于信息收集阶段。

**示例命令**：

```bash
# 1. 基础目录扫描
ruoyi-scan -m http://target:8080/

# 2. 高并发扫描（注意目标承受能力）
ruoyi-scan -m http://target:8080/ --threads 20 --rate 50

# 3. 通过代理池轮换 IP（避免被封）
ruoyi-scan -m http://target:8080/ \
  --proxy-file proxies.txt --proxy-rotate round-robin

# 4. 结合爬虫深入发现
ruoyi-scan -m http://target:8080/ --crawl --crawl-depth 3 --crawl-max-pages 100

# 5. 子域名枚举 + 目录扫描
ruoyi-scan -m http://target.com/ --subdomain

# 6. JS 端点提取（从 JS 文件中提取 API 路径）
ruoyi-scan -m http://target:8080/ --js-extract
```

**字典文件**：内置字典位于 `data/` 目录，覆盖若依/Spring 常见路径。

### -u 综合扫描模式

**适用场景**：一站式完整渗透测试，自动执行「目录扫描 + 漏洞检测 + 登录爆破」三阶段，适合对单个目标做全面体检。

**示例命令**：

```bash
# 1. 综合扫描（一站式）
ruoyi-scan -u http://target:8080/

# 2. 指定口令字典级别
ruoyi-scan -u http://target:8080/ --pass-level top100     # 快速
ruoyi-scan -u http://target:8080/ --pass-level top1000    # 平衡
ruoyi-scan -u http://target:8080/ --pass-level full       # 全量（耗时较长）

# 3. 综合扫描 + 端口扫描 + 服务识别
ruoyi-scan -u http://target:8080/ --portscan

# 4. 综合扫描 + 业务逻辑漏洞检测
ruoyi-scan -u http://target:8080/ --logic-scan \
  --logic-endpoints endpoints.txt --logic-concurrency 20

# 5. 综合扫描 + 全格式报告
ruoyi-scan -u http://target:8080/ --report ./reports --report-format all --lang zh

# 6. 使用 deep 模板（深度扫描）
ruoyi-scan -u http://target:8080/ --template deep
```

**执行阶段**：
1. **指纹识别**：判定 CMS 类型与版本
2. **目录扫描**：探测敏感路径与备份文件
3. **漏洞检测**：执行对应版本的 POC
4. **登录爆破**：基于识别到的登录入口尝试弱口令

### -l 登录爆破模式

**适用场景**：已知目标登录入口，需进行弱口令爆破。支持验证码自动处理（OCR 识别 / 跳过 / 自动探测三种模式）。

**示例命令**：

```bash
# 1. 基础登录爆破
ruoyi-scan -l http://target:8080/login

# 2. 指定字典级别
ruoyi-scan -l http://target:8080/login --pass-level top1000

# 3. 全量字典爆破（耗时较长）
ruoyi-scan -l http://target:8080/login --pass-level full --threads 5 --rate 10

# 4. 通过代理爆破（避免触发 WAF）
ruoyi-scan -l http://target:8080/login --proxy http://127.0.0.1:8080
```

**验证码处理策略**：
- **自动探测**（默认）：检测到验证码自动调用 OCR
- **OCR 识别**：使用本地 OCR 引擎识别图形验证码
- **跳过**：忽略验证码字段（适用于无验证码场景）

### -f 批量扫描模式

**适用场景**：对大量目标进行统一扫描，生成批量汇总报告。适合资产盘点、合规检查、护网行动前摸底。

**targets.txt 文件格式**：

```text
# 每行一个目标 URL，# 开头为注释，空行自动忽略
# 支持 http/https，可带端口

# 若依系统
http://10.0.0.1:8080/
http://10.0.0.2:8080/
https://ruoyi.example.com/

# Spring Boot 系统
http://10.0.0.3:9090/
http://spring.example.com/

# 带路径的目标
http://10.0.0.4:8080/ruoyi/
```

**示例命令**：

```bash
# 1. 批量漏洞扫描
ruoyi-scan -f targets.txt -p --report ./batch_reports

# 2. 批量综合扫描（耗时较长，建议配合分布式）
ruoyi-scan -f targets.txt -u --report ./batch_reports --report-format all

# 3. 批量扫描 + 限速（避免对网络造成压力）
ruoyi-scan -f targets.txt -p --threads 20 --rate 100 --timeout 10

# 4. 批量扫描 + 异步引擎（千级目标推荐）
ruoyi-scan -f targets.txt -p --async --async-workers 50

# 5. 批量扫描 + 分布式（万级目标推荐）
# 见「分布式扫描」章节

# 6. 批量扫描 + CI 模式（合规检查）
ruoyi-scan -f targets.txt -p --ci --severity-threshold high
```

**批量报告**：
- 每个目标生成独立的报告文件（命名：`<target>_<timestamp>.<ext>`）
- 额外生成一份汇总报告 `summary.<ext>`，包含所有目标的漏洞统计
- 汇总报告包含：目标总数、漏洞总数、按严重度分布、按 CMS 分布、TOP 10 漏洞类型

### --passive 被动代理模式

**适用场景**：通过浏览器代理正常访问目标，扫描器自动捕获流量并扫描，无需主动发起请求。适合「人工浏览 + 自动扫描」组合，可绕过主动扫描的 WAF 检测。

**工作原理**：
1. Ruoyi-Scan 启动一个本地 HTTP/HTTPS 代理服务器
2. 浏览器配置代理指向 Ruoyi-Scan
3. 用户正常浏览目标站点
4. 扫描器捕获所有 HTTP 流量，自动去重并执行 POC 检测

**配置步骤**：

```bash
# 1. 启动被动代理（默认 127.0.0.1:8080）
ruoyi-scan --passive

# 2. 自定义监听地址与端口
ruoyi-scan --passive --passive-host 0.0.0.0 --passive-port 9090

# 3. 启用报告输出
ruoyi-scan --passive --report ./passive_reports --report-format all
```

**浏览器代理配置**（以 Firefox 为例）：

1. 打开 `about:preferences`
2. 搜索「网络设置」→ 点击「设置...」
3. 选择「手动代理配置」
4. HTTP 代理：`127.0.0.1`，端口：`8080`
5. 勾选「也将此代理用于 HTTPS」
6. 点击「确定」

**Chrome 命令行启动**：

```bash
# Windows
chrome.exe --proxy-server="http://127.0.0.1:8080"

# Linux / macOS
google-chrome --proxy-server="http://127.0.0.1:8080"
```

**配合 BurpSuite 上游代理**：

```bash
# Ruoyi-Scan 作为下游，BurpSuite 作为上游
ruoyi-scan --passive --passive-port 8080 --proxy http://127.0.0.1:8888
# 浏览器 → Ruoyi-Scan(8080) → BurpSuite(8888) → 目标
```

> 提示：被动模式不会主动发起任何请求到目标，仅分析浏览器实际访问的 URL，对目标零压力，是合规扫描的首选方式。

---

## 配置文件

通过 `--config` 参数加载 YAML 配置文件，将常用参数固化，避免每次扫描都输入长串命令。**CLI 参数优先级高于配置文件**，便于临时覆盖。

### 启用前提

YAML 配置文件功能需要安装 `yaml` 可选依赖：

```bash
pip install "ruoyi-scan[yaml]"
# 或
pip install pyyaml
```

### 完整配置示例

创建 `config.yaml`：

```yaml
# Ruoyi-Scan 完整配置文件示例
# 所有字段均可选，未配置的字段使用默认值

# ── 扫描模式 ──
# mode: p | m | u | l | passive | serve
# 与 CLI 的 -p/-m/-u/-l/--passive/--serve 对应
mode: p
target: http://target:8080/
targets_file: targets.txt        # 批量扫描目标文件（mode 为批量时使用）
cms: ruoyi                        # 手动指定 CMS，留空则自动指纹识别
category: ruoyi                   # 插件类别 ruoyi/spring/common

# ── 扫描模板 ──
template: deep                    # quick/deep/compliance/dengbao

# ── 网络与并发 ──
threads: 10                       # 并发线程数
rate: 20                          # 每秒请求数（0=不限速）
timeout: 10                       # 请求超时秒数
proxy: http://127.0.0.1:8080      # 代理地址
proxy_file: proxies.txt           # 代理池文件
proxy_rotate: round-robin         # 代理轮换策略 round-robin/random/least-fail
debug: false                      # 调试模式

# ── 信息收集 ──
crawl: true                       # 启用主动爬虫
crawl_depth: 3                    # 爬虫最大深度
crawl_max_pages: 100              # 爬虫最大页面数
subdomain: false                  # 子域名枚举
js_extract: true                  # JS 端点提取
portscan: false                   # 端口扫描
ports: "22,80,443,3306,6379,8080" # 自定义端口列表

# ── 登录爆破 ──
pass_level: top1000               # 口令字典级别 top100/top1000/full

# ── WAF 绕过 ──
bypass_waf: auto                  # auto/on/off

# ── 漏洞利用链 ──
chain: ruoyi_sql_to_rce           # 执行指定的利用链

# ── 认证扫描 ──
auth:
  - "cookie: SESSIONID=abc123"
  - "bearer: eyJhbGciOi..."
auth_file: auth.txt               # 从文件加载认证信息
auth_login: "admin:admin123"      # 自动登录

# ── 报告输出 ──
report: ./reports                 # 报告输出目录
report_format: all                # html/json/csv/pdf/docx/xlsx/sarif/all
no_dedup: false                   # 关闭结果去重
lang: zh                          # 报告语言 zh/en
diff: old_report.json             # 与历史扫描对比
save_baseline: false              # 保存为基线

# ── OAST 带外检测 ──
oast: false                       # 启用 OAST

# ── 业务逻辑检测 ──
logic_scan: false                 # 业务逻辑漏洞检测
logic_endpoints: endpoints.txt    # 业务端点列表
logic_concurrency: 20             # 竞争条件检测并发数

# ── 异步引擎 ──
async: false                      # 启用异步引擎
async_workers: 10                 # 异步并发线程数

# ── 分布式扫描 ──
distributed: standalone           # master/worker/standalone
redis_url: redis://localhost:6379/0
distributed_rate: 100             # 分布式全局限速
worker_max_tasks: 0               # Worker 最大任务数
distributed_timeout: 600          # 分布式超时秒数

# ── 结果缓存 ──
cache: true                       # 启用 SQLite 缓存
cache_ttl: 3600                   # 缓存有效期秒数
cache_db: ./cache/scan_cache.db   # 缓存数据库路径

# ── Web API 服务 ──
serve: false
host: 0.0.0.0
port: 8000
api_key: your-secret-key
cors_origins: "https://scanner.internal,https://admin.internal"
db_path: ./data/tasks.db

# ── CI/CD 集成 ──
ci: false                         # CI 模式
severity_threshold: high          # CI 失败阈值 low/medium/high

# ── SIEM 集成 ──
siem_export: ecs                  # ecs/cef/leef/json
siem_output: ./siem/events.json
siem_syslog: "10.0.0.100:514"
siem_protocol: udp                # udp/tcp

# ── 通知 ──
notify:
  - "webhook:https://hooks.slack.com/services/xxx"
  - "mail:security@example.com"
```

### 使用配置文件

```bash
# 加载配置文件运行
ruoyi-scan --config config.yaml

# 配置文件 + CLI 参数混用（CLI 优先级更高）
ruoyi-scan --config config.yaml -p http://other-target:8080/ --threads 20

# 配置文件中的 threads=10 会被 CLI 的 --threads 20 覆盖
# 配置文件中的 target 会被 CLI 的 -p 参数覆盖
```

### CLI 参数优先级说明

优先级从高到低：

1. **CLI 显式参数**（最高优先级）
   - 例：`--threads 20` 覆盖配置文件中的 `threads: 10`
2. **配置文件中的参数**
   - 例：`config.yaml` 中的 `timeout: 10`
3. **内置默认值**（最低优先级）
   - 例：未指定时 `threads` 默认为 5

**优先级规则**：
- CLI 参数一旦显式指定，配置文件中同名字段失效
- CLI 未指定的字段，使用配置文件中的值
- 配置文件未指定的字段，使用内置默认值
- 配置文件不存在或字段缺失不影响运行（仅记录警告）

---

## 扫描模板

为简化不同场景下的参数组合，Ruoyi-Scan 内置 4 种扫描模板板，覆盖快速验证、深度渗透、合规检查、护网行动四类典型场景。

### 四种模板说明

| 模板 | 用途 | 适用场景 | 关键参数 |
|------|------|---------|---------|
| `quick` | 快速扫描 | 资产盘点、初步摸底、CI 流水线 | 低并发、TOP100 字典、仅高危 POC、无爬虫、无爆破 |
| `deep` | 深度扫描 | 完整渗透测试、漏洞挖掘 | 高并发、全量字典、全量 POC、爬虫深度 3、启用 OAST |
| `compliance` | 合规扫描 | ISO 27001 / PCI DSS / 等保测评 | 全量 POC、SARIF 报告、CVE 映射、OWASP Top 10 映射 |
| `dengbao` | 等保专项 | 网络安全等级保护测评 | 等保 2.0 合规映射、中文报告、严重度分级、合规结论 |

### 模板差异对比

| 维度 | quick | deep | compliance | dengbao |
|------|-------|------|-----------|---------|
| 并发线程数 | 5 | 20 | 10 | 10 |
| 请求速率（QPS） | 20 | 50 | 30 | 30 |
| POC 范围 | 仅高危 | 全部 | 全部 | 全部 |
| 字典级别 | top100 | full | top1000 | top1000 |
| 爬虫 | 关闭 | 开启（深度 3） | 关闭 | 关闭 |
| 端口扫描 | 关闭 | 开启 | 关闭 | 关闭 |
| OAST 带外检测 | 关闭 | 开启 | 关闭 | 关闭 |
| 业务逻辑检测 | 关闭 | 开启 | 开启 | 开启 |
| 报告格式 | JSON | all | SARIF + JSON | HTML + PDF |
| 报告语言 | zh | zh | en | zh |
| CVE 映射 | 关闭 | 关闭 | 开启 | 开启 |
| 合规映射 | 无 | 无 | OWASP Top 10 | 等保 2.0 |

### 查看可用模板

```bash
# 列出所有可用模板及其参数
ruoyi-scan --template-list
```

输出示例：

```
可用扫描模板：
┌──────────────┬──────────────────┬─────────────────────────┐
│ 模板名称     │ 用途             │ 关键参数                │
├──────────────┼──────────────────┼─────────────────────────┤
│ quick        │ 快速扫描         │ threads=5 rate=20       │
│ deep         │ 深度扫描         │ threads=20 rate=50      │
│ compliance   │ 合规扫描         │ report=sarif cve=on     │
│ dengbao      │ 等保专项         │ report=html+pdf lang=zh │
└──────────────┴──────────────────┴─────────────────────────┘
```

### 使用模板

```bash
# 快速扫描（CI 流水线推荐）
ruoyi-scan -p http://target:8080/ --template quick

# 深度扫描（完整渗透测试）
ruoyi-scan -u http://target:8080/ --template deep

# 合规扫描（生成 SARIF + OWASP 映射）
ruoyi-scan -p http://target:8080/ --template compliance

# 等保专项（生成中文 HTML + PDF 报告）
ruoyi-scan -p http://target:8080/ --template dengbao

# 模板 + CLI 参数混用（CLI 覆盖模板参数）
ruoyi-scan -p http://target:8080/ --template deep --threads 30 --rate 100
```

### 自定义模板方法

#### 方式一：通过配置文件自定义

创建 `my_template.yaml`，参照「配置文件」章节填写参数，然后通过 `--config` 加载：

```bash
ruoyi-scan --config my_template.yaml -p http://target:8080/
```

#### 方式二：继承内置模板并覆盖

```yaml
# my_deep.yaml — 基于 deep 模板，调整并发与限速
template: deep        # 继承 deep 模板
threads: 30            # 覆盖并发数
rate: 100              # 覆盖限速
crawl_depth: 5         # 加深爬虫深度
```

```bash
ruoyi-scan --config my_deep.yaml -u http://target:8080/
```

#### 方式三：编写 Python 脚本调用

```python
from core.runner import ScanRunner

runner = ScanRunner(
    target="http://target:8080/",
    template="deep",
    threads=30,
    rate=100,
)
runner.run()
```

---

## WAF 绕过

Ruoyi-Scan 内置 11 种 WAF 绕过策略，配合三态判定保护矩阵与成功率追踪，能在检测到 WAF 时自动调整请求特征，提升 POC 命中率。

### 三种模式

通过 `--bypass-waf` 参数控制：

| 模式 | 行为 | 适用场景 |
|------|------|---------|
| `auto`（默认） | 先探测是否存在 WAF，检测到则自动启用绕过策略 | 推荐生产环境使用 |
| `on` | 强制启用 WAF 绕过（无论是否检测到 WAF） | 已知目标有 WAF，跳过探测阶段 |
| `off` | 禁用 WAF 绕过，使用原始请求 | 调试、无 WAF 环境加速扫描 |

### 使用方式

```bash
# 自动模式（默认，推荐）
ruoyi-scan -p http://target:8080/ --bypass-waf auto

# 强制启用
ruoyi-scan -p http://target:8080/ --bypass-waf on

# 禁用绕过
ruoyi-scan -p http://target:8080/ --bypass-waf off
```

### 11 种绕过策略

| 编号 | 策略名称 | 原理 | 典型对抗的 WAF |
|------|---------|------|---------------|
| 1 | 大小写混淆 | 将关键字大小写混写（`SeLeCt`） | 基于正则的 WAF |
| 2 | URL 编码 | 对 payload 进行 URL 编码（`%53%45%4C%45%43%54`） | 字符串匹配 WAF |
| 3 | 双重 URL 编码 | 二次 URL 编码绕过解码层 | 多层解码 WAF |
| 4 | Unicode 编码 | 使用 Unicode 转义（`\u0053`） | 字符集处理 WAF |
| 5 | HTML 实体编码 | 使用 HTML 实体（`&#83;`） | XSS 过滤器 |
| 6 | 注释混淆 | 插入 SQL 注释（`S/**/ELECT`） | SQL 注入 WAF |
| 7 | 空字节填充 | 在 payload 中插入 `%00` | C 语言解析差异 WAF |
| 8 | 分块传输编码 | 使用 `Transfer-Encoding: chunked` | 内容长度检测 WAF |
| 9 | HTTP 参数污染 | HPP 技术（`?id=1&id=1'`） | 参数解析差异 WAF |
| 10 | 请求方法变换 | GET ↔ POST ↔ PUT 切换 | 方法白名单 WAF |
| 11 | 头部伪装 | 修改 `User-Agent`、`X-Forwarded-For` 等 | 基于 IP/UA 的 WAF |

### 工作流程

1. **WAF 探测**：发送特征请求，根据响应判断是否存在 WAF（识别主流 WAF：阿里云、腾讯云、Cloudflare、ModSecurity 等）
2. **策略选择**：根据 WAF 类型从 11 种策略中选择最可能有效的组合
3. **三态判定保护**：每条策略执行后判定 CONFIRMED/SAFE/UNKNOWN，避免误判
4. **成功率追踪**：记录每种策略的成功率，动态调整后续请求的策略选择
5. **自动降级**：若所有策略均失败，标记为 UNKNOWN 而非误报

### 成功率追踪

Ruoyi-Scan 持续记录每种绕过策略的成功率，并在扫描结束后输出统计：

```
WAF 绕过策略统计：
┌────────────────┬──────────┬──────────┬──────────┐
│ 策略           │ 尝试次数 │ 成功次数 │ 成功率   │
├────────────────┼──────────┼──────────┼──────────┤
│ 大小写混淆     │ 15       │ 12       │ 80.0%    │
│ URL 编码       │ 15       │ 10       │ 66.7%    │
│ 双重 URL 编码  │ 10       │ 8        │ 80.0%    │
│ 注释混淆       │ 12       │ 9        │ 75.0%    │
│ ...            │ ...      │ ...      │ ...      │
└────────────────┴──────────┴──────────┴──────────┘
```

该统计也会写入 JSON 报告的 `waf_bypass_stats` 字段，便于后续分析与策略优化。

---

## 漏洞利用链

漏洞利用链（Chain）将多个漏洞串联成 DAG（有向无环图）拓扑，实现「单点突破 → 横向扩展 → 最终利用」的自动化攻击编排，支持条件分支与多路径执行。

### 查看可用链

```bash
# 列出所有可用的漏洞利用链
ruoyi-scan --chain-list
# 或
ruoyi-scan --chain list
```

输出示例：

```
可用漏洞利用链：
┌─────────────────────────────┬────────────────────────────┬─────────────────────┐
│ 链名称                      │ 描述                       │ 步骤数              │
├─────────────────────────────┼────────────────────────────┼─────────────────────┤
│ ruoyi_sql_to_rce            │ SQL 注入 → 文件写入 → RCE  │ 3                   │
│ ruoyi_nacos_to_dbcreds      │ Nacos 未授权 → DB 凭据泄露 │ 2                   │
│ ruoyi_defaultpw_to_webshell │ 默认口令 → Webshell 上传   │ 2                   │
└─────────────────────────────┴────────────────────────────┴─────────────────────┘
```

### 执行利用链

```bash
# 执行指定的利用链
ruoyi-scan --chain ruoyi_sql_to_rce -u http://target:8080/

# 执行链 + 生成报告
ruoyi-scan --chain ruoyi_nacos_to_dbcreds -u http://target:8080/ \
  --report ./reports --report-format all

# 执行链 + WAF 绕过
ruoyi-scan --chain ruoyi_defaultpw_to_webshell -u http://target:8080/ \
  --bypass-waf auto
```

### 3 条内置链说明

#### 1. ruoyi_sql_to_rce（SQL 注入 → 远程代码执行）

**攻击路径**：3 步

```
SQL 注入漏洞（如 druid 监控页未授权 / SQL 注入点）
    ↓
通过 SQL 注入写入 Webshell 到 Web 目录
    ↓
通过 Webshell 执行任意命令（RCE）
```

**适用版本**：RuoYi 4.2 / 4.7（v5 已修复该路径）

**前置条件**：
- 目标存在 SQL 注入漏洞
- 数据库用户具有 `FILE` 权限
- 已知 Web 绝对路径（或可通过其他漏洞获取）

**利用效果**：获取目标服务器命令执行权限

#### 2. ruoyi_nacos_to_dbcreds（Nacos 未授权 → 数据库凭据泄露）

**攻击路径**：2 步

```
Nacos 未授权访问（/nacos/v1/auth/users?pageNo=1&pageSize=1）
    ↓
读取 Nacos 配置文件，提取数据库账号密码
```

**适用版本**：所有使用 Nacos 的若依版本

**前置条件**：
- 目标暴露 Nacos 服务（默认 8848 端口）
- Nacos 未配置认证或使用默认密钥

**利用效果**：获取后端数据库连接凭据，可进一步连接数据库窃取/篡改数据

#### 3. ruoyi_defaultpw_to_webshell（默认口令 → Webshell 上传）

**攻击路径**：2 步

```
使用若依默认口令（admin/admin123）登录后台
    ↓
利用文件上传功能上传 Webshell
```

**适用版本**：RuoYi 4.2 / 4.7 / v5（未修改默认口令的系统）

**前置条件**：
- 目标未修改默认管理员口令
- 后台存在文件上传功能（如头像上传、附件管理）

**利用效果**：获取目标服务器 Webshell 权限

### 利用链 DAG 拓扑说明

每条利用链本质上是一个 DAG（有向无环图），节点为漏洞利用步骤，边为执行顺序与条件：

```
ruoyi_sql_to_rce 的 DAG 结构：

[SQL 注入检测] ──CONFIRMED──> [文件写入] ──CONFIRMED──> [RCE 验证]
       │                          │
       └──SAFE/UNKNOWN──> 终止     └──SAFE/UNKNOWN──> 终止
```

- **条件分支**：每步执行后根据三态判定决定是否继续
- **多路径**：部分链支持多路径，优先尝试成功率高的路径
- **回滚机制**：失败时自动清理中间产物（如已写入的临时文件）

> 安全声明：利用链默认仅做存在性验证与最小化利用（如写入 `echo test` 验证 RCE），不做实际破坏性操作。所有利用操作均记录在报告中，便于审计。

---

## 报告输出

Ruoyi-Scan 支持 7 种报告格式，覆盖交付、归档、合规、机器处理等不同场景，并支持中英文切换与增量对比。

### 7 种格式说明

| 格式 | 扩展名 | 用途 | 特点 |
|------|--------|------|------|
| HTML | `.html` | 交付客户、可视化展示 | 内嵌 SVG 图表，单文件可直接打开 |
| JSON | `.json` | 机器处理、二次开发 | 结构化数据，含完整漏洞信息 |
| CSV | `.csv` | Excel 分析、漏洞清单 | 表格形式，可导入 Excel/Security Hub |
| PDF | `.pdf` | 正式报告、归档 | 适合打印与正式交付（需 `report` 依赖） |
| Word | `.docx` | 客户编辑、协同修订 | 可二次编辑（需 `report` 依赖） |
| Excel | `.xlsx` | 漏洞跟踪表、整改清单 | 多 Sheet 分类展示（需 `report` 依赖） |
| SARIF | `.sarif` | CI/CD 集成、IDE 集成 | OASIS 标准，GitHub/GitLab 原生支持 |

### 生成报告

```bash
# 1. 生成单一格式报告
ruoyi-scan -p http://target:8080/ --report ./reports --report-format html
ruoyi-scan -p http://target:8080/ --report ./reports --report-format json
ruoyi-scan -p http://target:8080/ --report ./reports --report-format pdf
ruoyi-scan -p http://target:8080/ --report ./reports --report-format sarif

# 2. 生成全部格式报告（推荐）
ruoyi-scan -p http://target:8080/ --report ./reports --report-format all

# 3. 生成中文报告（默认）
ruoyi-scan -p http://target:8080/ --report ./reports --report-format all --lang zh

# 4. 生成英文报告
ruoyi-scan -p http://target:8080/ --report ./reports --report-format all --lang en

# 5. 关闭结果去重（保留原始记录）
ruoyi-scan -p http://target:8080/ --report ./reports --no-dedup
```

### 报告内容结构

以 HTML 报告为例，包含以下部分：

1. **扫描概览**：目标、扫描时间、扫描模式、POC 总数、漏洞统计
2. **漏洞列表**：按严重度（Critical / High / Medium / Low / Info）排序
3. **漏洞详情**：
   - 漏洞名称、CVE 编号、CWE 分类
   - 严重度、CVSS 评分
   - 受影响版本、利用条件
   - 请求/响应证据（脱敏后）
   - 修复建议
   - 三态判定结果（CONFIRMED/SAFE/UNKNOWN）
4. **统计图表**（内嵌 SVG）：
   - 漏洞严重度分布饼图
   - 漏洞类型分布柱状图
   - CMS 版本分布
   - 扫描耗时分布
5. **附录**：
   - 完整 POC 执行清单
   - WAF 绕过统计（如启用）
   - 合规映射表（如启用 compliance 模板）

### --report-format all 生成全部

```bash
ruoyi-scan -p http://target:8080/ --report ./reports --report-format all
```

执行后在 `./reports/` 目录生成：

```
reports/
├── report_<target>_<timestamp>.html
├── report_<target>_<timestamp>.json
├── report_<target>_<timestamp>.csv
├── report_<target>_<timestamp>.pdf
├── report_<target>_<timestamp>.docx
├── report_<target>_<timestamp>.xlsx
└── report_<target>_<timestamp>.sarif
```

> 提示：生成 PDF / Word / Excel 需要安装 `report` 可选依赖：`pip install "ruoyi-scan[report]"`

### --lang zh|en 中英文切换

```bash
# 中文报告（默认）
ruoyi-scan -p http://target:8080/ --report ./reports --report-format html --lang zh

# 英文报告
ruoyi-scan -p http://target:8080/ --report ./reports --report-format html --lang en
```

- `zh`：中文，适合国内客户交付、等保测评
- `en`：英文，适合国际客户、跨国团队协作

### --diff 增量对比

将本次扫描结果与历史扫描报告对比，突出新增与已修复的漏洞，适合跟踪整改进度。

```bash
# 1. 第一次扫描，保存为基线
ruoyi-scan -p http://target:8080/ --report ./reports --report-format json --save-baseline

# 2. 整改后第二次扫描，与基线对比
ruoyi-scan -p http://target:8080/ --report ./reports --report-format json \
  --diff ./reports/report_target_20260701.json

# 3. 仅对比两个 JSON 报告（不执行扫描）
ruoyi-scan --diff-only old_report.json new_report.json
```

**对比报告内容**：

| 类别 | 说明 |
|------|------|
| 新增漏洞 | 本次扫描发现但基线中不存在的漏洞 |
| 已修复漏洞 | 基线中存在但本次扫描未发现的漏洞 |
| 持续存在 | 基线与本次扫描均存在的漏洞 |
| 状态变化 | 漏洞严重度或三态判定结果发生变化 |

对比结果会以独立章节附加在报告中，并生成 `diff_<old>_<new>.json` 供程序化处理。

---

## Web API 服务

通过 `--serve` 启动 FastAPI Web API 服务，支持 REST 接口、WebSocket 实时事件推送与 Web 控制台，适合团队共享扫描能力或集成到现有安全平台。

### 启用前提

Web API 服务需要安装 `serve` 可选依赖：

```bash
pip install "ruoyi-scan[serve]"
```

### 启动服务

```bash
# 1. 基本启动（默认 0.0.0.0:8000）
ruoyi-scan --serve

# 2. 自定义监听地址与端口
ruoyi-scan --serve --host 0.0.0.0 --port 9000

# 3. 启用 API Key 鉴权
ruoyi-scan --serve --api-key your-secret-key

# 4. 配置 CORS（允许前端跨域访问）
ruoyi-scan --serve --cors-origins "https://scanner.internal,https://admin.internal"

# 5. 自定义任务数据库路径
ruoyi-scan --serve --db-path ./data/tasks.db

# 6. Docker 启动
docker run --rm -p 8000:8000 ruoyi-scan \
  --serve --host 0.0.0.0 --port 8000 --api-key your-secret
```

启动后可访问：

| 路径 | 说明 |
|------|------|
| `http://localhost:8000/` | Web 控制台（单页应用） |
| `http://localhost:8000/docs` | OpenAPI 3.0 交互式文档（Swagger UI） |
| `http://localhost:8000/redoc` | ReDoc 文档 |
| `http://localhost:8000/api/v1/...` | REST API 端点 |
| `ws://localhost:8000/ws` | WebSocket 实时事件 |

### API Key 鉴权

启用 API Key 后，所有 API 请求需在 Header 中携带 `X-API-Key`：

```bash
# 启动带鉴权的服务
ruoyi-scan --serve --api-key your-secret-key

# 调用 API 时携带 Key
curl -H "X-API-Key: your-secret-key" http://localhost:8000/api/v1/tasks

# 也可通过环境变量配置
export RUOYI_SCAN_API_KEY=your-secret-key
ruoyi-scan --serve
```

未携带或携带错误 Key 的请求将返回 `401 Unauthorized`。

### WebSocket 实时事件

通过 WebSocket 实时接收扫描进度、漏洞发现等事件：

```javascript
// JavaScript 示例
const ws = new WebSocket("ws://localhost:8000/ws?api_key=your-secret-key");

ws.onmessage = (event) => {
  const data = JSON.parse(event.data);
  console.log("事件类型:", data.type);
  console.log("事件数据:", data.payload);
};

// 事件类型示例：
// { type: "scan_started",  payload: { task_id, target, mode } }
// { type: "fingerprint",   payload: { task_id, cms, version } }
// { type: "vuln_found",    payload: { task_id, vuln_id, severity, name } }
// { type: "scan_progress", payload: { task_id, progress, current_poc } }
// { type: "scan_finished", payload: { task_id, total_vulns, duration } }
```

**Python 客户端示例**：

```python
import websockets
import asyncio
import json

async def listen():
    uri = "ws://localhost:8000/ws?api_key=your-secret-key"
    async with websockets.connect(uri) as ws:
        async for message in ws:
            event = json.loads(message)
            print(f"[{event['type']}] {event['payload']}")

asyncio.run(listen())
```

### Web 控制台

访问 `http://localhost:8000/` 即可使用内置 Web 控制台（单页应用），功能包括：

- **任务管理**：创建、查看、取消扫描任务
- **实时监控**：WebSocket 推送的扫描进度与漏洞发现
- **漏洞浏览**：按严重度、CMS、类型筛选漏洞
- **报告下载**：在线预览与下载各格式报告
- **链执行**：可视化选择并执行漏洞利用链
- **配置管理**：在线编辑扫描模板与配置

### 链接到 API 文档

> 详细的 API 端点说明、请求/响应示例、WebSocket 事件格式、错误码定义请参考 [API 使用指南](./API.md)。
>
> OpenAPI 3.0 规范可通过以下命令导出：
>
> ```bash
> python scripts/export_openapi.py
> # 输出至 docs/openapi.json
> ```

---

## 认证扫描

针对需要登录才能访问的目标，Ruoyi-Scan 提供 4 种认证注入方式，将认证信息自动附加到所有扫描请求中。

### --auth cookie/token/bearer

通过 `--auth` 参数直接指定认证信息，可多次指定以叠加多种认证：

```bash
# 1. Cookie 认证（最常用）
ruoyi-scan -p http://target:8080/ --auth "cookie: SESSIONID=abc123; JSESSIONID=xyz789"

# 2. Token 认证（如自定义 Header）
ruoyi-scan -p http://target:8080/ --auth "token: X-Token:my-token-value"

# 3. Bearer 认证（JWT 等）
ruoyi-scan -p http://target:8080/ --auth "bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."

# 4. 组合多种认证
ruoyi-scan -p http://target:8080/ \
  --auth "cookie: SESSIONID=abc123" \
  --auth "bearer: eyJhbGciOi..."

# 5. 认证扫描 + 漏洞检测 + 报告
ruoyi-scan -p http://target:8080/ \
  --auth "cookie: SESSIONID=abc123" \
  --report ./reports --report-format all
```

**认证类型说明**：

| 类型 | 格式 | 注入位置 | 适用场景 |
|------|------|---------|---------|
| `cookie` | `cookie: name=value; name2=value2` | `Cookie` Header | 传统 Session 认证 |
| `token` | `token: Header-Name:token-value` | 自定义 Header | API Token 认证 |
| `bearer` | `bearer: <jwt-token>` | `Authorization: Bearer <token>` | JWT / OAuth 2.0 |

### --auth-file 文件加载

将认证信息保存到文件，适合复杂认证或多目标复用：

```bash
# 1. 创建认证文件 auth.txt
cat > auth.txt << 'EOF'
cookie: SESSIONID=abc123; JSESSIONID=xyz789
bearer: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
EOF

# 2. 从文件加载认证
ruoyi-scan -p http://target:8080/ --auth-file auth.txt

# 3. 批量扫描时复用认证
ruoyi-scan -f targets.txt -p --auth-file auth.txt --report ./reports
```

**文件格式**：每行一条认证信息，格式与 `--auth` 参数一致，`#` 开头为注释。

### --auth-login 自动登录

提供用户名密码，由扫描器自动完成登录流程并获取认证信息：

```bash
# 1. 自动登录（用户名:密码）
ruoyi-scan -p http://target:8080/ --auth-login "admin:admin123"

# 2. 自动登录 + 综合扫描
ruoyi-scan -u http://target:8080/ --auth-login "admin:Password123!"

# 3. 自动登录 + 验证码自动识别
ruoyi-scan -p http://target:8080/ --auth-login "admin:admin123"
# （扫描器自动检测验证码并调用 OCR）

# 4. 自动登录 + 报告
ruoyi-scan -p http://target:8080/ --auth-login "admin:admin123" \
  --report ./reports --report-format all
```

**自动登录流程**：

1. 探测登录入口（常见路径：`/login`、`/admin/login`、`/ruoyi/login`）
2. 识别登录表单字段（用户名、密码、验证码）
3. 如有验证码，自动 OCR 识别
4. 提交登录请求，提取返回的 Cookie / Token
5. 将认证信息附加到后续所有扫描请求

> 提示：自动登录功能会自动处理 CSRF Token、验证码等常见防护机制。如登录失败，会在日志中输出失败原因。

---

## 分布式扫描

针对万级以上的大规模批量扫描场景，Ruoyi-Scan 提供 Redis Master-Worker 分布式架构，支持多机协作扫描与全局限速。

### 启用前提

分布式扫描需要安装 `distributed` 可选依赖与 Redis 服务：

```bash
pip install "ruoyi-scan[distributed]"
# 或
pip install redis
```

### 三种模式

| 模式 | 角色 | 说明 | 适用场景 |
|------|------|------|---------|
| `standalone`（默认） | 单机 | 单进程扫描，无 Redis 依赖 | 小规模扫描（<1000 目标） |
| `master` | 调度节点 | 将目标分发到队列，监控 Worker 状态 | 分布式调度 |
| `worker` | 执行节点 | 从队列领取任务执行扫描，结果回传 | 分布式执行 |

### Redis 配置

**1. 启动 Redis 服务**

```bash
# Docker 启动 Redis
docker run -d --name redis -p 6379:6379 redis:7

# 或使用 docker-compose
# 见项目 docker-compose.yml
```

**2. 配置 Redis 连接**

```bash
# 通过 CLI 参数
ruoyi-scan --distributed master --redis-url redis://localhost:6379/0

# 通过环境变量
export REDIS_URL=redis://localhost:6379/0
ruoyi-scan --distributed master

# 通过配置文件（config.yaml）
# distributed: master
# redis_url: redis://localhost:6379/0
```

**Redis 连接 URL 格式**：

```
redis://[:password@]host:port/db
redis://localhost:6379/0                    # 无密码
redis://:mypassword@localhost:6379/0        # 带密码
redis://user:mypassword@redis-host:6379/0   # ACL 用户
rediss://localhost:6379/0                   # TLS 加密
```

### Master 节点配置

```bash
# 1. 启动 Master，分发批量目标
ruoyi-scan --distributed master \
  --redis-url redis://localhost:6379/0 \
  -f targets.txt -p

# 2. 配置全局限速（所有 Worker 共享）
ruoyi-scan --distributed master \
  --redis-url redis://localhost:6379/0 \
  -f targets.txt -p \
  --distributed-rate 1000

# 3. 配置超时（默认 600 秒）
ruoyi-scan --distributed master \
  --redis-url redis://localhost:6379/0 \
  -f targets.txt -p \
  --distributed-timeout 3600
```

**Master 职责**：
- 将目标列表分发到 Redis 队列
- 监控 Worker 心跳与状态
- 汇总各 Worker 上报的结果
- 生成最终汇总报告

### Worker 节点配置

```bash
# 1. 启动 Worker（可启动多个）
ruoyi-scan --distributed worker \
  --redis-url redis://localhost:6379/0

# 2. 限制 Worker 最大任务数（执行完毕自动退出）
ruoyi-scan --distributed worker \
  --redis-url redis://localhost:6379/0 \
  --worker-max-tasks 100

# 3. Worker 也配置并发与限速
ruoyi-scan --distributed worker \
  --redis-url redis://localhost:6379/0 \
  --threads 10 --rate 20

# 4. 多机部署：在多台服务器上分别启动 Worker
# 服务器 A
ruoyi-scan --distributed worker --redis-url redis://redis-host:6379/0
# 服务器 B
ruoyi-scan --distributed worker --redis-url redis://redis-host:6379/0
```

**Worker 职责**：
- 从 Redis 队列领取目标
- 执行扫描任务
- 上报扫描结果到 Redis
- 定期发送心跳保活

### 全局限速

`--distributed-rate` 控制**所有 Worker 总和**的请求速率，避免对目标网络造成过大压力：

```bash
# 假设有 10 个 Worker，希望总计 1000 QPS
# Master 配置全局限速
ruoyi-scan --distributed master \
  --redis-url redis://localhost:6379/0 \
  -f targets.txt -p \
  --distributed-rate 1000

# 每个 Worker 无需单独配置 rate，由 Master 统一调度
ruoyi-scan --distributed worker \
  --redis-url redis://localhost:6379/0
```

限速算法：基于 Redis 的分布式令牌桶，确保跨 Worker 的精确限速。

### Standalone 降级模式

当 Redis 不可用时，自动降级为单机模式：

```bash
# 显式指定 standalone（默认）
ruoyi-scan --distributed standalone -f targets.txt -p

# Redis 连接失败时自动降级为 standalone
ruoyi-scan --distributed master --redis-url redis://unavailable:6379/0
# 日志输出：Redis 连接失败，降级为 standalone 模式
```

### 典型部署架构

```
                    ┌─────────────┐
                    │   Master    │
                    │  (调度节点)  │
                    └──────┬──────┘
                           │
                    ┌──────┴──────┐
                    │   Redis     │
                    │  (任务队列)  │
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          │                │                │
   ┌──────┴──────┐  ┌──────┴──────┐  ┌──────┴──────┐
   │   Worker 1  │  │   Worker 2  │  │   Worker N  │
   │ (执行节点)   │  │ (执行节点)   │  │ (执行节点)   │
   └─────────────┘  └─────────────┘  └─────────────┘
```

---

## CI/CD 集成

Ruoyi-Scan 提供原生 CI/CD 集成能力，支持根据漏洞严重度自动决定流水线成败，并一键生成主流 CI 平台的配置文件。

### --ci 模式 + 严重度阈值

`--ci` 模式下，扫描器根据漏洞严重度与阈值决定退出码，便于 CI 流水线判断：

```bash
# 1. CI 模式（默认阈值 high，发现高危及以上漏洞则失败）
ruoyi-scan -p http://target:8080/ --ci

# 2. 自定义阈值
ruoyi-scan -p http://target:8080/ --ci --severity-threshold high      # 高危及以上失败
ruoyi-scan -p http://target:8080/ --ci --severity-threshold medium    # 中危及以上失败
ruoyi-scan -p http://target:8080/ --ci --severity-threshold low       # 低危及以上失败

# 3. CI 模式 + SARIF 报告（GitHub/GitLab 原生展示）
ruoyi-scan -p http://target:8080/ --ci --report ./reports --report-format sarif

# 4. CI 模式 + quick 模板（快速扫描，适合每次提交触发）
ruoyi-scan -p http://target:8080/ --ci --template quick --report-format sarif
```

**退出码规则**：

| 退出码 | 含义 | CI 行为 |
|--------|------|---------|
| 0 | 未发现超阈值的漏洞 | 流水线通过 |
| 1 | 发现超阈值的漏洞 | 流水线失败 |
| 2 | 扫描过程发生错误 | 流水线失败（需人工排查） |
| 3 | 配置错误（参数无效） | 流水线失败（需修复配置） |

**严重度等级**（从高到低）：

```
Critical > High > Medium > Low > Info
```

`--severity-threshold high` 表示：发现 High 或 Critical 级别漏洞时退出码为 1。

### --ci-init 生成 CI 配置

一键生成主流 CI 平台的配置文件：

```bash
# 1. 生成 GitHub Actions 配置
ruoyi-scan --ci-init github
# 生成 .github/workflows/ruoyi-scan.yml

# 2. 生成 GitLab CI 配置
ruoyi-scan --ci-init gitlab
# 生成 .gitlab-ci.yml

# 3. 生成 Jenkins Pipeline 配置
ruoyi-scan --ci-init jenkins
# 生成 Jenkinsfile
```

### 示例 GitHub Actions Workflow

以下是 `--ci-init github` 生成的典型 workflow，也可手动创建：

```yaml
# .github/workflows/ruoyi-scan.yml
name: Ruoyi-Scan Security Check

on:
  push:
    branches: [ main, develop ]
  pull_request:
    branches: [ main ]
  schedule:
    # 每天凌晨 2 点定时扫描
    - cron: '0 18 * * *'  # UTC 时间，对应北京时间 02:00

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Setup Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install Ruoyi-Scan
        run: |
          pip install ruoyi-scan
          pip install "ruoyi-scan[report]"  # PDF/Word/Excel 报告

      - name: Run Security Scan
        env:
          TARGET_URL: ${{ secrets.TARGET_URL }}
        run: |
          ruoyi-scan -p "$TARGET_URL" \
            --ci \
            --severity-threshold high \
            --template quick \
            --report ./reports \
            --report-format sarif,json

      - name: Upload SARIF Report
        if: always()
        uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: ./reports/report.sarif

      - name: Upload Artifacts
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: security-reports
          path: ./reports/
          retention-days: 30
```

### 示例 GitLab CI 配置

```yaml
# .gitlab-ci.yml
stages:
  - security

ruoyi-scan:
  stage: security
  image: python:3.11
  script:
    - pip install ruoyi-scan
    - ruoyi-scan -p "$TARGET_URL" --ci --severity-threshold high --template quick
  artifacts:
    when: always
    paths:
      - ./reports/
    expire_in: 30 days
  only:
    - main
    - schedules
```

### 示例 Jenkins Pipeline

```groovy
// Jenkinsfile
pipeline {
    agent any
    stages {
        stage('Security Scan') {
            steps {
                sh 'pip install ruoyi-scan'
                sh '''
                    ruoyi-scan -p ${TARGET_URL} \
                      --ci \
                      --severity-threshold high \
                      --template quick \
                      --report ./reports \
                      --report-format all
                '''
            }
            post {
                always {
                    archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
                }
            }
        }
    }
}
```

---

## 缓存与性能优化

Ruoyi-Scan 提供多层性能优化机制，包括 SQLite 结果缓存、并发线程池、令牌桶限速与异步引擎，可针对不同规模目标灵活调优。

### --cache SQLite 缓存

扫描结果缓存到 SQLite 数据库，避免对相同目标重复扫描，大幅提升批量扫描与增量扫描效率。

**启用前提**：无需额外依赖，SQLite 为 Python 内置模块。

```bash
# 1. 启用缓存（默认 TTL 3600 秒 = 1 小时）
ruoyi-scan -p http://target:8080/ --cache

# 2. 自定义 TTL（如 24 小时）
ruoyi-scan -p http://target:8080/ --cache --cache-ttl 86400

# 3. 自定义缓存数据库路径
ruoyi-scan -p http://target:8080/ --cache --cache-db ./cache/scan_cache.db

# 4. 查看缓存统计（命中率、条目数、占用空间）
ruoyi-scan --cache-stats --cache-db ./cache/scan_cache.db

# 5. 清除过期缓存
ruoyi-scan --cache-clear --cache-db ./cache/scan_cache.db

# 6. 清除全部缓存
ruoyi-scan --cache-clear-all --cache-db ./cache/scan_cache.db

# 7. 批量扫描 + 缓存（强烈推荐）
ruoyi-scan -f targets.txt -p --cache --cache-ttl 86400
```

**缓存机制说明**：

| 维度 | 说明 |
|------|------|
| 缓存键 | 目标 URL + POC 名称 + 请求参数的 SHA256 哈希 |
| 存储内容 | POC 执行结果（三态判定）、请求/响应证据、时间戳 |
| TTL | 默认 3600 秒，可通过 `--cache-ttl` 自定义 |
| 持久化 | SQLite 数据库，跨进程共享，重启不丢失 |
| 失效策略 | TTL 过期自动失效；目标变更需手动清除 |

**缓存统计输出示例**：

```
缓存统计：
  数据库路径: ./cache/scan_cache.db
  总条目数:   1,234
  有效条目:   1,100
  过期条目:   134
  命中率:     87.5%
  占用空间:   2.3 MB
  最旧条目:   2026-07-15 10:30:00
  最新条目:   2026-07-21 14:20:00
```

### --threads 并发

通过 ThreadPoolExecutor 实现多线程并发扫描，显著提升扫描速度：

```bash
# 1. 默认并发（5 线程）
ruoyi-scan -p http://target:8080/

# 2. 提高并发（10 线程，推荐生产环境）
ruoyi-scan -p http://target:8080/ --threads 10

# 3. 高并发（20 线程，注意目标承受能力）
ruoyi-scan -p http://target:8080/ --threads 20

# 4. 批量扫描高并发
ruoyi-scan -f targets.txt -p --threads 20

# 5. 调试模式（单线程，便于排查）
ruoyi-scan -p http://target:8080/ --threads 1 --debug
```

**并发调优建议**：

| 目标规模 | 推荐 threads | 说明 |
|---------|-------------|------|
| 单目标 | 5 ~ 10 | 避免对单目标压力过大 |
| 10 ~ 100 目标 | 10 ~ 20 | 平衡速度与稳定性 |
| 100 ~ 1000 目标 | 20 ~ 50 | 配合 `--rate` 限速 |
| 1000+ 目标 | 50 ~ 100 | 建议使用 `--async` 或分布式 |

### --rate 限速

基于令牌桶算法的精确限速，避免对目标造成 DoS：

```bash
# 1. 不限速（默认）
ruoyi-scan -p http://target:8080/ --rate 0

# 2. 限速 20 QPS（推荐生产环境）
ruoyi-scan -p http://target:8080/ --rate 20

# 3. 保守限速（10 QPS，适合敏感目标）
ruoyi-scan -p http://target:8080/ --rate 10

# 4. 并发 + 限速组合
ruoyi-scan -p http://target:8080/ --threads 20 --rate 50

# 5. 批量扫描 + 全局限速
ruoyi-scan -f targets.txt -p --threads 20 --rate 100
```

**令牌桶特性**：
- 锁外 sleep，无并发退化（高并发下性能不衰减）
- 支持突发流量（桶容量 = rate）
- 精确到毫秒级的速率控制

### --async 异步引擎

基于 aiohttp 的异步 HTTP 引擎，适合千级以上目标的批量扫描：

**启用前提**：需要安装 `async` 可选依赖：

```bash
pip install "ruoyi-scan[async]"
# 或
pip install aiohttp
```

```bash
# 1. 启用异步引擎（默认 10 workers）
ruoyi-scan -p http://target:8080/ --async

# 2. 自定义异步并发数
ruoyi-scan -p http://target:8080/ --async --async-workers 50

# 3. 异步引擎 + 批量扫描（千级目标推荐）
ruoyi-scan -f targets.txt -p --async --async-workers 100

# 4. 异步引擎 + 限速
ruoyi-scan -f targets.txt -p --async --async-workers 100 --rate 500

# 5. 异步引擎 + 缓存（万级目标最优组合）
ruoyi-scan -f targets.txt -p \
  --async --async-workers 100 \
  --rate 1000 \
  --cache --cache-ttl 86400
```

**同步 vs 异步性能对比**：

| 场景 | 同步（ThreadPoolExecutor） | 异步（aiohttp） | 推荐 |
|------|---------------------------|----------------|------|
| 单目标 | 优秀 | 一般 | 同步 |
| 10 ~ 100 目标 | 优秀 | 优秀 | 均可 |
| 100 ~ 1000 目标 | 良好 | 优秀 | 异步 |
| 1000+ 目标 | 一般（线程开销大） | 优秀 | 异步或分布式 |

### 性能优化组合推荐

根据目标规模选择最优组合：

```bash
# 1. 单目标快速扫描
ruoyi-scan -p http://target:8080/ --threads 10 --rate 20

# 2. 单目标深度扫描
ruoyi-scan -u http://target:8080/ --template deep --threads 20 --rate 50

# 3. 小批量扫描（<100 目标）
ruoyi-scan -f targets.txt -p --threads 20 --rate 100 --cache

# 4. 中批量扫描（100~1000 目标）
ruoyi-scan -f targets.txt -p --async --async-workers 50 --rate 200 --cache

# 5. 大批量扫描（1000+ 目标，分布式）
# Master 节点
ruoyi-scan --distributed master --redis-url redis://redis:6379/0 \
  -f targets.txt -p --distributed-rate 1000
# Worker 节点（多机部署）
ruoyi-scan --distributed worker --redis-url redis://redis:6379/0 \
  --async --async-workers 50

# 6. CI 流水线（快速 + SARIF）
ruoyi-scan -p http://target:8080/ --ci --template quick \
  --report-format sarif --threads 10 --rate 20
```

---

## 附录

### 相关文档

- [API 使用指南](./API.md) — Web API 端点、WebSocket 事件、错误码详解
- [项目 README](../README.md) — 项目概览与快速开始
- [OpenAPI 3.0 规范](./openapi.json) — 通过 `python scripts/export_openapi.py` 生成

### 常见问题

**Q1：扫描时提示 `ModuleNotFoundError: No module named 'yaml'`**

A：未安装 `yaml` 可选依赖，执行 `pip install "ruoyi-scan[yaml]"` 或 `pip install pyyaml`。

**Q2：生成 PDF 报告失败**

A：未安装 `report` 可选依赖，执行 `pip install "ruoyi-scan[report]"`。

**Q3：分布式模式 Worker 无法连接 Master**

A：检查 Redis 连接 URL 是否正确、Redis 服务是否启动、防火墙是否放行 6379 端口。

**Q4：扫描被目标 WAF 拦截**

A：使用 `--bypass-waf auto` 启用 WAF 绕过，或降低并发与速率：`--threads 5 --rate 10`。

**Q5：CI 模式下扫描超时**

A：使用 `--template quick` 减少扫描范围，或增大 CI 任务超时时间。

### 技术支持

- 仓库：https://github.com/xiabai2004/Ruoyi-Scan
- 问题反馈：https://github.com/xiabai2004/Ruoyi-Scan/issues
- 许可：MIT License © 2026 XIABAI

---

> **安全声明**：本工具仅用于**授权范围内**的安全测试与学习研究。不得用于未授权目标。涉及利用的插件默认仅做存在性验证，不做实际破坏。使用本工具进行的所有操作由使用者自行承担法律责任。
