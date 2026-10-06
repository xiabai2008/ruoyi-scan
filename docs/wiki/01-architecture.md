# 01 · 整体架构

本章回答两个问题：**项目是怎么分层的**、**一次扫描从点击到出报告发生了什么**。

---

## 一、分层结构

项目采用自上而下的单向分层，越靠下的层被越多上层依赖：

```
┌──────────────────────────────────────────────────────────────────────┐
│  接入层   main.py（参数解析）· web/index.html · desktop/（Tauri+React）│
└───────────────────────────┬──────────────────────────────────────────┘
                            │  Namespace / HTTP
┌───────────────────────────▼──────────────────────────────────────────┐
│  控制层   cli/（dispatcher · runner · preflight · 各模式执行器）      │
│           api/（FastAPI 应用工厂 · 路由 · WebSocket · 鉴权）          │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  ScanRequest
┌───────────────────────────▼──────────────────────────────────────────┐
│  编排层   core/orchestrator.py —— ScanOrchestrator（CLI/API 共用）     │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  插件类列表 + SessionManager
┌───────────────────────────▼──────────────────────────────────────────┐
│  引擎层   core/engine.py（并发 + 令牌桶）                             │
│           core/chain.py（利用链 DAG 引擎）                            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  verify(target, session)
┌───────────────────────────▼──────────────────────────────────────────┐
│  插件层   plugins/base.py（PluginBase 契约）                          │
│           ruoyi/ · spring/ · common/ · jeecgboot/ · chain/            │
└───────────────────────────┬──────────────────────────────────────────┘
                            │  基础能力调用
┌───────────────────────────▼──────────────────────────────────────────┐
│  能力层   core/session.py（网络）· core/fingerprint.py（识别）         │
│           lib/*（40 个独立工具模块）                                  │
└───────────────────────────┬──────────────────────────────────────────┘
                            │
┌───────────────────────────▼──────────────────────────────────────────┐
│  基础层   common/models.py（ScanResult 三态）· common/logger.py        │
│           config/settings.py · data/（字典与 CVE 映射）                │
└──────────────────────────────────────────────────────────────────────┘
```

### 各层职责与约束

| 层 | 目录 | 职责 | 关键约束 |
|----|------|------|----------|
| 接入层 | `main.py`、`web/`、`desktop/` | 参数解析、UI 呈现 | `main.py` **只做参数解析 + 分发**，业务编排全部下沉（P0 重构） |
| 控制层 | `cli/`、`api/` | 把用户输入翻译成 `ScanRequest`，消费事件与结果 | 不直接调用插件；事件输出与业务编排解耦 |
| 编排层 | `core/orchestrator.py` | 串起「预检 → 识别 → 加载 → 执行 → 报告」 | CLI 与 API **共用同一实现**，避免双份逻辑漂移 |
| 引擎层 | `core/engine.py`、`core/chain.py` | 并发调度、限速、结果收集、链式拓扑执行 | 引擎不关心插件语义，只负责「跑起来 + 兜异常」 |
| 插件层 | `plugins/` | 单漏洞判定逻辑 | 每个插件必须返回三态；异常由引擎兜为 `UNKNOWN` |
| 能力层 | `core/session.py`、`core/fingerprint.py`、`lib/*` | 可复用的横切能力 | `lib/` 模块之间尽量互不依赖，通过编排层组合 |
| 基础层 | `common/`、`config/`、`data/` | 数据模型、日志、配置、字典 | `common/` + `core/` 启用 mypy `--strict`（见 [08](08-dependencies.md)） |

---

## 二、端到端数据流

### 2.1 核心数据对象

| 对象 | 定义位置 | 作用 |
|------|----------|------|
| `ScanResult` | [common/models.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/models.py) | **全局结果契约**。含 `kind/name/severity/status/url/evidence/extra/fix/fix_detail/reproduce/cve/cvss_score/cvss_vector/compliance` |
| `FingerprintResult` | 同上 | 指纹识别结果：`cms/version/confidence/matched/variant` |
| `ComponentVersionResult` | 同上 | 组件版本检测结果（`lib/component_detect.py` 产出） |
| `ScanRequest` | [core/orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py) | **跨 CLI/API 的输入契约**，封装一次扫描的全部参数 |
| `ScanTask` | 同上 | 任务句柄：状态、结果、计时、报告路径，供 `TaskRegistry` 管理 |

> 设计要点：`ScanRequest` 与 `ScanResult` 分别是系统的**输入契约**与**输出契约**。CLI 与 API 都只构造 `ScanRequest`，这让「HTTP 提交的扫描」和「命令行扫描」走完全相同的代码路径。

### 2.2 结果对象的三态语义

```python
STATUS_CONFIRMED = "CONFIRMED"  # 确认存在
STATUS_SAFE      = "SAFE"       # 确认不存在
STATUS_UNKNOWN   = "UNKNOWN"    # 无法判定（网络异常等）
```

`ScanResult.kind` 与 `status` 是**联动**的：只有 `CONFIRMED` 才能是 `kind="vuln"`，其余一律 `kind="info"`。这个归一化在 [plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py) 的 `PluginBase.enrich()` 中强制执行，防止 `SAFE` 结果被下游报告当成漏洞渲染。

---

## 三、一次扫描的完整流程

`ScanOrchestrator._run()`（[core/orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py)）是全局主流程，共 9 步：

```
run_sync(req, on_event)                      ← CLI 入口
  └── 构造 ScanTask（uuid12） → _run(task, on_event)

submit(req) → TaskRegistry.register()        ← API 入口
  └── _DaemonThreadPoolExecutor.submit(_run) → 返回 task_id
```

`_run()` 内部步骤（代码中带编号注释，可直接对照）：

| 步骤 | 动作 | 关键实现 |
|------|------|----------|
| 1 | **端口扫描**（可选 `--portscan`） | `core.portscan.PortScanner`，纯 socket，不依赖 nmap |
| 1′ | **主动信息收集**（可选 `--crawl/--subdomain/--js-extract`） | `_run_recon()`：爬虫 + 子域名 + JS 端点提取，使用**独立临时 session** 避免污染主 session |
| 2 | **创建会话与引擎** | `SessionManager(proxy, debug, timeout)` + `ScanEngine(threads, rate)`；注入 `req.auth` 认证信息 |
| 3 | **口令字典分级** | `settings.PASSWORD_DICT` 按 `pass_level` 切换 top100 / top1000 / full |
| 4 | **指纹识别** | 人工 `--cms` 走 `Router.resolve_by_name()`；否则 `detect_cms()` 自动识别（含若依变体与版本） |
| 5 | **WAF 探测 + 组件检测**（可选） | `detect_waf()` → `_build_waf_bypass()` 构造绕过协调器；`--components` 走 `ComponentDetector` |
| 6 | **插件加载与路由** | 路由结果 + `plugins.common`（始终参与）+ 外部路径 + 用户安装目录 + entry_points + nuclei 模板；再按 `--template` 过滤 |
| 6′ | **按 category 分组** | `u=[recon,vuln,brute]`、`m=[recon]`、`p=[vuln]`、`l=[brute]` |
| 7 | **引擎执行** | 逐 category 调 `engine.run(classes, target, session, on_result, waf_bypass_coordinator)` |
| 8 | **报告生成**（可选 `report_dir`） | `ReportBuilder.render_all()` + 版本对照矩阵 `build_version_matrix()` |
| 9 | **完成 / 异常** | 成功发 `complete` 事件；异常发 `error` + `status=failed`，**已收集的结果仍返回** |

### 3.1 引擎内部单插件执行序列

`ScanEngine._exec()`（[core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py)）对每个插件类做 5 件事：

```
1. _rate_limit()            ← 令牌桶限速（sleep 在锁外，避免并发退化）
2. inst = cls()
3. result = inst.verify(target, session)
4. WAF 绕过                 ← 仅当：协调器存在 + 插件 supports_waf_bypass + 原状态非 CONFIRMED
5. inst.enrich(result)      ← 元信息回填（cve/cvss/compliance/fix_detail/reproduce）
   except Exception → ScanResult(kind="error", status=UNKNOWN)   ← 绝不判 SAFE
```

> **共享会话的认证状态泄漏**：引擎所有插件复用同一个 `SessionManager`，而某些插件（如 `job_invoke_target`）会在其上登录。代码中明确注释：**不能用 cookie 快照/还原做隔离**（Shiro 认证状态存在服务端 session，按 `JSESSIONID` 索引，还原 cookie 无效）——需鉴权的插件必须**自建独立会话**。

### 3.2 事件机制（on_event）

编排层的 `_emit(event_type, payload)` 有**两个消费方**：

| 消费方 | 通道 | 用途 |
|--------|------|------|
| CLI | `on_event` 回调 | `cli/runner.py:_cli_event_handler()` 把事件渲染成彩色终端输出 |
| API | `registry.notify()` | 推送到 WebSocket 订阅队列，并落 SQLite 历史 |

事件类型（[api/ws/events.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/api/ws/events.py)）：`status`、`complete`、`fingerprint`、`waf`、`portscan`、`category_start`、`result`、`progress`、`report`、`error`。
编排层额外发出：`recon`、`recon_start`、`recon_error`、`auth`、`template`、`component`、`waf_bypass`、`plugin_fallback`、`plugins_loaded`、`nuclei_error`。

> **注意**：`submit()` 调用 `_run(task, None)` 时 `on_event` 传 `None`。原因是事件推送已统一走 `_emit` 内的 `registry.notify`，若再传回调会导致每个事件被推送两次（代码中有明确注释）。

---

## 四、核心设计纪律

这些约束贯穿全代码库，是本项目与通用扫描器的主要区别，改动代码时不应破坏。

### 4.1 三态判定纪律

- 网络异常、执行异常、无法取证 → 一律 `UNKNOWN`；
- **绝不把无法判定降级为 SAFE**（`ScanEngine._exec` 的 `except` 分支、`SessionManager` 的熔断异常都遵守）；
- 报告与 UI 中 SAFE / UNKNOWN 与 CONFIRMED **分开展示**，不做「结果全红」；
- WAF 绕过异常也不降级为 SAFE，只把错误写进 `result.extra["waf_bypass_error"]`。

### 4.2 保守过滤：识别不出就不筛

`Router.resolve()` 的策略是**信息不足时跑全部 POC**：

```python
# 版本未识别（空串）→ 不过滤
if not version: return plugins
# 变体未识别 → 不过滤（插件 variant='' 表示全变体适用）
```

理由：漏报的代价高于多跑几个 POC 的代价。

### 4.3 目标无响应熔断

`SessionManager` 维护**按 host 分键**的连续超时熔断（`_HostBreaker`，模块级共享）：

| 机制 | 说明 |
|------|------|
| 阈值 | `settings.TIMEOUT_BREAKER_THRESHOLD = 5` |
| 触发后 | 抛出 `TargetUnresponsiveError`（继承 `ConnectionError`），后续请求**立即失败** |
| 为何继承 `ConnectionError` | 插件既有的 `except Exception` 语义不变，结果仍按三态降级为 `UNKNOWN` |
| 为何按 host 分键 | 批量扫描时某个死目标不应短路其余目标 |
| 为何模块级而非实例级 | 一次扫描会创建多个 `SessionManager`（侦察/漏洞/爆破/认证链），实例级计数会让每个新实例重新积累阈值 |
| 超时识别 | `is_timeout_error()` 沿 `reason/__cause__/__context__` 链判定——启用 Retry 后超时会被包装成 `MaxRetryError → ConnectionError`，只看最外层类型熔断永不触发 |
| 计数复位规则 | 仅在**确实收到响应**时复位；超时与其他错误交替的目标不会让计数反复归零 |

熔断异常消息**刻意不含请求 URL**（否则每条路径异常文本不同，下游按原因去重失效、报告 evidence 被撑爆）。

### 4.4 TLS 校验默认关闭

`settings.VERIFY_TLS = False`（可用 `--verify-tls` 打开）。理由：内网若依部署普遍用自签名证书，开启校验会让每个请求抛 `SSLError`，插件按三态纪律全部降级为 `UNKNOWN`——工具对这类目标完全失效且没有提示。关闭时同步 `urllib3.disable_warnings(InsecureRequestWarning)` 避免刷屏。

### 4.5 结果去重聚合

`core/dedup.py` 用 `sha1(endpoint | vuln_type | payload_class)` 构造指纹，把「同一漏洞被多个插件/多条 payload 命中」合并为一条：

- endpoint 归一化：去参数、去尾部括号；
- 合并策略：证据拼接、`extra` 合并、URL 主记录取代表；
- 输出 `DedupReport`（`original_count` / `aggregated_count` / `merged_groups`），CLI 会打印去重统计；
- `--no-dedup` 可关闭。

### 4.6 版本感知与变体感知过滤

三层收窄，逐层兜底：

```
Router.candidates(fp)   → 按 cms + variant 收窄（插件 variant='' 表示通用）
Router.resolve(fp)      → 再按 affected_versions 版本范围收窄
build_version_matrix()  → 用「未过滤候选集」生成对照表，展示哪些插件因版本被跳过
```

若依变体在 `core/fingerprint_features.py` 中以数据驱动方式定义：`ruoyi-vue3`、`ruoyi-app`、`ruoyi-plus`、`ruoyi-cloud-plus`、`ruoyi-magic`，全部共享 `plugins.ruoyi` 插件包（`Router.mapping`）。

### 4.7 CLI / API 共用编排

`ScanOrchestrator` 的架构红线（源码注释原文）：

> `core/engine.py` 零修改（通过 `on_result` 回调）、`core/router.py` 零修改、`core/models.py` 零修改

即：新增能力应通过**回调与组合**接入，而不是修改引擎核心。这是 CLI 与 API 行为一致、且新增 D 系列特性不互相打架的原因。

### 4.8 daemon 线程池

`_DaemonThreadPoolExecutor` 重写 `_adjust_thread_count()`，**不把线程注册到 `concurrent.futures.thread._threads_queues`**。原因：标准 `ThreadPoolExecutor` 的 `_python_exit` atexit 处理器会 join 所有注册线程（即使 daemon），导致 API 测试中后台扫描线程阻止 pytest 退出（CI 挂起根因）。

---

## 五、命令与代码路径对照

| 用户命令 | 代码路径 |
|----------|----------|
| `-p <url>` | `main.main` → `cli.dispatcher.dispatch` → `preflight_target` → `cli.runner.run_mode('p')` → `ScanOrchestrator.run_sync` |
| `-u <url>` | 同上，`mode='u'`，category 顺序 `recon → vuln → brute` |
| `-f targets.txt -p` | `cli.runner.run_mode_batch` → 逐目标 `preflight` + `run_mode` → `BatchReport` |
| `-f targets.txt -p --async` | `cli.runner._run_batch_async` → `lib.async_engine.scan_batch_targets` |
| `--serve` | `cli.serve_runner.run_serve_mode` → `api.app.create_app` → `uvicorn.run` |
| `--chain <name>` | `cli.chain_runner.run_chain_mode` → `core.chain.ChainEngine.run` |
| `--passive` | `cli.passive_runner.run_passive_mode` → `core.proxy_server` |
| `--plugin-*` / `--wiki` / `--ci-init` / `--diff-only` / `--template-list` | `cli.plugin_runner` / `cli.tool_runner`（纯工具模式，不扫描） |
| `--ai` / `--ai-validate` / `--cve-sync` / `--oast-server` / `--web-ui` / `--cache-*` | `lib/*` 对应的 `run_*_mode()` |

---

## 六、架构上的取舍记录

| 取舍 | 选择 | 代价/理由 |
|------|------|-----------|
| 插件并发 vs 结果顺序 | `threads<=1` 时串行保证顺序稳定；`>1` 用 `as_completed`（无序） | 顺序在报告可读性上有价值，默认 `THREADS=1` |
| 限速实现 | 时间戳滑动窗口令牌桶 | 简单、无外部依赖；sleep 必须在锁外 |
| 配置求值时机 | `settings` 模块导入时求值 | 简单直接；代价是运行时改动需显式赋值（如 `settings.PASSWORD_DICT` 在扫描后手动恢复） |
| 循环依赖规避 | 函数内**延迟导入**（如 `cli/runner.py` 底部导入子模块） | 保持模块顶层依赖图清晰，代价是可读性略降 |
| 报告无第三方依赖 | HTML/JSON/CSV 用标准库；PDF/DOCX/XLSX 走可选依赖组 | `pip install ruoyi-scan` 保持极轻（仅 requests） |
| 新增框架不改代码 | 指纹特征库 + `Router` 动态 `plugins.<cms>` 推导 | JeecgBoot 是第一个实证（`plugins/jeecgboot/`，指纹/路由/三态/报告零改动接入） |