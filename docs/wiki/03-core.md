# 03 · core 核心引擎

> 这一章回答：一条扫描请求进来之后，`core/` 里的 24 个模块是怎么协作的？每个模块的边界在哪里？
>
> 相关源码：[core/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/core) · [common/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/common) · [config/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/config)

---

## 1. core 层的定位

`core/` 是**与 CLI/API 无关的纯引擎层**：它不 `print`、不读 `argparse`、不碰 `sys.exit`。CLI 与 Web API 都通过同一个 `ScanOrchestrator` 驱动它，差异只体现在事件回调的落点上。

这条边界的价值在 [orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py) 的头部注释里写得很明确：

```
架构约束（红线）：
  - core/engine.py 零修改（通过 on_result 回调）
  - core/router.py 零修改
  - core/models.py 零修改
  - ThreadPoolExecutor 使用 daemon 线程（避免测试/进程退出时后台线程阻塞）
```

「零修改」是**接口稳定性契约**：新增能力必须通过回调、插件、数据文件扩展，不能改这三个文件的签名。

---

## 2. 模块全景（24 个）

按职责分为六组：

### 2.1 编排与执行

| 模块 | 职责 | 关键符号 |
| --- | --- | --- |
| [orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py) | 扫描编排器：CLI 与 API 共用主流程 | `ScanOrchestrator` `ScanRequest` `ScanTask` `_DaemonThreadPoolExecutor` |
| [engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py) | 并发编排 + 令牌桶限速；单插件执行序列 | `ScanEngine` |
| [loader.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/loader.py) | 插件动态发现与加载（内置/外部/entry_points） | `load_plugins` `load_external_plugins` `discover_plugin_packages` `load_entry_point_plugins` |
| [chain.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/chain.py) | 漏洞利用链编排（DAG） | `ChainDef` `ChainStep` `ChainEdge` `ChainContext` `ChainEngine` `ChainResult` |

### 2.2 网络与会话

| 模块 | 职责 | 关键符号 |
| --- | --- | --- |
| [session.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/session.py) | 会话封装：Cookie/代理/重试/连接池/TLS/超时熔断 | `SessionManager` `TargetUnresponsiveError` `_HostBreaker` `is_timeout_error` |
| [http.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/http.py) | URL 归一化与可达性预检 | `normalize_target` `join_url` `host_of` `split_target` `probe_reachable` `probe_http_responsive` |
| [portscan.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/portscan.py) | 端口扫描 + Banner 识别（纯 socket，无 nmap 依赖） | `PortScanner` `PortResult` |
| [proxy_server.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/proxy_server.py) | HTTP/HTTPS 代理（被动扫描模式） | — |
| [captcha_solver.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/captcha_solver.py) | 验证码识别（D3） | — |
| [auth_chain.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/auth_chain.py) | 若依登录链编排（D1） | — |

### 2.3 识别与路由

| 模块 | 职责 | 关键符号 |
| --- | --- | --- |
| [fingerprint.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/fingerprint.py) | 指纹识别接口 + 多 CMS 交叉判定 | `Fingerprint` `FeatureBasedFingerprint` `RuoyiFingerprint` `detect_cms` `detect_waf` `detect_variant` |
| [fingerprint_features.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/fingerprint_features.py) | 指纹特征库（数据驱动） | `CMS_FEATURES` `VARIANT_FEATURES` `get_feature` `list_cms` `list_variants` |
| [waf_features.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/waf_features.py) | WAF 指纹特征库 | `get_waf_names` `is_waf_blocked` |
| [ruoyi_versions.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/ruoyi_versions.py) | 若依版本指纹库与区间判定 | `extract_version` `detect_version` `version_in_range` `build_version_matrix` `get_variant_api_prefixes` |
| [router.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/router.py) | 指纹 → 插件包路由 | `Router.candidates/resolve/resolve_by_name` |
| [cache.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/cache.py) | 指纹识别请求级缓存 | `FingerprintCache` |

### 2.4 结果处理

| 模块 | 职责 | 关键符号 |
| --- | --- | --- |
| [dedup.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/dedup.py) | 结果去重聚合 | `fingerprint` `aggregate` `DedupReport` `AggregatedVuln` |
| [report.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report.py) | 报告渲染（HTML/JSON/CSV，纯标准库） | `ReportBuilder` `BatchReport` |
| [report_pdf.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report_pdf.py) | PDF 报告（reportlab） | — |
| [report_docx.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report_docx.py) | Word 报告（python-docx） | — |
| [report_xlsx.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report_xlsx.py) | Excel 报告（openpyxl） | — |
| [report_sarif.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report_sarif.py) | SARIF 2.1.0 报告（D22） | — |

### 2.5 服务端支撑

| 模块 | 职责 | 关键符号 |
| --- | --- | --- |
| [task_registry.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/task_registry.py) | 任务状态管理 + WebSocket 推送桥 | `TaskRegistry` `TaskRecord` |
| [storage.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/storage.py) | SQLite 持久层：任务历史 + 事件 + 定时任务 | `Storage` `DEFAULT_DB_PATH` |

### 2.6 共享基础与配置

| 路径 | 职责 |
| --- | --- |
| [common/models.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/models.py) | `ScanResult` / `FingerprintResult` / `ComponentVersionResult` + 三态与严重度常量 |
| [common/logger.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/logger.py) | 项目级日志（`get_logger` / `setup_logging` / `set_quiet`） |
| [common/console.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/console.py) | `force_utf8_stdio()` Windows 代码页兜底 |
| [config/settings.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/config/settings.py) | 全局配置：超时/线程/限速/TLS/字典/报告目录/凭据 |

---

## 3. `ScanOrchestrator._run()` 九步主流程

这是整个项目的**主动脉**。方法很长（约 450 行），但结构是线性的九步：

| 步 | 动作 | 产出 | 事件 |
| --- | --- | --- | --- |
| 1 | 端口扫描（`req.portscan` 时） | `PortResult[]` | `portscan` |
| 1b | D14 主动信息收集（爬虫/子域名/JS 提取） | `recon_info` | `recon_start` / `recon` / `recon_error` |
| 2 | 创建 `SessionManager` + `ScanEngine` | — | — |
| 2b | D26 认证注入 `apply_auth_to_session` | — | `auth` |
| 3 | 口令字典分级（`pass_level` → `settings.PASSWORD_DICT`） | — | — |
| 4 | 指纹识别 `detect_cms`（或 `--cms` 手动）→ `Router.resolve` | `FingerprintResult` + 插件类列表 | `fingerprint` |
| 5 | WAF 探测 `detect_waf` + 构建绕过协调器 + E2 组件检测 | `waf_info` / `WafBypassCoordinator` | `waf` / `waf_bypass` / `component` |
| 6 | 插件加载与过滤（5 条来源 + 模板过滤 + category 分组） | `plugins_by_cat` | `plugins_loaded` / `template` / `plugin_fallback` |
| 7 | 引擎执行（按 category 顺序调 `engine.run`） | `all_results` | `category_start` / `result` / `progress` |
| 8 | 报告生成（`req.report_dir` 非空时） | `report_paths` | `report` |
| 9 | 完成收尾 | `task.status = "done"` | `status(done)` / `complete` |

异常兜底：整个 try 块外层捕获后置 `task.status = "failed"`，发 `error` + `status(failed)`，并**返回已收集的 `task.results`**——部分结果不因异常丢失。

### 3.1 步骤 1b 的位置值得注意

信息收集（爬虫/子域名）**排在会话创建之前**，且内部**另建一个临时 session**：

```python
recon_session = SessionManager(proxy=..., debug=..., timeout=...)
...
recon_session.close()
```

理由（代码注释）：避免与主 session 状态污染。爬虫会带上大量非目标 Cookie / 走不同跳转链，混进主 session 会污染后续插件的请求基线。

### 3.2 步骤 4：手动 CMS 与自动识别是同一条出口

```python
if req.cms:
    fp_result = FingerprintResult(cms=req.cms, version="", confidence=1.0, matched=["manual"])
    all_plugins = router.resolve_by_name(req.cms)
else:
    fp_result = detect_cms(target, session)
    all_plugins = router.resolve(fp_result)
```

两条分支都产出「`FingerprintResult` + 插件类列表」，后续流程完全一致。`matched=["manual"]` 是可审计的标记——报告里能看出这次是手动指定还是自动识别。

### 3.3 步骤 5：WAF 绕过的三个分支

```python
if waf_type and bypass_mode in ("auto", "on"):   # 识别到 WAF → 建协调器（含源站 IP 探测）
if not waf_type and bypass_mode == "on":          # 没识别到但用户强制 on → 仍建（对未知 WAF 保留尝试）
return None                                        # 其余（off / auto 且无 WAF）→ 不建
```

`auto` + 未识别 WAF 时返回 `None`，**不产生任何额外请求**——这是"默认零成本"的取舍。

### 3.4 步骤 6：插件来源的叠加顺序

```
Router.resolve(cms)                 # 1. 按指纹路由（可能为空）
  └─ 空 → load_plugins("plugins.ruoyi")   fallback 并记 plugin_fallback 事件
load_plugins("plugins.common")      # 2. 通用检测包（恒加载）
load_external_plugins(plugin_paths) # 3. --plugin-path 外部插件
load_user_installed_plugins()       # 4. ~/.ruoyi-scan/plugins/（--plugin-update 安装）
load_entry_point_plugins()          # 5. pip entry_points
load_nuclei_templates(...)          # 6. nuclei YAML 模板
  ↓
req.plugins 过滤（API 指定子集）
  ↓
template 过滤（filter_plugins）
  ↓
按 category 分组 → plugins_by_cat
```

**叠加而非替换**：后加载的来源只能追加插件，不能覆盖前面的。这样「外部插件意外覆盖内置插件」这类事故从结构上被排除。除第 2 条外，每一条加载路径都包在 `try/except` 里，失败只 `logger.debug` 并继续——**插件生态故障不能拖垮主扫描**。

### 3.5 步骤 7：进度计算的口径

```python
total_plugins = sum(len(plugins_by_cat.get(c, [])) for c in categories)
```

分母只统计**本次模式会跑的 category**（`p` 模式不会把 `brute` 插件算进进度），所以百分比是真实的完成度而非虚高。

### 3.6 步骤 8：版本矩阵用「未过滤」候选集

```python
# 用「未按版本过滤」的候选集——否则 applicable 恒为真，对照表失去意义
version_matrix = build_version_matrix(fp_result.version, router.candidates(fp_result))
```

`router.resolve()` 已经按 `affected_versions` 过滤过插件了；如果直接拿过滤后的结果做矩阵，所有条目都会显示"适用"，矩阵就没信息量了。因此矩阵刻意回到**过滤前的候选集** `candidates()`。这是一个很容易写错、且错了也不会报错的细节。

---

## 4. `ScanEngine`：单插件执行序列

[core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py) 只有 132 行，是并发与限速的唯一实现处。

### 4.1 构造函数

```python
ScanEngine(threads=1, rate=0)
```

- `threads=1` 是默认值——**默认串行**。理由：扫描目标多为生产系统，默认并发可能触发风控或造成压力；要并发得显式 `--threads`。
- `rate=0` 表示不限速。

### 4.2 `_exec()` 的五步序列

```
1. _rate_limit()                       # 令牌桶：时间戳滑动窗口
2. plugin = plugin_cls()               # 实例化（每个插件独立实例，无状态共享）
3. res = plugin.verify(target, session) # 核心判定
4. WAF 绕过重试（若 verify 未确认且有协调器）
     → plugin.verify_with_bypass(...)
5. res.enrich()                        # 幂等回填元数据 + kind 归一化
   except Exception → 兜底为 UNKNOWN（绝不吞成 SAFE）
```

第 5 步的 `except` 是**全项目最重要的错误处理**：任何未预期异常都产出 `UNKNOWN`，而不是让它冒泡或静默成 `SAFE`。三态纪律在引擎层被物理保证。

### 4.3 `_rate_limit()`：sleep 必须在锁外

```python
with self._lock:
    now = time.time()
    self._timestamps = [t for t in self._timestamps if now - t < 1.0]
    if len(self._timestamps) >= self._rate:
        wait = 1.0 - (now - self._timestamps[0])
    else:
        self._timestamps.append(now)
# ↓ sleep 在锁外
if wait > 0:
    time.sleep(wait)
```

若把 `sleep` 放在锁内，多线程会**退化为串行**——每个线程持锁睡觉，等于全局停顿。这是限速器最常见的实现陷阱，此处有注释显式标出。

---

## 5. `SessionManager`：网络层的所有策略集中地

[core/session.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/session.py) 承载 4 类策略，是唯一被允许直接构造 `requests` 请求的地方：

### 5.1 连接池与重试

```python
HTTPAdapter(pool_connections=..., pool_maxsize=..., max_retries=Retry(
    total=2, backoff_factor=0.3, status_forcelist=(502, 503, 504)
))
```

只对 **5xx 网关类错误**重试（502/503/504），不对 4xx 重试——4xx 是确定的业务响应，重试只会浪费预算并可能触发风控。

### 5.2 TLS 策略

读 `settings.VERIFY_TLS`（默认 `False`）。内网自签名证书是若依部署的常态，默认不校验是**面向真实使用场景**的选择，反向需求由 `--verify-tls` 显式打开。

### 5.3 超时熔断：`_HostBreaker`

```python
TIMEOUT_BREAKER_THRESHOLD = 5    # config/settings.py
```

按 host 分键统计连续超时次数，达到阈值后抛 `TargetUnresponsiveError`（继承 `requests.exceptions.ConnectionError`，因此**对既有 `except requests.RequestException` 代码天然兼容**）。

配套工具：

| 符号 | 作用 |
| --- | --- |
| `is_timeout_error(exc)` | 沿 `reason` → `__cause__` → `__context__` 链判定是否超时类异常 |
| `_HOST_BREAKERS` | 模块级字典（跨 session 实例共享熔断状态） |
| `reset_host_breakers()` | 测试隔离用 |

为什么熔断按 host 而不是全局：多目标批量扫描时，一个死目标不应影响其他目标的熔断统计。

### 5.4 `request_count`

`SessionManager` 自己统计请求数，供报告与 API 的 `request_count` 字段使用。指标口径统一在会话层，避免各插件自报。

---

## 6. 指纹识别：数据驱动 + 两级防误判

[core/fingerprint.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/fingerprint.py) 的设计核心是**把知识放进数据文件、把逻辑放进通用引擎**。

### 6.1 加权打分

```
强特征（login_keywords / strong_paths / favicon 命中）→ +weight_strong（默认 0.5）/个
弱特征（weak_keywords / favicon 不匹配）        → +weight_weak（默认 0.2）/个
confidence = min(1.0, 强×w_strong + 弱×w_weak)
```

### 6.2 D5 弱特征阈值：0.4

```python
weak_confidence = weak_hits * w_weak
if strong_hits > 0 or weak_confidence >= 0.4:
    return FingerprintResult(cms=self.cms, ...)
return FingerprintResult(cms="", ...)      # 未识别
```

代码注释写明了边界用例：

> 含"若依"二字的非若依页面（单弱特征）不应误判。

单个弱特征给 0.2，不到 0.4 阈值；需要**至少 2 个弱特征或 1 个强特征**才判为该 CMS。

### 6.3 软 404 排除

`expect="any"` 的强特征路径探测里有一层额外校验：

```python
if body and root_body and body == root_body:
    ok = False      # 与根路径响应体完全相同 → 视为通配 200，不算特征
```

理由（代码注释）：SPA 前端兜底、静态站 catch-all、部分 CDN/WAF 会对任意路径返回与首页完全相同的内容。不排除就会把 wordpress/django/nginx 站点误判为若依变体。

### 6.4 `detect_cms` 的组合逻辑

```
FingerprintCache(session)                        # 多 CMS 遍历共享根/favicon 响应
  ↓
for cms in list_cms():  取 confidence 最高者
  ↓
if best.cms == "ruoyi":
    detect_variant(...)                          # E1 变体细分
    extract_version(...)                         # D2 版本号（优先从 cache 里已抓到的响应提取）
```

**变体与版本探测都优先走 `cache.get()`**：如果根路径或 `/login` 已经被指纹流程请求过，就直接复用响应提取版本，不再多发请求。

### 6.5 变体识别的正负特征

`detect_variant()` 对每个变体：

1. 先查 `negative_paths`——**任一命中（200）即排除该变体**；
2. 再查 `strong_paths`，按 `expect`（`json` / `image` / `any`）判定；
3. 取强特征命中数最多者；全未命中返回 `''`（通用版）。

「先排除再确认」的顺序很关键：正向路径可能被其他变体共享，负向路径才是区分度所在。

---

## 7. `Router`：指纹 → 插件包

[core/router.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/router.py) 只有 83 行，但它是**插件体系的入口闸门**。

```python
mapping = {
    "ruoyi": "plugins.ruoyi",  "ruoyi-cloud": "plugins.ruoyi",
    "ruoyi-vue3": "plugins.ruoyi", "ruoyi-app": "plugins.ruoyi",
    "ruoyi-plus": "plugins.ruoyi", "ruoyi-cloud-plus": "plugins.ruoyi",
    "ruoyi-magic": "plugins.ruoyi",
    "spring": "plugins.spring",
    "jeecgboot": "plugins.jeecgboot",
}
```

三个方法：

| 方法 | 语义 |
| --- | --- |
| `candidates(fp)` | 按 **cms + variant** 拿到候选插件类（**不**按版本过滤） |
| `resolve(fp)` | 在 `candidates` 基础上按 `affected_versions` 过滤版本 |
| `resolve_by_name(cms)` | 手动指定 CMS 时用（无版本信息，不过滤版本） |

**所有 7 个若依变体共享 `plugins.ruoyi`**——版本/变体差异靠插件自身的 `variant` / `affected_versions` 属性表达，而不是拆成 7 个包。这是控制包数量的取舍。

---

## 8. 去重聚合：`dedup.py`

```python
sha1(endpoint | vuln_type | payload_class)   → 指纹
```

同一目标、同一端点、同一漏洞类型、同一 payload 类的结果聚合为一条 `AggregatedVuln`，证据合并（`_merge_evidence`）、`extra` 合并（`_merge_extra`）。

辅助函数 `_normalize_endpoint` / `_strip_parens` 负责把「同一端点的不同写法」（带括号、query 顺序不同）归一化到同一 key，否则去重会漏。

`DedupReport` 提供聚合视图；CLI/API 的 `--no-dedup` 可关闭。

---

## 9. `chain.py`：DAG 利用链

[core/chain.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/chain.py) 是一个**小型工作流引擎**（约 400 行），实现拓扑执行 + 条件分支 + 失败策略。

| 类 | 职责 |
| --- | --- |
| `ChainStep` | 一个步骤：`id` / `plugin_cls` / `depends_on` / `on_fail` / `outputs` / `condition` |
| `ChainEdge` | 步骤间连线（可作为步骤的补充表达） |
| `ChainDef` | 链定义：`name` / `display_name` / `severity` / `affected_versions` / `steps`；`validate()` + `_detect_cycle()` 做环检测 |
| `ChainContext` | 运行时上下文：`set_result` / `extract_outputs` / `snapshot` |
| `ChainResult` | 链结果聚合，`to_scan_result()` 转回标准 `ScanResult` |
| `ChainEngine` | 执行器：`_topological_sort` → `_evaluate_condition` → `_execute_step` → `_is_critical_failed` → `_propagate_abort` → `_aggregate_status` |

三个设计要点：

1. **环检测在 `validate()` 里做**，不在执行时。链定义是静态资产，错误应该在加载期暴露。
2. **`on_fail` 三值语义**：`abort`（整链终止）/ `continue`（跳过依赖此步的支线）/ —— 由 `_propagate_abort()` 统一传播。
3. **`outputs` 用前缀区分敏感度**：`secret:` 前缀 → 凭证类，脱敏存储；`extra:` → 附加事实，明文保留。前缀约定见 [chains/ruoyi_sql_to_rce.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/chains/ruoyi_sql_to_rce.py)。

细节见 [04 章 · 插件与利用链](04-plugins-chains.md)。

---

## 10. 报告层

### 10.1 `ReportBuilder`（[core/report.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report.py)）

| 方法 | 作用 |
| --- | --- |
| `_effective_results` | 按 `dedup` 开关决定用原始结果还是去重后的结果 |
| `risk_distribution` | 风险分布统计 |
| `confirmed_results` | 仅 CONFIRMED 结果 |
| `compliance_summary` / `render_compliance_html` | 合规映射汇总（等保/CWE→OWASP） |
| `sorted_results` | 排序（严重度优先） |
| `to_dict` / `to_json` / `to_csv` | 序列化 |
| `_render_risk_donut_svg` | 内联 SVG 环形图（**不引前端图表库**） |
| `to_html` | HTML 报告 |
| `render_all` | 一次性渲染全部格式，返回路径列表 |

`BatchReport` 是批量扫描版本，对应 `_render_targets_bar_svg`（目标维度柱状图）。

**HTML 报告用内联 SVG 画图**：零第三方依赖、离线可看、单文件可发。这是「安服交付物要能直接微信发出去」这一真实需求的产物。

### 10.2 可选格式走独立模块

`report_pdf.py` / `report_docx.py` / `report_xlsx.py` / `report_sarif.py` 各自独立，依赖 reportlab / python-docx / openpyxl。它们在 `pyproject.toml` 里属于 `[report]` 可选组——**不装这些包，HTML/JSON/CSV 依旧可用**。

---

## 11. 服务端支撑两个模块

### 11.1 `TaskRegistry`（[core/task_registry.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/task_registry.py)）

内存中的任务表 + WebSocket 推送桥。

| 方法 | 作用 |
| --- | --- |
| `bind_loop` / `unbind_loop` | 绑定/解绑 asyncio loop（**跨线程推送的前提**） |
| `register` / `update_task_dict` / `get` / `list` | 任务状态读写 |
| `notify` / `unsubscribe` | 向订阅者推送事件 |
| `get_history` | 事件历史（WS 重连补播用） |
| `cleanup_expired` / `task_count` | 清理与统计 |
| `restore_from_storage` | 启动时从 SQLite 恢复 |

`bind_loop` 的存在说明了架构约束：扫描线程是普通线程，而 WS 推送必须在 asyncio loop 上执行，因此需要 `loop.call_soon_threadsafe` 这类桥接。绑定时机在 FastAPI 的 `lifespan` startup。

### 11.2 `Storage`（[core/storage.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/storage.py)）

SQLite 持久层，三张逻辑表（任务 / 事件 / 定时任务）：

`save_task` `get_task` `list_tasks` `delete_task` `cleanup_expired` `count_tasks` · `save_event` `get_events` · `save_schedule` `list_schedules` `get_schedule` `delete_schedule`

默认路径 `data/tasks.db`（`DEFAULT_DB_PATH`），可由 `--db-path` 覆盖。

---

## 12. `_DaemonThreadPoolExecutor`：一个 CI 挂起 bug 的沉淀

这是 `core/` 里最"有故事"的 20 行代码：

```python
class _DaemonThreadPoolExecutor(ThreadPoolExecutor):
    def _adjust_thread_count(self) -> None:
        # ... 创建 daemon=True 线程并启动
        self._threads.add(t)
        # 不注册到 _threads_queues，避免 _python_exit atexit handler join daemon 线程
```

**问题**：标准 `ThreadPoolExecutor` 会把线程注册进 `concurrent.futures.thread._threads_queues`，而 `_python_exit` atexit 处理器会 join 其中所有线程——**即使是 daemon 线程**。在 API 测试里，后台扫描线程会让 pytest 无法退出，表现为 CI 挂起。

**解法**：子类重写 `_adjust_thread_count`，跳过注册这一步。daemon 标志随之生效，进程退出时线程被直接终止。

代价是放弃了标准库的优雅关闭保证，因此 `shutdown()` 里补上了显式策略：

```python
pool.shutdown(wait=False, cancel_futures=True)
for t in list(pool._threads):
    t.join(timeout=5)      # 给 5s 让运行中的任务收尾，超时则放弃
```

---

## 13. mypy 严格度分层

`pyproject.toml` 对 `core/` 与 `common/` 开了 `--strict`，而 `lib/` / `api/` 是 `ignore_errors`：

```toml
[[tool.mypy.overrides]]
module = ["common.*", "core.*"]
strict = true

[[tool.mypy.overrides]]
module = ["lib.*", "api.*"]
ignore_errors = true
```

这是**渐进式类型化**的取舍：`core/` 是接口契约所在（`ScanResult`、`PluginBase`、`ChainDef` 的字段签名一改就满地开花），值得付出 strict 成本；`lib/` 是工具集与外部集成密集区（动态 JSON、LLM 响应、第三方 SDK），strict 的收益低于摩擦。

---

## 14. 本章小结

- `core/` 是无 CLI/API 依赖的引擎层，三个文件的签名被当作**红线契约**保护。
- `ScanOrchestrator._run()` 九步是主动脉；所有能力（信息收集、组件检测、WAF 绕过、模板、外部插件）都是**在固定位置插入的可选段**，主流程顺序不变。
- 三态纪律在引擎层由 `except → UNKNOWN` 物理保证，不依赖各插件的自觉。
- 网络策略全部收在 `SessionManager`，包括限速器（锁外 sleep）、超时熔断（按 host）、TLS（默认不校验）。
- 指纹与路由是**数据驱动**的：新增 CMS 改数据文件，`fingerprint.py` / `router.py` 不改。

→ 下一章：[04 · 插件体系与利用链](04-plugins-chains.md)