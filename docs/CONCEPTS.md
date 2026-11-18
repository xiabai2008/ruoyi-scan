# 核心概念地图（接手先读这页）

> 这页只回答"项目里有哪些必须同时掌握的规则"，每条控制在 15 行内，先给结论，再给代码入口。
> 需要背景（为什么这样设计）时，再看对应模块的长注释或 `docs/design/` 下的历史文档。

---

## 1. 三态判定：CONFIRMED / SAFE / UNKNOWN

**规则**：只有拿到肯定证据才 CONFIRMED；能证明"不存在"才 SAFE；其余（网络异常、登录墙、
证据不足、超时、预算耗尽）一律 UNKNOWN。**UNKNOWN 永远不能降级成 SAFE**。

**为什么**：扫描器最大的风险是"没测到"被读者当成"不存在"。三态是报告可信度的根。

**代码**：[common/models.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/models.py#L7-L10)（状态常量）、
[plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py) 的 `PluginBase.enrich()`（强制 kind/status 联动）。
**测试**：`tests/test_orchestrator.py`、`tests/test_plugin_unknown_contract.py`。

---

## 2. UNKNOWN 原因码（unknown_reason）

**规则**：写 UNKNOWN 时必须说明原因（`auth_wall` / `denied` / `unreachable` /
`insufficient_evidence` / `budget_exceeded` …）。原因由产生点写入，报告只展示。

**为什么**：v1.6 复盘发现"按证据文本猜原因"会把正确的登录墙降级误判成误降级。

**代码**：[common/models.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/common/models.py) 的 `UnknownReason` 与展示标签；
收口点在 [core/orchestrator.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/orchestrator.py) 的 `fill_unknown_reasons()`。
**测试**：`tests/test_unknown_reason.py`、`tests/test_unknown_reason_coverage.py`。

---

## 3. 插件契约（PluginBase）

**规则**：每个漏洞一个插件，继承 `PluginBase`，实现 `verify(target, session) -> ScanResult`；
元信息（name/severity/fix/fix_detail/reproduce/cve/cvss/compliance）由 `enrich()` 回填。

**必填**：`name`、`severity`、`category`（阶段：vuln/recon/brute）、`verify`。
**建议**：`affected_versions`、`variant`、`vuln_type`、`compliance`。

**代码**：[plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py)。**测试**：`tests/test_plugin_contracts.py`。

---

## 4. 插件发现：五条路径

1. `plugins/<framework>/__init__.py` 的 `plugin_list`（内置，唯一权威清单）；
2. `--plugin-path` 外部目录/单文件；
3. `~/.ruoyi-scan/plugins/` 用户安装目录；
4. Python entry_points（第三方 `pip install`）；
5. `--nuclei` YAML 模板（运行时转成插件类）。

**代码**：[core/loader.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/loader.py)、[core/router.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/router.py)。
**注意**：新增框架要同时登记包目录、`plugin_list`、acceptance 基线；
门禁见 `scripts/check_framework_registration.py`。

---

## 5. 插件能力声明（四个正交开关）

| 声明 | 含义 | 引擎动作 |
|---|---|---|
| `requires_auth=True` | 必须登录才能测 | 无高权会话时，CONFIRMED/SAFE 降级为 UNKNOWN |
| `anonymous_probe=True` | 必须**不登录**才能测 | 插件自己用 `session.anonymous()`；与上者互斥 |
| `path_scope="api"/"root"/"both"` | 探测基准是否跟随 API 前缀 | 引擎拼接/双探 |
| `consumes_surface=True` | 依赖攻击面清单 | 清单为空时强制 UNKNOWN |

**代码**：[plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py#L152-L214)、[core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py)。
**测试**：`tests/test_anon_session_plugins.py`、`tests/test_path_scope.py`。

---

## 6. 认证的三层含义（别再混用 auth）

| 层 | 模块 | 做什么 |
|---|---|---|
| 登录链 | [core/login_chain.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/login_chain.py) | 探测 v4 Session / v5 JWT，处理验证码，建立高权会话 |
| 凭据注入 | [lib/auth_inject.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/auth_inject.py) | `--auth` / `--auth-file` / `--auth-login` 解析后写入 session |
| 登录后盘点 | [lib/auth_surface.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/auth_surface.py) | 高权会话盘点资产 + 匿名/低权重放，输出越权矩阵 |

"未授权访问"插件（`*_unauth`）与上面三者都不同：它们测的是**匿名可达性**。

---

## 7. 框架 / 变体 / 版本（三层收窄）

- **框架（framework）**：`ruoyi` / `spring` / `common` / `jeecgboot` / `yudao`，对应插件包目录。
- **变体（variant）**：`ruoyi-vue3` / `ruoyi-plus` / `ruoyi-cloud-plus` 等，同一插件包内的细分。
- **版本（version）**：插件用 `affected_versions=">=4.2,<4.7"` 声明影响范围。

**规则**：版本未识别（空串）→ 不过滤（宁可多跑）；变体未识别 → 不过滤。
**代码**：[core/fingerprint.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/fingerprint.py)、[core/router.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/router.py)、
[core/ruoyi_versions.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/ruoyi_versions.py)。

---

## 8. 路径作用域（path_scope / self_prefixes / base_path）

前后端分离部署下，Nginx 只把 `/prod-api/` 反代到后端，根路径给 SPA：

- API 端点必须加前缀才探得到 → `path_scope="api"`；
- `.git`/`.env`/备份文件在站点根 → `path_scope="root"`；
- 两种都可能 → `both`（引擎双探，取更严重结果）；
- 插件路径自带前缀 → `self_prefixes`，避免拼成 `/prod-api/prod-api/...`。

**代码**：[core/basepath.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/basepath.py)、[core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py)。
**测试**：`tests/test_basepath.py`、`tests/test_path_scope.py`。

---

## 9. 判定辅助：matcher / reachability / soft404

| 模块 | 职责 |
|---|---|
| [lib/matcher.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/matcher.py) | 正向特征 + 负向排除的共享判据（SQL 报错、文件读取、Actuator、Swagger、Jolokia…） |
| [lib/reachability.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/reachability.py) | 登录墙/鉴权墙/全站拦截的识别与降级 |
| [lib/soft404.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/soft404.py) | catch-all 路由基线（任意路径返回同一页时，不能据此判存在） |

**规则**：新判据优先加进 matcher 并配靶场负样本；不要在插件里重新写一套关键字。

---

## 10. 去重与归属

- **去重**：[core/dedup.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/dedup.py)，按 `sha1(endpoint|vuln_type|payload_class)` 聚合；
  `--no-dedup` 可关。
- **归属**：[lib/attribution.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/attribution.py)，区分"站点级"与"宿主级"（中间件端口探测）。

**测试**：`tests/test_dedup.py`、`tests/test_attribution_and_redis_port.py`。

---

## 11. 限速、预算、熔断

| 机制 | 位置 | 语义 |
|---|---|---|
| `--rate` + `--rate-scope` | [lib/rate_limit.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/rate_limit.py)、[core/session.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/session.py) | 默认逐 HTTP 请求；`plugin` 为旧语义 |
| `--time-budget` | [core/engine.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/engine.py) | 单目标预算；超时插件记 UNKNOWN(budget_exceeded) |
| 目标无响应熔断 | [core/session.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/session.py) | 按 host 连续超时 5 次 → 抛 `TargetUnresponsiveError` |

**规则**：一次扫描的主会话、recon 会话、匿名会话共享同一个令牌桶。

---

## 12. 报告管线

`ScanResult` → `ReportBuilder`（去重、排序、统计、合规映射）→ 各格式渲染器。

- 入口：[core/report.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/report.py) 的 `ReportBuilder.render_all()`；
- 格式：HTML/JSON/CSV 内置，PDF/Word/Excel/SARIF 为独立模块；
- 附加：`--report-template`（客户 docx 模板）、`--siem-export`、`--diff`、`--remediation`；
- 注意：CLI 与 API 的报告生成路径不同（CLI 传 `report_dir=""` 自行生成，API 交给编排层）。

---

## 附：术语对照

| 中文 | 代码里的规范名 | 不要再用 |
|---|---|---|
| 框架 | framework | cms / category |
| 扫描阶段 | category（插件属性） | phase（暂未统一，见 NAMING） |
| 输出桥 | lib.output | reporter |
| 登录链 | login_chain | auth_chain |
| 利用链 | chains.engine + chains/definitions | core.chain |
| 攻击面清单 | surface_inventory | surface |
| 扫描预设 | scan_profiles | scan_templates |
