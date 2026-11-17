# 时序盲注人工验收脚本

> 本目录下 3 个 `acceptance_*.py` 是 **版本发布前的人工验收卡点**，不是 pytest 用例，
> 也不接入 CI / nightly / pre-commit。任何自动化流水线都不得调用它们。

## 1. 三套脚本的作用与判定规则

| 脚本 | 靶场 | 目的 | 通过规则 | 失败含义 |
|---|---|---|---|---|
| `scripts/acceptance_vuln_positive.py` | `lab/server.py` vuln 模式 + 临时时序垫片（仅 `if(1=1,sleep(3),0)` 延迟 3s） | 漏洞正样本 | 至少 1 条 `CONFIRMED`，且必须是「时间盲注（dept）」 | 漏报，时序盲注检测失效 |
| `scripts/acceptance_vuln_negative.py` | `lab/server.py` safe 模式（同版本已修复的干净若依靶场） | 干净负样本 | 0 条 `CONFIRMED` | 误报，基线判定逻辑异常 |
| `scripts/acceptance_chaos_timing.py` | `lab/chaos/server.py` `CHAOS_PROFILE=slow`（每个响应随机延迟 2-5s） | 慢站干扰样本 | 0 条 `CONFIRMED` | 网络抖动/延迟造成误报，阈值、限速耦合问题 |

三套脚本统一遵守：

- 跨平台 Windows / Linux，自动分配空闲端口、处理进程与路径；
- 自动拉起对应 lab 靶场，扫描结束/异常/超时都在 `finally` 中强制回收进程树；
  Windows 使用 `taskkill /F /T`，Linux 使用 `SIGTERM`，5 秒未退出再 `SIGKILL`；
- 扫描参数语义统一为 `--time-based --time-budget 120 --format json`；
  本版本 CLI 的 JSON 报告参数名为 `--report-format json`，脚本内部按等价参数执行；
- 扫描超时 120s，靶场启动后等待 3s 再做健康检查；
- 报告写到系统临时目录的 JSON 文件，脚本结束自动删除；
- 日志用 `✅ 通过` / `❌ 失败` 明确区分，并打印命中的漏洞名称、URL、severity、evidence。

> 为什么只调度「时间盲注（dept）」插件：指纹、WAF、API 前缀、目录扫描等预检在
> chaos slow（2-5s/请求）上会先吃掉 120s 预算，导致时序插件根本没机会采样。
> 验收脚本因此用 `ScanEngine + SqlBlindTimePlugin` 隔离时序判定，仍使用同一套
> `lib/timing.py`、同一套 `time_based/time_budget` 参数，不修改任何存量代码。

## 2. 执行命令

在项目根目录执行，使用项目虚拟环境：

### Windows PowerShell

```powershell
.venv\Scripts\python.exe scripts/acceptance_chaos_timing.py
.venv\Scripts\python.exe scripts/acceptance_vuln_positive.py
.venv\Scripts\python.exe scripts/acceptance_vuln_negative.py
```

### Linux / macOS

```bash
.venv/bin/python scripts/acceptance_chaos_timing.py
.venv/bin/python scripts/acceptance_vuln_positive.py
.venv/bin/python scripts/acceptance_vuln_negative.py
```

退出码约定：

- `0`：验收通过；
- `1`：验收门禁失败（漏报 / 误报 / 超时）；
- `2`：环境或执行错误（靶场未启动、报告缺失、脚本异常等）。

## 3. 版本发布卡点规则

**v1.8 合并 main 之前，必须 3 个脚本全部跑通，时序盲注验收才算通过。**

推荐按以下顺序执行并保留终端输出：

1. `acceptance_vuln_positive.py` —— 确认漏洞能检出（防止漏报）；
2. `acceptance_vuln_negative.py` —— 确认干净站不误报；
3. `acceptance_chaos_timing.py` —— 确认慢站干扰不误报。

任意一项为 `❌ 失败`，不得合并到 main。

## 4. 不跑在 CI，仅人工回归

这些脚本故意不注册到 pytest，也不接入任何 CI / nightly / 自动发布流水线：

- 时序检测需要真实等待 3 秒级延迟，CI 共享 runner 的抖动会污染结论；
- 验收结论需要人工判断日志与 evidence，不适合作为自动门禁；
- 脚本会拉起本地靶场服务，CI 容器的端口/进程模型与开发机不同。

**修改以下内容后必须执行全套 3 个脚本回归：**

- `lib/timing.py`（阈值、`classify` 判定顺序、采样窗口）；
- 限速逻辑（`core/engine.py`、`core/session.py`、`lib/rate_limit.py`、`--rate` / `--rate-scope`）；
- `plugins/ruoyi/sql_blind_time.py` 或 `plugins/spring/cloud_function_rce.py` 的时序判定；
- `--time-budget`、`--time-based`、请求超时/重试等影响采样预算的参数。

## 5. 失败场景说明

### 5.1 正样本失败（漏报）

现象：`acceptance_vuln_positive.py` 输出 `❌ 失败：正样本 0 条时序盲注 CONFIRMED`，
时序插件状态为 `SAFE` 或 `UNKNOWN`。

含义：**漏报，时序盲注检测失效**。重点排查：

- `lib/timing.py` 的 `DELAY_SECONDS`、`classify` 阈值是否被调得过高；
- 探测组是否真的发出 `if(1=1,sleep(3),0)`，对照组/探测组请求形状是否一致；
- `--time-budget` 是否不足以完成一轮采样（插件会返回 `budget_exceeded`）；
- 靶场时序垫片是否未生效（打印的临时靶场日志会给出原因）。

### 5.2 负样本失败（误报）

现象：`acceptance_vuln_negative.py` 出现 `CONFIRMED`。

含义：**误报，基线判定逻辑异常**。重点排查：

- 是否只看绝对耗时，没有做「探测组 - 对照组」差分；
- 是否把单次抖动当成了稳定延迟（至少 2 次采样的门槛失效）；
- 修复版 dept 接口是否仍返回延迟（靶场/补丁不一致）；
- 是否把超时、`None` 采样当成了「有延迟」。

### 5.3 chaos 慢站脚本失败（干扰误报）

现象：`acceptance_chaos_timing.py` 在 2-5s/请求的 slow 靶场上出现 `CONFIRMED`。

含义：**网络抖动/延迟会造成误报，阈值、限速耦合问题**。重点排查：

- `classify` 是否过度依赖绝对阈值，导致慢站被误判；
- 对照组和探测组采样次数是否太少，随机延迟恰好形成「假差分」；
- 限速/超时/重试是否改变了探测组和对照组的采样分布；
- 是否需要提高采样次数或收紧 `probe_median - baseline` 门槛（修改后必须全套回归）。
