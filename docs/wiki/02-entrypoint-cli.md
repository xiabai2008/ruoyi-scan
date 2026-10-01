# 02 · 入口与 CLI

> 这一章回答：命令行的参数是怎么被解析的？一次扫描从敲下回车到发出第一个 HTTP 请求，中间经过了哪些层？
>
> 相关源码：[main.py](../../main.py) · [cli/](../../cli)

---

## 1. 入口三件套

`main.py` 在 P0 重构后被刻意削薄——**只做参数解析与模式分发**，业务编排全部下沉到 `cli/runner.py`。

| 函数 | 位置 | 职责 |
| --- | --- | --- |
| `print_banner()` | [main.py#L15-L29](../../main.py#L15-L29) | 打印 ASCII Art banner（绿色）+ 版本/作者/GitHub 信息（黄色） |
| `build_parser()` | [main.py#L32-L294](../../main.py#L32-L294) | 构建 argparse 解析器，约 150 个参数按功能分成 **23 个参数组** |
| `print_help()` | [main.py#L297-L418](../../main.py#L297-L418) | 自建帮助输出，对齐原脚本的 `-h` 排版（不用 argparse 默认格式） |
| `main(argv=None)` | [main.py#L422-L521](../../main.py#L422-L521) | 主入口：编码兜底 → 日志 → TLS 策略 → banner → YAML 回填 → 模板 → 校验 → 分发 |

### 1.1 为什么禁用 argparse 内置 `-h`

```python
parser = argparse.ArgumentParser(add_help=False)
group.add_argument("-h", dest="help", nargs="?", const="flag", default=None, help="帮助")
```

`-h` 被重定义为 `nargs="?"`——这样既能作为裸开关（`-h`）也能带值，同时把帮助输出交给 `print_help()` 控制排版。这是向前兼容老用户习惯的取舍：老脚本的 `-h` 输出是手工排版的，换成 argparse 默认格式会破坏既有肌肉记忆。

### 1.2 `const="__flag__"` 的技巧

```python
group.add_argument("-u", metavar="target", nargs="?", const="__flag__", default=None, help="综合扫描")
```

`nargs="?"` + `const="__flag__"` 让 `-u` 同时支持三种形态：

| 写法 | `args.u` 的值 | 含义 |
| --- | --- | --- |
| 未指定 | `None` | 该模式未被选中 |
| `-u` | `"__flag__"` | 只标记模式，目标是别的参数给的（配合 `-f` 批量用） |
| `-u http://x` | `"http://x"` | 模式 + 目标 |

这个设计是为 `-f targets.txt -p` 这种「批量 + 指定模式」的组合服务的：`-p` 只负责声明"用漏洞检测类别"，目标列表来自文件。

---

## 2. `main()` 的初始化顺序

```
force_utf8_stdio()                     # Windows ANSI 代码页兜底，避免中文乱码
        ↓
setup_logging(debug=args.debug)        # 默认 WARNING 静默，--debug 开 DEBUG 到 stderr
        ↓
if args.verify_tls: settings.VERIFY_TLS = True   # 写入全局 settings（与 core/session 同一事实来源）
        ↓
print_banner()
        ↓
if args.config:  load_yaml_config → normalize_config_keys → apply_config_to_args
                 （仅在命令行未显式给 -u/-m/-p/-l 时，才用 YAML 的 mode/target 回填）
        ↓
if args.template:  apply_template(args, template)   # D19 扫描模板
        ↓
has_mode = any([...28 个可执行模式...])
        ↓
if args.help is not None or not has_mode:  print_help(); return
        ↓
from cli.dispatcher import dispatch;  dispatch(args)
```

两个关键纪律：

1. **TLS 策略入 `settings`**：`VERIFY_TLS` 不是散落在各处的局部变量，而是写进 `config/settings.py` 的模块级常量。这样 `core/session.py`（实际发请求）和 `core/http.py`（可达性预检）读的是同一个值，**策略只有一处定义**。
2. **YAML 不覆盖命令行**：`cli_has_mode` 为真时跳过 YAML 的 `mode/target` 回填。命令行显式意图 > 配置文件默认值。

---

## 3. 参数分组全景

`build_parser()` 里的 23 个参数组，按「用户视角的功能」聚类，组名直接带上了设计编号（D7/D9/E9…），便于反查设计文档：

| 参数组 | 代表参数 | 设计编号 |
| --- | --- | --- |
| 核心参数（向后兼容） | `-h` `-u` `-m` `-p` `-l` `-f` | — |
| 通用参数 | `--proxy` `--threads` `--rate` `--timeout` `--cms` `--skip-preflight` `--verify-tls` | — |
| 扫描模式 | `--portscan` `--ports` `--passive` `--components` `--nuclei*` | E2 / E4 |
| 报告 | `--report-format` `--remediation` `--report-template` `--no-dedup` | G5 |
| D6 利用链 | `--chain` `--chain-list` | D6 |
| D7 WAF 绕过 | `--bypass-waf auto\|on\|off` | D7 |
| D9 Web API 服务 | `--serve` `--host` `--port` | D9 |
| D11 API 鉴权 | `--api-key` `--cors-origins` `--db-path` | D11 |
| E9 定时扫描 | `--schedule` `--schedule-target` | E9 |
| D14 信息收集 | `--crawl` `--subdomain` `--js-extract` | D14 |
| D19 扫描模板 | `--template` `--template-list` | D19 |
| D27 YAML 配置 | `--config` | D27 |
| D20 差异对比 | `--diff` `--diff-only` `--save-baseline` | D20 |
| D21 通知 | `--notify TYPE=TARGET` | D21 |
| D26 认证扫描 | `--auth` `--auth-file` `--auth-login` | D26 |
| D23 国际化 | `--lang zh\|en` | D23 |
| D25 插件 SDK | `--plugin-init/check/new/list/path` `--category` | D25 |
| E5 插件模板仓库 | `--plugin-export` `--plugin-manifest` `--plugin-update` | E5 |
| E7 AI 插件生成 | `--ai` `--ai-triage` `--ai-validate` `--ai-*` | E7 / G3 |
| E8 AI 报告解读 | `--ai-report [zh\|en]` | E8 |
| D28 CI/CD 集成 | `--ci` `--severity-threshold` `--ci-init` | D28 |
| D29 漏洞知识库 | `--wiki` `--wiki-output` | D29 |
| D30 OAST 带外检测 | `--oast` `--oast-server` `--oast-host` `--oast-port` | D30 |
| D31 业务逻辑检测 | `--logic-scan` `--logic-endpoints` `--logic-concurrency` | D31 |
| G1 认证后深度扫描 | `--auth-surface` `--surface-account` `--surface-output` | G1 |
| D32 CVE 同步 | `--cve-sync` `--cve-id` `--cve-offline` `--nvd-api-key` | D32 |
| D33 SIEM 集成 | `--siem-export` `--siem-output` `--siem-syslog` | D33 |
| D34 异步引擎 | `--async` `--async-workers` | D34 |
| D35 Web UI | `--web-ui` `--web-ui-output` `--web-ui-api` | D35 |
| D36 分布式扫描 | `--distributed` `--redis-url` `--distributed-rate` | D36 |
| D37 结果缓存 | `--cache` `--cache-ttl` `--cache-stats` … | D37 |

> 参数数量是这个项目「能力密度」的直接体现：CLI 层几乎是一个功能矩阵的入口清单。但它也带来了维护成本——`print_help()` 里有一张 100+ 行的手工参数表，与 `build_parser()` 存在漂移风险（见 [README 的文档漂移清单](README.md#文档与实现不一致清单)）。

---

## 4. `cli/` 控制层：8 个模块

`cli/` 是 **CLI 专属的编排层**，与 `core/` 的区别在于：`core/` 只管"怎么扫"，`cli/` 管"扫完之后怎么落盘、怎么打印、怎么退出"。

| 模块 | 职责 | 关键入口 |
| --- | --- | --- |
| [dispatcher.py](../../cli/dispatcher.py) | 模式分发总闸：按 args 决定走哪条路 | `dispatch(args)` |
| [runner.py](../../cli/runner.py) | 核心扫描：`run_mode` / `run_mode_batch` + 报告后处理；并**重导出**其余模式函数 | `run_mode()` `run_mode_batch()` `final_prompt()` |
| [preflight.py](../../cli/preflight.py) | 目标可达性预检（单目标/批量/链 三种入口共用） | `preflight_target()` `EXIT_UNREACHABLE` |
| [chain_runner.py](../../cli/chain_runner.py) | 漏洞利用链执行 | `run_chain_mode()` |
| [passive_runner.py](../../cli/passive_runner.py) | 被动代理模式 | `run_passive_mode()` |
| [plugin_runner.py](../../cli/plugin_runner.py) | 插件管理（init/new/check/list/export/manifest/update） | `run_plugin_*_mode()` |
| [serve_runner.py](../../cli/serve_runner.py) | 启动 Web API 服务（uvicorn） | `run_serve_mode()` |
| [tool_runner.py](../../cli/tool_runner.py) | 纯工具模式（diff/wiki/ci-init/template-list…） | `run_diff_only_mode()` 等 |

### 4.1 为什么 `preflight` 要独立成模块

[preflight.py](../../cli/preflight.py) 的模块 docstring 给出了理由：

> 独立成模块的原因：`dispatcher`、`runner`、`chain_runner` 三者都需要它，而 `chain_runner` 由 `runner` 导入——若把实现放在 `dispatcher` 会形成循环导入。

这是**用模块拆分切断循环依赖**的典型手法：把「三方共用的叶子能力」提到依赖图的最外层。

### 4.2 两级探测量什么

```python
ok, reason = probe_reachable(target)          # TCP 层：秒级判定端口是否可连
if not ok: return False
ok, reason = probe_http_responsive(target)    # HTTP 层：端口通但服务不回数据
```

第二级探测的存在理由（原文 docstring）：

> 端口可连接但服务无响应（防火墙接受 SYN 后丢包、服务假死）——TCP 探测会放行，而每个插件都要等满超时，实测这类目标 120 秒仅完成数个插件。

即：**两级探测是为了避免"扫描看似在进行、实则全在等超时"的假进度**。

### 4.3 `EXIT_UNREACHABLE = 3`

退出码是刻意与 CI 模式错开的：

| 退出码 | 含义 |
| --- | --- |
| `0` | CI 模式：通过（未超阈值） |
| `1` | CI 模式：扫出漏洞且超阈值 |
| `2` | 异常 |
| `3` | **目标不可达**（`EXIT_UNREACHABLE`） |

让脚本能区分「扫描没跑成」与「扫出漏洞了」两种失败——前者是环境问题，后者是安全结论，CI 里的处置动作完全不同。

**代理存在时跳过预检**：配置了 `--proxy` / `--proxy-file` 就直连探测会误判（目标可能只对代理侧可达），因此直接放行。

---

## 5. 模式分发决策树

[dispatcher.dispatch()](../../cli/dispatcher.py#L35-L175) 是一条**严格有序**的 `if` 链，顺序即优先级：

```
dispatch(args)
│
├─【第一段：纯工具模式（不扫描，立即 return）】
│   --diff-only → --template-list → --plugin-new → --plugin-init → --plugin-check
│   → --plugin-list → --ci-init → --wiki → --oast-server → --cve-sync/--cve-id/--cve-offline
│   → --web-ui → --cache-stats → --cache-clear → --nuclei-validate
│   → --plugin-export → --plugin-manifest → --plugin-update
│   → --ai-validate <path>（sys.exit(返回码)）
│   → --ai-triage 守卫（无扫描模式则报错返回）
│   → --ai
│
├─【第二段：独立进程模式（自己占住终端/端口）】
│   --serve → --chain-list / --chain list → --chain <name> → --passive
│
└─【第三段：标准扫描模式】
    ├─ -f <file>：需配合 -u/-m/-p/-l 开关指定扫描类型 → run_mode_batch()
    ├─ 单目标：按 u → m → p → l 取第一个有效目标
    │           preflight_target() 失败 → sys.exit(EXIT_UNREACHABLE)
    │           成功 → run_mode(k, target, args)
    └─ final_prompt()   # 收尾提示
```

### 5.1 顺序背后的三条规则

1. **工具 > 服务 > 扫描**。纯工具模式（生成配置、查缓存、验证模板）不算扫描，先处理并 `return`，避免被后续扫描分支误捕获。
2. **`--ai-triage` 是「修饰符」而非「模式」**。它单独出现无意义——[dispatcher.py#L111-L115](../../cli/dispatcher.py#L111-L115) 显式拦截并给出提示，要求配合扫描模式使用。这是**防止参数误用**的显式守卫，而不是静默忽略。
3. **单目标优先级 `u > m > p > l` 隐含在元组顺序里**。同时给多个目标时只有第一个会被执行，且不警告。这是继承自原脚本的行为。

### 5.2 `-f` 批量模式的约束

```python
if args.file:
    mode = None
    for k in ("u", "m", "p", "l"):
        if k in flag_for:      # flag_for 只收 value == "__flag__" 的键
            mode = k
            break
    if not mode:
        print("[-f 批量扫描需配合 -u/-m/-p/-l 指定扫描模式]")
        return
```

批量模式**必须**知道用哪个扫描类别，因此 `-f targets.txt` 单用会报错，要写成 `-f targets.txt -p`。这里的 `flag_for` / `target_for` 拆分正是 §1.2 那个 `"__flag__"` 设计的落地——把"开关"与"目标值"分开收集，才能正确识别 `-p`（开关）和 `-p http://x`（带目标）的区别。

---

## 6. `runner.run_mode()` 的主干

`run_mode()` 是 CLI 扫描的实际执行者，[cli/runner.py](../../cli/runner.py)：

```
run_mode(mode, target, args, show_cta=True)
│
├─ 1. _build_scan_request(mode, target, args)   # 把 Namespace 收敛成 ScanRequest
│       └─ D26 认证三来源合并（--auth / --auth-file / --auth-login → auto_login）
├─ 2. ScanOrchestrator().run_sync(request)      # ← 进入 core 层（见 03 章）
├─ 3. 报告后处理链（顺序敏感）：
│       report_template（G5 模板渲染）
│       → remediation（G5 整改复测对比）
│       → ai_triage（G3 UNKNOWN 聚类降噪）
│       → save_baseline（D20 存基线）
│       → diff（D20 与历史对比）
│       → notify（D21 通知推送）
│       → ai_report（E8 AI 摘要）
│       → logic_scan / auth_surface / siem_export / ci
└─ 4. print_star_cta()（除非 --no-cta）
```

设计要点：

- **`report_dir=""` 刻意留空**：CLI 自己负责报告的落盘与后处理链，`ScanOrchestrator` 只负责产出结果对象。这样 API 模式可以复用同一个 orchestrator 而不带上 CLI 的文件副作用。
- **认证三来源合并且有兜底**：三条来源（参数、文件、自动登录）合并进同一个 `auth_config`；若最终 `cookies` 与 `headers` 都为空，整体回退为 `None`——**避免传一个"空认证对象"给下游导致语义歧义**。

### 6.1 `MODE_CATEGORIES`：模式 → 插件类别

```python
MODE_CATEGORIES = {
    "u": ["recon", "vuln", "brute"],   # 综合
    "m": ["recon"],                    # 目录扫描
    "p": ["vuln"],                     # 漏洞检测
    "l": ["brute"],                    # 登录爆破
}
```

四个字母模式最终被翻译成**插件 `category` 过滤条件**。这是 CLI 与插件体系之间唯一的耦合点——CLI 不需要知道有哪些插件，只需要说"我要 recon/vuln/brute 三类"。

### 6.2 指纹回流给报告

`runner.py` 里有一个模块级变量 `_LAST_DETECTED_FINGERPRINT`，通过 `_cli_event_handler()` 在收到 `fingerprint` 事件时捕获。作用：CLI 报告要写明"目标是什么 CMS / 什么版本"，而这个信息由 `core/orchestrator` 在扫描早期产生，需要跨层带到报告阶段。

---

## 7. 环境变量表

| 变量 | 默认值 | 作用域 | 说明 |
| --- | --- | --- | --- |
| `RUOYI_SCAN_DEBUG` | 空 | [common/logger.py](../../common/logger.py) | 非空即启用 DEBUG 日志级别 |
| `RUOYI_SCAN_REPORT_DIR` | `<BASE_DIR>/reports` | [config/settings.py](../../config/settings.py) | 覆盖报告默认输出目录 |
| `RUOYI_SCAN_API_KEY` | 空 | [api/auth.py](../../api/auth.py) / [cli/serve_runner.py](../../cli/serve_runner.py) | API Key 兜底来源（`--api-key` 优先） |
| `RUOYI_SCAN_LOWPRIV_USER` | `scanner_low` | [config/settings.py](../../config/settings.py) | G1 垂直越权对比用低权账号 |
| `RUOYI_SCAN_LOWPRIV_PASS` | `LowPriv_2026` | 同上 | 低权账号密码 |
| `RUOYI_SCAN_LOWPRIV_TARGET` | `1` | 同上 | 越权对比目标用户 ID |
| `RUOYI_SCAN_HOME` | `<home>/Ruoyi-Scan` | [desktop/engine/ruoyi_scan_engine.py](../../desktop/engine/ruoyi_scan_engine.py) | 桌面端引擎解压目录 |
| `RUOYI_AI_API_KEY` | 空 | [lib/ai_generator.py](../../lib/ai_generator.py) | LLM Key（无 Key 时降级规则模板） |
| `RUOYI_AI_BASE_URL` | `https://api.openai.com/v1` | 同上 | LLM 接口地址（可指向兼容网关） |
| `RUOYI_AI_MODEL` | `gpt-4o-mini` | 同上 | LLM 模型名 |
| `RUOYI_AI_TIMEOUT` | `60` | 同上 | LLM 请求超时秒数 |
| `SMTP_HOST` / `SMTP_PORT` / `SMTP_USER` / `SMTP_PASS` / `SMTP_FROM` | — | [lib/notifier.py](../../lib/notifier.py) | D21 邮件通知 SMTP 配置 |

---

## 8. 运行方式

### 8.1 安装

```bash
# 从源码（开发）
pip install -e ".[dev]"

# 最小运行（仅 CLI 扫描）
pip install -e .

# 按需装可选依赖组
pip install -e ".[report]"      # pdf/docx/xlsx 报告
pip install -e ".[serve]"       # FastAPI Web 服务
pip install -e ".[distributed]" # Redis 分布式
pip install -e ".[all]"         # 全量
```

安装后可直接调用 `ruoyi-scan`（`[project.scripts] ruoyi-scan = "main:main"`）；未安装时用 `python main.py`。

### 8.2 四种核心扫描模式

```bash
python main.py -u http://target:8080        # 综合（recon + vuln + brute）
python main.py -m http://target:8080        # 目录扫描（recon）
python main.py -p http://target:8080        # 漏洞检测（vuln）
python main.py -l http://target:8080        # 登录爆破（brute）

python main.py -f targets.txt -p            # 批量（必须带模式开关）
```

### 8.3 常用组合

```bash
# 带报告与并发
python main.py -u http://t:8080 --threads 10 --rate 20 --report ./out --report-format all

# 指定 CMS 跳过指纹识别 + 端口扫描
python main.py -p http://t:8080 --cms ruoyi --portscan --ports 8080,8848,6379

# WAF 场景
python main.py -u http://t:8080 --bypass-waf on

# 认证后深度扫描（G1 越权矩阵）
python main.py -p http://t:8080 --auth-login admin:admin123 \
    --auth-surface --surface-account user:user123 --surface-output assets.json

# CI 集成（退出码驱动）
python main.py -p http://t:8080 --ci --severity-threshold high

# 漏洞利用链
python main.py --chain-list                        # 列出可用链
python main.py --chain ruoyi_sql_to_rce -u http://t:8080   # 执行指定链

# Web API 服务
python main.py --serve --host 0.0.0.0 --port 8000 \
    --api-key "key1:read,key2:scan,key3:admin"

# 定时扫描
python main.py --serve --schedule "0 2 * * *" --schedule-target http://t:8080

# 配置文件驱动
python main.py --config scan.yaml
python main.py --template deep -u http://t:8080
```

### 8.4 预检与排障

| 现象 | 原因 | 处置 |
| --- | --- | --- |
| 输出后立即退出，码 `3` | 目标不可达/无 HTTP 响应 | 检查地址端口；经代理时加 `--proxy`；必要时 `--skip-preflight` |
| 中文乱码 | Windows 代码页 | 已由 `force_utf8_stdio()` 兜底；仍乱码则设 `PYTHONIOENCODING=utf-8` |
| TLS 报错 | 目标自签名证书 | 默认 `VERIFY_TLS=False` 已兼容；反向需求加 `--verify-tls` |
| 想看请求细节 | 默认静默 | `--debug`（写 stderr）或 `RUOYI_SCAN_DEBUG=1` |

### 8.5 测试

```bash
pytest                    # 默认 -q --timeout=30 --timeout-method=thread
ruff check .
mypy                      # common.*/core.* 走 strict；lib.*/api.* 被 ignore
```

---

## 9. 本章小结

- `main.py` 是纯参数层，`cli/` 是 CLI 编排层，`core/` 是无 CLI 依赖的引擎层——**三层各自可独立测试**。
- 「模式」在 CLI 层被翻译成 `category` 过滤条件后才进入引擎，CLI 不知道任何具体插件。
- 分发顺序是有语义的：工具 → 服务 → 扫描；`--ai-triage` 这类修饰符有显式守卫。
- 预检的两级探测与 `EXIT_UNREACHABLE=3` 都是为了**让失败可区分**，而不是让失败静默。

→ 下一章：[03 · core 核心引擎](03-core.md)