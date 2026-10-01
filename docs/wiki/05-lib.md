# 05 · lib 工具库

> 这一章回答：`lib/` 的 40 个模块分别解决什么问题？几个关键机制（WAF 绕过、OAST、nuclei 兼容、插件仓库签名、分布式）是怎么实现的？
>
> 相关源码：[lib/](../../lib)

---

## 1. lib 层的定位

`lib/` 与 `core/` 的分界：

| | `core/` | `lib/` |
| --- | --- | --- |
| 性质 | 引擎**内核** | 可插拔**能力集** |
| 依赖 | 只依赖 `common` / `config` | 可依赖 `core`、可用可选第三方包 |
| mypy | `strict = true` | `ignore_errors = true` |
| 失败影响 | 失败 = 扫描不可用 | 失败 = **该能力降级**，主扫描继续 |

**「可选能力」是这个包的统一定位**。这解释了为什么 orchestrator 在加载 `component_detect` / `nuclei_loader` / `scheduler` / `plugin_repo` 时全都包在 `try/except` 里——它们都属于「有更好，没有也能跑」。

模块名里的 `D7` / `D11` / `D13` / `E2` / `G1`… 是设计文档的编号锚点，用来反查需求来源。

---

## 2. 40 个模块按功能分组

### 2.1 基础与输出（4）

| 模块 | 作用 |
| --- | --- |
| [colors.py](../../lib/colors.py) | ANSI 颜色常量（`GREEN`/`RED`/`YELLOW`/`RESET`/`SEPARATOR`）+ `ok()` / `no()` 语义函数 |
| [reporter.py](../../lib/reporter.py) | 扫描进度输出桥：`set_quiet()` / `is_quiet()` / `strip_ansi()` / `emit()` |
| [i18n.py](../../lib/i18n.py) | D23 中英文报告：`get_text` / `localize_report_dict` / `get_csv_header` |
| [star_cta.py](../../lib/star_cta.py) | 扫描结束的仓库引导（`print_star_cta` / `cta_enabled`） |

**`reporter.emit()` 的意义**：CLI 下走 stdout（带颜色），库/服务模式下 `set_quiet(True)` 后改走 logging。这就是 [api/app.py](../../api/app.py) 在 `create_app()` 第一行调 `set_quiet(True)` 的原因——**服务进程的 stdout 不该被插件的进度输出污染**，实时进度已经由 WebSocket 推送。

### 2.2 判定辅助（2）

| 模块 | 作用 |
| --- | --- |
| [matcher.py](../../lib/matcher.py) | **降误报判定工具**：正向关键字 + 负向排除联合判定；12+ 个专用匹配器（`match_sql_error` / `match_file_read_leak` / `match_spring_actuator_env` / `match_heapdump_binary` / `match_jolokia_response` / `match_cloud_function_spel` …） |
| [soft404.py](../../lib/soft404.py) | 软 404（catch-all 路由）基线探测：`Soft404Baseline` 用 `_digest(body)` 对比，识别"任意路径都返回同一页面"的站点 |

这两个模块直接服务于**误报率**这个核心质量指标。`matcher.match_positive(text, positives, negatives)` 的签名本身就体现了方法论：**只匹配正向关键字不够，必须同时排除负向特征**。

### 2.3 信息收集（4）

| 模块 | 作用 |
| --- | --- |
| [crawler.py](../../lib/crawler.py) | D14 主动爬虫：`Crawler` BFS + `LinkExtractor(HTMLParser)` 解析链接；`crawl_with_js_urls()` 额外收集 JS URL |
| [js_extractor.py](../../lib/js_extractor.py) | D14 JS 端点提取：从 JS 文件提取 API 路径/URL |
| [subdomain.py](../../lib/subdomain.py) | D14 被动子域名枚举（`verify_dns=False` 默认不爆破，避免对目标造成压力） |
| [origin_finder.py](../../lib/origin_finder.py) | D7 源站真实 IP 探测：`OriginIPFinder`，标准库 + 免费 API，**零依赖** |

**子域名枚举默认不做 DNS 爆破**——`enumerate_subdomains(verify_dns=False, use_crtsh=True)` 优先走证书透明日志（crt.sh）。这是"不攻击目标"的自我约束。

### 2.4 认证与会话增强（3）

| 模块 | 作用 |
| --- | --- |
| [auth_scan.py](../../lib/auth_scan.py) | D26 认证注入：`parse_auth_arg` / `load_auth_file` / `auto_login` / `apply_auth_to_session` / `parse_login_arg` |
| [auth_surface.py](../../lib/auth_surface.py) | G1 认证后深度扫描：登录态资产盘点 + 越权矩阵（`AuthSurfaceScanner` / `SurfaceAsset` / `_looks_denied`） |
| [proxy_pool.py](../../lib/proxy_pool.py) | D13 代理池：`ProxyPool` + `ProxyStats`，轮换 + 健康检查 + 自动剔除 |

**`auth_surface` 的核心难点在"如何判断拒绝"**：`_looks_denied(status_code, body)` 不只看 403——若依会返回 HTTP 200 但内容为"没有权限"错误码，只看状态码会把拒绝误判成越权成功。

### 2.5 业务逻辑与竞态（1）

| 模块 | 作用 |
| --- | --- |
| [logic_scan.py](../../lib/logic_scan.py) | D31 业务逻辑漏洞：`IDORDetector`（越权）/ `PrivilegeEscalationDetector`（提权）/ `ParameterTamperingDetector`（参数篡改）/ `RaceConditionDetector`（竞争条件）/ `LogicScanner` 编排 |

### 2.6 WAF 绕过（3）

| 模块 | 作用 |
| --- | --- |
| [waf_bypass.py](../../lib/waf_bypass.py) | D7 WAF 绕过策略库与编排器（见 §3） |
| [tamper.py](../../lib/tamper.py) | payload 变形器**纯函数**：`space2comment` / `mysql_version_comment` / `randomcase` / `between_replace` / `url_encode` / `double_urlencode` / `hex_encode` / `base64_encode` / `split_for_chunked` / `hpp_duplicate` / `append_nullbyte` / `apply_chain` |
| [origin_finder.py](../../lib/origin_finder.py) | 源站 IP 探测（见 §2.3） |

**`tamper.py` 刻意为纯函数**（无 IO、无状态）——因此可被单测穷举，也可以在 `apply_chain(payload, *tampers)` 里任意组合。

### 2.7 带外与组件检测（2）

| 模块 | 作用 |
| --- | --- |
| [oast.py](../../lib/oast.py) | D30 OAST 带外检测（见 §4） |
| [component_detect.py](../../lib/component_detect.py) | E2 组件版本检测：fastjson / Spring Boot / Shiro / Nacos / Log4j（见 §5） |

### 2.8 模板兼容与插件生态（4）

| 模块 | 作用 |
| --- | --- |
| [nuclei_loader.py](../../lib/nuclei_loader.py) | E4 nuclei YAML 兼容层（见 §6） |
| [plugin_sdk.py](../../lib/plugin_sdk.py) | D25 插件 SDK：`generate_plugin` / `init_plugin_file` / `check_plugin` / `list_all_plugins` / `generate_plugin_docs` |
| [plugin_repo.py](../../lib/plugin_repo.py) | E5 插件模板仓库：导出 / manifest / Ed25519 签名 / 远程更新（见 §7） |
| [scan_templates.py](../../lib/scan_templates.py) | D19 扫描模板：`ScanTemplate` / `apply_template` / `filter_plugins`（quick/deep/compliance/dengbao） |

### 2.9 报告与交付（6）

| 模块 | 作用 |
| --- | --- |
| [report_template.py](../../lib/report_template.py) | G5 docx 合规报告模板引擎：占位符替换（`build_scalar_values`）+ 块级填充（`_fill_block_vuln_table` / `_fill_block_vuln_details`） |
| [remediation.py](../../lib/remediation.py) | G5 整改复测：`build_remediation_report` / `render_remediation_docx` |
| [diff_scan.py](../../lib/diff_scan.py) | D20 增量差异：`VulnFingerprint` / `DiffEntry` / `DiffReport` / `load_report` |
| [notifier.py](../../lib/notifier.py) | D21 告警通知（见 §8） |
| [siem_export.py](../../lib/siem_export.py) | D33 SIEM 集成：`to_ecs_event`/`render_ecs`（ECS）+ `to_cef_event`/`render_cef`（CEF） |
| [vuln_wiki.py](../../lib/vuln_wiki.py) | D29 漏洞知识库（离线 Wiki 生成） |

**报告模板引擎有两种替换机制**：标量占位符（`{{target}}`）直接替换段落文本；表格类占位符（`{{vuln_table}}`）则是**在文档中插入真实表格对象**（`_style_table` + `doc.add_table`）。后者是难点——python-docx 里"在一个段落位置插入表格"需要先拿到段落的 XML 位置。

### 2.10 CVE 数据（1）

| 模块 | 作用 |
| --- | --- |
| [cve_sync.py](../../lib/cve_sync.py) | D32 CVE 同步：NVD + GHSA + CNVD 三源查询 + 离线库（见 §9） |

### 2.11 AI 能力（4）

| 模块 | 作用 |
| --- | --- |
| [ai_generator.py](../../lib/ai_generator.py) | E7 AI 生成插件（见 §10） |
| [ai_validate.py](../../lib/ai_validate.py) | G3 生成即验证（见 §10） |
| [ai_triage.py](../../lib/ai_triage.py) | G3 UNKNOWN 智能降噪：`cluster_unknowns` / `triage_unknowns` |
| [ai_report.py](../../lib/ai_report.py) | E8 AI 报告解读：`generate_analysis` / `_template_summary`（无 Key 降级模板） |

### 2.12 引擎与集成（5）

| 模块 | 作用 |
| --- | --- |
| [async_engine.py](../../lib/async_engine.py) | D34 异步扫描引擎：`AsyncScanEngine` / `scan_batch_targets` / `scan_plugins_concurrent` / `benchmark_sync_vs_async` |
| [distributed.py](../../lib/distributed.py) | D36 分布式任务队列（见 §11） |
| [cache.py](../../lib/cache.py) | D37 结果缓存：`generate_cache_key` / `CacheStorage` / `ScanCache` / `cached_scan` 装饰器 |
| [ci_runner.py](../../lib/ci_runner.py) | D28 CI/CD 集成：`should_fail_ci` / `get_ci_exit_code` / `generate_ci_config`（github/gitlab/jenkins） |
| [scheduler.py](../../lib/scheduler.py) | E9 定时扫描：`parse_schedule_expr` / `ScanScheduler` |
| [config_loader.py](../../lib/config_loader.py) | D27 YAML 配置：`load_yaml_config` / `normalize_config_keys` / `apply_config_to_args` |
| [web_ui.py](../../lib/web_ui.py) | D35 Web UI 生成：`generate_web_ui`（单文件控制台） |

---

## 3. 关键机制一：WAF 绕过（D7）

[waf_bypass.py](../../lib/waf_bypass.py) 是全项目最长的 `lib` 模块之一（550+ 行），结构是一个**策略模式 + 统计追踪 + 会话代理**的三件套。

### 3.1 11 个绕过策略

抽象基类 `WafBypassStrategy`，11 个具体策略分两类：

| 类型 | 策略 | 做法 |
| --- | --- | --- |
| payload 变形 | `InlineCommentStrategy` | 空格 → `/**/` |
| | `MysqlVersionCommentStrategy` | 插入 `/*!50000…*/` |
| | `RandomCaseStrategy` | 关键字随机大小写 |
| | `BetweenReplaceStrategy` | `=` → `BETWEEN … AND` |
| | `UrlEncodeStrategy` | URL 编码 |
| | `DoubleUrlEncodeStrategy` | 双重 URL 编码 |
| 传输层变换 | `ChunkedTransferStrategy` | `Transfer-Encoding: chunked` 分块 |
| | `HppStrategy` | HTTP 参数污染 |
| | `Http10DowngradeStrategy` | 降级到 HTTP/1.0 |
| | `GooglebotStrategy` | 伪装 Googlebot UA |
| | `OriginDirectStrategy` | 直连源站 IP 绕过 CDN/WAF |

**payload 变形类复用 `tamper.py` 的纯函数**——策略类只负责"什么条件下用哪个变形"，变形逻辑本身不重复实现。

`OriginDirectStrategy` 依赖 `origin_finder` 探测出的源站 IP（在 orchestrator `_build_waf_bypass()` 里完成探测并传入）。

### 3.2 `StrategyRegistry`

管理策略的注册与按 `vuln_type` / `waf_type` 选取。策略与漏洞类型的匹配靠插件类上的 `vuln_type` 属性（`sqli`/`xss`/`rce`/`file_read`/`auth`）。

### 3.3 `BypassStatsTracker`

记录每个策略的尝试次数与成功率，供"哪种策略对这个 WAF 有效"的统计。**这个统计是可观测性的基础**——否则用户不知道绕过为什么没成功。

### 3.4 `BypassSession` 与 `WafBypassCoordinator`

`BypassSession` 是 `SessionManager` 的包装（应用传输层变换），`WafBypassCoordinator` 是顶层编排：拿 `waf_type` + `vuln_type` → 选策略 → 包 session → 调插件的 `verify_with_bypass()`。

**引擎侧只看到一个 `waf_bypass_coordinator` 对象**，不知道 11 个策略的存在。这是 [core/engine.py](../../core/engine.py) 能保持 132 行的原因。

---

## 4. 关键机制二：OAST 带外检测（D30）

[oast.py](../../lib/oast.py) 用标准库实现了一个完整的带外回调服务：

| 组件 | 作用 |
| --- | --- |
| `CallbackStore` | 回调记录存储（按 `interaction_id` 索引） |
| `CallbackHTTPHandler(BaseHTTPRequestHandler)` | 接收回调的 HTTP 处理器 |
| `OASTServer` | 回调服务器（`--oast-server`，默认 `127.0.0.1:5555`） |
| `OASTClient` | 探测端：生成 payload、发起请求、等待回调 |
| `generate_interaction_id()` | 生成唯一交互 ID |
| `build_payload_domain` / `build_payload_url` / `build_payload` | 构造带外 payload |
| `check_dns_callback` | DNS 回调检查 |
| `generate_batch_payloads` | 批量构造 |

带外检测的价值：**无回显漏洞（blind RCE / SSRF / Log4j JNDI）唯一可靠的确认手段**。Log4j 组件检测（`detect_log4j`）就接入了 OAST client。

**用标准库而非第三方 OAST 平台**的取舍：不需要外部网络与账号，内网可用；代价是需要目标能访问到扫描器的监听地址（因此有 `--oast-host` 参数）。

---

## 5. 关键机制三：组件版本检测（E2）

[component_detect.py](../../lib/component_detect.py) 覆盖 5 个组件，每个一个 `detect_*` 函数：

```
detect_fastjson / detect_spring_boot / detect_shiro / detect_nacos / detect_log4j
        ↓
ComponentDetector.detect_all(target, session, ruoyi_version=...)   # 统一编排
        ↓
to_scan_result(ComponentVersionResult)   # 转成标准 ScanResult（category='component'）
```

三个设计点：

1. **版本推断可借用若依版本**：`_infer_from_ruoyi_version(component, ruoyi_version)` —— 若依各版本内置的组件版本是已知的，识别出若依版本就能推断组件版本。这是**知识复用**，比逐个探测省请求。
2. **CVE 映射走数据文件**：`_load_cve_map()` 读 `data/component_cve_map.json`，`match_cve(component, version)` 做区间匹配。新增 CVE 只改 JSON。
3. **探测失败给 `fallback_note`**：无法识别版本时返回说明性文字而非空字符串，让报告能解释"为什么这项是 UNKNOWN"。

`detect_log4j` 接受可选 `oast_client`——只有带外回调才能确证 JNDI 注入。

**规格驱动扩展**：`_detect_by_spec` / `_make_spec_detector` 表明后来者可以用声明式规格（dict）定义新组件的探测方式，不必再写一个 `detect_*` 函数。

---

## 6. 关键机制四：nuclei YAML 兼容层（E4）

[nuclei_loader.py](../../lib/nuclei_loader.py) 让项目能直接加载 nuclei 社区的 YAML 模板。

### 6.1 数据模型

| 类 | 对应 nuclei YAML 结构 |
| --- | --- |
| `NucleiHttpRequest` | `http:` 下的请求定义 |
| `NucleiMatcher` | `matchers:` |
| `NucleiExtractor` | `extractors:` |
| `NucleiTemplate` | 整个模板 |
| `NucleiTemplatePlugin` | 把模板**包装成 `PluginBase` 子类** |
| `build_template_plugin(tpl, source)` | 动态生成插件类 |

`build_template_plugin` 是这个模块的关键——**把 YAML 变成类**，于是 nuclei 模板和原生插件在引擎里完全同质，走同一条执行与报告管线。

### 6.2 零依赖 YAML 解析

```python
def _try_import_yaml():        # 有 PyYAML 就用
def _parse_simple_yaml(content): # 没有就用内置简化解析器
```

nuclei 模板是简单结构（嵌套 dict/list + 标量），内置解析器够用。这样 nuclei 能力**不需要 `yaml` 可选依赖也能工作**（装了 PyYAML 则更健壮）。

### 6.3 DSL 白名单求值

```python
def _eval_dsl(expr, status_code, body, headers_str) -> bool
```

nuclei 的 matcher 支持 `dsl:` 表达式（如 `status_code == 200 && contains(body, 'xxx')`）。直接 `eval()` 用户提供的模板字符串是**远程代码执行漏洞**。

因此 `_eval_dsl` 采用**白名单求值**：只允许模板里出现预定义的函数与运算符，不满足即视为不匹配。这是安全边界的必要实现，也是本章最值得注意的一处防御。

配套的 `validate_template(filepath)` 在扫描前做静态校验——`--nuclei-validate` 就是它的 CLI 入口。

---

## 7. 关键机制五：插件仓库与签名（E5）

[plugin_repo.py](../../lib/plugin_repo.py) 是插件生态的供应链层。

### 7.1 函数族

```
user_plugin_dir()   → ~/.ruoyi-scan/plugins/
signing_dir()       → 签名密钥目录

export_plugins(out_dir)                     # 导出内置插件源码 + 元信息
build_manifest(out_dir, version, sign_key)  # 生成 manifest.json
_sign_manifest(manifest, sign_key)          # Ed25519 签名
verify_manifest(...)                        # 验签
download_and_install(...)                   # 远程更新并安装
load_user_installed_plugins()               # 加载用户目录插件
```

### 7.2 两道安全防线

**(a) 路径穿越防护**

```python
def _is_safe_rel(rel) -> bool     # 拒绝 ../ 与绝对路径
def _safe_join(base, rel)         # 校验后再拼接
```

更新的插件包来自网络，若 tar/zip 里含 `../../etc/xxx`，直接解压会覆盖系统文件。所有路径先过 `_is_safe_rel`。

**(b) Ed25519 验签 fail-closed**

`--plugin-update` 的描述写得很明确：

> 从模板仓库更新插件（默认官方仓库；**强制 Ed25519 验签，需 cryptography + 可信公钥**）

- 验签需要 `cryptography`（`[distributed]`/`all` 可选组里）；
- **缺可信公钥或验签失败 → 拒绝安装**（fail-closed），不是降级为"跳过验签"。

`_load_or_create_key()` / `_sync_default_pub()` 负责本地密钥与内置公钥的同步。`_github_api_fallback(url)` 提供 GitHub API 兜底下载路径。

### 7.3 `load_user_installed_plugins()`

作为插件发现的第 4 条路径被 orchestrator 调用，失败时只 `logger.debug`——**用户插件目录损坏不应导致扫描起不来**。

---

## 8. 告警通知（D21）

[notifier.py](../../lib/notifier.py) 支持 5 种通道：

| 通道 | 函数 | 协议 |
| --- | --- | --- |
| 通用 Webhook | `send_webhook` | POST JSON |
| 钉钉 | `send_dingtalk` | 机器人 Webhook |
| 企业微信 | `send_wechat` | 机器人 Webhook |
| 飞书 | `send_feishu` | 机器人 Webhook |
| 邮件 | `send_email` | SMTP（`SMTP_HOST` 等环境变量） |

`_build_text_message` / `_build_markdown_message` / `_build_email_html` 提供三种消息体形态；`parse_notify_arg` 解析 `--notify webhook=https://...` 形式的多值参数；`send_notifications` 统一派发。

**每个通道一个函数、不抽象成"Provider 接口"**：5 个通道的消息格式（钉钉 vs 飞书 vs 企微的 JSON schema）差异大且稳定，抽象层的收益低于复杂度。

---

## 9. CVE 数据同步（D32）

[cve_sync.py](../../lib/cve_sync.py) 是四层数据源 + 缓存的组合：

```
lookup_cve(cve_id, use_cache=True, api_key=None)
  ├─ load_from_cache(cve_id)             # 本地 JSON 缓存（get_cache_path/save_to_cache）
  ├─ lookup_offline(cve_id)              # data/cve_offline.json（内网模式）
  ├─ query_nvd_api(cve_id, api_key)      # NVD（parse_nvd_response）
  ├─ query_ghsa(cve_id, token)           # GitHub Security Advisory（parse_ghsa_response）
  └─ query_cnvd(keyword)                 # CNVD（HTML 解析，parse_cnvd_response）
```

| 类/函数 | 作用 |
| --- | --- |
| `CVEInfo` | 归一化的 CVE 数据结构 |
| `extract_cve_ids_from_plugins()` | 从所有插件的 `cve` 类属性反查 CVE 清单 |
| `build_cve_update_report(...)` | 生成 CVE 更新报告 |
| `batch_lookup_cves(...)` | 批量查询 |
| `clear_cache()` | 清缓存 |

**「本地缓存 → 离线库 → 三个在线源」的降级顺序**是内网可用的关键：离线库让 `--cve-offline` 完全不需要联网。

**归一化 `CVEInfo` 的价值**：NVD / GHSA / CNVD / 离线库的原始字段名完全不同，统一成 `CVEInfo` 后，上层（报告、`component_cve_map`）只认一种结构。

---

## 10. AI 能力：生成与自验证闭环（E7/G3）

### 10.1 `ai_generator` — 生成插件

```
generate_ai_plugin(description, name, model, api_key, base_url)
  ├─ _llm_complete(...)        # 有 Key：调 LLM（OpenAI 兼容接口）
  └─ _rule_fallback(...)       # 无 Key：规则模板降级
  ↓
_clean_code(source)            # 去 markdown 围栏等
  ↓
_write_source(path, source)    # 落盘
```

**无 Key 时不报错而是降级为规则模板**——保证 `--ai` 在任何环境都能产出可用的插件骨架。

`_load_prompt_template()` 从文件加载提示词模板，把 prompt 与代码分离。

### 10.2 `ai_validate` — 生成即验证

这是项目里最"工程化"的 AI 设计：**生成的插件必须通过靶场三态验证才算通过**。

```
validate_generated_source(name, category, source, max_retries)
  → 写临时文件 → validate_ai_plugin(filepath) → 不合格则重试（最多 max_retries 轮）
  ↓
decide_install_path(filepath, category, verdict)   # 通过才决定安装路径
```

| 函数 | 作用 |
| --- | --- |
| `_LabHandle` | 拉起签名靶场（lab）并管理其生命周期 |
| `load_plugin_classes(filepath)` | 从生成的文件加载插件类 |
| `_run_plugin_on_lab(plugin_cls, target)` | 在靶场上跑插件 |
| `validate_ai_plugin(filepath, port)` | 完整验证流程，返回 verdict |
| `validate_generated_source(...)` | **生成 → 验证 → 失败重试**的闭环 |

靶场是「签名靶场」——即已知漏洞存在/不存在的地面真值（见 [07 章](07-desktop-deploy.md#3-lab-靶场)）。**三态判定给了 AI 生成一个客观的验收标准**：插件在 vuln 模式下必须 CONFIRMED，在 safe 模式下必须 SAFE。

这就把"AI 生成的代码看起来对不对"变成了"AI 生成的代码在靶场上的行为对不对"。

### 10.3 `ai_triage` — UNKNOWN 降噪

```
cluster_unknowns(results)       # 按证据聚类（_rule_classify 规则分类）
  ↓
triage_unknowns(...)            # 每组分流
  └─ _llm_classify_group(...)   # 可选 LLM 辅助归类
```

**先规则聚类、再可选 LLM**：聚类本身不依赖 LLM，因此无 Key 也能工作；LLM 只用于对聚类结果做更细的语义归类。这是"AI 是可选项而非依赖"这一原则的延续。

`--ai-triage` 在 dispatcher 里有显式守卫——必须配合扫描模式，因为它需要扫描产出的 UNKNOWN 结果作为输入。

### 10.4 `ai_report` — 报告解读

`generate_analysis(...)` 用 LLM 生成漏洞分析摘要；`_template_summary(...)` 是无 Key 时的模板降级。同样遵循"AI 可选"原则。

---

## 11. 分布式扫描（D36）

[distributed.py](../../lib/distributed.py) 是一个**基于 Redis 的极简分布式框架**：

| 类 | 角色 |
| --- | --- |
| `ScanTask` / `TaskResult` | 可序列化的任务与结果 |
| `DistributedTaskQueue` | Redis 队列（任务分发 + 结果回收） |
| `DistributedRateLimiter` | **全局**限速（跨 worker 共享） |
| `MasterNode` | 分发任务、汇总结果 |
| `WorkerNode` | 拉任务、执行、回传 |
| `StandaloneDistributor` | 单机多进程模式 |

对应的 CLI 入口：`run_distributed_master_mode` / `run_distributed_worker_mode` / `run_distributed_standalone_mode`。

### 11.1 `DistributedRateLimiter` 的价值

单机限速器（`core/engine.py` 的令牌桶）只能在**本进程内**限速。分布式场景下 N 个 worker 各自限速，对目标的实际压力是 N 倍——**恰恰违背了限速的初衷**。

因此需要一个跨进程的全局限速器。这类实现通常用 **Redis Lua 脚本保证原子性**（读计数 + 判断 + 写回必须是一个原子操作，否则并发下会超发）。`--distributed-rate` 就是这个全局限速的开关。

### 11.2 `--distributed-rate` 与 `--rate` 的区别

| 参数 | 作用域 |
| --- | --- |
| `--rate` | 单进程内限速（`core/engine.py`） |
| `--distributed-rate` | **全局**限速（Redis，跨所有 worker） |

---

## 12. 缓存与 CI

### 12.1 结果缓存（D37）

```python
generate_cache_key(target, plugin_config, scan_mode)          # 扫描级 key
generate_plugin_cache_key(target, plugin_name, plugin_config) # 插件级 key
```

两个 key 生成函数分开，是因为缓存可以按**扫描粒度**或**插件粒度**命中。

| 组件 | 作用 |
| --- | --- |
| `CacheStorage` | SQLite 存储（`--cache-db`，默认 `data/scan_cache.db`） |
| `ScanCache` | 缓存门面（TTL 管理、统计、清理） |
| `cached_scan(cache, target_arg, plugin_name, ttl)` | **装饰器**，可直接包裹扫描函数 |

CLI 入口：`--cache-stats` / `--cache-clear` / `--cache-clear-all`，分别对应 `run_cache_stats_mode` / `run_cache_clear_mode`。

### 12.2 CI 集成（D28）

```python
should_fail_ci(results, severity_threshold)              # 是否有超阈值漏洞
get_ci_exit_code(results, severity_threshold, has_error) # 计算退出码
format_ci_summary(...) / format_ci_vulns(...)            # 输出格式
generate_ci_config(platform, output_path)                # 生成 github/gitlab/jenkins 配置
```

退出码三段式（0 通过 / 1 超阈值 / 2 异常）与 `cli/preflight.py` 的 `EXIT_UNREACHABLE=3` 刻意错开，让流水线能区分四种结果。

---

## 13. 定时扫描与配置

### 13.1 `scheduler.py`（E9）

```python
parse_schedule_expr(expr)   # 解析 cron 5 段式 或 every:<秒>
class ScanScheduler:        # start() / shutdown() / add_job()
```

被 [api/app.py](../../api/app.py) 的 `lifespan` 在 startup 时 `start()`、shutdown 时 `shutdown()`。加载失败则降级为无调度模式（`scheduler = None`），不影响主服务。

### 13.2 `config_loader.py`（D27）

```python
load_yaml_config(filepath)               # 优先 PyYAML，回退 _simple_yaml_parse
normalize_config_keys(config)            # 键名归一（- 与 _ 互换等）
apply_config_to_args(args, filepath)     # 回填到 argparse Namespace
create_example_config(filepath)          # 生成示例配置
```

`_get_parser_defaults()` / `set_parser_defaults()` 的存在揭示了一个巧妙做法：**先用 parser 的默认值建立基线，再只回填"用户没在命令行显式指定"的项**。这是"命令行优先于配置"原则的实现基础（见 [02 章 §2](02-entrypoint-cli.md#2-main-的初始化顺序)）。

---

## 14. 本章小结

- `lib/` 是**可选能力集**：任何一个模块加载失败都只降级该能力，不影响主扫描。
- 三个机制值得单独记住：
  - **WAF 绕过**用 11 个策略 + `BypassSession` 包装，引擎侧只见一个 coordinator；
  - **nuclei 兼容层**把 YAML 动态变成插件类（`build_template_plugin`），并**用白名单求值 `_eval_dsl` 防止模板 RCE**；
  - **插件仓库**的路径穿越防护 + Ed25519 fail-closed 验签，是供应链安全的两道硬防线。
- AI 相关四个模块都遵循同一原则：**LLM 是增强，不是依赖**——无 Key 一律降级为规则/模板实现。
- `ai_generator` + `ai_validate` 构成了「生成 → 靶场三态验证 → 失败重试」的闭环，把 AI 代码质量变成可客观验收的指标。
- 分布式限速（`DistributedRateLimiter`）与单机限速（`core/engine.py`）解决的是不同问题，不要混用。

→ 下一章：[06 · Web API 与控制台](06-api-web.md)