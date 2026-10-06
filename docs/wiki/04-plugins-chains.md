# 04 · 插件体系与利用链

> 这一章回答：一个漏洞是怎么变成"一个插件"的？插件从哪来、怎么被选中、结果怎么变成报告里的一行？
>
> 相关源码：[plugins/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/plugins) · [chains/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/chains) · [data/](https://github.com/xiabai2008/Ruoyi-Scan/tree/main/data)

---

## 1. 设计纲领：每漏洞一插件

[plugins/base.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/base.py) 的开头直接引用了设计文档的纲领：

```
# 插件抽象基类（agents.md §5：每漏洞一插件，继承 PluginBase）
```

**一个漏洞 = 一个类 = 一个文件**。这条纪律带来三个可预期的好处：

1. 新增漏洞不改任何既有文件（只在包 `__init__.py` 里加一行注册）；
2. 插件的元信息（CVE/CVSS/修复建议/复现命令）与检测逻辑同居一处，不会漂移；
3. `--plugin-list`、报告、API `/api/plugins` 都能直接从类属性生成，无需额外元数据表。

代价是文件数量：53 个已注册插件 = 53 个文件 + 4 个 `__init__.py`。

---

## 2. `PluginBase` 契约

### 2.1 类属性（元信息）

所有字段都是**类属性**，不在 `__init__` 里赋值——因为插件实例是引擎每轮新建的（`plugin_cls()`），元信息应属于类。

| 属性 | 默认 | 用途 |
| --- | --- | --- |
| `name` | `""` | 中文漏洞名（报告主键） |
| `cve` | `""` | CVE 编号（无 CVE 时填 CNVD 或 `N/A`） |
| `severity` | `"low"` | `high` / `medium` / `low` |
| `category` | `""` | **模式过滤键**：`recon` / `vuln` / `brute` |
| `description` | `""` | 漏洞描述 |
| `fix` | `""` | 修复建议（一句话概要） |
| `fix_detail` | `""` | D18 修复详情（代码/配置 diff、升级版本号、操作步骤，多行） |
| `reproduce` | `""` | D24 复现命令（可直接复制的 curl / Python 片段，多行） |
| `affected_versions` | `""` | D2 影响版本区间，如 `">=4.2,<4.6"`；空串 = 全版本适用 |
| `variant` | `""` | E1 适用变体，如 `"ruoyi-app"`；空串 = 全变体适用 |
| `cvss_vector` | `""` | D12 CVSS v3.1 向量 |
| `compliance` | `""` | D12 合规映射标签，如 `"等保2.0:8.1.3;OWASP:A03:2021"` |
| `vuln_type` | `""` | D7 漏洞类型（`sqli`/`xss`/`rce`/`file_read`/`auth`），供绕过策略匹配 |
| `supports_waf_bypass` | `False` | 是否支持 WAF 绕过 |
| `bypass_max_attempts` | `3` | 每策略算一次的最大绕过尝试数 |

### 2.2 方法

| 方法 | 抽象 | 作用 |
| --- | --- | --- |
| `verify(target, session)` | ✅ | **核心判定**，返回 `ScanResult`（三态） |
| `verify_with_bypass(target, bypass_session, bypass_ctx)` | — | D7 绕过验证；默认实现=用 `BypassSession` 调 `verify()` |
| `_build_result(status, url, evidence, extra)` | — | 构造结果的便捷方法，自动填充元信息、CVSS、合规 |
| `enrich(result)` | — | **幂等回填**：只填空值，不覆盖插件已写的值 |
| `meta()` | — | 返回元信息字典（API `/api/plugins` 用） |

### 2.3 `verify()` 的硬性约定

```python
@abstractmethod
def verify(self, target: str, session: "SessionManager") -> ScanResult:
    """执行检测，返回 ScanResult（三态判定）

    网络异常等不可判定情形必须返回 status=UNKNOWN，不得判为 SAFE。
    """
```

这是整个项目的**判定纪律**，写在了抽象方法的 docstring 里：

- `CONFIRMED` —— 有明确证据确认存在
- `SAFE` —— 有明确证据确认不存在
- `UNKNOWN` —— 无法判定（网络异常、响应异常、被 WAF 拦截等）

**绝不把"没检测出来"当成"不存在"**。这条规则决定了报告的可信度：`UNKNOWN` 会被单独统计并可由 G3 智能降噪处理，而不会被悄悄洗成 `SAFE`。

### 2.4 `_build_result()` 里的 `kind` 联动

```python
kind="vuln" if status == STATUS_CONFIRMED else "info"
```

`kind` 字段（`vuln`/`brute`/`dir`/`info`）**必须与 `status` 一致**：只有 CONFIRMED 才能是 `vuln`。`enrich()` 里还有一道兜底：

```python
if result.status != STATUS_CONFIRMED and result.kind == "vuln":
    result.kind = "info"
```

因为绝大多数插件是**直接构造 `ScanResult`** 而不是调 `_build_result()`，很容易忘掉这个联动。`enrich()` 的存在就是为了修这类不一致：

> 背景：绝大多数插件直接构造 `ScanResult` 而非调用 `_build_result()`，导致类上声明的 cve / cvss_vector / compliance / fix_detail / reproduce 等元信息从未进入结果对象，报告里这些字段恒为空。

`enrich()` 在引擎收集结果时统一调用，**只填空值**（因此对所有插件安全、幂等），把类属性上的元信息补进结果对象。

### 2.5 CVSS v3.1 计算（`cvss_score`）

`plugins/base.py` 里内联了一份完整的 CVSS v3.1 Base Score 实现，不引第三方库：

| 步骤 | 说明 |
| --- | --- |
| 解析向量 | 剥离 `CVSS:3.1/` 前缀，按 `/` 拆成 `k:v`；8 个基础指标（AV/AC/PR/UI/S/C/I/A）缺一即返回 `0.0` |
| ISS | `1 - ((1-C)(1-I)(1-A))` |
| Impact | `S:C` → `7.52*(ISS-0.029) - 3.25*(ISS-0.02)^15`；否则 `6.42*ISS` |
| Exploitability | `8.22 * AV * AC * PR * UI` |
| PR 权重 | `S:C` 时用专用表 `_CVSS_PR_SC`（`PR:L`=0.68 而非 0.62）——**跨安全边界所需权限门槛更高** |
| 封顶 | `impact <= 0` 直接 0；`S:C` 时额外乘 1.08 并与 10.0 取小 |
| 取整 | `math.ceil(base*10)/10` —— 规范要求的 **Roundup（向上取整到 0.1）**，不是四舍五入 |

「向上取整而非四舍五入」是 CVSS 规范里最容易被实现错的一处：`7.61` 必须报 `7.7`。

### 2.6 合规标签解析（`parse_compliance`）

```
"等保2.0:8.1.3;OWASP:A03:2021"  →  {"等保2.0": "8.1.3", "OWASP": "A03:2021"}
```

用 `split(":", 1)` 而非 `split(":")`——因为 `OWASP:A03:2021` 的右值里还有冒号。

---

## 3. 插件发现：五条路径

插件不是"扫描目录自动发现"，而是**五条显式路径叠加**（顺序即优先级，见 [03 章 §3.4](03-core.md#34-步骤-6插件来源的叠加顺序)）：

| # | 路径 | 入口函数 | 说明 |
| --- | --- | --- | --- |
| 1 | 内置包 `plugin_list` | [`load_plugins()`](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/loader.py) | 每个包 `__init__.py` 显式登记；**顺序 = 执行优先级** |
| 2 | 外部路径 | [`load_external_plugins()`](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/loader.py) | `--plugin-path` 目录或 `.py` 文件，模块名前缀 `_external_plugin_` 隔离 |
| 3 | 用户目录 | [`load_user_installed_plugins()`](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/plugin_repo.py) | `~/.ruoyi-scan/plugins/`（由 `--plugin-update` 安装） |
| 4 | entry_points | [`load_entry_point_plugins()`](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/loader.py) | `ruoyi_scan.plugins` 组，pip 安装即发现 |
| 5 | nuclei YAML | [`load_nuclei_templates()`](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/nuclei_loader.py) | E4 兼容层，把 YAML 模板包装成插件类 |

另外还有一个独立的 `discover_plugin_packages()`：遍历 `plugins/` 下所有子包（**排除 `chain`**，因为链步骤插件不参与常规扫描）。

**外部插件用模块名前缀隔离**的原因：若外部插件文件名与内置插件重名，直接 `import` 会污染 `sys.modules`，导致后续加载拿到错误的类。加前缀让两者共存。

**`plugin_list` 顺序即优先级**：各包注释里明确了排序原则——高危优先。

```python
plugin_list = [
    # 高危优先
    JeecgFreemarkerSstiPlugin,   # Freemarker SSTI RCE（high）
    ...
]
```

---

## 4. 插件清单

### 4.1 `plugins/ruoyi` — 20 个

| # | 类名 | 文件 | 覆盖点 |
| --- | --- | --- | --- |
| 1 | `DirectoryScanPlugin` | `directory_scan.py` | 目录/路径发现 |
| 2 | `FileReadPlugin` | `file_read.py` | 任意文件读取 |
| 3 | `JobInvokeTargetPlugin` | `job_invoke_target.py` | 定时任务 invokeTarget |
| 4 | `SqlInjectRolePlugin` | `sql_inject_role.py` | `/system/role/list` SQL 注入 |
| 5 | `SqlInjectDeptPlugin` | `sql_inject_dept.py` | `/system/dept/list` SQL 注入 |
| 6 | `FileUploadPlugin` | `file_upload.py` | 任意文件上传 |
| 7 | `JobRcePlugin` | `job_rce.py` | 定时任务 RCE |
| 8 | `ThymeleafSstiPlugin` | `thymeleaf_ssti.py` | Thymeleaf SSTI |
| 9 | `RuoyiFileReadPathPlugin` | `file_read_path.py` | 路径穿越文件读取 |
| 10 | `UnauthBatchPlugin` | `unauth_batch.py` | 未授权接口批量探测 |
| 11 | `RuoyiNacosUnauthPlugin` | `nacos_unauth.py` | Nacos 未授权 |
| 12 | `DruidBrutePlugin` | `druid_brute.py` | Druid 监控页口令 |
| 13 | `DefaultPasswordPlugin` | `default_password.py` | 默认口令 |
| 14 | `RuoyiCloudNacosPlugin` | `ruoyi_cloud_nacos.py` | 微服务版 Nacos |
| 15 | `RuoyiSwaggerUnauthPlugin` | `ruoyi_swagger_unauth.py` | Swagger 未授权 |
| 16 | `RuoyiGenRcePlugin` | `ruoyi_gen_rce.py` | 代码生成器 RCE |
| 17 | `Cve202546174ResetPwdScopePlugin` | `cve_2025_46174_resetpwd_scope.py` | 重置密码越权（CVE-2025-46174） |
| 18 | `Cve202570986SelectDeptTreePlugin` | `cve_2025_70986_select_dept_tree.py` | `selectDeptTree` SQL 注入（CVE-2025-70986） |
| 19 | `PlusAuthLoginProbePlugin` | `plus_auth_login.py` | Plus 版登录探测 |
| 20 | `PlusJobUnauthPlugin` | `plus_job_unauth.py` | Plus 版定时任务未授权 |

> 20 个文件全部登记进 `plugin_list`。

### 4.2 `plugins/spring` — 14 个

| # | 类名 | 文件 | 覆盖点 |
| --- | --- | --- | --- |
| 1 | `Spring4shell` | `spring4shell.py` | Spring4Shell RCE |
| 2 | `SpringGatewayRce` | `gateway_rce.py` | Gateway Actuator RCE |
| 3 | `SpringActuatorEnvRce` | `actuator_env_rce.py` | Actuator env 属性注入 RCE |
| 4 | `SpringJolokiaRce` | `jolokia_rce.py` | Jolokia RCE |
| 5 | `SpringJolokiaMletRce` | `jolokia_mlet_rce.py` | Jolokia MLet RCE |
| 6 | `SpringCloudFunctionRce` | `cloud_function_rce.py` | Cloud Function SpEL RCE |
| 7 | `SpringH2ConsoleRce` | `h2_console_rce.py` | H2 Console RCE |
| 8 | `SpringActuatorUnauth` | `actuator_unauth.py` | Actuator 未授权 |
| 9 | `SpringHeapdumpLeak` | `heapdump_leak.py` | heapdump 泄露 |
| 10 | `SpringMappingsLeak` | `mappings_leak.py` | mappings 接口泄露 |
| 11 | `SpringTraceLeak` | `trace_leak.py` | trace 泄露 |
| 12 | `SpringCloudConfig` | `spring_cloud_config.py` | Cloud Config 泄露 |
| 13 | `SpringBootAdmin` | `spring_boot_admin.py` | Boot Admin 暴露 |
| 14 | `SpringDataRest` | `spring_data_rest.py` | Data REST 暴露 |

### 4.3 `plugins/common` — 11 个（`plugin_list` 登记）

| # | 类名 | 文件 | 覆盖点 |
| --- | --- | --- | --- |
| 1 | `GitLeak` | `git_leak.py` | `.git` 泄露 |
| 2 | `EnvLeak` | `env_leak.py` | `.env` 泄露 |
| 3 | `BackupScan` | `backup_scan.py` | 备份文件泄露 |
| 4 | `RedisUnauth` | `redis_unauth.py` | Redis 未授权 |
| 5 | `CorsMisconfig` | `cors_misconfig.py` | CORS 配置错误 |
| 6 | `SwaggerLeak` | `swagger_leak.py` | Swagger 泄露 |
| 7 | `SourceLeak` | `source_leak.py` | 源码泄露 |
| 8 | `MinioUnauth` | `minio_unauth.py` | MinIO 未授权 |
| 9 | `RocketmqUnauth` | `rocketmq_unauth.py` | RocketMQ 未授权 |
| 10 | `DirListing` | `dir_listing.py` | 目录列表 |
| 11 | `TraceMethod` | `trace_method.py` | TRACE 方法 |

> ⚠️ **`shiro_rememberme.py` 存在但未登记进 `plugin_list`**——包内有 12 个 `.py`，只登记了 11 个。该文件的探测思路被 [lib/component_detect.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/lib/component_detect.py) 的 Shiro 组件版本检测复用。这是文档漂移清单中的一项（见 [README](README.md#五文档与实现的一致性说明)）。

### 4.4 `plugins/jeecgboot` — 8 个

| # | 类名 | 文件 | 覆盖点 |
| --- | --- | --- | --- |
| 1 | `JeecgFreemarkerSsti` | `freemarker_ssti.py` | Freemarker SSTI RCE（high） |
| 2 | `JeecgSqlInjectQueryUser` | `sql_inject_query_user.py` | `queryUserByDepId` SQL 注入（high） |
| 3 | `JeecgSqlInjectJmreport` | `sql_inject_jmreport.py` | jmreport SQL 注入（high） |
| 4 | `JeecgFileUploadJmreport` | `file_upload_jmreport.py` | jmreport 任意文件上传（high） |
| 5 | `JeecgFileReadDownload` | `file_read_download.py` | 任意文件读取（high） |
| 6 | `JeecgJmreportListUnauth` | `jmreport_list_unauth.py` | 报表未授权（medium） |
| 7 | `JeecgDictUnauth` | `dict_unauth.py` | 字典越权（medium） |
| 8 | `JeecgDefaultPassword` | `default_password.py` | 默认口令（brute） |

这个包的战略意义写在 [plugins/jeecgboot/__init__.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/plugins/jeecgboot/__init__.py) 的注释里：

> JeecgBoot 插件包（F5：第一个拓展框架）
> 定位：证明基建通用性——指纹/路由/三态/报告零改动接入新框架

**它是架构通用性的证明物**：接入 JeecgBoot 时，`core/` 一个文件都没改，只加了「特征库数据 + 一个插件包 + 一行路由映射」。

### 4.5 合计

| 包 | 登记数 |
| --- | --- |
| `plugins.ruoyi` | 20 |
| `plugins.spring` | 14 |
| `plugins.common` | 11 |
| `plugins.jeecgboot` | 8 |
| **合计** | **53** |

> **插件数量有三个口径，勿混用**：
> - **57** = `plugins/` 下插件文件总数（`scripts/verification_matrix.py` 按文件统计，含未登记的 `shiro_rememberme.py` 与 `plugins/chain/` 的 3 个链步骤文件）；
> - **53** = `plugin_list` 登记总数（上表合计，**本 Wiki 与 README 统一采用此口径**）；
> - **51** = 通用目标实际执行数（`Router().resolve()` 减去 2 个 RuoYi-Plus 变体专属插件，与 [tests/test_fingerprint.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/tests/test_fingerprint.py) 断言一致）。
>
> README 原先的「51 / 若依 18」即第三种口径，已统一为 53 / 20 并保留 Plus 专属说明。详见 [README 的文档漂移清单](README.md#五文档与实现的一致性说明)。

---

## 5. 路由：指纹怎么变成插件包

[core/router.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/router.py) 的映射表：

```python
mapping = {
    "ruoyi": "plugins.ruoyi", "ruoyi-cloud": "plugins.ruoyi",
    "ruoyi-vue3": "plugins.ruoyi", "ruoyi-app": "plugins.ruoyi",
    "ruoyi-plus": "plugins.ruoyi", "ruoyi-cloud-plus": "plugins.ruoyi",
    "ruoyi-magic": "plugins.ruoyi",
    "spring": "plugins.spring",
    "jeecgboot": "plugins.jeecgboot",
}
```

| 方法 | 过滤维度 |
| --- | --- |
| `candidates(fp)` | cms + variant（**不过滤版本**） |
| `resolve(fp)` | cms + variant + `affected_versions` |
| `resolve_by_name(cms)` | 仅 cms（手动指定时无版本信息） |

**7 个若依变体共享 `plugins.ruoyi`**：差异靠插件类上的 `variant` / `affected_versions` 表达。这样包数量可控，但代价是 `plugins/ruoyi` 内部要靠属性区分适用面。

**`candidates()` 单独存在**是为版本对照矩阵服务——矩阵必须看"过滤前"的全集才有信息量（见 [03 章 §3.6](03-core.md#36-步骤-8版本矩阵用未过滤候选集)）。

---

## 6. 利用链（D6）

### 6.1 链的定位

插件回答"某个漏洞存不存在"，**链回答"这些漏洞串起来能走多远"**。这是从「漏扫」到「渗透验证」的跃迁，也是安服交付里最有说服力的部分。

### 6.2 注册表与惰性导入

[chains/registry.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/chains/registry.py) 用 `name → (模块路径, 变量名)` 的字典登记三条链：

```python
_CHAIN_REGISTRY = {
    "ruoyi_sql_to_rce": ("chains.ruoyi_sql_to_rce", "CHAIN"),
    "ruoyi_defaultpw_to_webshell": ("chains.ruoyi_defaultpw_to_webshell", "CHAIN"),
    "ruoyi_nacos_to_dbcreds": ("chains.ruoyi_nacos_to_dbcreds", "CHAIN"),
}
```

两个设计点：

1. **惰性导入**：`get_chain()` 里才 `importlib.import_module`。不用 `--chain` 时零导入开销。
2. **`list_chains()` 不导入链模块**，而是另存一份元信息字典（`_META`）。这样 `--chain-list` 极快，且**避免"列个链还要把所有链模块的依赖都加载一遍"**的副作用。代价是元信息有两处（`list_chains` 的 `_META` 与链模块里的 `ChainDef`），存在漂移风险。

`register_chain()` 允许第三方插件替换内置链（**同名直接覆盖，不报重复注册错误**）——这是刻意的扩展点。

### 6.3 链定义契约

```python
# 变量名 CHAIN 是 registry 的注册契约（链定义模块须导出同名变量），改名会破坏惰性加载
CHAIN = ChainDef(...)
```

变量名 `CHAIN` 是 `_CHAIN_REGISTRY` 里第二个元素指定的，**改名会静默失效**（`getattr` 抛 `AttributeError`）。代码里有注释显式警告。

### 6.4 三条链

| 链名 | 路径 | 严重度 | 影响版本 |
| --- | --- | --- | --- |
| `ruoyi_sql_to_rce` | SQL 注入 → 文件读取配置 → 定时任务 RCE | high | `>=4.0,<4.7` |
| `ruoyi_defaultpw_to_webshell` | 默认口令 → 登录链 → 任意文件上传 → webshell | high | — |
| `ruoyi_nacos_to_dbcreds` | Nacos 未授权 → 配置泄露 → 数据库凭证 | high | — |

> `ruoyi_defaultpw_to_webshell` 的描述里明确写了「上传 JSP 探针文件验证可执行性（**非真实 webshell**）」——链的产物是"证明可执行"，不是"真的驻留后门"。这是**合规边界**的自觉。

### 6.5 逐行解剖 `ruoyi_sql_to_rce`

[chains/ruoyi_sql_to_rce.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/chains/ruoyi_sql_to_rce.py)：

```
步骤 1: sql_inject     on_fail=abort      ← 链路起点，失败则整链无意义
步骤 2: config_read    depends_on=[sql_inject]  on_fail=continue
步骤 3: job_rce        depends_on=[sql_inject]  on_fail=continue   ← 只依赖步骤 1，不依赖步骤 2
```

三个关键决策：

**(a) `on_fail` 的语义分层**

| 值 | 含义 | 用在 |
| --- | --- | --- |
| `abort` | 整链终止 | 起点步骤（后续所有步骤都以它为前置） |
| `continue` | 跳过依赖此步的支线，继续其他支线 | 支线步骤 |

**(b) `job_rce` 只依赖 `sql_inject`，不依赖 `config_read`**

注释写得很清楚：

> RCE 验证仅依赖 sql_inject（而非 config_read）：配置读取失败（continue）不阻塞该支线

如果写成 `depends_on=["sql_inject", "config_read"]`，配置读取失败就会连带跳过 RCE 验证——**丢掉了本来能拿到的结论**。依赖边要表达"真正的前置条件"，不是"执行顺序"。

**(c) `outputs` 的敏感度前缀**

```python
outputs={"db_name": "extra:db_name"}                                    # 附加事实，明文
outputs={"db_password": "secret:db_password",                           # 凭证类，脱敏
         "redis_password": "secret:redis_password"}
```

`secret:` → 脱敏存储（报告里不出现明文口令）；`extra:` → 明文保留。这个前缀约定在链定义注释里被显式声明为契约。

### 6.6 链步骤插件

`plugins/chain/` 下是**链专用的步骤插件**，不参与常规扫描（因此 `discover_plugin_packages()` 显式排除 `chain`）：

| 文件 | 提供的步骤插件 |
| --- | --- |
| `sql_to_rce_steps.py` | `SQLInjectExtractPlugin` / `ConfigReadPlugin` / `JobRCEVerifyPlugin` |
| `defaultpw_to_webshell_steps.py` | 默认口令→上传 链的步骤 |
| `nacos_to_dbcreds_steps.py` | Nacos→凭证 链的步骤 |

### 6.7 `ChainEngine` 执行机制

[core/chain.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/core/chain.py) 的执行流程：

```
_topological_sort()       # 拓扑排序（ChainDef.validate() 已在加载期做过环检测）
  ↓ for step in 拓扑序
_evaluate_condition()     # 条件分支（condition 不满足则跳过该步）
  ↓
_execute_step()           # 实例化插件 → verify → 结果写入 ChainContext
  ↓ 失败时
_is_critical_failed()     # 判定是否关键失败
_propagate_abort()        # 按 on_fail 传播：abort 终止 / continue 跳过下游支线
  ↓ 全部结束
_aggregate_status()       # 聚合链状态 → ChainResult
```

`ChainContext` 的 `extract_outputs()` 按 `outputs` 映射把插件结果里的字段抽成变量（如 `db_name`），供后续步骤引用；`snapshot()` 提供执行过程的可回溯视图。

`ChainResult.to_scan_result()` 把链结果**转回标准 `ScanResult`**，因此链的产出与普通插件的产出在报告里走同一条管线，无需特殊渲染。

---

## 7. `data/` 数据资产

| 文件 | 大小 | 用途 |
| --- | --- | --- |
| `password.txt` | 10 KB | 完整口令字典（`--pass-level full`） |
| `pass_top1000.txt` | 9.5 KB | Top1000 口令（`--pass-level top1000`） |
| `pass_top100.txt` | 0.7 KB | Top100 口令（`--pass-level top100`） |
| `ruoyi.txt` | 15.5 KB | 若依路径字典（目录扫描） |
| `component_cve_map.json` | 7.5 KB | E2 组件 → CVE 映射表 |
| `cve_offline.json` | 5.1 KB | D32 离线 CVE 库（内网模式 `--cve-offline`） |
| `acceptance_baseline.json` | 1.7 KB | 验收基线 |
| `acceptance_report.json` / `_fixed.json` | 1.4 KB ×2 | 验收报告样例 |
| `scan_cache.db` | 20 KB | D37 结果缓存（SQLite） |
| `tasks.db` | 112 KB | D11 Web API 任务持久化（SQLite） |

字典分级由 [config/settings.py](https://github.com/xiabai2008/Ruoyi-Scan/blob/main/config/settings.py) 的 `PASSWORD_DICT_BY_LEVEL` 映射，`--pass-level` 在 orchestrator 第 3 步生效（见 [03 章 §3](03-core.md#3-scanorchestrator_run-九步主流程)）。

> `scan_cache.db` / `tasks.db` 是**运行时产物**，不应随仓库分发（已在 `.gitignore` 中）。

---

## 8. 写一个新插件（最短路径）

1. 在对应包下建文件，继承 `PluginBase`：
   ```python
   from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN
   from plugins.base import PluginBase

   class MyVulnPlugin(PluginBase):
       name = "某某漏洞"
       cve = "CVE-2025-XXXXX"
       severity = "high"
       category = "vuln"
       affected_versions = ">=4.2,<4.6"
       variant = ""
       cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N"
       compliance = "等保2.0:8.1.3;OWASP:A03:2021"
       description = "..."
       fix = "..."
       fix_detail = "..."
       reproduce = "curl ..."

       def verify(self, target, session):
           try:
               r = session.get(target + "path")
           except Exception as e:
               return self._build_result(STATUS_UNKNOWN, evidence=str(e))   # 网络异常 → UNKNOWN
           if "关键字" in r.text:
               return self._build_result(STATUS_CONFIRMED, url=r.url, evidence="命中关键字")
           return self._build_result(STATUS_SAFE)
   ```
2. 在包 `__init__.py` 的 `plugin_list` 里按**严重度位置**插入注册。
3. 用 `--plugin-check <path>` 校验、`--plugin-list` 确认加载。

也可用 `--plugin-new <name>` 生成脚手架，`--plugin-init <name>` 生成模板。

外部插件无需改仓库：`--plugin-path ./my_plugins/` 即可加载（模块名前缀自动隔离）。

---

## 9. 本章小结

- 插件契约的价值集中在三点：**类属性承载元信息**、**三态判定纪律**、**`enrich()` 幂等回填**。
- 插件发现是"五条显式路径叠加"，而非目录扫描——可控性与可审计性优先。
- `candidates()` 与 `resolve()` 的区分（是否过滤版本）是为版本矩阵服务的，容易误用。
- 利用链是小型 DAG 引擎：`on_fail` 分层语义、依赖边表达真实前置条件、`outputs` 用前缀区分敏感度——三个决策都直接影响链的结论质量。
- `plugins/jeecgboot` 是架构通用性的活证明：接新框架零改 `core/`。

→ 下一章：[05 · lib 工具库](05-lib.md)