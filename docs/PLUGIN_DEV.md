# Ruoyi-Scan 插件开发教程

本教程面向二次开发者，详细说明 Ruoyi-Scan 漏洞扫描器的插件系统架构、注册机制、CVSS/合规映射、WAF 绕过扩展与完整开发流程。所有代码示例均可在当前仓库直接运行。

---

## 目录

- [插件架构概览](#插件架构概览)
- [快速开始：第一个插件](#快速开始第一个插件)
- [PluginBase 详解](#pluginbase-详解)
- [三态判定最佳实践](#三态判定最佳实践)
- [插件注册方式](#插件注册方式)
- [WAF 绕过插件开发](#waf-绕过插件开发)
- [CVSS 评分与合规映射](#cvss-评分与合规映射)
- [插件测试](#插件测试)
- [完整插件示例](#完整插件示例)

---

## 插件架构概览

Ruoyi-Scan 采用「每漏洞一插件」的设计：每个漏洞 POC 是一个独立的 `PluginBase` 子类，引擎按指纹路由到对应插件包并依次调用 `verify()`，结果汇总为 `ScanResult` 列表。

### PluginBase 抽象基类

`PluginBase`（位于 `plugins/base.py`）是所有插件的根类，继承自 `abc.ABC`：

```python
from abc import ABC, abstractmethod

class PluginBase(ABC):
    # 类属性：插件元信息（子类覆盖）
    name = ""
    cve = ""
    severity = "low"   # high / medium / low
    category = ""
    # ... 其他元属性

    @abstractmethod
    def verify(self, target: str, session: "SessionManager") -> ScanResult:
        """执行检测，返回 ScanResult（三态判定）"""
        raise NotImplementedError
```

关键设计：

- **`verify()` 是唯一抽象方法**：子类必须实现，签名固定为 `verify(self, target, session)`。
- **元信息以类属性声明**：所有元数据（CVE、CVSS、合规、修复建议等）通过类属性暴露，引擎通过 `meta()` 一次性读取。
- **`_build_result()` 辅助方法**：自动把类属性填充到 `ScanResult`，避免样板代码。
- **`verify_with_bypass()` 可选覆盖**：WAF 绕过时引擎调用此方法，默认实现复用 `verify()`。

### 三态判定（CONFIRMED / SAFE / UNKNOWN）

定义在 `common/models.py`：

```python
STATUS_CONFIRMED = "CONFIRMED"   # 确认漏洞存在（有明确证据）
STATUS_SAFE       = "SAFE"       # 确认漏洞不存在（有明确反证）
STATUS_UNKNOWN    = "UNKNOWN"    # 无法判定（网络异常、超时、响应异常等）
```

铁律（见 `plugins/base.py` `verify()` 文档）：

> **网络异常等不可判定情形必须返回 `status=UNKNOWN`，不得判为 `SAFE`。**

把无法判定的情况判为 SAFE 会产生漏报；UNKNOWN 在统计中独立计数，不与 SAFE 混淆。

### 插件生命周期

引擎对一个目标执行插件的标准流程：

```
load  →  route  →  verify  →  result
 │        │        │          │
 │        │        │          └─ ScanResult（CONFIRMED / SAFE / UNKNOWN）
 │        │        └─ 调用 plugin.verify(target, session)
 │        └─ 按指纹 cms 选择插件包（plugins/<cms>/__init__.py 的 plugin_list）
 └─ core/loader.py: load_plugins / load_external_plugins / load_entry_point_plugins
```

1. **load**：扫描器启动时由 `core/loader.py` 加载所有插件类。三种加载方式见 [插件注册方式](#插件注册方式)。
2. **route**：`core/orchestrator.py` 根据指纹（`detect_cms`）选择 `plugins/<cms>/` 插件包，未识别时回退 `ruoyi` 包。
3. **verify**：依次实例化每个插件并调用 `verify(target, session)`。若 `supports_waf_bypass=True` 且响应被 WAF 拦截，引擎会再调用 `verify_with_bypass(target, bypass_session, bypass_ctx)`。
4. **result**：`verify()` 返回的 `ScanResult` 由 `ReportBuilder` 汇总，按 `severity` 分类统计、去重、生成报告。

---

## 快速开始：第一个插件

### 1. 用 `--plugin-init` 生成模板

最快的方式是使用内置脚手架（`lib/plugin_sdk.py`）：

```bash
python main.py --plugin-init my_plugin --category ruoyi
```

执行后生成 `plugins/ruoyi/my_plugin.py`：

```bash
[*]生成插件模板
    名称: my_plugin
    类别: ruoyi
[+]插件已生成: plugins/ruoyi/my_plugin.py
[*]下一步:
    1. 编辑 plugins/ruoyi/my_plugin.py 完善检测逻辑
    2. 运行 python main.py --plugin-check plugins/ruoyi/my_plugin.py 验证
    3. 运行 python main.py -u http://target/ 扫描
```

`--category` 决定输出目录（`plugins/<category>/`），常用值为 `ruoyi` / `spring` / `common`。若目录不存在会自动创建。

### 2. 最小可运行插件示例

以下是一个完整可运行的最小插件示例（继承 `PluginBase`，实现 `verify` 方法）：

```python
# plugins/ruoyi/my_plugin.py
# 最小可运行插件示例：检测 /demo/test 端点是否暴露
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import ok, no
from plugins.base import PluginBase


class MyPluginPlugin(PluginBase):
    """最小可运行插件示例"""
    name = "测试端点暴露"
    cve = "N/A"
    severity = "low"
    category = "vuln"
    description = "检测 /demo/test 端点是否可被未授权访问"
    fix = "关闭 /demo/test 端点或添加鉴权"
    # CVSS v3.1 向量 + 合规映射（可省略，默认 0.0 / 空）
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N"
    compliance = "等保2.0:8.1.4;OWASP:A05:2021"
    # WAF 绕过支持
    vuln_type = "info"          # info / sqli / xss / rce / file_read / auth / other
    supports_waf_bypass = False

    def verify(self, target, session):
        url = join_url(target, "/demo/test")
        try:
            resp = session.get(url, timeout=10)
        except Exception as e:
            # 铁律：网络异常 → UNKNOWN，绝不判 SAFE
            print(no(f"{self.name}（网络异常）"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=str(e),
            )

        text = resp.text or ""
        # 明确证据 → CONFIRMED
        if "demo-test-marker" in text:
            print(ok(f"存在{self.name}"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence="响应含 demo-test-marker 特征",
                fix=self.fix,
            )
        # 明确反证 → SAFE
        print(no(f"不存在{self.name}"))
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE,
            url=url, evidence="响应不含特征",
        )
```

### 3. 注册到 `plugin_list`

打开 `plugins/ruoyi/__init__.py`，在 `plugin_list` 列表中添加新插件：

```python
from plugins.ruoyi.my_plugin import MyPluginPlugin

plugin_list = [
    # ... 其他插件
    MyPluginPlugin,  # 新增插件
]
```

### 4. 验证与运行

```bash
# 静态 + 导入双重验证
python main.py --plugin-check plugins/ruoyi/my_plugin.py

# 列出所有插件元数据
python main.py --plugin-list

# 扫描
python main.py -u http://target/ -p
```

### 5. 插件文件结构

```
plugins/
└── ruoyi/                       # 插件包（按 CMS 分类）
    ├── __init__.py              # 声明 plugin_list = [PluginA, PluginB, ...]
    ├── base.py → (实际位于 plugins/base.py)
    ├── file_read.py             # FileReadPlugin
    ├── sql_inject_role.py       # SqlInjectRolePlugin
    ├── ...
    └── my_plugin.py             # MyPluginPlugin（新插件）
```

文件命名规范：插件文件名采用 `snake_case`，类名采用 `PascalCase + Plugin` 后缀（如 `file_read` → `FileReadPlugin`）。`lib/plugin_sdk.py::_to_pascal_case` 会自动完成转换。

---

## PluginBase 详解

### 类属性完整说明

`PluginBase`（`plugins/base.py` 第 130-155 行）暴露以下类属性，子类按需覆盖：

| 属性 | 类型 | 默认值 | 说明 |
|------|------|--------|------|
| `name` | `str` | `""` | 中文漏洞名（如「任意文件读取」），报告中展示 |
| `cve` | `str` | `""` | CVE 编号；无 CVE 时填 CNVD 编号或 `N/A` |
| `severity` | `str` | `"low"` | 危害等级：`high` / `medium` / `low` |
| `category` | `str` | `""` | 分类：`vuln` / `brute` / `recon` / `info` |
| `description` | `str` | `""` | 漏洞描述（一句话说明成因与入口点） |
| `fix` | `str` | `""` | 修复建议（一句话概要） |
| `fix_detail` | `str` | `""` | 修复详情：多行字符串，含升级版本号、代码 diff、配置加固、WAF 规则、合规映射 |
| `reproduce` | `str` | `""` | 复现命令：多行字符串，可直接复制执行的 `curl` 或 Python PoC |
| `affected_versions` | `str` | `""` | 影响版本范围（如 `>=4.0,<4.7`），空串表示全版本 |
| `cvss_vector` | `str` | `""` | CVSS v3.1 向量（如 `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`） |
| `compliance` | `str` | `""` | 合规映射标签（如 `等保2.0:8.1.4;OWASP:A01:2021`），分号分隔 |
| `vuln_type` | `str` | `""` | 漏洞类型标识：`sqli` / `xss` / `rce` / `file_read` / `auth` / `info_leak` / `info` / `other`，供 WAF 绕过策略匹配 |
| `supports_waf_bypass` | `bool` | `False` | 是否支持 WAF 绕过。`True` 时引擎在 WAF 命中后调用 `verify_with_bypass()` |
| `bypass_max_attempts` | `int` | `3` | 最大绕过尝试次数（每种策略算一次） |

**必填项**（`check_plugin` 强制校验，见 `lib/plugin_sdk.py`）：`name` / `severity` / `category` / `description` / `fix`。

**建议填写**（缺省会警告）：`cve` / `cvss_vector` / `compliance` / `fix_detail` / `reproduce`。

### `verify()` 方法签名与返回值

```python
@abstractmethod
def verify(self, target: str, session: "SessionManager") -> ScanResult:
    """执行检测，返回 ScanResult（三态判定）

    网络异常等不可判定情形必须返回 status=UNKNOWN，不得判为 SAFE。
    """
    raise NotImplementedError
```

- **参数**：
  - `target`：目标 URL（已归一化，保证以 `/` 结尾）。
  - `session`：`SessionManager` 实例，提供 `get()` / `post()` / `request()` / `close()` 方法（见 `core/session.py`）。
- **返回值**：`ScanResult` 数据类（`common/models.py`），最少需填充 `kind` / `name` / `status` / `url`。
- **铁律**：捕获到网络异常时返回 `STATUS_UNKNOWN`，**绝不**返回 `STATUS_SAFE`。

`SessionManager` 关键方法签名（来自 `core/session.py`）：

```python
def get(self, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response
def post(self, url: str, headers: Optional[Dict[str, str]] = None,
         data: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response
def request(self, method: str, url: str, headers: Optional[Dict[str, str]] = None, **kwargs) -> requests.Response
def close(self) -> None
```

### `_build_result()` 辅助方法

`PluginBase._build_result()`（`plugins/base.py` 第 184-209 行）自动从类属性填充 `ScanResult`，减少样板代码：

```python
def _build_result(
    self, status: str, url: str = "", evidence: str = "",
    extra: Optional[Dict[str, Any]] = None,
) -> ScanResult:
    """辅助方法：构造 ScanResult 并自动填充 kind/name/severity/fix

    插件在 verify() 中可直接用此方法构建结果，自动继承插件类属性。
    D12：自动填充 cve/cvss_score/cvss_vector/compliance。
    D18/D24：自动填充 fix_detail/reproduce。
    """
    return ScanResult(
        kind="vuln" if status == STATUS_CONFIRMED else "info",
        name=self.name,
        severity=self.severity,
        status=status,
        url=url,
        evidence=evidence,
        extra=extra or {},
        fix=self.fix or "",
        fix_detail=self.fix_detail or "",
        reproduce=self.reproduce or "",
        cve=self.cve or "",
        cvss_score=cvss_score(self.cvss_vector) if self.cvss_vector else 0.0,
        cvss_vector=self.cvss_vector or "",
        compliance=parse_compliance(self.compliance) if self.compliance else {},
    )
```

使用 `_build_result()` 可大幅简化 `verify()`，例如：

```python
def verify(self, target, session):
    url = join_url(target, "/some/path")
    try:
        resp = session.get(url)
    except Exception as e:
        return self._build_result(STATUS_UNKNOWN, url=url, evidence=str(e))

    if "vuln-marker" in resp.text:
        return self._build_result(
            STATUS_CONFIRMED, url=url,
            evidence="响应含 vuln-marker 特征",
            extra={"vuln_type": "sqli", "payload_class": "marker_probe"},
        )
    return self._build_result(STATUS_SAFE, url=url)
```

对比手写 `ScanResult(...)`：`_build_result()` 会自动填充 `cve` / `cvss_score` / `cvss_vector` / `compliance` / `fix_detail` / `reproduce`，避免每次都重复写字段。

### `verify_with_bypass()` WAF 绕过方法

```python
def verify_with_bypass(
    self, target: str, bypass_session: "SessionManager", bypass_ctx: Any
) -> ScanResult:
    """WAF 绕过验证（D7）：子类覆盖以实现绕过逻辑

    默认实现：复用 verify()，但使用 BypassSession（已应用传输层变换）。
    子类可覆盖此方法，利用 bypass_ctx.original_payload 和策略变形函数
    构造绕过 payload。
    """
    return self.verify(target, bypass_session)
```

- **参数**：
  - `target`：目标 URL（与 `verify()` 相同）。
  - `bypass_session`：`BypassSession` 实例（`lib/waf_bypass.py`），是 `SessionManager` 的轻量包装，已应用传输层变换（自定义 headers、`Transfer-Encoding: chunked`、源站 IP 直连等）。
  - `bypass_ctx`：`BypassContext` 实例（见下表）。
- **返回值**：`ScanResult`，与 `verify()` 一致（三态判定）。
- **调用时机**：仅当 `supports_waf_bypass=True` 且原 `verify()` 结果非 CONFIRMED 且响应被 WAF 拦截时，引擎才调用此方法。

`BypassContext` 字段（`lib/waf_bypass.py` 第 36-58 行）：

| 字段 | 类型 | 说明 |
|------|------|------|
| `waf_type` | `str` | WAF 标识（如 `cloudflare` / `safedog` / `aliyun_waf` / `modsecurity`） |
| `vuln_type` | `str` | 漏洞类型（与插件 `vuln_type` 一致） |
| `original_payload` | `str` | 原始 payload 字符串（插件可设置） |
| `original_url` | `str` | 原始请求 URL |
| `origin_ip` | `str` | 源站 IP（L4 策略使用，可能为空） |
| `attempt` | `int` | 当前尝试次数（第几次绕过，从 1 开始） |
| `max_attempts` | `int` | 最大尝试次数 |
| `strategy` | `WafBypassStrategy` | 当前策略实例，插件可调用 `strategy.tamper_payload(payload, ctx)` 变形 payload |

### `meta()` 元信息方法

```python
def meta(self) -> Dict[str, str]:
    """返回插件元信息字典"""
    return {
        "name": self.name,
        "cve": self.cve,
        "severity": self.severity,
        "category": self.category,
        "description": self.description,
        "fix": self.fix,
        "fix_detail": self.fix_detail,
        "reproduce": self.reproduce,
        "cvss_vector": self.cvss_vector,
        "cvss_score": cvss_score(self.cvss_vector),
        "compliance": parse_compliance(self.compliance),
        "affected_versions": self.affected_versions,
    }
```

用于 `--plugin-list` 命令、`vuln_wiki` 知识库生成、报告附录等场景。所有字段都自动从类属性读取，并自动计算 `cvss_score` 和解析 `compliance`。

---

## 三态判定最佳实践

### CONFIRMED：确认漏洞存在

**判定标准**：响应中包含明确的漏洞特征（不可复制的漏洞回显、敏感数据、命令执行结果等）。

```python
# 好：双关键词联合判定，降低误报
if match_all(resp.text, ["root", ":/"]):
    return self._build_result(
        STATUS_CONFIRMED, url=url,
        evidence="响应含 root 与 :/ 特征（/etc/passwd）",
    )
```

### SAFE：确认漏洞不存在

**判定标准**：响应明显是正常业务返回（HTTP 200 + 正常业务页面），或返回明确的「不存在」标志（如 404 / 重定向 / 业务错误页）。

```python
# 好：响应不含任何漏洞特征，且非异常状态码
if resp.status_code == 200 and "vuln-marker" not in resp.text:
    return self._build_result(STATUS_SAFE, url=url)
```

### UNKNOWN：无法判定

**判定标准**：以下情况必须判 UNKNOWN，**绝不判 SAFE**：

- 网络异常（`ConnectionError` / `Timeout` / `SSLError`）
- HTTP 5xx 服务端错误（可能是 WAF 拦截、服务过载）
- 响应体异常（空响应、非预期 Content-Type）
- 鉴权失效（302 跳转登录页）

```python
# 铁律：网络异常 → UNKNOWN
try:
    resp = session.get(url, timeout=10)
except Exception as e:
    return self._build_result(
        STATUS_UNKNOWN, url=url,
        evidence=f"网络异常: {e}",
    )

# 5xx 也归 UNKNOWN（可能服务过载或 WAF 拦截）
if resp.status_code >= 500:
    return self._build_result(
        STATUS_UNKNOWN, url=url,
        evidence=f"服务端错误: HTTP {resp.status_code}",
    )
```

### 误报 reduction 技巧：`match_all` 多关键词联合匹配

`lib/matcher.py::match_all(text, keywords)` 要求响应**同时包含**所有关键字（AND 关系），是降误报的核心工具：

```python
from lib.matcher import match_all

# 差：单关键字容易误报（业务页面里恰好出现 "root"）
if "root" in resp.text:
    return self._build_result(STATUS_CONFIRMED, ...)

# 好：多关键字联合（/etc/passwd 同时含 "root" 和 ":/"）
if match_all(resp.text, ["root", ":/"]):
    return self._build_result(STATUS_CONFIRMED, ...)
```

`lib/matcher.py` 还提供一系列针对特定漏洞的判定函数，可直接复用：

| 函数 | 用途 | 关键特征 |
|------|------|---------|
| `match_all(text, keywords)` | 通用 AND 联合判定 | 全部关键字命中 |
| `match_positive(text, positives, negatives)` | 正向命中 + 负向排除 | 含任一 positives 且不含任何 negatives |
| `match_file_read_leak(text)` | /etc/passwd 等敏感文件特征 | `root:x:0:0:` / `daemon:x:1:1:` 等 |
| `match_sql_error(text)` | SQL 报错注入特征 | `XPATH syntax error` / `SQLSTATE` 等 |
| `match_spring_actuator_env(text)` | Spring Actuator env 真实响应 | `propertySources` / `activeProfiles` |
| `match_heapdump_binary(text)` | Spring heapdump 二进制特征 | `JAVA PROFILE` / `jdbc:mysql://` |
| `match_h2_console(text)` | H2 Console 页面 | `<title>H2 Console</title>` |
| `match_jolokia_response(text)` | Jolokia JMX-HTTP 真实响应 | `reloadByURL` / `JMXConfigurator` |
| `match_spring4shell_response(text)` | Spring4Shell 利用响应 | 排除 `Bad Request` / `error` 后判定 |
| `match_cloud_function_spel(text)` | SpEL 求值结果 | 短数字字符串（如 `49`） |

示例：检测 Spring Actuator env 泄露：

```python
from lib.matcher import match_spring_actuator_env

if match_spring_actuator_env(resp.text):
    return self._build_result(
        STATUS_CONFIRMED, url=url,
        evidence="响应含 propertySources / activeProfiles 特征",
    )
```

---

## 插件注册方式

Ruoyi-Scan 支持三种插件注册方式，按推荐度排序：

### 方式 1：内置插件（`plugin_list`）

最常用方式。在 `plugins/<category>/__init__.py` 中声明 `plugin_list`：

**目录结构**：

```
plugins/
└── my_cms/                    # 新增 CMS 框架时只需建包
    ├── __init__.py             # 声明 plugin_list
    ├── vuln_a.py               # VulnAPlugin
    └── vuln_b.py               # VulnBPlugin
```

**`plugins/my_cms/__init__.py`**：

```python
from plugins.my_cms.vuln_a import VulnAPlugin
from plugins.my_cms.vuln_b import VulnBPlugin

plugin_list = [
    # 按危险度从高到低排序（high 在前）
    VulnAPlugin,  # 高危漏洞
    VulnBPlugin,  # 中危漏洞
]
```

**自动发现机制**（`core/loader.py::discover_plugin_packages`）：扫描 `plugins/` 下所有含 `__init__.py` 的子目录，自动注册为插件包，无需修改任何代码。排除 `chain`（链专用步骤插件，不参与主扫描引擎路由）。

```python
# core/loader.py 第 140-161 行
def discover_plugin_packages() -> List[str]:
    """自动发现所有插件包（消除硬编码，P1: 插件自动发现）"""
    _EXCLUDED = {"chain"}
    plugins_dir = os.path.join(os.path.dirname(os.path.dirname(__file__)), "plugins")
    packages = []
    for name in sorted(os.listdir(plugins_dir)):
        if name in _EXCLUDED:
            continue
        pkg_path = os.path.join(plugins_dir, name)
        if os.path.isdir(pkg_path) and os.path.isfile(os.path.join(pkg_path, "__init__.py")):
            packages.append(f"plugins.{name}")
    return packages
```

**加载方式**（`core/loader.py::load_plugins`）：按 `plugin_list` 顺序加载，元素可为类对象（推荐）或类名字符串。

### 方式 2：外部插件（`--plugin-path`）

适合临时调试、私有插件、客户环境部署。支持两种形式：

#### 目录形式

**目录结构**：

```
/path/to/my_plugins/
├── __init__.py             # 含 plugin_list = [MyPlugin, ...]
├── plugin_a.py             # PluginA
└── plugin_b.py             # PluginB
```

**`/path/to/my_plugins/__init__.py`**：

```python
from my_plugins.plugin_a import PluginA
from my_plugins.plugin_b import PluginB

plugin_list = [
    PluginA,
    PluginB,
]
```

#### 单文件形式

单个 `.py` 文件含 `PluginBase` 子类，无需 `__init__.py`：

```python
# /path/to/my_standalone_plugin.py
from plugins.base import PluginBase
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import ok, no


class StandalonePlugin(PluginBase):
    name = "独立插件示例"
    cve = "N/A"
    severity = "medium"
    category = "vuln"
    description = "通过 --plugin-path 加载的单文件插件"
    fix = "修复建议"

    def verify(self, target, session):
        url = join_url(target, "/some/path")
        try:
            resp = session.get(url)
        except Exception as e:
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=str(e),
            )
        if "marker" in resp.text:
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url, fix=self.fix,
            )
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE, url=url,
        )
```

**CLI 用法**（可多次指定，混合目录与文件）：

```bash
# 加载目录 + 单文件
python main.py -u http://target/ -p \
    --plugin-path /path/to/my_plugins \
    --plugin-path /path/to/my_standalone_plugin.py
```

**加载逻辑**（`core/loader.py::load_external_plugins` 第 28-66 行）：

- 目录形式：若有 `__init__.py` 则按包导入（调用 `load_plugins`），否则扫描所有非 `_` 开头的 `.py` 文件。
- 单文件形式：用 `importlib.util.spec_from_file_location` 动态加载，先找 `plugin_list`，找不到则自动扫描所有 `PluginBase` 子类（`__module__` 必须等于当前模块名）。

### 方式 3：PyPI 插件（`entry_points`）

适合公开发布的第三方插件包。`pip install` 后自动发现，无需 `--plugin-path`。

#### 完整的第三方插件包示例

**目录结构**：

```
ruoyi_scan_extra/
├── pyproject.toml
├── README.md
└── ruoyi_scan_extra/
    ├── __init__.py           # 声明 plugin_list
    └── extra_vuln.py        # ExtraVulnPlugin
```

**`ruoyi_scan_extra/pyproject.toml`**（核心是 `entry-points` 声明）：

```toml
[build-system]
requires = ["setuptools>=68.0", "wheel"]
build-backend = "setuptools.build_meta"

[project]
name = "ruoyi-scan-extra"
version = "0.1.0"
description = "Ruoyi-Scan 第三方插件扩展包"
requires-python = ">=3.8"
dependencies = [
    "ruoyi-scan>=1.1.0",  # 依赖主程序
    "requests>=2.28",
]

# 关键：注册到 ruoyi_scan.plugins entry-point 组
[project.entry-points."ruoyi_scan.plugins"]
extra-vuln = "ruoyi_scan_extra:plugin_list"
```

**`ruoyi_scan_extra/ruoyi_scan_extra/__init__.py`**：

```python
from ruoyi_scan_extra.extra_vuln import ExtraVulnPlugin

# entry-point 指向 plugin_list 变量
plugin_list = [
    ExtraVulnPlugin,
]
```

**`ruoyi_scan_extra/ruoyi_scan_extra/extra_vuln.py`**：

```python
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import join_url
from lib.colors import ok, no
from plugins.base import PluginBase


class ExtraVulnPlugin(PluginBase):
    name = "第三方扩展插件示例"
    cve = "CVE-2026-XXXXX"
    severity = "high"
    category = "vuln"
    description = "通过 pip install 自动发现的第三方插件"
    fix = "升级至最新版本"
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"

    def verify(self, target, session):
        url = join_url(target, "/some/vulnerable/path")
        try:
            resp = session.get(url)
        except Exception as e:
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=str(e),
            )
        if "extra-vuln-marker" in resp.text:
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url, fix=self.fix,
            )
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE, url=url,
        )
```

**使用流程**：

```bash
# 发布到 PyPI（或本地安装）
cd ruoyi_scan_extra
pip install .

# 安装后 ruoyi-scan 自动发现，无需 --plugin-path
python main.py -u http://target/ -p
python main.py --plugin-list   # 应能看到 ExtraVulnPlugin
```

**加载逻辑**（`core/loader.py::load_entry_point_plugins` 第 164-210 行）：

```python
# 查找所有 ruoyi_scan.plugins 组的 entry-points
eps = entry_points(group="ruoyi_scan.plugins")
for ep in eps:
    plugin_list = ep.load()  # 加载 entry-point 指向的对象
    if isinstance(plugin_list, list):
        result.extend(plugin_list)
    else:
        # 加载的是模块，尝试取 plugin_list 属性
        plugin_list = getattr(plugin_list, "plugin_list", [])
        if isinstance(plugin_list, list):
            result.extend(plugin_list)
```

entry-point 的 value 可以是：

- `module:plugin_list` — 直接指向 `plugin_list` 列表（推荐）。
- `module:SomeClass` — 指向单个插件类。
- `module` — 指向模块，自动取 `plugin_list` 属性。

---

## WAF 绕过插件开发

WAF 绕过是 Ruoyi-Scan 的 D7 阶段能力。当引擎检测到 WAF 命中且原 `verify()` 结果非 CONFIRMED 时，会自动调用支持绕过的插件的 `verify_with_bypass()`。

### 1. 启用 WAF 绕过支持

在插件类属性中设置：

```python
class MyPlugin(PluginBase):
    # ...
    vuln_type = "sqli"                  # 必填，供策略匹配
    supports_waf_bypass = True           # 启用绕过
    bypass_max_attempts = 3             # 最大尝试次数（默认 3）
```

`vuln_type` 决定哪些绕过策略可用（见 `lib/waf_bypass.py::StrategyRegistry`）：

| `vuln_type` | 可用策略 |
|------------|---------|
| `sqli` | 大小写混淆 / URL 编码 / 内联注释 / MySQL 版本注释 / BETWEEN 替换 / 双重 URL 编码 / 分块传输 / HPP |
| `xss` | 大小写混淆 / URL 编码 |
| `rce` | 大小写混淆 / URL 编码 / 双重 URL 编码 / 分块传输 |
| `file_read` | URL 编码 / 分块传输 |
| `auth` | 通用策略（大小写混淆 / URL 编码 / 分块传输） |
| `info_leak` | 通用策略 |
| `*` | 任意漏洞类型可用（策略自身声明） |

### 2. `verify_with_bypass()` 实现

默认实现是 `return self.verify(target, bypass_session)`，仅复用传输层变换（headers / chunked / origin IP）。若需要 payload 变形，需覆盖此方法：

```python
from lib.waf_bypass import BypassContext, BypassSession
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult


class SqlInjectPlugin(PluginBase):
    # ... 其他属性
    vuln_type = "sqli"
    supports_waf_bypass = True

    # 原始 payload（供绕过时变形）
    _ORIGINAL_PAYLOAD = "and extractvalue(1,concat(0x7e,(select database()),0x7e))"

    def verify(self, target, session):
        # 正常检测逻辑（不带绕过）
        ...

    def verify_with_bypass(self, target, bypass_session, bypass_ctx):
        """WAF 绕过验证

        Args:
            target: 目标 URL
            bypass_session: BypassSession 实例（已应用传输层变换）
            bypass_ctx: BypassContext（含 waf_type/vuln_type/strategy 等）
        """
        # 1. 用当前策略变形 payload
        strategy = bypass_ctx.strategy
        if strategy is not None:
            tampered_payload = strategy.tamper_payload(self._ORIGINAL_PAYLOAD, bypass_ctx)
        else:
            tampered_payload = self._ORIGINAL_PAYLOAD

        # 2. 用变形后的 payload 发请求（bypass_session 已应用传输层变换）
        url = join_url(target, "/vulnerable/endpoint")
        data = {"param": tampered_payload}

        try:
            resp = bypass_session.post(url, data=data)
        except Exception as e:
            # 铁律：绕过异常 → UNKNOWN（绝不判 SAFE）
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=f"绕过异常: {e}",
            )

        # 3. 判定（与 verify() 一致的三态）
        if "XPATH syntax error" in resp.text or "database()" in resp.text:
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=f"绕过成功（策略={bypass_ctx.strategy.strategy_id}）",
                fix=self.fix,
            )

        # 4. 绕过未成功，返回 SAFE 或 UNKNOWN（不能 CONFIRMED）
        #    引擎会自动尝试下一个策略
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE,
            url=url, evidence="绕过后仍未命中特征",
        )
```

### 3. `bypass_ctx` 参数说明

`BypassContext` 提供以下信息供插件决策（见 `lib/waf_bypass.py` 第 36-58 行）：

| 字段 | 用途 |
|------|------|
| `waf_type` | 当前 WAF 类型（如 `cloudflare`），插件可据此选择针对性 payload |
| `vuln_type` | 当前漏洞类型（与插件 `vuln_type` 一致） |
| `original_payload` | 原始 payload（插件可设置以便引擎记录） |
| `original_url` | 原始请求 URL |
| `origin_ip` | 源站 IP（L4 策略使用，可能为空） |
| `attempt` | 当前尝试次数（第几次绕过，1 开始） |
| `max_attempts` | 最大尝试次数 |
| `strategy` | 当前策略实例，可调用 `strategy.tamper_payload(payload, ctx)` 变形 payload |

### 4. 绕过策略示例

`lib/waf_bypass.py` 内置 11 个策略，按层级分类：

| 层级 | 策略 ID | 名称 | 适用 WAF | 适用漏洞 |
|------|--------|------|---------|---------|
| L1 | BP-GEN-1 | 大小写混淆 | `*`（通用） | sqli / xss / rce |
| L1 | BP-SD-1 | 内联注释变形 | safedog / aliyun_waf / modsecurity | sqli |
| L1 | BP-SD-1b | MySQL 版本注释 | safedog / aliyun_waf | sqli |
| L1 | BP-SD-3 | BETWEEN 替换 | safedog / modsecurity | sqli |
| L2 | BP-GEN-2 | URL 编码 | `*`（通用） | sqli / xss / rce / file_read |
| L2 | BP-CP-1 | 双重 URL 编码 | chaitin / modsecurity | sqli / rce |
| L3 | BP-GEN-3 | 分块传输 | `*`（通用） | sqli / rce / file_read |
| L3 | BP-ALI-3 | HPP 参数污染 | aliyun_waf / tencent_waf | sqli |
| L3 | BP-CP-2b | HTTP/1.0 降级 | chaitin / knownsec | `*` |
| L3 | BP-CF-2 | Googlebot 伪装 | cloudflare | `*` |
| L4 | BP-CF-1 | 源站 IP 直连 | cloudflare / baidu_waf / chaitin | `*` |

**三态判定保护矩阵**（`lib/waf_bypass.py` 第 11-16 行注释）：

- CONFIRMED 不绕过（已确认不绕过）
- 真 SAFE 不绕过（不误绕）
- 假 SAFE（被拦）尝试绕过，成功 → CONFIRMED，失败 → 原状态 + 标记
- UNKNOWN 尝试绕过，成功 → CONFIRMED，失败 → UNKNOWN + 标记（不降级）
- 绕过异常 → 原状态 + UNKNOWN 兜底（**绝不判 SAFE**）

成功绕过的 `ScanResult.extra` 会自动标记：

```json
{
  "waf_bypass": {
    "strategy_used": "BP-GEN-1",
    "strategy_name": "大小写混淆",
    "layer": "L1",
    "attempt": 1,
    "waf_type": "cloudflare"
  }
}
```

---

## CVSS 评分与合规映射

### CVSS v3.1 向量格式

`cvss_vector` 属性使用标准 CVSS v3.1 向量字符串（不带 `CVSS:3.1/` 前缀也可，引擎会自动处理）：

```python
cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
```

8 个基础指标：

| 指标 | 含义 | 取值 |
|------|------|------|
| `AV` | Attack Vector（攻击途径） | `N` 网络 / `A` 邻近 / `L` 本地 / `P` 物理 |
| `AC` | Attack Complexity（攻击复杂度） | `L` 低 / `H` 高 |
| `PR` | Privileges Required（所需权限） | `N` 无 / `L` 低 / `H` 高 |
| `UI` | User Interaction（用户交互） | `N` 不需要 / `P` 需要 |
| `S` | Scope（影响范围） | `U` 不变 / `C` 改变 |
| `C` | Confidentiality（机密性影响） | `H` 高 / `L` 低 / `N` 无 |
| `I` | Integrity（完整性影响） | `H` 高 / `L` 低 / `N` 无 |
| `A` | Availability（可用性影响） | `H` 高 / `L` 低 / `N` 无 |

### 合规映射格式

`compliance` 属性使用分号分隔的标签字符串，每项格式为 `标准名:条款`：

```python
compliance = "等保2.0:8.1.4;OWASP:A01:2021"
```

`parse_compliance("等保2.0:8.1.4;OWASP:A01:2021")` 返回：

```python
{
    "等保2.0": "8.1.4",
    "OWASP":   "A01:2021",
}
```

常见合规标准与条款示例：

| 标准 | 条款示例 | 说明 |
|------|---------|------|
| 等保2.0 | `8.1.3` | 输入校验 |
| 等保2.0 | `8.1.4` | 访问控制 |
| 等保2.0 | `8.1.5` | 安全审计 |
| OWASP Top 10:2021 | `A01:2021` | 失效的访问控制 |
| OWASP Top 10:2021 | `A03:2021` | 注入 |
| OWASP Top 10:2021 | `A05:2021` | 安全配置错误 |
| OWASP Top 10:2021 | `A06:2021` | 脆弱和过时的组件 |

### `cvss_score()` 自动计算

`plugins/base.py::cvss_score(vector)` 实现 CVSS v3.1 Base Score 计算（无需手填分数）：

```python
from plugins.base import cvss_score

# 完整向量
cvss_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
# → 9.8（Critical）

# 文件读取（仅机密性影响）
cvss_score("AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N")
# → 7.5（High）

# SQL 报错注入（需要低权限）
cvss_score("AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N")
# → 6.5（Medium）
```

权重表见 `plugins/base.py` 第 13-42 行，严格遵循 CVSS v3.1 规范（包括 Scope Changed 时的 PR 权重调整、Roundup 向上取整到 0.1 等）。

**自动填充机制**：`_build_result()` 和 `meta()` 会自动调用 `cvss_score(self.cvss_vector)` 填充 `ScanResult.cvss_score`，插件无需手动计算。

---

## 插件测试

### 1. `--plugin-check` 验证完整性

`lib/plugin_sdk.py::check_plugin` 提供两层验证：

```bash
python main.py --plugin-check plugins/ruoyi/my_plugin.py
```

输出示例：

```
[*]验证插件: plugins/ruoyi/my_plugin.py
────────────────────────────────────────────────
静态检查:
  ✓ 通过
导入检查:
  ✓ 通过
────────────────────────────────────────────────
[+]插件验证通过
```

**静态检查**（`check_plugin`）— 用正则表达式检查源代码：

- 必需属性是否声明：`name` / `severity` / `category` / `description` / `fix`
- 是否含 `verify(self, target, session):` 方法
- 是否导入 `ScanResult`
- 是否继承 `PluginBase`
- 建议属性（警告）：`cve` / `cvss_vector` / `compliance` / `fix_detail` / `reproduce`
- TODO 标记数量提示

**导入检查**（`check_plugin_by_import`）— 动态导入并实例化插件：

- 实际加载模块并查找 `PluginBase` 子类
- 实例化每个插件类，检查必需属性非空
- 检查 `verify` 方法存在
- 建议属性非空（警告）
- 多个插件类时警告（建议每文件一个）

### 2. 单元测试示例（mock session）

使用 `requests_mock` 模拟 HTTP 响应，无需真实目标：

```python
# tests/test_my_plugin.py
import os
import sys

import requests_mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED, STATUS_SAFE
from core.session import SessionManager
from plugins.ruoyi.my_plugin import MyPluginPlugin


def test_my_plugin_confirmed():
    """命中漏洞特征 → CONFIRMED"""
    plugin = MyPluginPlugin()
    session = SessionManager(timeout=5)

    with requests_mock.Mocker() as m:
        m.get(
            "http://target/demo/test",
            text="this is a demo-test-marker page",
            status_code=200,
        )
        result = plugin.verify("http://target/", session)

    assert result.status == STATUS_CONFIRMED
    assert "demo-test-marker" in result.evidence
    session.close()


def test_my_plugin_safe():
    """正常页面 → SAFE"""
    plugin = MyPluginPlugin()
    session = SessionManager(timeout=5)

    with requests_mock.Mocker() as m:
        m.get(
            "http://target/demo/test",
            text="normal page without any marker",
            status_code=200,
        )
        result = plugin.verify("http://target/", session)

    assert result.status == STATUS_SAFE
    session.close()


def test_my_plugin_network_error():
    """网络异常 → UNKNOWN（铁律）"""
    from common.models import STATUS_UNKNOWN

    plugin = MyPluginPlugin()
    session = SessionManager(timeout=5)

    with requests_mock.Mocker() as m:
        m.get(
            "http://target/demo/test",
            exc=requests_mock.exceptions.ConnectTimeout,
        )
        result = plugin.verify("http://target/", session)

    assert result.status == STATUS_UNKNOWN
    session.close()
```

运行：

```bash
pip install requests-mock
pytest tests/test_my_plugin.py -v
```

### 3. 签名靶场端到端测试

仓库内置签名靶场（`lab/` 目录，需安装 `pip install ".[lab]"`），用于端到端验证：

```python
# tests/test_my_plugin_e2e.py
import os
import sys

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from common.models import STATUS_CONFIRMED
from core.session import SessionManager
from plugins.ruoyi.my_plugin import MyPluginPlugin


@pytest.mark.skipif(
    not os.environ.get("RUN_E2E_TESTS"),
    reason="需启动签名靶场并设置 RUN_E2E_TESTS=1",
)
def test_my_plugin_e2e():
    """端到端：对真实签名靶场执行扫描"""
    plugin = MyPluginPlugin()
    session = SessionManager(timeout=10)

    # 假设靶场已启动在 http://127.0.0.1:5000/
    result = plugin.verify("http://127.0.0.1:5000/", session)

    assert result.status == STATUS_CONFIRMED
    session.close()
```

运行端到端测试：

```bash
# 1. 启动签名靶场
cd lab && python app.py &

# 2. 运行端到端测试
RUN_E2E_TESTS=1 pytest tests/test_my_plugin_e2e.py -v
```

测试规范参考 `tests/test_d7_plugins.py`（D7 阶段全量插件 WAF 绕过适配验证），其中演示了如何批量验证插件属性：

```python
def test_all_bypass_plugins_support_waf_bypass():
    """所有支持绕过的插件 supports_waf_bypass=True"""
    for plugin_cls, _ in _BYPASS_PLUGINS:
        assert plugin_cls.supports_waf_bypass is True, \
            f'{plugin_cls.__name__}.supports_waf_bypass 应为 True'
```

---

## 完整插件示例

以下是一个完整的 SQL 注入检测插件示例，包含所有类属性、`verify()`、`verify_with_bypass()`、CVSS 评分、合规映射、修复详情与复现命令。可直接复制到 `plugins/ruoyi/sql_inject_demo.py` 运行：

```python
# plugins/ruoyi/sql_inject_demo.py
# SQL 报错注入（demo）：完整插件示例，含 WAF 绕过、CVSS、合规、修复详情
from common.models import STATUS_CONFIRMED, STATUS_SAFE, STATUS_UNKNOWN, ScanResult
from core.http import host_of, join_url
from lib.colors import no, ok
from lib.matcher import match_sql_error
from plugins.base import PluginBase


class SqlInjectDemoPlugin(PluginBase):
    """SQL 报错注入检测插件（完整示例）

    演示内容：
    - 所有类属性（name/cve/severity/category/description/fix/fix_detail/reproduce）
    - CVSS v3.1 向量与合规映射
    - WAF 绕过支持（vuln_type/supports_waf_bypass/bypass_max_attempts）
    - verify() 三态判定实现
    - verify_with_bypass() payload 变形实现
    """

    # ===== 基础元信息 =====
    name = "SQL报错注入（demo）"
    cve = "CVE-2026-XXXXX"
    severity = "high"
    category = "vuln"
    description = (
        "/demo/sqlInject 端点的 username 参数拼接 SQL，"
        "可通过 extractvalue 报错注入泄露 database()、version() 等敏感信息"
    )
    fix = "对 username 参数做白名单校验，使用参数化查询，禁止拼接 SQL"

    # ===== 修复详情（多行字符串） =====
    fix_detail = (
        "【升级方案】升级至 demo-app 2.0.0+（该版本已修复 SQL 注入）\n"
        "【代码修复】修改 DemoMapper.xml，对 username 参数做白名单校验：\n"
        "  - 修改前：SELECT * FROM user WHERE username = '${username}'\n"
        "  - 修改后：SELECT * FROM user WHERE username = #{username}（参数化）\n"
        "【配置加固】启用 MyBatis 参数化：\n"
        "  mybatis.configuration.safe-result-handler-enabled: true\n"
        "【WAF 规则】拦截包含 extractvalue/updatexml/concat 的 username 参数\n"
        "【合规】OWASP A03:2021 注入；等保 2.0 8.1.3 输入校验"
    )

    # ===== 复现命令（可直接复制执行） =====
    reproduce = (
        'curl -X POST "http://target/demo/sqlInject" \\\n'
        '  -H "Content-Type: application/x-www-form-urlencoded" \\\n'
        '  -H "Accept: application/json" \\\n'
        "  -d 'username=admin%27+and+extractvalue(1,concat(0x7e,(select+database()),0x7e))--' \\\n"
        '  --cookie ""\n'
        "\n"
        '# 预期响应：HTTP 500 + 响应体含 "XPATH syntax error" 或 "database()" 报错特征'
    )

    # ===== 影响版本 =====
    affected_versions = ">=1.0,<2.0"

    # ===== CVSS v3.1 + 合规映射 =====
    cvss_vector = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    compliance = "等保2.0:8.1.3;OWASP:A03:2021"
    # CVSS Base Score 自动计算为 7.5（High）

    # ===== WAF 绕过支持 =====
    vuln_type = "sqli"
    supports_waf_bypass = True
    bypass_max_attempts = 3

    # 原始 payload（供 verify_with_bypass 变形）
    _ORIGINAL_PAYLOAD = (
        "admin' and extractvalue(1,concat(0x7e,(select database()),0x7e))--"
    )

    def verify(self, target, session):
        """执行 SQL 报错注入检测

        Args:
            target: 目标 URL（已归一化，以 / 结尾）
            session: SessionManager 实例

        Returns:
            ScanResult（CONFIRMED/SAFE/UNKNOWN 三态判定）
        """
        host = host_of(target)
        headers = {
            "Host": host,
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:98.0) Gecko/20100101 Firefox/98.0",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "Content-Type": "application/x-www-form-urlencoded",
            "X-Requested-With": "XMLHttpRequest",
            "Origin": f"http://{host}",
            "Referer": f"http://{host}/demo",
            "Connection": "close",
        }
        data = {"username": self._ORIGINAL_PAYLOAD}

        url = join_url(target, "/demo/sqlInject")
        try:
            resp = session.post(url, headers=headers, data=data, timeout=10)
        except Exception as e:
            # 铁律：网络异常 → UNKNOWN
            print(no(f"{self.name}（网络异常）"))
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=str(e),
            )

        text = resp.text or ""

        # 判定：SQL 报错特征（用 lib/matcher.py 统一降误报工具）
        if match_sql_error(text) or "database()" in text:
            print(ok(f"存在{self.name}"))
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence="响应含 SQL 报错特征（XPATH syntax error / database()）",
                fix=self.fix, fix_detail=self.fix_detail,
                reproduce=self.reproduce, cve=self.cve,
                cvss_vector=self.cvss_vector,
                extra={
                    "vuln_type": "sqli",
                    "payload_class": "extractvalue_database",
                    "plugin_name": "sql_inject_demo",
                },
            )

        # 明确反证：正常业务响应
        print(no(f"不存在{self.name}"))
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE,
            url=url, evidence="响应不含 SQL 报错特征",
        )

    def verify_with_bypass(self, target, bypass_session, bypass_ctx):
        """WAF 绕过验证：用当前策略变形 payload 后重试

        Args:
            target: 目标 URL
            bypass_session: BypassSession 实例（已应用传输层变换）
            bypass_ctx: BypassContext（含 strategy/waf_type/attempt 等）

        Returns:
            ScanResult（三态判定，与 verify() 一致）
        """
        # 1. 用当前策略变形 payload
        strategy = bypass_ctx.strategy
        if strategy is not None:
            tampered_payload = strategy.tamper_payload(
                self._ORIGINAL_PAYLOAD, bypass_ctx
            )
        else:
            tampered_payload = self._ORIGINAL_PAYLOAD

        # 2. 构造请求（bypass_session 已应用 headers/chunked/origin IP 变换）
        url = join_url(target, "/demo/sqlInject")
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept": "application/json",
        }
        data = {"username": tampered_payload}

        try:
            resp = bypass_session.post(url, headers=headers, data=data, timeout=10)
        except Exception as e:
            # 铁律：绕过异常 → UNKNOWN（绝不判 SAFE）
            return ScanResult(
                kind="vuln", name=self.name, status=STATUS_UNKNOWN,
                url=url, evidence=f"绕过异常（策略={strategy.strategy_id if strategy else 'N/A'}）: {e}",
            )

        text = resp.text or ""

        # 3. 判定（与 verify() 一致）
        if match_sql_error(text) or "database()" in text:
            return ScanResult(
                kind="vuln", name=self.name, severity=self.severity,
                status=STATUS_CONFIRMED, url=url,
                evidence=(
                    f"绕过成功（策略={strategy.strategy_id if strategy else 'N/A'}, "
                    f"layer={strategy.layer if strategy else 'N/A'}, "
                    f"attempt={bypass_ctx.attempt}）"
                ),
                fix=self.fix, fix_detail=self.fix_detail,
                reproduce=self.reproduce, cve=self.cve,
                cvss_vector=self.cvss_vector,
                extra={
                    "vuln_type": "sqli",
                    "payload_class": "extractvalue_database_bypassed",
                    "plugin_name": "sql_inject_demo",
                },
            )

        # 4. 绕过未命中，返回 SAFE（引擎会自动尝试下一策略）
        return ScanResult(
            kind="vuln", name=self.name, status=STATUS_SAFE,
            url=url,
            evidence=f"绕过后仍未命中特征（策略={strategy.strategy_id if strategy else 'N/A'}）",
        )
```

### 注册与验证

```bash
# 1. 注册到 plugin_list
# 编辑 plugins/ruoyi/__init__.py，添加：
#   from plugins.ruoyi.sql_inject_demo import SqlInjectDemoPlugin
#   plugin_list = [..., SqlInjectDemoPlugin]

# 2. 验证插件完整性
python main.py --plugin-check plugins/ruoyi/sql_inject_demo.py

# 3. 列出所有插件（确认已加载）
python main.py --plugin-list

# 4. 扫描
python main.py -u http://target/ -p

# 5. 启用 WAF 绕过扫描
python main.py -u http://target/ -p --bypass-waf auto
```

### 参考实现

仓库内已有的完整插件实现，可作为开发参考：

| 插件文件 | 漏洞类型 | 关键特性 |
|---------|---------|---------|
| `plugins/ruoyi/file_read.py` | 任意文件读取 | `match_all(["root", ":/"])` 双关键词联合判定 |
| `plugins/ruoyi/sql_inject_role.py` | POST 型报错注入 | 完整 headers / data 构造，`supports_waf_bypass=True` |
| `plugins/ruoyi/file_upload.py` | 任意文件上传 | 文件上传 multipart 构造 |
| `plugins/ruoyi/job_rce.py` | 定时任务 RCE | 未授权访问 + 命令拼接 |
| `plugins/ruoyi/thymeleaf_ssti.py` | 模板注入 | SpEL/Thymeleaf 表达式注入 |
| `plugins/ruoyi/nacos_unauth.py` | Nacos 未授权 | 未授权 API 访问 |
| `plugins/ruoyi/default_password.py` | 默认口令 | 登录爆破 |

更多开发规范、CI 集成、报告生成等内容请参阅：

- `docs/USAGE.md` — 完整 CLI 用法
- `docs/API.md` — Web API 服务模式
- `lib/plugin_sdk.py` — 插件 SDK 源码
- `plugins/base.py` — `PluginBase` 基类源码
- `core/loader.py` — 插件加载机制源码
- `lib/waf_bypass.py` — WAF 绕过策略库源码
- `lib/matcher.py` — 降误报判定工具源码
