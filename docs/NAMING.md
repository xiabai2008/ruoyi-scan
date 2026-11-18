# 命名规范与术语表

> 命名问题不是风格问题：同一个词表示四个意思，会让新人读错模块、改错层。
> 本页是唯一权威；新增模块/开关前先查这里。

---

## 1. 规范术语（一个词一个意思）

| 概念 | 规范名 | 说明 | 禁止 |
|---|---|---|---|
| 框架 | **framework** | `ruoyi` / `spring` / `common` / `jeecgboot` / `yudao`，对应 `plugins/<framework>/` | cms、category（CLI 旧名仅作别名） |
| 扫描阶段 | **category**（插件属性） | `vuln` / `recon` / `brute`，引擎按此分组执行 | phase（未统一，暂不用） |
| 漏洞条目 | **result**（数据）/ **finding**（报告行） | `ScanResult` 是数据；报告里的行叫 finding | vuln（仅用于 kind 取值） |
| 输出桥 | **output** | stdout/logging 分流，`emit()` | reporter |
| 登录链 | **login_chain** | 建立高权会话 | auth_chain |
| 凭据注入 | **auth_inject** | `--auth` 系列解析 | auth_scan |
| 登录后盘点 | **auth_surface** | 资产清单 + 越权矩阵 | surface（单独使用） |
| 攻击面清单 | **surface_inventory** | `session.surface` 的数据结构 | surface.py |
| 利用链 | **chains** | 引擎 `chains/engine.py`，定义 `chains/*.py`，步骤 `plugins/chain/` | core.chain |
| 扫描预设 | **scan_profiles** | quick/deep/compliance/dengbao | scan_templates |
| 报告渲染 | **report** | `core/report.py`（渲染）与 `lib/report_docx_template.py`（模板） | reporter |
| 插件生命周期 | **plugin_*** | base（契约）/ sdk（脚手架）/ repo（分发）/ loader（发现）/ router（选择） | 混用 |

---

## 2. 文件命名规则

- **角色后缀**：`*_renderer`（渲染）、`*_registry`（注册表）、`*_inventory`（清单）、
  `*_profile`（预设）、`*_chain`（链）、`*_cache`（缓存）。
- **限定词前置**：`report_docx_template` 而不是 `report_template`；`fingerprint_cache`
  而不是 `cache`。
- **一个模块一个职责**：文件名要能回答"它做什么、属于哪层"，而不是"它属于哪个工单"。

---

## 3. 已完成的改名（v1.8 清理）

| 旧名 | 新名 | 原因 |
|---|---|---|
| `lib/reporter.py` | `lib/output.py` | 它是输出桥，不是报告器 |
| `core/cache.py` | `core/fingerprint_cache.py` | 单一用途（指纹请求缓存） |
| `core/auth_chain.py` | `core/login_chain.py` | 与利用链区分 |
| `core/chain.py` | `chains/engine.py` | 链只保留一个命名空间 |
| `lib/auth_scan.py` | `lib/auth_inject.py` | 与登录链/盘点区分 |
| `lib/surface.py` | `lib/surface_inventory.py` | 与 auth_surface 区分 |
| `lib/scan_templates.py` | `lib/scan_profiles.py` | 它是预设，不是模板 |
| `lib/report_template.py` | `lib/report_docx_template.py` | 限定格式与用途 |
| `--category`（CLI） | `--framework`（`--category` 兼容别名） | 与插件 `category` 同名不同义 |
| `--plugin-new` | 删除，只留 `--plugin-init` | 同一功能两个入口 |

---

## 4. CLI 命名规则

- 开关名用**名词**（`--framework`、`--report`），行为用**动词**（`--no-dedup`、`--skip-preflight`）。
- 一个开关只能有一个 dest；别名必须显式标注"兼容别名"。
- 新增开关必须同时有消费方；门禁：`tests/test_cli_flag_consumers.py`。
- 帮助文本由 `build_parser()` 自动生成，不再维护第二张表。

---

## 5. 注释与历史编号

- 注释顺序：**规则（1–3 行）→ 为什么（≤5 行）→ 证据/链接**。
- `D7/E2/F1/G3/WP-1` 是历史工单编号，只允许出现在"背景"段，不作为句子主语。
- 长事故复盘移到 `docs/design/`，代码里留一句结论 + 链接。
- 每个模块首行建议：

  ```python
  """扫描编排：预检 → 侦察 → 指纹 → 能力 → 插件 → 报告。

  层：编排层（core）｜上游：cli/api｜下游：engine/session/plugins
  先读：docs/CONCEPTS.md#12-报告管线
  """
  ```

---

## 6. 测试命名

- 按**行为**命名：`test_path_scope.py`、`test_plugin_contracts.py`，不按工单号。
- 一个测试文件对应一个模块或一个概念；跨概念的放到 `test_e2e_*.py`。
- 失败信息写"用户可见的后果"，不写"断言失败"。
