# Phase 5 P0 验收（p0-1 / p0-2 / p0-3）

- 日期：2026-10-31
- 范围：只做 P0-1 / P0-2 / P0-3；P1/P2 未动
- 靶场：R1、R6（`restore_demo.py R1 R6`），R12 全程未触碰
- 约束：未合并认证链；未改靶场；P0-1 验收在 `RUOYI_SCAN_LOWPRIV_USER/PASS` **已 unset** 的前提下执行

> 后续补充（2026-10-31）：`auth_status` 已拆为 `{admin, surface}` 两类；P0-2 段落中的字符串形态是当时验收记录，当前形态与新增的公共登录器见 [phase5_p1_0_验收.md](phase5_p1_0_验收.md)。

---

## P0-1　删除硬编码靶场低权账号

### 改前

`config/settings.py:111-112`：

```python
USERNAME = os.environ.get("RUOYI_SCAN_LOWPRIV_USER", "scanner_low")
PASSWORD = os.environ.get("RUOYI_SCAN_LOWPRIV_PASS", "LowPriv_2026")
```

三个插件直接读 `settings.RuoYiLowPriv.USERNAME/PASSWORD`：

- `plugins/ruoyi/cve_2025_46174_resetpwd_scope.py`
- `plugins/ruoyi/cve_2025_70986_select_dept_tree.py`
- `plugins/ruoyi/job_invoke_target.py`

后果：`main.py -u http://127.0.0.1:19101`（未登录扫描）会拿默认账号偷偷登录，报出「低权账号越权」；R1 的 3 条 CONFIRMED 全部依赖这个默认值。

### 改后

- `config/settings.py`：`USERNAME = None` / `PASSWORD = None`，删除「由 lab/version_matrix/run_matrix.py seed 创建」的说明；`TARGET_USER_ID` 保留（只是探测对象，不是凭据）。
- 新增 `core/lowpriv.py`：`parse_account()` + `resolve_surface_account(session)`，只从 `SessionManager.surface_account` 读取显式账号，不读 settings/env。
- `ScanRequest.surface_account` 承接 `--surface-account`（可多次，取第一个可解析的）；orchestrator 在每次扫描的 session 上挂 `surface_account`，不写进程级 settings（并发隔离）。
- 三个插件在无显式账号时返回 `STATUS_UNKNOWN`，evidence 以「缺少低权账号，需 --surface-account user:pass 提供，无法判定越权」开头，并给出获取账号的 `fix`；**不返回 SAFE**。
- 三个插件仍各自使用 `isolated_auth_session` 建独立会话（未合并认证链）。

### 验收命令（环境已清空）

```bash
unset RUOYI_SCAN_LOWPRIV_USER RUOYI_SCAN_LOWPRIV_PASS
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19101 \
  --report artifacts/p5/R1-nolowpriv --no-pause --no-cta
```

### 结果

- `report.json` → `meta.auth_status = "not_attempted"`，`risk_distribution.total = 0`
- 三条 CVE 均为 `UNKNOWN`：
  - 定时任务调用目标未校验：「缺少低权账号，需 --surface-account user:pass 提供…」
  - 部门树越权访问：「缺少低权账号…」
  - 重置密码页数据权限绕过：「缺少低权账号…」
- `grep -c scanner_low artifacts/p5/R1-nolowpriv/report.json` → **0**
- `grep -c '缺少低权账号' …` → **3**
- 终端/HTML：HTML 顶部出现「未认证扫描」提示条

### 显式账号对照

```bash
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19101 \
  --auth-login admin:admin123 --auth-surface \
  --surface-account scanner_low:LowPriv_2026 \
  --surface-output artifacts/p5/R1-withlowpriv-surface.json \
  --report artifacts/p5/R1-withlowpriv --no-pause --no-cta
```

结果：

- 主扫描 `risk_distribution.total = 3`，三条 CVE 恢复为 `CONFIRMED`：
  - 定时任务调用目标未校验（写入 → 回读 → 还原）
  - 重置密码页数据权限绕过（泄露 `loginName=admin`）
  - 部门树越权访问（`treeData` 返回 `[]`，无数据泄露）
- `--auth-surface` 未崩溃：`盘点资产 32 个，越权/未授权发现 13 个`，`R1-withlowpriv-surface.json` 已写出
- `report.json` 中 `scanner_low` 出现 2 次（显式账号，预期）
- 主扫描 `meta.auth_status = "failed"`：`--auth-login` 走的是 `lib.auth_scan.auto_login`（不支持验证码），与 `--auth-surface` 的 `RuoYiAuthChain` 是两条独立链路；本次没有合并它们

### 结论：默认值撤掉后，R1 那 3 条 CONFIRMED 还剩几条是真的

- **没有默认值时，默认扫描剩 0 条 CONFIRMED**（3 条全部 UNKNOWN）。
- 显式提供 `scanner_low` 后，3 条都能复现：
  - **2 条强证据**：任务 `invokeTarget` 写入/回读/还原成功；重置密码页泄露 `admin`。
  - **1 条弱证据**：部门树端点缺权限注解，但 `treeData/0` 返回 `[]`，按任务书「拿到数据」口径证据不足（07 预期口径算命中）。
- 因此：**默认值贡献的是 3 条「未登录扫描里的低权结论」，不是 3 条纯编造**；撤掉默认值消除了「对没有该账号的真实客户环境也报越权」的假阳性，同时保留了显式账号下的可复现能力。

---

## P0-2　登录失败必须显式降级

### 改后

- `ScanRequest.auth_status`：`ok` / `failed` / `not_attempted`（API 直接传 `auth` 时由 `__post_init__` 提升为 `ok`）。
- 终端：`--auth-login` 失败时固定打印
  `[!] 本次为未认证扫描：--auth-login <user>:*** 登录失败，需要会话的插件结论不可信`。
- JSON：`report.json.meta.auth_status`。
- HTML：顶部「未认证扫描」横幅（failed / not_attempted 均显示，文案区分）。
- 统一降级入口：`core/orchestrator.py:downgrade_auth_required_results(results, auth_status, auth_required_names)`；插件通过 `PluginBase.requires_auth` 标记（本次标记 `sql_inject_role` / `sql_inject_dept` / `ruoyi_gen_rce`）。`auth_status != ok` 时，这些插件的 `CONFIRMED/SAFE` 原地降为 `UNKNOWN`，evidence 追加 `auth_status=...`。低权对照插件不标记（它们自己处理显式账号）。
- 单测：`tests/test_auth_status_gate.py`（3 例，覆盖 failed 降级、ok 保留、not_attempted 降级）。

### 验收命令

```bash
unset RUOYI_SCAN_LOWPRIV_USER RUOYI_SCAN_LOWPRIV_PASS
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19101 \
  --auth-login admin:wrongpass --report artifacts/p5/R1-badauth --no-pause --no-cta
```

### 结果

- `report.json.meta.auth_status = "failed"`
- `risk_distribution.total = 0`；所有需要会话的插件均为 `UNKNOWN`：
  - `POST型报错注入（role/dept）` → UNKNOWN
  - `RuoYi 代码生成模块 SSTI` → UNKNOWN
  - 三条低权 CVE → UNKNOWN（无显式账号）
- 终端出现：
  `[!] 本次为未认证扫描：--auth-login admin:*** 登录失败，需要会话的插件结论不可信`
- HTML 顶部出现「未认证扫描」提示条

R6 对照（错误口令 + `--auth-surface`）也验证了同一门禁：`auth_status=failed`，SQLi 结果为 UNKNOWN，HTML 横幅存在。

---

## P0-3　`--auth-surface` 返回值修复

### 改前

`lib/auth_surface.py` 三处二元组返回：

- `:507`（缺少 `--auth-login`）`return [], []`
- `:512`（高权登录失败）`return [], []`
- `:549`（成功路径）`return assets, vulns`

调用方 `cli/runner.py:613` 按 3 元组解包 → `ValueError: not enough values to unpack (expected 3, got 2)`，5/5 崩溃。

### 改后

三处统一为 3 元组：`return [], [], "login_failed"` / `return assets, vulns, "ok"`。

### 验收命令

```bash
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19106 \
  --auth-login admin:wrongpass --auth-surface \
  --surface-account scanner_low:LowPriv_2026 \
  --surface-output artifacts/p5/R6-surface.json \
  --report artifacts/p5/R6-wrongauth-surface --no-pause --no-cta
```

### 结果

- `rc=0`，无 traceback / `ValueError`
- 明确提示：`[!]认证后深度扫描未执行：高权登录失败（检查 --auth-login）`
- `R6-surface.json` 未写出（登录失败时明确不写，符合现有语义）
- 主扫描正常出报告，`meta.auth_status = "failed"`

---

## 三个门禁（改前 / 改后）

```bash
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py -q
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_logging_hygiene.py -q
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_session_isolation_gate.py -q
```

| 门禁 | 改前 | 改后 |
|---|---|---|
| `test_fp_baseline` | exit 0 | exit 0 |
| `test_logging_hygiene` | exit 0 | exit 0（1 个既有 skip） |
| `test_session_isolation_gate` | exit 0 | exit 0 |

补充回归：`tests/test_auth_surface.py`、`tests/test_anon_session_plugins.py`、`tests/regression_ruoyi.py`、`tests/test_report.py` 全部通过（`regression_ruoyi.py` 仅把测试脚手架改为显式注入假凭据 `test_user/test_pass`，未删语料/未加 skip）。

---

## 改动文件

- `config/settings.py`
- `core/lowpriv.py`（新增）
- `core/orchestrator.py`
- `core/report.py`
- `cli/runner.py`
- `lib/auth_surface.py`
- `plugins/base.py`
- `plugins/ruoyi/cve_2025_46174_resetpwd_scope.py`
- `plugins/ruoyi/cve_2025_70986_select_dept_tree.py`
- `plugins/ruoyi/job_invoke_target.py`
- `plugins/ruoyi/sql_inject_role.py`
- `plugins/ruoyi/sql_inject_dept.py`
- `plugins/ruoyi/ruoyi_gen_rce.py`
- `tests/test_auth_status_gate.py`（新增）
- `tests/test_anon_session_plugins.py`（测试脚手架显式注入假凭据）
- `tests/regression_ruoyi.py`（测试脚手架显式注入假凭据）

## 残余风险 / 未做

- **P1/P2 未做**：base-path/版本指纹/变体、Swagger 路径回显、子模式冲突、写入型探测 opt-in 都留到下一批。
- 主扫描 `auth_status` 只反映 `--auth-login`（`lib/auth_scan.auto_login`）；`--auth-surface` 的 `RuoYiAuthChain` 是另一条链，可能在主扫描 `failed` 时仍成功（R1-withlowpriv 即如此）。本批按约束**没有合并**两条链，报告里按主扫描状态标注。
- R12 未触碰；R8 未建成；WAF 场景未验证。
- 未修改 `artifacts/blind_20261031/` 封存证据。

**本轮停在 P0；P1/P2 等确认。**
