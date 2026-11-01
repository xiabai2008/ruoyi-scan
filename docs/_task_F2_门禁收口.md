# 工单 F2：门禁收口（只修格式与类型，不改判定、不提交）

> 执行者：opencode。验收者：lead（独立复跑）。
> 本单**不做 commit**，也不动判定逻辑。目标只有一个：让整棵树的 `ruff format` 与
> `mypy --strict` 变绿，为后续按批次提交扫清障碍。

---

## 零、边界

1. 工作区 `D:\HZR_PROJECTS\ruoyi-scan`，不读写工作区外路径。
2. **禁止 `git commit` / `git push` / `git add`**。本单只改文件。
3. 只允许改下面点名的 7 个文件；不许顺手重构、不许改名、不许删代码逻辑。
4. 工作区已有 40+ 条未提交改动（Phase 5 在制品 + F1/F1b + 并行会话），**不许回滚任何一条**。
5. 库代码禁裸 `print()`；本单不应新增任何 `print`。
6. Python 一律 `"D:\tools\Python 3.12.9\python.exe"`。

---

## 一、F2-1 格式：6 个文件

当前 `ruff format --check` 报这 6 个文件需要重排：

```
cli/runner.py
core/auth_chain.py
core/lowpriv.py
core/orchestrator.py
core/report.py
lib/auth_scan.py
```

执行：

```
"D:\tools\Python 3.12.9\python.exe" -m ruff format cli/runner.py core/auth_chain.py core/lowpriv.py core/orchestrator.py core/report.py lib/auth_scan.py
```

要求：

- 只做格式化，**不许顺手改逻辑**。跑完用 `git diff --numstat` 对比，改动行数应只来自换行/缩进/行合并。
- 如果格式化后某个文件出现语法/导入错误，说明原文件本身坏了，停下来报告，不要自行修逻辑。

---

## 二、F2-2 类型：4 个 mypy 错误

当前 `mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores` 报：

```
core\lowpriv.py:25: error: Function is missing a type annotation for one or more parameters  [no-untyped-def]
core\orchestrator.py:79: error: Missing type arguments for generic type "set"  [type-arg]
core\orchestrator.py:570: error: "SessionManager" has no attribute "surface_account"  [attr-defined]
core\orchestrator.py:1293: error: No overload variant of "dict" matches argument type "ScanResult"  [call-overload]
```

### 2.1 `core/lowpriv.py:25`

`resolve_surface_account(session)` 的 `session` 参数没注解。加 `session: Any`
（文件里已有 `Any` 导入的话直接复用；没有就补 `from typing import Any`）。

**不许**把参数改成具体类型 `SessionManager`：本模块被设计成可接受测试替身，绑死类型会破坏隔离性。

### 2.2 `core/orchestrator.py:79`

`auth_required_names: set` → `auth_required_names: set[str]`。

### 2.3 `core/orchestrator.py:570`

`session.surface_account = parsed` 写入了一个 `SessionManager` 未声明的属性。

改 `core/session.py`：

- `typing` 导入补 `Tuple`；
- 在 `SessionManager.__init__` 末尾加：

```python
# 显式低权账号（--surface-account）：由 orchestrator 在扫描前写入。
# 只允许由 CLI 显式提供，不设环境变量/配置兜底——默认值会在真实客户环境里
# 变成一个静默生效的假账号（Phase 5 P0-1 已删除硬编码靶场账号）。
self.surface_account: Optional[Tuple[str, str]] = None
```

**不许**改成 `getattr(session, "surface_account", None)` 绕过类型检查——那只是把错误藏起来。

### 2.4 `core/orchestrator.py:1293`

```python
rows = [r.to_dict() if hasattr(r, "to_dict") else dict(r) for r in results]
```

`results` 的类型是 `List[ScanResult]`，`dict(ScanResult)` 永远不合法。改成保留防御性回退、但类型可推导：

```python
rows = [r.to_dict() if hasattr(r, "to_dict") else dict(vars(r)) for r in results]
```

`vars()` 对 dataclass/普通对象都成立，且返回 `Dict[str, Any]`，mypy 可以通过。
如果 `vars()` 在某个替身上会抛 `TypeError`，改成显式 `getattr(r, "__dict__", {})`。

---

## 三、F2-3 行为不变证明

这 4 处类型改动必须证明没有改变行为，跑：

```
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_orchestrator.py tests/test_auth_surface.py tests/test_auth_status_gate.py tests/test_lowpriv.py -q
```

（`test_lowpriv.py` 不存在就跳过，并在报告里写明「无该测试文件」。）

另外单独验证 `--surface-account` 仍然生效：

```
"D:\tools\Python 3.12.9\python.exe" main.py -u http://127.0.0.1:19102 --surface-account scanner_low:LowPriv_2026 --report artifacts/f2/r2-low --no-pause --no-cta
```

期望：报告里「定时任务调用目标未校验」「重置密码页数据权限绕过」为 CONFIRMED（R2 在线时）。
若靶场不在线，记录「靶场不可用，未做真站验证」，不许伪造结果。

---

## 四、门禁（逐条跑，贴输出）

```
"D:\tools\Python 3.12.9\python.exe" -m ruff check common/ core/ lib/ api/ plugins/ chains/ cli/ tests/ main.py
"D:\tools\Python 3.12.9\python.exe" -m ruff format --check common/ core/ lib/ api/ plugins/ chains/ cli/ main.py
"D:\tools\Python 3.12.9\python.exe" -m mypy common/ core/ --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" -m mypy lib/reporter.py lib/soft404.py --strict --ignore-missing-imports --no-warn-unused-ignores
"D:\tools\Python 3.12.9\python.exe" -m pytest tests/test_fp_baseline.py tests/test_logging_hygiene.py tests/test_session_isolation_gate.py -q
"D:\tools\Python 3.12.9\python.exe" scripts/verification_matrix.py --check --max-none 13
"D:\tools\Python 3.12.9\python.exe" scripts/export_plugin_list.py --check
"D:\tools\Python 3.12.9\python.exe" scripts/check_version.py
```

全部必须 exit 0。任何一条红了，停下报告，不许用 `# type: ignore` 或 `noqa` 糊过去。

---

## 五、交付

1. 贴 8 条门禁的完整输出（含退出码）。
2. 贴 `git diff --numstat -- cli/runner.py core/auth_chain.py core/lowpriv.py core/orchestrator.py core/report.py lib/auth_scan.py core/session.py`。
3. 贴 `git status --short`，确认只多出 `core/session.py` 一条 M，其余条目与开工前一致。
4. 一句话结论：这 7 个文件的改动是否只包含「格式化 + 类型注解」。
5. **停在这里，不要 commit，不要开 C2。**
